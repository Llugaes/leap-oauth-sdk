/*
 * leap-sso.js - browser half of Leap Auth sign-in (MIT, part of leap-oauth-sdk).
 *
 * Authorization code + PKCE with a top-level redirect; no iframes, popups or third-party
 * cookies. Tokens never appear in URLs. The page talks only to its own backend:
 *
 *   GET  {endpointBase}/config    -> BrowserSSO.browser_config()
 *   POST {endpointBase}/exchange  {code, code_verifier}
 *   POST {endpointBase}/refresh   {refresh_token}            (bearer mode only)
 *   POST {endpointBase}/logout    {scope}
 *
 * Error responses use OAuthSDKError.to_dict(): {"error": code, "message", "retryable"}.
 */
(function (global) {
  "use strict";

  var ROTATION_IN_PROGRESS = "refresh_rotation_in_progress";
  var PENDING_TTL_MS = 5 * 60 * 1000;
  var REFRESH_MARGIN_MS = 60 * 1000;
  var COOKIE_RETRY_LIMIT = 3;

  var DEFAULT_MESSAGES = {
    configUnavailable: "无法读取登录配置，请重试",
    disabled: "网页登录尚未配置",
    callbackInvalid: "登录回调无效或已过期，请重新登录",
    loginRequired: "请登录后继续",
    sessionExpired: "登录已失效，请重新登录",
    forbidden: "当前账号没有访问权限",
    unavailable: "身份服务暂时不可用，请重试",
    invalidResponse: "登录响应无效，请联系管理员",
    logoutFailed: "尚未完成退出，请重试",
    logoutNeedsLogin: "登录已过期，请重新登录后再退出",
    redirecting: "正在跳转登录",
  };

  class LeapSSOError extends Error {
    constructor(message, details) {
      super(message);
      var info = details || {};
      this.name = "LeapSSOError";
      this.status = info.status || 0;
      this.code = info.code || "";
      this.retryable = Boolean(info.retryable);
      this.redirecting = Boolean(info.redirecting);
    }
  }

  function base64url(bytes) {
    var text = "";
    for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
    return global.btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function safeNext(value, fallback) {
    return typeof value === "string" && value.charAt(0) === "/" && value.charAt(1) !== "/" &&
      value.indexOf("\\") < 0 ? value : fallback;
  }

  async function readJson(response) {
    try {
      var data = await response.json();
      return data && typeof data === "object" ? data : {};
    } catch (_) {
      return {};
    }
  }

  // Accepts the SDK payload and the older {token, root_session: {refresh_token}} shape, so
  // sessions stored by a previous page version keep working.
  function normalizeSession(value) {
    if (!value || typeof value !== "object") return null;
    var accessToken = value.access_token || value.token;
    var refreshToken = value.refresh_token || (value.root_session && value.root_session.refresh_token);
    var expiresAt = Number(value.expires_at);
    if (typeof accessToken !== "string" || !accessToken || typeof refreshToken !== "string" ||
        !refreshToken || !Number.isFinite(expiresAt)) return null;
    return {access_token: accessToken, refresh_token: refreshToken, expires_at: expiresAt};
  }

  function create(options) {
    var opts = Object.assign({
      credentialMode: "bearer",
      storagePrefix: "leap.sso",
      defaultNext: "/",
      hooks: {},
      messages: {},
    }, options || {});
    if (typeof opts.endpointBase !== "string" || opts.endpointBase.charAt(0) !== "/") {
      throw new TypeError("endpointBase must be a same-origin path such as /api/auth/browser");
    }
    if (opts.credentialMode !== "bearer" && opts.credentialMode !== "cookie") {
      throw new TypeError("credentialMode must be 'bearer' or 'cookie'");
    }
    var base = opts.endpointBase.replace(/\/+$/, "");
    var bearer = opts.credentialMode === "bearer";
    var messages = Object.assign({}, DEFAULT_MESSAGES, opts.messages);
    var keys = Object.assign({
      session: opts.storagePrefix + ".session",
      pending: opts.storagePrefix + ".pending",
      loggedOut: opts.storagePrefix + ".logged-out",
    }, opts.storageKeys || {});
    var storage = opts.storage || global.sessionStorage;
    var location = opts.location || global.location;
    var history = opts.history || global.history;
    var fetcher = opts.fetch || global.fetch.bind(global);
    var now = opts.now || Date.now;
    var sleep = opts.sleep || function (ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); };
    var crypto = opts.crypto || global.crypto;

    var settings = null;
    // At most one automatic sign-in per page load; cleared after a successful request.
    var attempted = false;
    var leaving = false;
    var refreshing = null;
    var beginning = null;
    // Bumped by logout: a sign-in, callback or refresh started earlier must not finish.
    var epoch = 0;

    function hook(name) {
      var fn = opts.hooks[name];
      if (typeof fn === "function") fn.apply(null, Array.prototype.slice.call(arguments, 1));
    }

    function categoryError(status, code, fallback) {
      if (status === 401) return new LeapSSOError(messages.sessionExpired, {status: 401, code: code});
      if (status === 403) return new LeapSSOError(messages.forbidden, {status: 403, code: code});
      // 502 is InvalidResponse: an upstream or configuration fault; alert, do not retry.
      if (status === 502) return new LeapSSOError(messages.invalidResponse, {status: 502, code: code});
      if (status === 0 || status === 503 || status === 429 || status >= 500) {
        return new LeapSSOError(messages.unavailable, {status: status, code: code, retryable: true});
      }
      return new LeapSSOError(fallback, {status: status, code: code});
    }

    async function post(path, body, token) {
      var headers = {"Content-Type": "application/json", "Accept": "application/json"};
      if (token) headers.Authorization = "Bearer " + token;
      var response;
      try {
        response = await fetcher(base + path, {
          method: "POST", credentials: "same-origin", cache: "no-store", headers: headers,
          body: JSON.stringify(body),
        });
      } catch (_) {
        throw categoryError(0, "network_error", messages.unavailable);
      }
      return {response: response, data: await readJson(response)};
    }

    async function config() {
      if (settings) return settings;
      var response;
      try {
        response = await fetcher(base + "/config", {cache: "no-store", credentials: "same-origin"});
      } catch (_) {
        throw new LeapSSOError(messages.configUnavailable, {retryable: true});
      }
      if (!response.ok) throw new LeapSSOError(messages.configUnavailable, {status: response.status, retryable: true});
      var data = await readJson(response);
      if (data.enabled && (!data.issuer || !data.client_id || !data.redirect_uri || !data.resource)) {
        throw new LeapSSOError(messages.invalidResponse, {status: 502});
      }
      settings = data;
      return settings;
    }

    function loadSession() {
      try {
        return normalizeSession(JSON.parse(storage.getItem(keys.session) || "null"));
      } catch (_) {
        return null;
      }
    }

    function saveSession(data) {
      var session = normalizeSession(data);
      if (!session) throw new LeapSSOError(messages.invalidResponse, {status: 502});
      storage.setItem(keys.session, JSON.stringify(session));
      return session;
    }

    function clearSession() {
      storage.removeItem(keys.session);
    }

    // The callback origin is canonical; PKCE state lives in this origin's sessionStorage.
    function redirectToCanonical(cfg) {
      var callback = new URL(cfg.redirect_uri);
      if (location.origin === callback.origin) return false;
      location.replace(callback.origin + location.pathname + location.search + location.hash);
      return true;
    }

    // One authorization redirect at a time: concurrent 401s must not create two PKCE
    // transactions, or the second overwrites the state the first callback needs.
    function begin(explicit) {
      if (!beginning) {
        beginning = startAuthorization(explicit, epoch).finally(function () { beginning = null; });
      }
      return beginning;
    }

    async function startAuthorization(explicit, turn) {
      var cfg = await config();
      if (turn !== epoch) return false;
      if (!cfg.enabled) throw new LeapSSOError(messages.disabled, {status: 503});
      if (redirectToCanonical(cfg)) return true;
      attempted = true;
      var verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
      var state = base64url(crypto.getRandomValues(new Uint8Array(32)));
      var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
      if (turn !== epoch) return false;
      storage.removeItem(keys.loggedOut);
      storage.setItem(keys.pending, JSON.stringify({
        state: state, verifier: verifier, created: now(),
        next: location.pathname + location.search + location.hash,
      }));
      var url = new URL(cfg.authorization_endpoint || cfg.issuer.replace(/\/+$/, "") + "/api/oauth/authorize");
      var params = {
        response_type: "code", client_id: cfg.client_id, redirect_uri: cfg.redirect_uri,
        resource: cfg.resource, code_challenge: base64url(new Uint8Array(digest)),
        code_challenge_method: "S256", state: state,
      };
      if (explicit) params.allow_login = "1";
      url.search = new URLSearchParams(params).toString();
      location.assign(url.href);
      return true;
    }

    // Lost or rejected credentials: one automatic attempt per page load, then show sign-in.
    async function unauthorized(error) {
      if (bearer) clearSession();
      if (beginning || (!attempted && !leaving)) {
        attempted = true;
        await begin(false);
        throw new LeapSSOError(messages.redirecting, {status: 401, code: error.code, redirecting: true});
      }
      if (!leaving) hook("onLogin", error.message, false);
      throw error;
    }

    async function complete(cfg) {
      var turn = epoch;
      var query = new URLSearchParams(location.search);
      if (!query.has("code") && !query.has("error")) return false;
      if (location.pathname !== new URL(cfg.redirect_uri).pathname) return false;
      var flow = null;
      try {
        flow = JSON.parse(storage.getItem(keys.pending) || "null");
      } catch (_) {
        flow = null;
      }
      storage.removeItem(keys.pending);
      // A callback consumes this page's automatic attempt until a request succeeds.
      attempted = true;
      history.replaceState(null, "", safeNext(flow && flow.next, opts.defaultNext));
      if (!flow || !query.get("state") || query.get("state") !== flow.state ||
          now() - Number(flow.created) > PENDING_TTL_MS) {
        throw new LeapSSOError(messages.callbackInvalid, {status: 400});
      }
      if (query.has("error")) {
        throw new LeapSSOError(messages.loginRequired, {status: 401, code: query.get("error")});
      }
      var result = await post("/exchange", {code: query.get("code"), code_verifier: flow.verifier});
      if (!result.response.ok) {
        throw categoryError(result.response.status, result.data.error, messages.sessionExpired);
      }
      if (turn !== epoch) return false; // logged out while exchanging: drop the late tokens
      if (bearer) saveSession(result.data);
      storage.removeItem(keys.loggedOut);
      return true;
    }

    function stopped(error) {
      if (error.status === 403) {
        hook("onForbidden", error);
        return "forbidden";
      }
      hook("onLogin", error.message, Boolean(error.retryable));
      return "login";
    }

    async function boot() {
      hook("onLoading");
      try {
        var cfg = await config();
        if (!cfg.enabled) return "disabled";
        if (redirectToCanonical(cfg)) return "redirecting";
        if (await complete(cfg)) return "ready";
        if (storage.getItem(keys.loggedOut)) {
          // Written only by an explicit logout; read once.
          storage.removeItem(keys.loggedOut);
          attempted = true;
          hook("onLogin", "", false);
          return "login";
        }
        if (bearer && !loadSession()) {
          await begin(false);
          return "redirecting";
        }
        return "ready";
      } catch (error) {
        return stopped(error instanceof LeapSSOError ? error : new LeapSSOError(messages.unavailable, {retryable: true}));
      }
    }

    async function refreshNow(session) {
      var turn = epoch;
      var result = await post("/refresh", {refresh_token: session.refresh_token});
      if (turn !== epoch) throw new LeapSSOError(messages.sessionExpired, {status: 401});
      if (result.response.ok) return saveSession(result.data);
      var error = categoryError(result.response.status, result.data.error, messages.sessionExpired);
      // In bearer mode a rotation conflict means another tab (a duplicated tab copies
      // sessionStorage) already spent this refresh token. Retrying cannot succeed and a late
      // replay would revoke the chain, so drop it and get a new chain through SSO.
      if (error.status === 401 || error.code === ROTATION_IN_PROGRESS) {
        return unauthorized(categoryError(401, error.code, messages.sessionExpired));
      }
      throw error;
    }

    async function freshSession() {
      var session = loadSession();
      if (!session) return unauthorized(new LeapSSOError(messages.loginRequired, {status: 401}));
      if (session.expires_at * 1000 - now() > REFRESH_MARGIN_MS) return session;
      if (!refreshing) {
        refreshing = refreshNow(session).finally(function () { refreshing = null; });
      }
      return refreshing;
    }

    async function request(url, init, retry) {
      var options = Object.assign({}, init || {});
      var headers = new Headers(options.headers || {});
      var used = null;
      if (bearer) {
        used = (await freshSession()).access_token;
        headers.set("Authorization", "Bearer " + used);
      }
      options.headers = headers;
      var response = await fetcher(url, options);
      if (response.status === 401) {
        var data = await readJson(response);
        // A late answer to a request sent with an older token must not drop newer credentials.
        var current = bearer ? loadSession() : null;
        if (current && current.access_token !== used && retry < 1) return request(url, init, retry + 1);
        return unauthorized(categoryError(401, data.error, messages.sessionExpired));
      }
      // Cookie mode: two replicas refreshed the shared cookie at once. The winner's
      // Set-Cookie is already in the jar, so a short retry succeeds.
      if (!bearer && response.status === 503 && retry < COOKIE_RETRY_LIMIT) {
        var body = await readJson(response.clone());
        if (body.error === ROTATION_IN_PROGRESS) {
          await sleep(200 * Math.pow(2, retry));
          return request(url, init, retry + 1);
        }
      }
      if (response.ok) attempted = false;
      return response;
    }

    async function logout(scope) {
      leaving = true;
      try {
        try {
          var current = bearer ? loadSession() : null;
          // A spent refresh must first store its replacement so logout can revoke it.
          // A newer, already-fresh session can log out immediately and discard late work.
          if (refreshing && current && current.expires_at * 1000 - now() <= REFRESH_MARGIN_MS) {
            await refreshing;
          }
        } finally {
          epoch++;
        }
        var token = null;
        if (bearer) {
          if (!loadSession()) throw new LeapSSOError(messages.logoutNeedsLogin, {status: 401});
          token = (await freshSession()).access_token;
        }
        var result = await post("/logout", {scope: scope || "browser"}, token);
        if (!result.response.ok) {
          // Keep credentials so the user can retry; never claim a logout that did not happen.
          var error = categoryError(result.response.status, result.data.error, messages.logoutFailed);
          if (error.status === 401) error.message = messages.logoutNeedsLogin;
          throw error;
        }
        clearSession();
        storage.setItem(keys.loggedOut, "1");
        attempted = true;
        hook("onLogin", "", false);
      } finally {
        leaving = false;
      }
    }

    return {
      boot: boot,
      fetch: function (url, init) { return request(url, init, 0); },
      login: function () { leaving = false; return begin(true); },
      logout: logout,
      config: config,
    };
  }

  global.LeapSSO = {create: create, LeapSSOError: LeapSSOError, ROTATION_IN_PROGRESS: ROTATION_IN_PROGRESS};
})(typeof window !== "undefined" ? window : globalThis);
