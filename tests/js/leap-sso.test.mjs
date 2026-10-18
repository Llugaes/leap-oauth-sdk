// Behaviour tests for leap-sso.js with an in-memory browser and backend. Run: node --test tests/js/
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

vm.runInThisContext(
  readFileSync(new URL("../../src/leap_oauth_sdk/static/leap-sso.js", import.meta.url), "utf8"),
);
const { LeapSSO } = globalThis;

const ORIGIN = "https://app.example.com";
const CONFIG = {
  enabled: true,
  issuer: "https://auth.example.com",
  authorization_endpoint: "https://auth.example.com/api/oauth/authorize",
  client_id: "web-example",
  redirect_uri: ORIGIN + "/auth/callback",
  resource: ORIGIN + "/",
};
const BASE = "/api/auth/browser";

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const nowSeconds = () => Math.floor(Date.now() / 1000);
const session = (overrides = {}) => ({
  access_token: "at-1",
  refresh_token: "rt-1",
  expires_at: nowSeconds() + 300,
  ...overrides,
});

class Browser {
  constructor(href = ORIGIN + "/admin/page?x=1") {
    this.store = new Map();
    this.assigned = [];
    this.replaced = [];
    const browser = this;
    this.storage = {
      getItem: (key) => (browser.store.has(key) ? browser.store.get(key) : null),
      setItem: (key, value) => browser.store.set(key, String(value)),
      removeItem: (key) => browser.store.delete(key),
    };
    this.location = {
      assign: (url) => browser.assigned.push(url),
      replace: (url) => browser.replaced.push(url),
    };
    this.history = {
      replaceState: (_state, _title, path) => browser.navigate(new URL(path, browser.location.origin).href),
    };
    this.navigate(href);
  }

  navigate(href) {
    const url = new URL(href);
    Object.assign(this.location, { origin: url.origin, pathname: url.pathname, search: url.search, hash: url.hash });
  }

  // Simulates Leap Auth redirecting back to the callback with the pending state.
  callback(params) {
    const pending = JSON.parse(this.store.get("leap.sso.pending"));
    const query = new URLSearchParams({ state: pending.state, ...params });
    this.navigate(CONFIG.redirect_uri + "?" + query);
    this.assigned = [];
  }
}

class Backend {
  constructor(handlers = {}) {
    this.calls = [];
    this.handlers = { [BASE + "/config"]: () => json(200, CONFIG), ...handlers };
    this.fetch = async (url, init = {}) => {
      const call = {
        path: new URL(typeof url === "object" && url.url ? url.url : url, ORIGIN).pathname,
        method: init.method || (typeof url === "object" && url.method) || "GET",
        body: init.body ? JSON.parse(init.body) : undefined,
        authorization: new Headers(init.headers || {}).get("Authorization"),
      };
      this.calls.push(call);
      const handler = this.handlers[call.path];
      if (!handler) throw new TypeError("Failed to fetch");
      return handler(call, this.calls.filter((c) => c.path === call.path).length);
    };
  }

  count(path) {
    return this.calls.filter((call) => call.path === path).length;
  }
}

function start(browser, backend, options = {}) {
  const events = [];
  const sso = LeapSSO.create({
    endpointBase: BASE,
    storage: browser.storage,
    location: browser.location,
    history: browser.history,
    fetch: backend.fetch,
    sleep: async () => {},
    hooks: {
      onLoading: () => events.push(["loading"]),
      onLogin: (message, retryable) => events.push(["login", message, retryable]),
      onForbidden: (error) => events.push(["forbidden", error.status]),
    },
    ...options,
  });
  return { sso, events };
}

async function signedIn(backend = new Backend(), options = {}) {
  const browser = new Browser();
  browser.store.set("leap.sso.session", JSON.stringify(session()));
  return { browser, backend, ...start(browser, backend, options) };
}

test("first visit starts automatic SSO without allow_login", async () => {
  const browser = new Browser();
  const { sso, events } = start(browser, new Backend());

  assert.equal(await sso.boot(), "redirecting");

  assert.equal(browser.assigned.length, 1);
  const url = new URL(browser.assigned[0]);
  assert.equal(url.origin + url.pathname, CONFIG.authorization_endpoint);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("client_id"), "web-example");
  assert.equal(url.searchParams.get("resource"), CONFIG.resource);
  assert.equal(url.searchParams.has("allow_login"), false);
  const pending = JSON.parse(browser.store.get("leap.sso.pending"));
  assert.equal(url.searchParams.get("state"), pending.state);
  assert.equal(pending.next, "/admin/page?x=1");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pending.verifier));
  const challenge = Buffer.from(digest).toString("base64url");
  assert.equal(url.searchParams.get("code_challenge"), challenge);
  assert.deepEqual(events, [["loading"]]);
});

test("callback exchanges the code, stores the session and restores the deep link", async () => {
  const browser = new Browser();
  const backend = new Backend({
    [BASE + "/exchange"]: (call) => {
      assert.equal(call.body.code, "code-1");
      return json(200, { ...session(), token_type: "Bearer" });
    },
  });
  await start(browser, backend).sso.boot();
  const verifier = JSON.parse(browser.store.get("leap.sso.pending")).verifier;
  browser.callback({ code: "code-1" });

  const { sso } = start(browser, backend); // the page reloads on the callback URL
  assert.equal(await sso.boot(), "ready");

  assert.equal(backend.calls.find((c) => c.path === BASE + "/exchange").body.code_verifier, verifier);
  assert.equal(browser.location.pathname + browser.location.search, "/admin/page?x=1");
  const stored = JSON.parse(browser.store.get("leap.sso.session"));
  assert.deepEqual(stored, { access_token: "at-1", refresh_token: "rt-1", expires_at: stored.expires_at });
  assert.equal(browser.store.has("leap.sso.pending"), false);
});

test("invalid or failed callbacks stop instead of looping", async (t) => {
  const cases = [
    { name: "state mismatch", params: { code: "c", state: "forged" }, expect: ["login", "登录回调无效或已过期，请重新登录", false] },
    { name: "login required", params: { error: "login_required" }, expect: ["login", "请登录后继续", false] },
    { name: "exchange unavailable", params: { code: "c" }, exchange: json(503, { error: "auth_upstream_unavailable" }), expect: ["login", "身份服务暂时不可用，请重试", true] },
    { name: "exchange rejected", params: { code: "c" }, exchange: json(401, { error: "browser_session_invalid" }), expect: ["login", "登录已失效，请重新登录", false] },
    { name: "exchange forbidden", params: { code: "c" }, exchange: json(403, { error: "auth_access_denied" }), expect: ["forbidden", 403] },
    { name: "exchange misconfigured", params: { code: "c" }, exchange: json(502, { error: "auth_request_rejected" }), expect: ["login", "登录响应无效，请联系管理员", false] },
  ];
  for (const item of cases) {
    await t.test(item.name, async () => {
      const browser = new Browser();
      const backend = new Backend({ [BASE + "/exchange"]: () => item.exchange });
      await start(browser, backend).sso.boot();
      browser.callback(item.params);
      const { sso, events } = start(browser, backend);
      const state = await sso.boot();
      assert.equal(state, item.expect[0]);
      assert.deepEqual(events.at(-1), item.expect);
      assert.equal(browser.assigned.length, 0, "must not redirect again");
      assert.equal(backend.count(BASE + "/exchange"), item.exchange ? 1 : 0);
    });
  }
});

test("requests carry the bearer token and concurrent requests share one refresh", async () => {
  const backend = new Backend({
    [BASE + "/refresh"]: (call) => {
      assert.equal(call.body.refresh_token, "rt-1");
      return json(200, session({ access_token: "at-2", refresh_token: "rt-2" }));
    },
    "/api/data": () => json(200, { ok: true }),
  });
  const { browser, sso } = await signedIn(backend);
  browser.store.set("leap.sso.session", JSON.stringify(session({ expires_at: nowSeconds() + 30 })));

  const responses = await Promise.all([sso.fetch("/api/data"), sso.fetch("/api/data")]);

  assert.deepEqual(responses.map((r) => r.status), [200, 200]);
  assert.equal(backend.count(BASE + "/refresh"), 1);
  assert.deepEqual(backend.calls.filter((c) => c.path === "/api/data").map((c) => c.authorization), ["Bearer at-2", "Bearer at-2"]);
  assert.equal(JSON.parse(browser.store.get("leap.sso.session")).refresh_token, "rt-2");
});

test("sessions stored by the previous page shape still work", async () => {
  const backend = new Backend({ "/api/data": () => json(200, {}) });
  const { browser, sso } = await signedIn(backend);
  browser.store.set("leap.sso.session", JSON.stringify({ token: "old-at", expires_at: nowSeconds() + 300, root_session: { client_id: "web-example", refresh_token: "old-rt" } }));
  await sso.fetch("/api/data");
  assert.equal(backend.calls.at(-1).authorization, "Bearer old-at");
});

test("duplicated tab: rotation conflict drops the copied session and re-runs SSO", async () => {
  const backend = new Backend({
    [BASE + "/refresh"]: () => json(503, { error: "refresh_rotation_in_progress", retryable: true }),
  });
  const { browser, sso } = await signedIn(backend);
  browser.store.set("leap.sso.session", JSON.stringify(session({ expires_at: nowSeconds() + 10 })));

  await assert.rejects(sso.fetch("/api/data"), (error) => error.redirecting === true);

  assert.equal(backend.count(BASE + "/refresh"), 1, "never retries a spent refresh token");
  assert.equal(browser.store.has("leap.sso.session"), false);
  assert.equal(browser.assigned.length, 1);
});

test("refresh outage keeps credentials and reports a retryable error", async () => {
  const backend = new Backend({ [BASE + "/refresh"]: () => json(503, { error: "auth_upstream_unavailable" }) });
  const { browser, sso } = await signedIn(backend);
  browser.store.set("leap.sso.session", JSON.stringify(session({ expires_at: nowSeconds() + 10 })));

  await assert.rejects(sso.fetch("/api/data"), (error) => error.retryable && error.status === 503);
  delete backend.handlers[BASE + "/refresh"]; // network down
  await assert.rejects(sso.fetch("/api/data"), (error) => error.retryable && error.status === 0);

  assert.equal(JSON.parse(browser.store.get("leap.sso.session")).refresh_token, "rt-1");
  assert.equal(browser.assigned.length, 0);
});

test("401 triggers one automatic SSO per page load until a request succeeds", async () => {
  let status = 401;
  const backend = new Backend({ "/api/data": () => json(status, {}) });
  const { browser, sso, events } = await signedIn(backend);

  await assert.rejects(sso.fetch("/api/data"), (error) => error.redirecting);
  assert.equal(browser.assigned.length, 1);
  assert.equal(browser.store.has("leap.sso.session"), false);

  browser.store.set("leap.sso.session", JSON.stringify(session()));
  await assert.rejects(sso.fetch("/api/data"), (error) => error.status === 401 && !error.redirecting);
  assert.equal(browser.assigned.length, 1, "second 401 shows sign-in instead of looping");
  assert.deepEqual(events.at(-1), ["login", "登录已失效，请重新登录", false]);

  status = 200;
  browser.store.set("leap.sso.session", JSON.stringify(session()));
  await sso.fetch("/api/data");
  status = 401;
  await assert.rejects(sso.fetch("/api/data"), (error) => error.redirecting);
  assert.equal(browser.assigned.length, 2);
});

test("403 from the service is returned untouched", async () => {
  const backend = new Backend({ "/api/data": () => json(403, { error: "not_admin" }) });
  const { browser, sso, events } = await signedIn(backend);
  assert.equal((await sso.fetch("/api/data")).status, 403);
  assert.ok(browser.store.has("leap.sso.session"));
  assert.equal(browser.assigned.length, 0);
  assert.deepEqual(events, []);
});

test("logout clears credentials only after success and blocks one automatic SSO", async () => {
  let logoutStatus = 503;
  const backend = new Backend({ [BASE + "/logout"]: () => json(logoutStatus, logoutStatus === 200 ? { success: true } : { error: "auth_upstream_unavailable" }) });
  const { browser, sso, events } = await signedIn(backend);

  await assert.rejects(sso.logout(), (error) => error.message === "身份服务暂时不可用，请重试" && error.retryable);
  assert.ok(browser.store.has("leap.sso.session"));
  assert.equal(browser.store.has("leap.sso.logged-out"), false);

  logoutStatus = 200;
  await sso.logout();
  const call = backend.calls.at(-1);
  assert.deepEqual(call.body, { scope: "browser" });
  assert.equal(call.authorization, "Bearer at-1");
  assert.equal(browser.store.has("leap.sso.session"), false);
  assert.deepEqual(events.at(-1), ["login", "", false]);

  const reload = start(browser, backend);
  assert.equal(await reload.sso.boot(), "login", "logged-out page shows sign-in");
  assert.equal(browser.assigned.length, 0);
  assert.equal(await start(browser, backend).sso.boot(), "redirecting", "marker is read once");
});

test("logout without a local session asks to sign in first", async () => {
  const browser = new Browser();
  const backend = new Backend();
  const { sso } = start(browser, backend);
  await assert.rejects(sso.logout(), (error) => error.message === "登录已过期，请重新登录后再退出");
  assert.equal(backend.count(BASE + "/logout"), 0);
});

test("explicit login sends allow_login and clears the logged-out marker", async () => {
  const browser = new Browser();
  browser.store.set("leap.sso.logged-out", "1");
  const { sso } = start(browser, new Backend());
  await sso.login();
  assert.equal(new URL(browser.assigned[0]).searchParams.get("allow_login"), "1");
  assert.equal(browser.store.has("leap.sso.logged-out"), false);
});

test("cookie mode retries a cross-replica rotation conflict and never stores tokens", async () => {
  const backend = new Backend({
    "/api/data": (_call, n) => (n < 3 ? json(503, { error: "refresh_rotation_in_progress" }) : json(200, {})),
  });
  const browser = new Browser();
  const { sso } = start(browser, backend, { credentialMode: "cookie" });

  assert.equal(await sso.boot(), "ready");
  assert.equal((await sso.fetch("/api/data")).status, 200);
  assert.equal(backend.count("/api/data"), 3);
  assert.equal(backend.calls.at(-1).authorization, null);
  assert.equal(browser.store.has("leap.sso.session"), false);

  backend.handlers["/api/data"] = () => json(503, { error: "refresh_rotation_in_progress" });
  assert.equal((await sso.fetch("/api/data")).status, 503, "gives up after bounded retries");
});

test("cookie mode exchange and 401 handling", async () => {
  const backend = new Backend({
    [BASE + "/exchange"]: () => json(200, { expires_at: nowSeconds() + 300 }),
    "/api/data": () => json(401, {}),
  });
  const browser = new Browser();
  await start(browser, backend, { credentialMode: "cookie" }).sso.login();
  browser.callback({ code: "code-1" });
  const { sso } = start(browser, backend, { credentialMode: "cookie" });
  assert.equal(await sso.boot(), "ready");
  assert.equal(browser.store.has("leap.sso.session"), false);
  await assert.rejects(sso.fetch("/api/data"), (error) => error.status === 401 && !error.redirecting);
});

test("page on a non-canonical origin moves to the callback origin first", async () => {
  const browser = new Browser("https://alias.example.com/admin?q=1#top");
  const { sso } = start(browser, new Backend());
  assert.equal(await sso.boot(), "redirecting");
  assert.deepEqual(browser.replaced, [ORIGIN + "/admin?q=1#top"]);
  assert.equal(browser.assigned.length, 0);
});

test("disabled or unreachable configuration", async () => {
  const disabled = start(new Browser(), new Backend({ [BASE + "/config"]: () => json(200, { enabled: false }) }));
  assert.equal(await disabled.sso.boot(), "disabled");

  const down = start(new Browser(), new Backend({ [BASE + "/config"]: () => json(500, {}) }));
  assert.equal(await down.sso.boot(), "login");
  assert.deepEqual(down.events.at(-1), ["login", "无法读取登录配置，请重试", true]);

  const broken = start(new Browser(), new Backend({ [BASE + "/config"]: () => json(200, { enabled: true }) }));
  assert.equal(await broken.sso.boot(), "login");
});

test("options are validated and storage keys can keep existing names", async () => {
  assert.throws(() => LeapSSO.create({ endpointBase: "https://evil.example.com/x" }), TypeError);
  assert.throws(() => LeapSSO.create({ endpointBase: BASE, credentialMode: "token" }), TypeError);

  const browser = new Browser();
  browser.store.set("app.admin.session", JSON.stringify(session()));
  const backend = new Backend({ "/api/data": () => json(200, {}) });
  const { sso } = start(browser, backend, { storageKeys: { session: "app.admin.session" } });
  assert.equal(await sso.boot(), "ready");
  await sso.fetch("/api/data");
  assert.equal(backend.calls.at(-1).authorization, "Bearer at-1");
});

function heldCrypto() {
  let release, entered;
  const held = new Promise((resolve) => (release = resolve));
  const started = new Promise((resolve) => (entered = resolve));
  return {
    crypto: {
      getRandomValues: (bytes) => crypto.getRandomValues(bytes),
      subtle: { digest: async (...args) => { entered(); await held; return crypto.subtle.digest(...args); } },
    },
    started,
    release: () => release(),
  };
}

test("concurrent 401s start a single authorization transaction", async () => {
  const backend = new Backend({ "/api/session": () => json(401, {}), "/api/services": () => json(401, {}) });
  const { browser, sso, events } = await signedIn(backend);

  const results = await Promise.allSettled([sso.fetch("/api/session"), sso.fetch("/api/services")]);

  assert.deepEqual(results.map((r) => r.reason.redirecting), [true, true]);
  assert.equal(browser.assigned.length, 1);
  const state = new URL(browser.assigned[0]).searchParams.get("state");
  assert.equal(JSON.parse(browser.store.get("leap.sso.pending")).state, state);
  assert.deepEqual(events, [], "no sign-in flash while redirecting");
});

test("logout cancels an automatic sign-in that is still preparing PKCE", async () => {
  const held = heldCrypto();
  const backend = new Backend({ "/api/data": () => json(401, {}), [BASE + "/logout"]: () => json(200, {}) });
  const { browser, sso } = await signedIn(backend, { crypto: held.crypto });

  const pending = sso.fetch("/api/data").catch((error) => error);
  await held.started;
  browser.store.set("leap.sso.session", JSON.stringify(session()));
  await sso.logout();
  held.release();
  await pending;

  assert.equal(browser.assigned.length, 0, "late navigation is dropped");
  assert.equal(browser.store.has("leap.sso.pending"), false);
});

test("logout during the callback exchange drops the late tokens", async () => {
  let releaseExchange;
  const backend = new Backend({
    [BASE + "/exchange"]: () => new Promise((resolve) => (releaseExchange = () => resolve(json(200, session())))),
  });
  const browser = new Browser();
  await start(browser, backend).sso.boot();
  browser.callback({ code: "code-1" });
  const { sso } = start(browser, backend);

  const booting = sso.boot();
  while (!releaseExchange) await new Promise((resolve) => setImmediate(resolve));
  await sso.logout().catch(() => {});
  releaseExchange();
  await booting;

  assert.equal(browser.store.has("leap.sso.session"), false);
});

test("a late 401 for an older token retries with the newer one", async () => {
  const backend = new Backend({
    "/api/data": (call) => (call.authorization === "Bearer at-2" ? json(200, {}) : json(401, {})),
  });
  const { browser } = await signedIn(backend);
  const original = backend.fetch;
  backend.fetch = async (url, init) => {
    const response = await original(url, init);
    // Another request refreshed the session while this one was in flight.
    browser.store.set("leap.sso.session", JSON.stringify(session({ access_token: "at-2", refresh_token: "rt-2" })));
    return response;
  };
  const { sso: racing } = start(browser, backend);

  assert.equal((await racing.fetch("/api/data")).status, 200);
  assert.equal(JSON.parse(browser.store.get("leap.sso.session")).access_token, "at-2");
  assert.equal(browser.assigned.length, 0);
});

test("a refresh that finishes after logout does not restore credentials", async () => {
  let releaseRefresh;
  const backend = new Backend({
    [BASE + "/refresh"]: () => new Promise((resolve) => (releaseRefresh = () => resolve(json(200, session({ access_token: "late" }))))),
    [BASE + "/logout"]: () => json(200, {}),
    "/api/data": () => json(200, {}),
  });
  const { browser, sso } = await signedIn(backend);
  browser.store.set("leap.sso.session", JSON.stringify(session({ expires_at: nowSeconds() + 10 })));

  const pending = sso.fetch("/api/data").catch((error) => error);
  while (!releaseRefresh) await new Promise((resolve) => setImmediate(resolve));
  browser.store.set("leap.sso.session", JSON.stringify(session()));
  await sso.logout();
  releaseRefresh();
  const error = await pending;

  assert.equal(error.status, 401);
  assert.equal(browser.store.has("leap.sso.session"), false);
});

test("logout uses the result of an existing refresh before invalidating its epoch", async () => {
  let releaseRefresh;
  const backend = new Backend({
    [BASE + "/refresh"]: () => new Promise(resolve => {
      releaseRefresh = () => resolve(json(200, session({access_token:"at-rotated",refresh_token:"rt-rotated"})));
    }),
    [BASE + "/logout"]: call => {
      assert.equal(call.authorization,"Bearer at-rotated");
      return json(200,{});
    },
    "/api/data": () => json(200,{}),
  });
  const {browser,sso} = await signedIn(backend);
  browser.store.set("leap.sso.session",JSON.stringify(session({expires_at:nowSeconds()+10})));
  const pending = sso.fetch("/api/data").catch(error=>error);
  while(!releaseRefresh) await new Promise(resolve=>setImmediate(resolve));
  const loggingOut = sso.logout().then(()=>({ok:true}),error=>({error}));
  releaseRefresh();
  await pending;
  assert.deepEqual(await loggingOut,{ok:true});
  assert.equal(backend.count(BASE+"/refresh"),1);
  assert.equal(backend.count(BASE+"/logout"),1);
  assert.equal(browser.store.has("leap.sso.session"),false);
});

test("logout outage after joining refresh keeps the rotated credentials for retry", async () => {
  let releaseRefresh, logoutStatus=503;
  const backend=new Backend({
    [BASE+"/refresh"]:()=>new Promise(resolve=>{
      releaseRefresh=()=>resolve(json(200,session({access_token:"at-rotated",refresh_token:"rt-rotated"})));
    }),
    [BASE+"/logout"]:call=>{
      assert.equal(call.authorization,"Bearer at-rotated");
      return json(logoutStatus,logoutStatus===200?{}:{error:"auth_upstream_unavailable"});
    },
    "/api/data":()=>json(200,{}),
  });
  const {browser,sso}=await signedIn(backend);
  browser.store.set("leap.sso.session",JSON.stringify(session({expires_at:nowSeconds()+10})));
  const pending=sso.fetch("/api/data").catch(error=>error);
  while(!releaseRefresh) await new Promise(resolve=>setImmediate(resolve));
  const loggingOut=sso.logout().catch(error=>error);
  releaseRefresh();
  await pending;
  assert.equal((await loggingOut).retryable,true);
  assert.equal(JSON.parse(browser.store.get("leap.sso.session")).refresh_token,"rt-rotated");
  logoutStatus=200;
  await sso.logout();
  assert.equal(backend.count(BASE+"/refresh"),1);
  assert.equal(backend.count(BASE+"/logout"),2);
  assert.equal(browser.store.has("leap.sso.session"),false);
});

for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
  test(`late 401 never replays ${method} or discards newer credentials`, async () => {
    const backend = new Backend({ "/api/data": () => json(401, { error: "old_token" }) });
    const { browser } = await signedIn(backend);
    const original = backend.fetch;
    backend.fetch = async (url, init) => {
      const response = await original(url, init);
      browser.store.set("leap.sso.session", JSON.stringify(session({ access_token: "at-new", refresh_token: "rt-new" })));
      return response;
    };
    const { sso } = start(browser, backend);
    const response = await sso.fetch("/api/data", { method, body: "{}" });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "old_token" });
    assert.equal(backend.count("/api/data"), 1);
    assert.equal(JSON.parse(browser.store.get("leap.sso.session")).refresh_token, "rt-new");
    assert.equal(browser.assigned.length, 0);
  });

  test(`cookie rotation conflict never replays ${method}`, async () => {
    const backend = new Backend({ "/api/data": () => json(503, { error: "refresh_rotation_in_progress" }) });
    const browser = new Browser();
    const { sso } = start(browser, backend, { credentialMode: "cookie" });
    const response = await sso.fetch("/api/data", { method, body: "{}" });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "refresh_rotation_in_progress" });
    assert.equal(backend.count("/api/data"), 1);
    assert.equal(browser.assigned.length, 0);
  });
}

test("a POST Request object is not mistaken for the default GET retry policy", async () => {
  const backend = new Backend({ "/api/data": () => json(401, { error: "old_token" }) });
  const { browser } = await signedIn(backend);
  const original = backend.fetch;
  backend.fetch = async (url, init) => {
    const response = await original(url, init);
    browser.store.set("leap.sso.session", JSON.stringify(session({ access_token: "at-new" })));
    return response;
  };
  const { sso } = start(browser, backend);
  const response = await sso.fetch(new Request(ORIGIN + "/api/data", { method: "POST", body: "{}" }));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "old_token" });
  assert.equal(backend.count("/api/data"), 1);
  assert.equal(backend.calls[0].method, "POST");
});

for (const method of ["GET", "HEAD", "OPTIONS"]) {
  test(`${method} keeps one bounded retry when another request already refreshed`, async () => {
    const backend = new Backend({ "/api/data": (_call, n) => json(n === 1 ? 401 : 200, {}) });
    const { browser } = await signedIn(backend);
    const original = backend.fetch;
    backend.fetch = async (url, init) => {
      const response = await original(url, init);
      browser.store.set("leap.sso.session", JSON.stringify(session({ access_token: "at-new" })));
      return response;
    };
    const { sso } = start(browser, backend);
    assert.equal((await sso.fetch("/api/data", { method })).status, 200);
    assert.equal(backend.count("/api/data"), 2);
    assert.equal(browser.assigned.length, 0);
  });
}

test("exhausting a safe retry preserves a still-newer session and readable 401", async () => {
  const backend = new Backend({ "/api/data": () => json(401, { error: "old_token" }) });
  const { browser } = await signedIn(backend);
  const original = backend.fetch;
  backend.fetch = async (url, init) => {
    const response = await original(url, init);
    browser.store.set("leap.sso.session", JSON.stringify(session({ access_token: "at-" + (backend.count("/api/data") + 1) })));
    return response;
  };
  const { sso } = start(browser, backend);
  const response = await sso.fetch("/api/data");
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "old_token" });
  assert.equal(backend.count("/api/data"), 2);
  assert.equal(JSON.parse(browser.store.get("leap.sso.session")).access_token, "at-3");
  assert.equal(browser.assigned.length, 0);
});

test("a safe retry keeps the sent method even if the caller mutates its init", async () => {
  let browser;
  const init = { method: "GET" };
  const backend = new Backend({ "/api/data": (_call, n) => {
    init.method = "POST";
    browser.store.set("leap.sso.session", JSON.stringify(session({ access_token: "at-new" })));
    return json(n === 1 ? 401 : 200, {});
  } });
  const signed = await signedIn(backend);
  browser = signed.browser;
  assert.equal((await signed.sso.fetch("/api/data", init)).status, 200);
  assert.deepEqual(backend.calls.map(call => call.method), ["GET", "GET"]);
});
