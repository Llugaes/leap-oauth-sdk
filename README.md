# leap-oauth-sdk

Business-side SDK for services that accept access tokens issued by Leap Auth, an OAuth 2.1
authorization server. It verifies tokens locally against the server's JWKS and reports every
failure as one of four error categories, so each service handles retries, re-login and
permission errors the same way.

Status: alpha. This release contains access token verification, the server side of browser
sign-in (code exchange, refresh, online session check, logout), encrypted cookie sessions and
`leap-sso.js`, the matching browser module. Directory lookup and member management are planned.

## Install

```bash
uv add leap-oauth-sdk
```

Python 3.12 or newer.

## Verify an access token

Create one verifier per process and reuse it, so the JWKS cache is shared by all requests.

```python
from leap_oauth_sdk import AccessTokenVerifier, LeapAuthConfig, OAuthSDKError

verifier = AccessTokenVerifier(
    LeapAuthConfig(
        issuer="https://auth.example.com",  # must equal the token's iss claim exactly
        audience="example-service",         # this service's own audience
    )
)

async def current_subject(bearer_token: str) -> str:
    try:
        context = await verifier.verify_async(bearer_token)
    except OAuthSDKError as exc:
        # exc.status is the suggested local HTTP status; exc.code is stable for logs.
        raise HTTPException(status_code=exc.status, detail={"error": exc.code})
    return context.subject_id
```

`verify()` is the blocking variant. Both share the same cache.

The SDK does not read environment variables and has no default hosts. Load settings in your
own configuration layer and pass them to `LeapAuthConfig`.

## Browser sign-in

One browser client is registered per service and environment. The browser runs authorization
code + PKCE with a top-level redirect; your backend exchanges the code. Tokens never appear in
URLs. Two ways to hold credentials:

- **bearer**: the page keeps the access and refresh token in `sessionStorage` and sends
  `Authorization: Bearer`. Your API verifies with `check_session()`.
- **cookie**: the backend keeps both tokens in an encrypted HttpOnly cookie and the page never
  sees them. Use `CookieSessionManager`.

```python
from leap_oauth_sdk import BrowserClientConfig, BrowserSSO, LeapAuthConfig, OAuthSDKError

sso = BrowserSSO(
    LeapAuthConfig(issuer="https://auth.example.com", audience="example-service"),
    BrowserClientConfig(
        client_id="web-example",
        redirect_uri="https://app.example.com/auth/callback",  # exact registered callback
        resource="https://app.example.com/",
    ),
)
```

Serve these routes under one base path (bearer mode shown). On `OAuthSDKError` every route
responds with `exc.status`, `exc.headers` and the body `exc.to_dict()`:

| Route | Handler |
| --- | --- |
| `GET {base}/config` | `sso.browser_config()` |
| `POST {base}/exchange` `{code, code_verifier}` | `sso.exchange_code(...).to_browser_payload()` |
| `POST {base}/refresh` `{refresh_token}` | `sso.refresh(...).to_browser_payload()` |
| `POST {base}/logout` `{scope}` + Bearer | `sso.logout(token, scope)` |

Protected API routes call `sso.check_session(bearer_token)` on every request and must not
cache the result, so that signing out in one service takes effect everywhere on the next
request. An already-ended sign-in counts as a successful logout.

### Browser module

`leap-sso.js` ships inside the package; `leap_oauth_sdk.static_dir()` returns its directory.

```html
<script src="/static/leap-sso.js"></script>
<script>
  const sso = LeapSSO.create({
    endpointBase: "/api/auth/browser",
    credentialMode: "bearer",          // or "cookie"
    storagePrefix: "example.admin",    // sessionStorage keys; storageKeys can keep old names
    defaultNext: "/admin",
    hooks: {
      onLoading: () => showSpinner(),
      onLogin: (message, retryable) => showSignIn(message, retryable),
      onForbidden: () => showNoAccess(),
    },
  });
  const state = await sso.boot();      // "ready" | "redirecting" | "login" | "forbidden" | "disabled"
  if (state === "ready") render(await (await sso.fetch("/api/me")).json());
  signInButton.onclick = () => sso.login();
  signOutButton.onclick = () => sso.logout().catch(showRetry);
</script>
```

- `boot()` finishes a callback, restores the deep link, or starts one automatic sign-in that
  only reuses an existing sign-in. Every page load makes at most one automatic attempt; a
  failed callback shows sign-in instead of looping.
- `fetch()` adds the bearer token and refreshes 60 seconds before expiry, one refresh at a time.
  A 401 drops local credentials and makes the one automatic attempt; 403 and other statuses
  are returned to you untouched.
- A duplicated tab copies `sessionStorage` and with it a refresh token the other tab may
  already have spent. The server then answers `refresh_rotation_in_progress`; the module drops
  the copy and signs in again through SSO instead of replaying it. In cookie mode the same
  answer comes from two replicas refreshing at once, so the request is retried briefly.
- `logout()` sends `scope=browser`, which ends the sign-in for every service in this browser.
  Credentials are cleared only when the backend confirms; the next page load shows sign-in once.
- Messages default to Chinese; pass `messages` to override.

### Cookie sessions

```python
from leap_oauth_sdk import CookieCipher, CookieSessionManager

cookies = CookieSessionManager(sso, CookieCipher(secret))  # secret: 32+ characters

# callback:    value = cookies.issue(sso.exchange_code(code, verifier), extra={"csrf": csrf})
# per request:
result = cookies.resolve(request.cookies.get("example_session"))
if result.cookie is not None:  # refreshed or migrated: write it back
    response.set_cookie(
        "example_session", result.cookie, max_age=cookies.max_age(result.session),
        httponly=True, secure=True, samesite="lax",
    )
# logout:      cookies.logout(value), then delete the cookie
```

`resolve()` refreshes shortly before expiry and checks the sign-in online. Requests carrying
the same old cookie share one refresh within the process, and the result is reused for ten
seconds so a late request never replays the spent refresh token. `CookieCipher` accepts
`previous_secrets` for rotation and a `context` string; `legacy_loader` lets a service read its
old cookie format once and rewrite it.

## Verification rules

- Signature algorithm must be in `allowed_algorithms` (default `EdDSA` only); the token must
  carry a `kid` that exists in the JWKS.
- Registered claims `exp`, `iat`, `nbf`, `iss`, `sub`, `aud`, `jti` are required; `aud` must be a
  single string equal to `audience`; `iss` must equal `issuer`.
- `ver` must equal `token_version`; `status` must be `active`; `source.channel` must be present;
  `purpose` must be in `allowed_purposes` (a token without `purpose` counts as `access`).
- The JWKS is cached for `jwks_cache_seconds` (300). An unknown `kid` forces at most one refetch
  per `jwks_refresh_cooldown_seconds` (10). A failed or malformed fetch is never cached and never
  falls back to expired keys. Redirects are not followed.

Business authorization (roles, resources, fields, actions) stays in your service. A verified
token only proves who the caller is.

## Error categories

| Exception | Status | Meaning | What to do |
| --- | --- | --- | --- |
| `Retryable` | 503 | Authorization server or JWKS unavailable, timeout, 5xx or 429, `temporarily_unavailable` (including `refresh_rotation_in_progress`) | Keep credentials, retry later |
| `ReauthRequired` | 401 | Token invalid, expired, revoked or unknown key; upstream 401 or `invalid_grant`; sign-in no longer active | Clear credentials, sign in again |
| `Forbidden` | 403 | Principal inactive, token purpose not accepted, upstream 403 | Show a permission error, do not re-login |
| `InvalidResponse` | 502 | Malformed upstream response, redirect, `invalid_client`, token not bound to a browser sign-in | Alert; do not loop sign-in |

All four inherit from `OAuthSDKError` and expose `code`, `message`, `status` and `retryable`;
`to_dict()` and `headers` (`Retry-After` when retryable) build your error response. Messages
never include tokens or upstream response bodies.

## Development

```bash
uv sync --extra dev
bash scripts/check.sh   # also runs the browser module tests (Node 20+)
```

## License

MIT
