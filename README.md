# leap-oauth-sdk

Business-side SDK for services that accept access tokens issued by Leap Auth, an OAuth 2.1
authorization server. It verifies tokens locally against the server's JWKS and reports every
failure as one of four error categories, so each service handles retries, re-login and
permission errors the same way.

Status: alpha. This release contains access token verification, the server side of browser
sign-in (code exchange, refresh, online session check, logout), encrypted cookie sessions,
`leap-sso.js` (the matching browser module), principal lookup for admin pickers and admin
member rules.

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

### Verify registered claims for an existing token contract

Use `verify()` or `verify_async()` for the complete access-token contract above. Services
that already accept a different metadata shape can instead use `verify_claims()` or
`verify_claims_async()`. Both return `VerifiedTokenClaims(raw_claims=...)`, with original
claim types and no invented identity fields.

```python
from leap_oauth_sdk import AccessTokenVerifier, LeapAuthConfig, RegisteredClaimsPolicy

verifier = AccessTokenVerifier(
    LeapAuthConfig(
        issuer="https://auth.example.com",
        audience="example-service",
        allowed_algorithms=("EdDSA", "RS256"),
        leeway_seconds=0,
        jwks_refresh_cooldown_seconds=30,
    )
)
verified = verifier.verify_claims(
    bearer_token,
    policy=RegisteredClaimsPolicy.PYJWT_COMPATIBLE,
)
claims = verified.raw_claims
# Apply the service's established version, purpose, status, revocation and authorization
# rules before using these claims as an authenticated application identity.
```

`RegisteredClaimsPolicy` has exactly two presets; arbitrary JWT options are not accepted:

| Rule | `STRICT` (default) | `PYJWT_COMPATIBLE` (explicit) |
| --- | --- | --- |
| Required registered claims | `exp`, `iat`, `nbf`, `iss`, `sub`, `aud`, `jti` | `exp`, `iat`, `sub`, `aud`; issuer validation also requires `iss` |
| Audience | One exact string | A string or string array containing the configured audience |
| Optional `nbf` / `jti` | Required | Validated when present |
| Key selection | Signing key matching `kid` and explicit `alg` | PyJWT-style signing-key order and exact `kid`; missing JWK `alg` is inferred by PyJWT |
| Additional size limits | 16 KiB token, 64 KiB JWKS | No additional token/JWKS byte cap |
| First unknown-key refresh | Respects the interval since the last fetch | Immediate, then limited by `jwks_refresh_cooldown_seconds` |

Both presets always verify the signature, algorithm allowlist, issuer, audience and token
timestamps. The compatible preset preserves the registered-claim and public-key selection
behavior used with PyJWT 2.10.1, including numeric-string timestamps and the first matching
signing key. It never retries a failed signature with another key. Private key material is
rejected, and keys declaring an encryption or other non-signature use are excluded in both
presets. No preset disables verification or changes the configured issuer or audience.

**Raw verified claims are not a complete application identity.** Neither raw-claims method
validates application metadata such as `status`, `ver`, `purpose`, `source` or
`principal_type`. Missing fields remain missing. The caller must enforce its own existing
contract. The complete `verify()` and `verify_async()` methods always use `STRICT`, retain
all metadata checks and return the unchanged `AccessTokenContext` type.

All four methods share one JWKS cache and one in-flight fetch, including mixed sync/async
callers. Size and key-selection checks apply on every use, so compatible cache entries do
not bypass strict checks. A failed refresh invalidates previously cached keys and enters
the configured failure cooldown. Empty, malformed or unusable JWKS produce an
`InvalidResponse` infrastructure error; transport failures produce `Retryable`. A usable
JWKS with no matching key produces `ReauthRequired`. Services can map infrastructure
errors to their established availability response without treating them as invalid tokens.
HTTP redirects are not followed. Call blocking methods from a worker thread rather than
an asynchronous event-loop thread.

Structurally broken entries in a mixed JWKS are infrastructure failures, rather than being
skipped to accept a later key. Key-shape or construction errors that previously escaped as
unhandled exceptions are reported as `InvalidResponse`.

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
request; pass `verified=` when the same token was already verified locally. An already-ended
sign-in counts as a successful logout.

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
  are returned to you untouched. A late 401 for an older bearer token keeps any newer session:
  `GET`, `HEAD` and `OPTIONS` may retry once; other methods return the original readable 401
  without replaying the request. A safe retry also keeps the newer session if its retry limit
  is reached. The method of a `Request` object is respected.
- A duplicated tab copies `sessionStorage` and with it a refresh token the other tab may
  already have spent. The server then answers `refresh_rotation_in_progress`; the module drops
  the copy and signs in again through SSO instead of replaying it. In cookie mode the same
  answer comes from two replicas refreshing at once, so safe methods are retried briefly.
  `POST`, `PUT`, `PATCH`, `DELETE` and other non-safe methods return the original 503 response.
  Business writes are never automatically replayed; the application decides whether and how
  to ask the user to retry.
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

## Principal lookup

Admin pages pick people through the authorization server instead of typing subject ids.
`PrincipalDirectory` uses a service lookup credential, never the admin's own token.

```python
from leap_oauth_sdk import PrincipalCandidate, PrincipalDirectory

directory = PrincipalDirectory(config, lookup_token=lookup_token)

result = directory.search("ann")           # principals plus directory users; < 2 chars → empty
rows = [c.to_dict() for c in result.candidates]   # send to the page; the page posts one back
picked = PrincipalCandidate.from_dict(posted)     # untrusted: only ids are kept
accepted = directory.canonicalize([picked, "usr_existing"])
```

- `canonicalize()` binds directory users to principals, follows aliases to the canonical
  subject and requires active principals of `allowed_principal_types` (default `human`). It is
  all or nothing: any rejected pick raises `PrincipalSelectionError` (422) whose `rejected`
  maps each pick to a reason, and nothing is accepted.
- `validate()` returns status and profile per subject in batches of 100, for listing.
- A rejected lookup credential is reported as `InvalidResponse`, not `ReauthRequired`: it is a
  configuration problem, and the admin must not be sent to sign in again.
- `api_base_url` points lookups at an internal address of the authorization server.

## Admin members

`MemberService` applies the same rules in every service; storage stays in the service.

```python
from leap_oauth_sdk import JsonFileMemberStore, MemberPolicy, MemberService

members = MemberService(
    MemberPolicy(owners=frozenset({owner_subject})),  # owners come only from configuration
    JsonFileMemberStore("/data/admins.json"),          # or your own MemberStore
    directory,                                         # None: list and remove only
)

members.role_for(subject)                  # "owner" | "member" | None, read on every call
snapshot = members.list()                  # profiles from validate(); degrades when it fails
version = members.add(actor, [picked], expected_version=snapshot.version)
members.remove(actor, subject, expected_version=version)
```

- Only owners add or remove members, owners cannot be removed, and owners in a selection are
  ignored. Every write carries the version the admin saw; a concurrent change raises
  `MemberError` `member_version_conflict` (409) instead of overwriting.
- `MemberStore` has two methods, `load()` and `apply(change, expected_version=)`; `apply` must
  persist the change and its `MemberChange` audit record atomically. `JsonFileMemberStore` is a
  reference implementation for a single replica on a persistent volume.
- `MemberError` has the same `to_dict()` shape as the SDK errors. Messages are English; map
  `code` to your own wording.

## Verification rules

- Signature algorithm must be in `allowed_algorithms` (default `EdDSA` only); the token must
  carry a `kid` that exists in the JWKS.
- Registered claims `exp`, `iat`, `nbf`, `iss`, `sub`, `aud`, `jti` are required; `aud` must be a
  single string equal to `audience`; `iss` must equal `issuer`.
- `ver` must equal `token_version`; `status` must be `active`; `source.channel` must be present;
  `purpose` must be in `allowed_purposes` (a token without `purpose` counts as `access`).
- The JWKS is cached for `jwks_cache_seconds` (300). An unknown `kid` forces at most one refetch
  per `jwks_refresh_cooldown_seconds` (10). A failed or malformed fetch is never cached, never
  falls back to expired keys and is not retried within the same cooldown. Redirects are not
  followed.

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
