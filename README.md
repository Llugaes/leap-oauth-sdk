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

## C-X export verification (0.5.0.dev4)

`verify_identity_binding_export` verifies a bounded, signed identity-binding export. It does
not accept access tokens, fetch people, change grants or activate a migration.

```python
from leap_oauth_sdk import IdentityBindingExportRejected, verify_identity_binding_export

try:
    export = verify_identity_binding_export(
        jws,
        issuer="https://auth.example.com",
        request_subjects=["usr_one", "usr_two"],
        jwks=trusted_public_jwks,
    )
except IdentityBindingExportRejected:
    abort_import()
else:
    # Verify your pinned epoch/generation/chain and local authorization separately.
    consume_verified_mapping(export.items)
```

Provide exactly one of `jwks` and `jwks_url`. A URL must be HTTP(S), with no credentials,
query or fragment. Each call makes one GET with a five-second timeout, no redirects,
cache or retry, and at most 64 KiB of raw UTF-8 JSON. JWS format and request errors cause
no HTTP call. All verification failures use the same fixed rejection message.
`VerifiedExport` and its items are immutable. C-X has no implicit freshness or permission
meaning; the caller owns the pinned proof, file limits and activation decision.

The six public exports are `EXPORT_TYP`, `EXPORT_VER`, `EXPORT_MAX_ITEMS`,
`IdentityBindingExportRejected`, `VerifiedExport` and `verify_identity_binding_export`.
Static JWKS selection matches AS commit `3b499cd`, including its selected-key-only private
material check. It reuses the SDK's existing `jwt.PyJWK.from_dict` conversion primitive;
it does not apply the token verifier's additional key-use filtering. Existing access token
and browser verification are unchanged. The shared, producer-generated component vectors
are in repository `testdata/identity_binding_export_vectors.json` and contain no private key.

## Feishu native v2

### Controlled migration support (0.5.0.dev2)

`allowed_channels` controls the strict native profile. For original v1 channels such as
`device` or `bot`, pass a separate explicit `legacy_allowed_channels=("device", "bot", "feishu_oauth")`
matching that service's original policy. It defaults to `allowed_channels`; it never broadens
the native channel policy. Browser transition SSO requires both sets to contain only
`feishu_oauth`, so a general MCP verifier cannot be reused as a browser verifier.


`leap_oauth_sdk.transition` provides an explicit temporary receiver for deployments that
must keep valid v1 sessions working while moving to native keys. It is not enabled by
default and does not change either existing token verifier.

```python
from leap_oauth_sdk import LeapAuthConfig
from leap_oauth_sdk.transition import MigrationIdentityMap, TransitionAccessTokenVerifier

# Trusted server material, validated before activation. Never accept a map from a request.
identity_map = MigrationIdentityMap(
    issuer="https://auth.example.com",
    feishu_tenant="configured-tenant-key",
    revision="verified-mapping-revision",
    legacy_to_person={"usr_existing": "feishu:user_id:Exact-User"},
)
verifier = TransitionAccessTokenVerifier(
    LeapAuthConfig(issuer=identity_map.issuer, audience="example-service"),
    identity_map=identity_map,
    required_purpose="access",
    allowed_channels=("feishu_oauth",),
)
identity = verifier.verify(bearer_token)  # verify_async also supported
# Read the storage format + mapping revision and grant in the same consistent transaction.
assert current_mapping_revision == identity.mapping_revision
stored_subject = identity_map.storage_subject(identity.person_key, current_storage_contract)
```

Both legal profiles identify the same `(issuer, person_key)`. `wire_subject`, `profile` and
the signed `raw_claims` remain available for session checks and audit. A v1 result does not
fabricate a native `person`, tenant claim or client ID. Only verified human v1 identities
in the exact frozen mapping are accepted. Unknown aliases, duplicate mappings, invalid
profiles and failed signatures are rejected; no email or display-name fallback exists.
The selector decodes only a header of at most 4 KiB; native tokens retain the shared
16 KiB strict envelope bound before PyJWT parses their payload. Legacy payloads retain
the existing compatible registered-claims policy, including valid larger claim sets.

`storage_subject(..., "principal_v1")` performs one exact reverse lookup for pre-existing
rows; `"feishu_native_v2"` uses the person key directly. Never query both formats or select
a second key after a denied lookup. The business owns transaction/epoch consistency, all
writers, grants and revocation. The SDK does not activate a migration or provide a readiness
proof for the supplied mapping.

For browser sessions, explicitly pass this verifier to
`BrowserSSO(..., token_profile="transition", expected_feishu_tenant=...)`, using only
`required_purpose="access"` and both native/legacy channels restricted to `feishu_oauth`. Existing encrypted
cookies retain their root/refresh credentials and extra fields; after successful identity
verification the cookie subject becomes the canonical person key. Native browser client
binding and online logout/revocation checks still apply.
Transition browser mode requires `browser_client_id` on v1 browser tickets. Before
activation, original browser tickets must have this binding or refresh normally through
the original v1 path. An unbound ticket cannot be treated as belonging to this client.

Remove the transition receiver and mapping only after an authoritative census proves all
in-scope refresh families, clients and storage have migrated and old access tokens can no
longer be valid. A fixed waiting period alone does not prove that condition. Runtime mapping
or storage-state failures must not silently fall back to a previous identity format.
The final receiver is strict native. Once cookie subjects have become person keys,
rolling the receiver back to the old v1-only SDK would require users to sign in again.
An issuance rollback must keep the transition receiver until its own exit conditions
are satisfied. Cookies and encryption contexts must not be shared between tenants.

### Online self binding and dual browser replies (0.5.0.dev3)

`SelfBindingResolver` is a separate, opt-in client for a user's own identity mapping.
Pass existing verifiers bound to this service's issuer and audience; it verifies the
token locally before sending that same Bearer to `/api/identity/binding/self`.
It never uses a directory/service credential or changes signed claims.

```python
from leap_oauth_sdk import (
    SelfBinding, SelfBindingMissing, SelfBindingResolver, SelfBindingUnavailable,
)

resolver = SelfBindingResolver(
    config,
    legacy_verifier=legacy_verifier,
    native_verifier=native_verifier,
    enrollment="off",
)
result = resolver.resolve(access_token)  # resolve_async is also available
if isinstance(result, SelfBinding):
    # Select a storage format explicitly; this object does not grant permission.
    legacy_key = result.legacy_subject
    person_key = result.person_key
    # Only lookup="person" identifies the canonical legacy storage key.
elif isinstance(result, SelfBindingMissing):
    pass  # Keep the existing v1 authorization path; never clear the login here.
elif isinstance(result, SelfBindingUnavailable):
    pass  # Treat this lookup as unavailable and allow a later retry.
```

Legacy and native indexes stay separate, so a legacy alias cannot become a native
storage key. Freshness is capped by the server, the local cap and the verified token
expiry; cache hits do not extend it. `epoch_invalidated()` reports only what this
resolver instance has observed. OBO never calls the endpoint and can only reuse a
still-fresh direct cache entry. Enrollment is unavailable in this release; no background
threads, tasks, service credentials or new logins are created. Call `close()` when done.

For browser refresh replies that can use either original token profile, use
`BrowserSSO(..., token_profile="dual", verifier=DualAccessTokenVerifier(...),
expected_feishu_tenant=...)`. The dual verifier takes the original `legacy` and `native`
verifiers. A custom verifier implementing the same sync/async protocol is also accepted.
Browser SSO does no mapping: it returns the verified wire identity and the AS's rotated
refresh credential unchanged. Passing `expected_subject_id` to dual refresh is rejected
before sending the request. The three existing browser profiles retain their behavior.

### Strict native receiver

The `leap_oauth_sdk.native` module accepts the final native contract. Its `ver` is
`sakamoto_feishu_access_token.v2`, its header is `typ=at+jwt`, and `client_id`, `purpose`,
`feishu_tenant` and an exact five-field `person` object are mandatory. Earlier pilot tokens
with the same `ver` are rejected. Native verification never invokes the Principal v1 verifier.

```python
from leap_oauth_sdk import LeapAuthConfig
from leap_oauth_sdk.native import NativeAccessTokenVerifier, grant_matches

native = NativeAccessTokenVerifier(
    LeapAuthConfig(issuer="https://auth.example.com", audience="example-service"),
    expected_feishu_tenant="configured-tenant-key",
    required_purpose="access",
    allowed_channels=("feishu_oauth", "feishu_bot", "obo"),
)
identity = native.verify(bearer_token)  # verify_async is also available
if grant_matches(stored_person_key, stored_union_fingerprint, identity):
    ...  # apply this grant's local business permissions
```

Reuse one verifier per process for JWKS caching and rotation. Static JWKS can instead be
passed to `verify_native_access_token(token, *, issuer, audience, jwks,
expected_feishu_tenant, required_purpose, allowed_channels)`. The pure helper defaults to
EdDSA/RS256; `NativeAccessTokenVerifier` uses `LeapAuthConfig.allowed_algorithms` (EdDSA by
default). Native leeway is limited to 60 seconds. All signature and registered-claim
checks remain enabled.

`identity.authorization_key` is the exact `(issuer, person_key)` pair. Scope stored grants
to the configured issuer before calling `grant_matches`; the helper compares person keys
without trimming, case folding or normalization. Only the fixed `feishu:user_id:` prefix
is removed, so a user ID may contain a colon. `identity.display.name` and `.email`, the
`client_id`, and delegated actors are never grant subjects. A configured union fingerprint
requires an exact non-null match; this check alone does not establish account-generation
or employment lifecycle guarantees. `unknown` source status stays unknown; `inactive` is
rejected.

For browser SSO, select a single local profile explicitly:

```python
sso = BrowserSSO(
    config, browser_client,
    token_profile="feishu_native_v2",
    expected_feishu_tenant="configured-tenant-key",
)
```

`exchange_code`, `refresh` and `check_session` then use the native verifier, including their
async variants. Browser identity must also match the registered client. Omitting
`token_profile` keeps the existing Principal v1 behavior. No response triggers a retry using
the other identity contract. PKCE, state, cookie encoding and `leap-sso.js` are unchanged.

### Native directory and grant selection

Use a backend-held `directory_reader` credential; never send it to the browser:

```python
from leap_oauth_sdk.native import DirectoryClient

directory = DirectoryClient(
    config,
    lookup_token=directory_reader_credential,
    bound_app_id="central-app-id",
)
person = directory.resolve(email="person@example.com")
person = directory.resolve(union_id="native-union-id")
person = directory.resolve(open_id="central-app-open-id")  # uses bound_app_id
grant_person = directory.resolve_for_grant(person_key=person.person_key)
stored_grant = grant_person.to_dict()  # only person_key and optional union_id
```

`resolve` accepts exactly one of `person_key`, `user_id`, `email`, `union_id`, `open_id`.
An Open ID needs `app_id=` unless `bound_app_id` was supplied; conflicting App bindings
are refused before a request. External-App Open IDs must first be converted by their own
App. The client never retries a failed locator using a different locator. Email and union
lookups are checked against the returned fresh profile; Open-ID checking remains on the
server because that field is not returned.

`search(q, limit=20)` returns `.items` and `.has_more`, and `batch(person_keys)` returns one
typed result per distinct requested key in request order. Batch requires the final
`results` contract, checks full coverage and rejects duplicate, extra or mismatched results;
legacy `items/invalid_keys` are not a fallback. `resolve_for_grant` always performs a fresh
resolve and rejects inactive users. Search profiles alone cannot create grants, and changing
an email's owner never rewrites a previously selected key. Sync calls have matching `_async`
methods. Upstream failures remain retryable; rejected reader credentials are configuration
errors and do not start user login. No user access token, phone or employee-ID locator is
supported.

The shared contract file is `testdata/feishu_native_v2_vectors.json` in this repository and
source distribution, or `leap_oauth_sdk/testdata/feishu_native_v2_vectors.json` in the wheel.
It fixes a test clock and contains full headers/claims: consumers sign each vector with a
local test key, apply any `signature=tampered` marker and check its `accept` result. It is
the same file for signing-side, resource-side and non-Python contract tests.

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
