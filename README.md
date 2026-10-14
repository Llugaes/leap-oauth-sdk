# leap-oauth-sdk

Business-side SDK for services that accept access tokens issued by Leap Auth, an OAuth 2.1
authorization server. It verifies tokens locally against the server's JWKS and reports every
failure as one of four error categories, so each service handles retries, re-login and
permission errors the same way.

Status: alpha. This release contains configuration, error types and access token
verification. Browser sign-in, refresh, logout and directory lookup helpers are planned.

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
| `Retryable` | 503 | Authorization server or JWKS temporarily unavailable | Keep credentials, retry later |
| `ReauthRequired` | 401 | Token invalid, expired, revoked or unknown key | Clear credentials, sign in again |
| `Forbidden` | 403 | Principal inactive, or token purpose not accepted here | Show a permission error, do not re-login |
| `InvalidResponse` | 502 | Unexpected upstream data or misconfiguration | Alert; do not loop sign-in |

All four inherit from `OAuthSDKError` and expose `code`, `message`, `status` and `retryable`.
Messages never include tokens or upstream response bodies.

## Development

```bash
uv sync --extra dev
bash scripts/check.sh
```

## License

MIT
