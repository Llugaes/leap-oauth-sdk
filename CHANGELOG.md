# Changelog

## 0.2.1 (2026-10-18)

- `leap-sso.js`: logout reuses an in-flight bearer refresh before invalidating its epoch,
  so the rotated credential can be revoked. A newer fresh session still logs out immediately
  and discards an older late refresh. No public API or Python verification policy changes.

## 0.2.0 (2026-10-16)

- `PrincipalDirectory`: picker search, directory user binding and subject validation through
  a service lookup credential; all-or-nothing `canonicalize()` with `PrincipalSelectionError`.
- `MemberService`, `MemberPolicy`, `MemberStore` and `JsonFileMemberStore`: admin member rules
  with configuration-only owners, versioned writes and audit records. Works without a directory
  for listing and removal.
- `check_session(verified=)` reuses a context the caller already verified.
- JWKS: a failed fetch is not retried within `jwks_refresh_cooldown_seconds`.
- `leap-sso.js`: fixes four races found in the first service migration — concurrent automatic
  sign-ins, tokens arriving after logout, a refresh finishing after logout, and a 401 for a
  request sent with a token that was replaced meanwhile.

## 0.1.0 (2026-10-14)

- `LeapAuthConfig` with explicit issuer, audience, JWKS URL and verification policy.
- `AccessTokenVerifier` with blocking and async verification sharing one JWKS cache.
- Error categories `Retryable`, `ReauthRequired`, `Forbidden`, `InvalidResponse`.
- `BrowserSSO`: code exchange, refresh, online session check and logout for one browser client,
  blocking and async; upstream responses classified into the four error categories.
- `CookieCipher` and `CookieSessionManager`: encrypted HttpOnly cookie sessions with in-process
  single-flight refresh, secret rotation and one-time migration of an old cookie format.
- `leap-sso.js`: browser module for automatic SSO, deep links, refresh, duplicated tabs and logout.
