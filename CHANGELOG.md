# Changelog

## 0.1.0 (unreleased)

- `LeapAuthConfig` with explicit issuer, audience, JWKS URL and verification policy.
- `AccessTokenVerifier` with blocking and async verification sharing one JWKS cache.
- Error categories `Retryable`, `ReauthRequired`, `Forbidden`, `InvalidResponse`.
- `BrowserSSO`: code exchange, refresh, online session check and logout for one browser client,
  blocking and async; upstream responses classified into the four error categories.
- `CookieCipher` and `CookieSessionManager`: encrypted HttpOnly cookie sessions with in-process
  single-flight refresh, secret rotation and one-time migration of an old cookie format.
- `leap-sso.js`: browser module for automatic SSO, deep links, refresh, duplicated tabs and logout.
