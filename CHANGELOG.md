# Changelog

## 0.1.0 (unreleased)

- `LeapAuthConfig` with explicit issuer, audience, JWKS URL and verification policy.
- `AccessTokenVerifier` with blocking and async verification sharing one JWKS cache.
- Error categories `Retryable`, `ReauthRequired`, `Forbidden`, `InvalidResponse`.
