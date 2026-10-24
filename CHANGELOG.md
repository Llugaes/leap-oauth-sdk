# Changelog

## 0.5.0.dev1 (unreleased)

- Add explicit, removable `transition` support for a controlled v1-to-native migration.
  Both token profiles are fully verified without fallback, and trusted issuer/tenant-scoped
  bijective mappings produce one canonical authorization key. The business selects exactly
  one storage-key format inside its own grant transaction; no grants are duplicated or merged.
- Preserve signed legacy claims and the wire subject separately from the canonical key.
  Browser refresh and online checks can retain an existing session across the subject change;
  existing encrypted cookies are rewritten only after verifying the same mapped person.
- Existing default v1 and strict native verifiers remain unchanged. The transition verifier
  requires an explicit trusted mapping, tenant, purpose and channel policy; no directory
  lookup, identity lifecycle, grant synchronization or migration activation is implicit.

## 0.4.0 (2026-10-21)

- Add `leap_oauth_sdk.native` with strict final Feishu v2 access-token verification,
  issuer-scoped person keys and optional union-ID grant fingerprint checks. Native
  verification requires an explicit tenant, purpose and channel policy; it never falls
  back to Principal v1 or the earlier pilot token format.
- Add a server-side `DirectoryClient` for five native locators, complete batch results,
  search and fresh grant selection. Open IDs require an explicit or constructor-bound App.
  Directory profiles omit App/Open-ID and tenant fields.
- Add explicit `BrowserSSO(token_profile="feishu_native_v2", expected_feishu_tenant=...)`.
  Existing constructors continue to select Principal v1. Cookie payloads, PKCE, state and
  `leap-sso.js` remain unchanged.
- Ship shared native contract vectors in source distributions and wheels. No dependencies
  were added.

## 0.3.0 (2026-10-18)

- Add `verify_claims()` / `verify_claims_async()`, `VerifiedTokenClaims` and the fixed
  `RegisteredClaimsPolicy.STRICT` / `PYJWT_COMPATIBLE` presets for explicit existing-token
  contracts. Raw results preserve claim values and missing metadata; callers retain their
  application status, purpose, version, revocation and authorization rules.
- Keep complete `verify()` / `verify_async()` on the strict policy with the existing
  `AccessTokenContext` metadata checks. No new dependencies or browser method signatures.
- Share a single JWKS fetch between synchronous and asynchronous callers, apply policy
  limits on cache hits, and support a bounded immediate unknown-key refresh in compatible
  mode. Failed refreshes invalidate old cached keys.
- Reject keys intended for encryption or other non-signature use. Empty, malformed and
  unusable JWKS are infrastructure errors rather than credential failures. Private key
  material remains rejected under both policies.
- Preserve strict first-match key rejection and recovery after an oversized JWKS. Compatible
  mode retains early malformed-payload rejection and rejects structurally broken mixed JWKS;
  formerly unhandled key-shape/construction errors become `InvalidResponse` infrastructure
  failures rather than being skipped to accept a later key.
- `leap-sso.js`: automatically retry only `GET`, `HEAD` and `OPTIONS`. A late 401 keeps newer
  credentials and returns its readable response for business writes or an exhausted safe
  retry; cookie rotation conflicts return the original 503 for non-safe methods. Request
  object methods and the originally sent method are respected, without replaying writes.

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
