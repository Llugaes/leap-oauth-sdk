"""Access token verification against the authorization server's JWKS.

One verifier instance per (issuer, audience) should live for the whole process so the
JWKS cache is shared across requests. Both a blocking and an ``async`` entry point are
provided; they share the same cache.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, cast

import httpx
import jwt

from .config import LeapAuthConfig
from .errors import Forbidden, InvalidResponse, OAuthSDKError, ReauthRequired, Retryable

_MAX_TOKEN_BYTES = 16 * 1024
_MAX_JWKS_BYTES = 64 * 1024
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_REQUIRED_REGISTERED_CLAIMS = ["exp", "iat", "nbf", "iss", "sub", "aud", "jti"]
_COMPATIBLE_REGISTERED_CLAIMS = ["exp", "iat", "sub", "aud"]


class RegisteredClaimsPolicy(Enum):
    """Fixed registered-claim, key-selection and input-size contracts.

    Neither policy disables signature, issuer, audience or timestamp verification.
    PYJWT_COMPATIBLE follows the PyJWT 2.10 registered-claims and signing-key contract;
    it does not impose the strict path's additional token/JWKS byte limits.
    """

    STRICT = "strict"
    PYJWT_COMPATIBLE = "pyjwt-compatible"


@dataclass(frozen=True, slots=True)
class VerifiedTokenClaims:
    """Signature and registered claims verified; application authorization is still required.

    No identity metadata is required, converted or fabricated. This result must not be
    treated as the complete access-token contract provided by AccessTokenContext.
    """

    raw_claims: Mapping[str, Any] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _SigningKey:
    raw: dict[str, Any]
    parsed: jwt.PyJWK


@dataclass(slots=True)
class _JWKSnapshot:
    content: bytes
    raw_keys: tuple[dict[str, Any], ...] | None = None
    non_object_keys: bool = False
    keys: tuple[_SigningKey, ...] | None = None


@dataclass(frozen=True, slots=True)
class AccessTokenContext:
    """Verified identity handed to the business service's own authorization policy."""

    subject_id: str
    audience: str
    issuer: str
    jti: str
    issued_at: int
    not_before: int
    expires_at: int
    principal_type: str
    status: str
    purpose: str
    source: Mapping[str, Any]
    identities: tuple[Mapping[str, Any], ...] = ()
    groups: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    claims: tuple[str, ...] = ()
    email: str | None = None
    display_name: str | None = None
    raw_claims: Mapping[str, Any] = field(default_factory=lambda: {}, repr=False)

    @property
    def browser_session_id(self) -> str | None:
        """Browser root-session binding, present only on browser SSO tokens."""
        return _optional_str(self.raw_claims.get("browser_sid"))


class AccessTokenVerifier:
    """Verify compact JWS access tokens issued for ``config.audience``."""

    def __init__(
        self,
        config: LeapAuthConfig,
        *,
        jwks: Mapping[str, Any] | None = None,
        http_client: httpx.Client | None = None,
        async_http_client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._static_jwks = deepcopy(dict(jwks)) if jwks is not None else None
        self._http_client = http_client
        self._async_http_client = async_http_client
        self._clock = clock
        self._snapshot: _JWKSnapshot | None = None
        self._fetched_at: float | None = None
        self._failed_at: float | None = None
        self._last_miss_refresh: float | None = None
        self._strict_rejected: _JWKSnapshot | None = None
        self._strict_rejected_at: float | None = None
        self._lock = threading.Lock()
        # A concurrent Future can be joined by synchronous and asynchronous callers.
        # No lock is held during network I/O or while waiting for its result.
        self._inflight: Future[_JWKSnapshot] | None = None

    @property
    def config(self) -> LeapAuthConfig:
        return self._config

    def verify(self, token: str) -> AccessTokenContext:
        return self._context(
            dict(self.verify_claims(token, policy=RegisteredClaimsPolicy.STRICT).raw_claims)
        )

    async def verify_async(self, token: str) -> AccessTokenContext:
        verified = await self.verify_claims_async(token, policy=RegisteredClaimsPolicy.STRICT)
        return self._context(dict(verified.raw_claims))

    def verify_claims(
        self,
        token: str,
        *,
        policy: RegisteredClaimsPolicy = RegisteredClaimsPolicy.STRICT,
    ) -> VerifiedTokenClaims:
        """Verify registered claims without imposing access-token metadata requirements."""
        _require_policy(policy)
        alg, kid = self._header(token, policy)
        snapshot = self._get_sync(policy)
        key = self._find(snapshot, kid, alg, policy)
        if key is None:
            key = self._find(self._get_sync(policy, observed=snapshot), kid, alg, policy)
        return self._decode(token, alg, _require_jwk(key), policy)

    async def verify_claims_async(
        self,
        token: str,
        *,
        policy: RegisteredClaimsPolicy = RegisteredClaimsPolicy.STRICT,
    ) -> VerifiedTokenClaims:
        """Async equivalent of verify_claims; shares its cache and in-flight fetch."""
        _require_policy(policy)
        alg, kid = self._header(token, policy)
        snapshot = await self._get_async(policy)
        key = self._find(snapshot, kid, alg, policy)
        if key is None:
            key = self._find(await self._get_async(policy, observed=snapshot), kid, alg, policy)
        return self._decode(token, alg, _require_jwk(key), policy)

    # -- header and claims -------------------------------------------------------------

    def _header(self, token: str, policy: RegisteredClaimsPolicy) -> tuple[str, str]:
        if not token or (
            policy is RegisteredClaimsPolicy.STRICT
            and len(token.encode("utf-8", "ignore")) > _MAX_TOKEN_BYTES
        ):
            raise ReauthRequired("access_token_invalid", "access token is missing or too large")
        try:
            header: Any = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise ReauthRequired(
                "access_token_header_invalid", "access token header is invalid"
            ) from exc
        fields: dict[str, Any] = cast(dict[str, Any], header) if isinstance(header, dict) else {}
        alg = fields.get("alg")
        kid = fields.get("kid")
        if policy is RegisteredClaimsPolicy.STRICT:
            alg, kid = _optional_str(alg), _optional_str(kid)
        if alg not in self._config.allowed_algorithms:
            raise ReauthRequired("access_token_alg_rejected", "access token alg is not allowed")
        if not isinstance(kid, str) or not kid:
            raise ReauthRequired("access_token_kid_required", "access token kid is required")
        if policy is RegisteredClaimsPolicy.PYJWT_COMPATIBLE:
            try:
                # Match get_signing_key_from_jwt's format check before any JWKS I/O.
                # This unverified result is discarded; _decode must still verify it.
                jwt.decode_complete(token, options={"verify_signature": False})
            except jwt.PyJWTError as exc:
                raise ReauthRequired(
                    "access_token_invalid", "access token payload is invalid"
                ) from exc
        return cast(str, alg), kid

    def _decode(
        self, token: str, alg: str, key: _SigningKey, policy: RegisteredClaimsPolicy
    ) -> VerifiedTokenClaims:
        strict = policy is RegisteredClaimsPolicy.STRICT
        try:
            claims: Any = jwt.decode(
                token,
                key=key.parsed.key,
                algorithms=[alg],
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.leeway_seconds,
                options={
                    "require": (
                        _REQUIRED_REGISTERED_CLAIMS if strict else _COMPATIBLE_REGISTERED_CLAIMS
                    ),
                    "strict_aud": strict,
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "verify_sub": True,
                    "verify_jti": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise ReauthRequired(
                "access_token_invalid", "access token signature or registered claims are invalid"
            ) from exc
        if not isinstance(claims, dict):
            raise ReauthRequired("access_token_invalid", "access token claims must be an object")
        return VerifiedTokenClaims(MappingProxyType(cast(dict[str, Any], claims)))

    def _context(self, claims: dict[str, Any]) -> AccessTokenContext:
        if claims.get("ver") != self._config.token_version:
            raise ReauthRequired(
                "access_token_version_rejected", "access token version is not supported"
            )
        status = _required_str(claims, "status")
        if status != "active":
            raise Forbidden("access_token_principal_inactive", "principal is not active")
        purpose = _optional_str(claims.get("purpose")) or "access"
        if purpose not in self._config.allowed_purposes:
            raise Forbidden(
                "access_token_purpose_rejected", "access token purpose is not accepted here"
            )
        source = claims.get("source")
        if not isinstance(source, dict) or not _optional_str(
            cast(dict[str, Any], source).get("channel")
        ):
            raise ReauthRequired(
                "access_token_source_invalid", "access token source channel is required"
            )
        return AccessTokenContext(
            subject_id=_required_str(claims, "sub"),
            audience=self._config.audience,
            issuer=_required_str(claims, "iss"),
            jti=_required_str(claims, "jti"),
            issued_at=_required_int(claims, "iat"),
            not_before=_required_int(claims, "nbf"),
            expires_at=_required_int(claims, "exp"),
            principal_type=_required_str(claims, "principal_type"),
            status=status,
            purpose=purpose,
            source=dict(cast(dict[str, Any], source)),
            identities=tuple(_object_list(claims.get("identities"), "identities")),
            groups=tuple(_str_list(claims.get("groups"), "groups")),
            roles=tuple(_str_list(claims.get("roles"), "roles")),
            claims=tuple(_str_list(claims.get("claims"), "claims")),
            email=_optional_str(claims.get("email")),
            display_name=_optional_str(claims.get("display_name")),
            raw_claims=claims,
        )

    # -- JWKS cache ------------------------------------------------------------------

    def _acquire(
        self, policy: RegisteredClaimsPolicy, observed: _JWKSnapshot | None
    ) -> tuple[_JWKSnapshot | Future[_JWKSnapshot], bool]:
        with self._lock:
            if self._static_jwks is not None:
                if self._snapshot is None:
                    raw = json.dumps(dict(self._static_jwks)).encode("utf-8")
                    self._snapshot = _JWKSnapshot(raw)
                return self._snapshot, False
            now = self._clock()
            if (
                self._failed_at is not None
                and now - self._failed_at < self._config.jwks_refresh_cooldown_seconds
            ):
                raise _jwks_unavailable()
            if self._inflight is not None:
                return self._inflight, False
            strict_retry = (
                policy is RegisteredClaimsPolicy.STRICT
                and self._snapshot is not None
                and self._snapshot is self._strict_rejected
                and self._strict_rejected_at is not None
            )
            if (
                strict_retry
                and self._strict_rejected_at is not None
                and now - self._strict_rejected_at < self._config.jwks_refresh_cooldown_seconds
            ):
                raise _jwks_unavailable()
            if (
                not strict_retry
                and self._snapshot is not None
                and self._fetched_at is not None
                and now - self._fetched_at < self._config.jwks_cache_seconds
            ):
                if observed is None or observed is not self._snapshot:
                    return self._snapshot, False
                last = (
                    self._last_miss_refresh
                    if policy is RegisteredClaimsPolicy.PYJWT_COMPATIBLE
                    else self._fetched_at
                )
                if last is not None and now - last < self._config.jwks_refresh_cooldown_seconds:
                    return self._snapshot, False
            if observed is not None and policy is RegisteredClaimsPolicy.PYJWT_COMPATIBLE:
                self._last_miss_refresh = now
            future: Future[_JWKSnapshot] = Future()
            self._inflight = future
            return future, True

    def _finish(
        self,
        future: Future[_JWKSnapshot],
        *,
        snapshot: _JWKSnapshot | None = None,
        error: BaseException | None = None,
    ) -> None:
        with self._lock:
            self._inflight = None
            self._strict_rejected = None
            self._strict_rejected_at = None
            if snapshot is not None:
                self._snapshot = snapshot
                self._fetched_at = self._clock()
                self._failed_at = None
            else:
                # A failed forced refresh also invalidates previously fresh keys.
                self._snapshot = None
                self._fetched_at = None
                self._failed_at = self._clock()
        if snapshot is not None:
            future.set_result(snapshot)
        else:
            future.set_exception(error if isinstance(error, OAuthSDKError) else _jwks_unavailable())

    def _get_sync(
        self, policy: RegisteredClaimsPolicy, *, observed: _JWKSnapshot | None = None
    ) -> _JWKSnapshot:
        value, owner = self._acquire(policy, observed)
        if isinstance(value, _JWKSnapshot):
            return value
        if not owner:
            return value.result()
        try:
            try:
                if self._http_client is not None:
                    response = self._http_client.get(
                        self._config.resolved_jwks_url, **_REQUEST_OPTIONS
                    )
                else:
                    with httpx.Client(timeout=self._config.timeout_seconds) as client:
                        response = client.get(self._config.resolved_jwks_url, **_REQUEST_OPTIONS)
            except httpx.HTTPError as exc:
                raise _jwks_unavailable() from exc
            snapshot = self._parse(response)
        except BaseException as exc:
            self._finish(value, error=exc)
            raise
        self._finish(value, snapshot=snapshot)
        return snapshot

    async def _get_async(
        self, policy: RegisteredClaimsPolicy, *, observed: _JWKSnapshot | None = None
    ) -> _JWKSnapshot:
        value, owner = self._acquire(policy, observed)
        if isinstance(value, _JWKSnapshot):
            return value
        if not owner:
            # Cancelling a waiter must not cancel another caller's request.
            return await asyncio.shield(asyncio.wrap_future(value))
        try:
            try:
                if self._async_http_client is not None:
                    response = await self._async_http_client.get(
                        self._config.resolved_jwks_url, **_REQUEST_OPTIONS
                    )
                else:
                    async with httpx.AsyncClient(timeout=self._config.timeout_seconds) as client:
                        response = await client.get(
                            self._config.resolved_jwks_url, **_REQUEST_OPTIONS
                        )
            except httpx.HTTPError as exc:
                raise _jwks_unavailable() from exc
            snapshot = self._parse(response)
        except BaseException as exc:
            self._finish(value, error=exc)
            raise
        self._finish(value, snapshot=snapshot)
        return snapshot

    @staticmethod
    def _parse(response: httpx.Response) -> _JWKSnapshot:
        if response.status_code != 200:
            raise _jwks_unavailable()
        return _JWKSnapshot(response.content)

    def _find(
        self, snapshot: _JWKSnapshot, kid: str, alg: str, policy: RegisteredClaimsPolicy
    ) -> _SigningKey | None:
        strict = policy is RegisteredClaimsPolicy.STRICT
        if strict and len(snapshot.content) > _MAX_JWKS_BYTES:
            with self._lock:
                if (
                    self._static_jwks is None
                    and self._snapshot is snapshot
                    and self._strict_rejected is not snapshot
                ):
                    self._strict_rejected = snapshot
                    self._strict_rejected_at = self._clock()
            raise InvalidResponse("access_token_jwks_invalid", "JWKS response is too large")
        selected: dict[str, Any] | None = None
        with self._lock:
            try:
                if snapshot.raw_keys is None:
                    try:
                        payload = json.loads(snapshot.content)
                    except ValueError as exc:
                        raise InvalidResponse(
                            "access_token_jwks_invalid", "JWKS response is not JSON"
                        ) from exc
                    snapshot.raw_keys, snapshot.non_object_keys = _raw_keys(payload)
                if not strict and snapshot.non_object_keys:
                    raise InvalidResponse(
                        "access_token_jwks_invalid", "JWKS contains a non-object key"
                    )
                if strict:
                    selected = next(
                        (
                            key
                            for key in snapshot.raw_keys
                            if key.get("kid") == kid
                            and key.get("alg") == alg
                            and key.get("use") in ("sig", None)
                        ),
                        None,
                    )
                if selected is None and snapshot.keys is None:
                    snapshot.keys = _signing_keys(snapshot.raw_keys)
            except OAuthSDKError:
                if self._static_jwks is None and self._snapshot is snapshot:
                    self._snapshot = None
                    self._fetched_at = None
                    self._failed_at = self._clock()
                raise
            keys = snapshot.keys
        if selected is not None:
            # Strict selection has always used the first raw kid/alg match. Do not let
            # compatible PyJWKSet filtering turn a broken first match into a fallback.
            try:
                return _SigningKey(selected, jwt.PyJWK.from_dict(selected))
            except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
                raise InvalidResponse(
                    "access_token_jwk_invalid", "JWKS key cannot verify tokens"
                ) from exc
        for key in keys or ():
            if key.parsed.key_id == kid and (not strict or key.raw.get("alg") == alg):
                return key
        return None


_REQUEST_OPTIONS: dict[str, Any] = {
    "headers": {"Accept": "application/json"},
    "follow_redirects": False,
}


def _jwks_unavailable() -> Retryable:
    return Retryable(
        "auth_upstream_unavailable", "unable to fetch JWKS from the authorization server"
    )


def _require_policy(policy: object) -> None:
    if not isinstance(policy, RegisteredClaimsPolicy):
        raise TypeError("policy must be a RegisteredClaimsPolicy member")


def _require_jwk(jwk: _SigningKey | None) -> _SigningKey:
    if jwk is None:
        raise ReauthRequired(
            "access_token_key_not_found", "JWKS does not contain the token kid/alg"
        )
    return jwk


def _raw_keys(payload: Any) -> tuple[tuple[dict[str, Any], ...], bool]:
    keys: Any = (
        cast(Mapping[str, Any], payload).get("keys") if isinstance(payload, Mapping) else None
    )
    if not isinstance(keys, list):
        raise InvalidResponse("access_token_jwks_invalid", "JWKS keys must be a list")
    result: list[dict[str, Any]] = []
    non_object = False
    for item in cast(list[Any], keys):
        if not isinstance(item, dict):
            non_object = True
            continue
        key = cast(dict[str, Any], item)
        if _PRIVATE_JWK_FIELDS.intersection(key):
            raise InvalidResponse("access_token_jwk_rejected", "JWKS contains private key material")
        result.append(key)
    return tuple(result), non_object


def _signing_keys(keys: tuple[dict[str, Any], ...]) -> tuple[_SigningKey, ...]:
    signing: list[_SigningKey] = []
    for key in keys:
        try:
            parsed = jwt.PyJWK.from_dict(key)
        except jwt.PyJWTError as exc:
            # Newer PyJWT wraps formerly bare construction errors in InvalidKeyError.
            # Preserve the 2.10.1 boundary without rejecting older algorithm-level
            # InvalidKeyError wrappers (e.g. an invalid OKP key length).
            if (
                isinstance(exc, jwt.InvalidKeyError)
                and isinstance(exc.__cause__, (ValueError, TypeError))
                and str(exc).startswith("Unable to construct key from JWK:")
            ):
                raise InvalidResponse(
                    "access_token_jwks_invalid", "JWKS key construction failed"
                ) from exc
            # PyJWKSet 2.10.1 skips its own parse errors, but not structural exceptions.
            continue
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
            raise InvalidResponse(
                "access_token_jwks_invalid", "JWKS key construction failed"
            ) from exc
        if parsed.public_key_use in ("sig", None) and parsed.key_id:
            signing.append(_SigningKey(key, parsed))
    if not signing:
        raise InvalidResponse("access_token_jwks_invalid", "JWKS contains no usable signing keys")
    return tuple(signing)


def _optional_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _required_str(claims: Mapping[str, Any], key: str) -> str:
    value = _optional_str(claims.get(key))
    if value is None:
        raise ReauthRequired("access_token_claim_invalid", f"{key} must be a non-empty string")
    return value


def _required_int(claims: Mapping[str, Any], key: str) -> int:
    value = claims.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReauthRequired("access_token_claim_invalid", f"{key} must be an integer")
    return value


def _str_list(value: Any, key: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in cast(list[Any], value)
    ):
        raise ReauthRequired("access_token_claim_invalid", f"{key} must be a string list")
    return list(cast(list[str], value))


def _object_list(value: Any, key: str) -> list[Mapping[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, dict) for item in cast(list[Any], value)
    ):
        raise ReauthRequired("access_token_claim_invalid", f"{key} must be an object list")
    return [dict(cast(dict[str, Any], item)) for item in cast(list[Any], value)]
