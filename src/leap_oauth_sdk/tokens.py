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
from dataclasses import dataclass, field
from typing import Any, cast

import httpx
import jwt

from .config import LeapAuthConfig
from .errors import Forbidden, InvalidResponse, OAuthSDKError, ReauthRequired, Retryable

_MAX_TOKEN_BYTES = 16 * 1024
_MAX_JWKS_BYTES = 64 * 1024
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_REQUIRED_REGISTERED_CLAIMS = ["exp", "iat", "nbf", "iss", "sub", "aud", "jti"]


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
        self._static_keys = _key_list(jwks) if jwks is not None else None
        self._http_client = http_client
        self._async_http_client = async_http_client
        self._clock = clock
        self._keys: list[dict[str, Any]] | None = None
        self._fetched_at: float | None = None
        self._failed_at: float | None = None
        self._sync_lock = threading.Lock()
        self._async_lock: asyncio.Lock | None = None

    @property
    def config(self) -> LeapAuthConfig:
        return self._config

    def verify(self, token: str) -> AccessTokenContext:
        alg, kid = self._header(token)
        jwk = self._find(self._cached_or_fetch_sync(), kid, alg)
        if jwk is None and self._refetch_allowed():
            jwk = self._find(self._fetch_sync(), kid, alg)
        return self._decode(token, alg, _require_jwk(jwk))

    async def verify_async(self, token: str) -> AccessTokenContext:
        alg, kid = self._header(token)
        jwk = self._find(await self._cached_or_fetch_async(), kid, alg)
        if jwk is None and self._refetch_allowed():
            jwk = self._find(await self._fetch_async(), kid, alg)
        return self._decode(token, alg, _require_jwk(jwk))

    # -- header and claims -------------------------------------------------------------

    def _header(self, token: str) -> tuple[str, str]:
        if not token or len(token.encode("utf-8", "ignore")) > _MAX_TOKEN_BYTES:
            raise ReauthRequired("access_token_invalid", "access token is missing or too large")
        try:
            header: Any = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise ReauthRequired(
                "access_token_header_invalid", "access token header is invalid"
            ) from exc
        fields: dict[str, Any] = cast(dict[str, Any], header) if isinstance(header, dict) else {}
        alg = _optional_str(fields.get("alg"))
        kid = _optional_str(fields.get("kid"))
        if alg not in self._config.allowed_algorithms:
            raise ReauthRequired("access_token_alg_rejected", "access token alg is not allowed")
        if not kid:
            raise ReauthRequired("access_token_kid_required", "access token kid is required")
        return alg, kid

    def _decode(self, token: str, alg: str, jwk: dict[str, Any]) -> AccessTokenContext:
        if _PRIVATE_JWK_FIELDS.intersection(jwk):
            raise InvalidResponse("access_token_jwk_rejected", "JWKS contains private key material")
        try:
            key = jwt.PyJWK.from_dict(jwk).key
        except jwt.PyJWTError as exc:
            raise InvalidResponse(
                "access_token_jwk_invalid", "JWKS key cannot verify tokens"
            ) from exc
        try:
            claims: Any = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.leeway_seconds,
                options={"require": _REQUIRED_REGISTERED_CLAIMS, "strict_aud": True},
            )
        except jwt.PyJWTError as exc:
            raise ReauthRequired(
                "access_token_invalid", "access token signature or registered claims are invalid"
            ) from exc
        if not isinstance(claims, dict):
            raise ReauthRequired("access_token_invalid", "access token claims must be an object")
        return self._context(cast(dict[str, Any], claims))

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

    def _fresh(self) -> list[dict[str, Any]] | None:
        if self._static_keys is not None:
            return self._static_keys
        if self._keys is not None and self._fetched_at is not None:
            if self._clock() - self._fetched_at < self._config.jwks_cache_seconds:
                return self._keys
        return None

    def _refetch_allowed(self) -> bool:
        if self._static_keys is not None:
            return False
        if self._fetched_at is None:
            return True
        return self._clock() - self._fetched_at >= self._config.jwks_refresh_cooldown_seconds

    def _cached_or_fetch_sync(self) -> list[dict[str, Any]]:
        return self._fresh() or self._fetch_sync()

    async def _cached_or_fetch_async(self) -> list[dict[str, Any]]:
        return self._fresh() or await self._fetch_async()

    def _fetch_sync(self) -> list[dict[str, Any]]:
        with self._sync_lock:
            self._require_retry_allowed()
            try:
                if self._http_client is not None:
                    response = self._http_client.get(
                        self._config.resolved_jwks_url, **_REQUEST_OPTIONS
                    )
                else:
                    with httpx.Client(timeout=self._config.timeout_seconds) as client:
                        response = client.get(self._config.resolved_jwks_url, **_REQUEST_OPTIONS)
            except httpx.HTTPError as exc:
                self._failed_at = self._clock()
                raise _jwks_unavailable() from exc
            return self._store(response)

    async def _fetch_async(self) -> list[dict[str, Any]]:
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        async with self._async_lock:
            self._require_retry_allowed()
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
                self._failed_at = self._clock()
                raise _jwks_unavailable() from exc
            return self._store(response)

    def _require_retry_allowed(self) -> None:
        # After a failed fetch, wait out the cooldown instead of letting every request hit
        # the authorization server while it is down.
        if (
            self._failed_at is not None
            and self._clock() - self._failed_at < self._config.jwks_refresh_cooldown_seconds
        ):
            raise _jwks_unavailable()

    def _store(self, response: httpx.Response) -> list[dict[str, Any]]:
        try:
            keys = self._parse(response)
        except OAuthSDKError:
            self._failed_at = self._clock()
            raise
        self._keys = keys
        self._fetched_at = self._clock()
        self._failed_at = None
        return keys

    @staticmethod
    def _parse(response: httpx.Response) -> list[dict[str, Any]]:
        # A failed or malformed fetch is never cached and never falls back to old keys.
        if response.status_code != 200:
            raise _jwks_unavailable()
        if len(response.content) > _MAX_JWKS_BYTES:
            raise InvalidResponse("access_token_jwks_invalid", "JWKS response is too large")
        try:
            payload = json.loads(response.content)
        except ValueError as exc:
            raise InvalidResponse("access_token_jwks_invalid", "JWKS response is not JSON") from exc
        return _key_list(payload)

    @staticmethod
    def _find(keys: list[dict[str, Any]], kid: str, alg: str) -> dict[str, Any] | None:
        for key in keys:
            if key.get("kid") == kid and key.get("alg") == alg:
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


def _require_jwk(jwk: dict[str, Any] | None) -> dict[str, Any]:
    if jwk is None:
        raise ReauthRequired(
            "access_token_key_not_found", "JWKS does not contain the token kid/alg"
        )
    return jwk


def _key_list(payload: Any) -> list[dict[str, Any]]:
    keys: Any = (
        cast(Mapping[str, Any], payload).get("keys") if isinstance(payload, Mapping) else None
    )
    if not isinstance(keys, list):
        raise InvalidResponse("access_token_jwks_invalid", "JWKS keys must be a list")
    return [cast(dict[str, Any], key) for key in cast(list[Any], keys) if isinstance(key, dict)]


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
