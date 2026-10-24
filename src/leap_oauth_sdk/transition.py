"""Explicit, removable v1/v2 migration support with one canonical authorization key.

The mapping is trusted server configuration, prepared and verified outside requests.
This module neither fetches a directory nor creates, combines or duplicates grants.
"""

from __future__ import annotations

import base64
import json
import unicodedata
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, cast

import httpx

from .config import DEFAULT_TOKEN_VERSION, STRICT_ACCESS_TOKEN_MAX_BYTES, LeapAuthConfig
from .errors import Forbidden, ReauthRequired
from .native import NativeAccessTokenVerifier, parse_person_key
from .tokens import AccessTokenVerifier, RegisteredClaimsPolicy

_MAX_SELECTOR_HEADER_BYTES = 4096


def _exact_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(unicodedata.category(char) == "Cc" for char in value)
    )


def select_native_profile(token: object) -> bool:
    """Inspect a bounded selector only; the chosen verifier still proves the identity."""
    if not isinstance(token, str):
        raise ReauthRequired("migration_token_invalid", "invalid migration access token")
    try:
        # Inspect only a bounded header. PyJWT's header helper also decodes
        # the payload, so calling it here would precede the native size gate.
        end = token.find(".", 0, _MAX_SELECTOR_HEADER_BYTES + 1)
        if end <= 0:
            raise ValueError("invalid header envelope")
        segment = token[:end].encode("ascii")
        header = json.loads(base64.urlsafe_b64decode(segment + b"=" * (-len(segment) % 4)))
        native = bool(
            isinstance(header, dict) and cast(dict[str, Any], header).get("typ") == "at+jwt"
        )
        if native and (
            len(token) > STRICT_ACCESS_TOKEN_MAX_BYTES
            or len(token.encode("utf-8")) > STRICT_ACCESS_TOKEN_MAX_BYTES
        ):
            raise ValueError("native token exceeds strict size bound")
        return native
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReauthRequired("migration_token_invalid", "invalid migration access token") from exc


@dataclass(frozen=True, slots=True)
class MigrationIdentityMap:
    """A frozen, issuer/tenant-scoped bijection from verified migration material.

    The owner must bind ``revision`` to the same authoritative storage-format state
    used by the grant transaction. A caller-supplied HTTP value is never a valid map.
    """

    issuer: str
    feishu_tenant: str
    revision: str
    legacy_to_person: Mapping[str, str] = field(repr=False)
    _person_to_legacy: Mapping[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        namespace = (self.issuer, self.feishu_tenant, self.revision)
        if not all(_exact_text(value) for value in namespace):
            raise ValueError("mapping namespace and revision must be exact nonempty strings")
        forward = dict(self.legacy_to_person)
        reverse: dict[str, str] = {}
        for legacy, person in forward.items():
            if not _exact_text(legacy) or not legacy.startswith("usr_") or len(legacy) <= 4:
                raise ValueError("mapping requires exact legacy human subjects")
            parse_person_key(person)
            if person in reverse:
                raise ValueError("mapping must be one-to-one; resolve duplicates before activation")
            reverse[person] = legacy
        object.__setattr__(self, "legacy_to_person", MappingProxyType(forward))
        object.__setattr__(self, "_person_to_legacy", MappingProxyType(reverse))

    def person_key(self, legacy_subject: str) -> str:
        person = self.legacy_to_person.get(legacy_subject)
        if person is None:
            raise Forbidden(
                "migration_identity_unmapped", "verified identity has no migration mapping"
            )
        return person

    def canonical_subject(self, subject: str) -> str:
        """Normalize an existing stored session subject, with no display-ID lookup."""
        if subject.startswith("feishu:user_id:"):
            parse_person_key(subject)
            return subject
        return self.person_key(subject)

    def storage_subject(self, person_key: str, identity_contract: str) -> str:
        """Select exactly one key format from the grant transaction's current state."""
        parse_person_key(person_key)
        if identity_contract == "feishu_native_v2":
            return person_key
        if identity_contract != "principal_v1":
            raise ValueError("storage identity contract must be principal_v1 or feishu_native_v2")
        legacy = self._person_to_legacy.get(person_key)
        if legacy is None:
            raise Forbidden("migration_identity_unmapped", "identity has no legacy storage key")
        return legacy


@dataclass(frozen=True, slots=True)
class TransitionIdentity:
    """Canonical user identity plus the unchanged identity carried on the wire.

    It deliberately is not a NativeIdentity: old claims do not prove a native
    person object. The business still owns grants, revocation and storage epochs.
    """

    person_key: str
    issuer: str
    audience: str
    profile: Literal["principal_v1", "feishu_native_v2"]
    wire_subject: str
    mapping_revision: str
    mapping_tenant: str
    expires_at: int
    raw_claims: Mapping[str, Any] = field(repr=False)

    @property
    def subject_id(self) -> str:
        return self.person_key

    @property
    def authorization_key(self) -> tuple[str, str]:
        return self.issuer, self.person_key

    @property
    def browser_session_id(self) -> str | None:
        value = self.raw_claims.get("browser_sid")
        return value if isinstance(value, str) and value else None


class TransitionAccessTokenVerifier:
    """Opt-in migration verifier; a failed profile never falls back to the other.

    Header ``typ`` only selects a verifier. Neither the header nor any unverified
    subject becomes identity evidence. Existing strict native/v1 verifiers and
    default SDK behavior are unchanged.
    """

    def __init__(
        self,
        config: LeapAuthConfig,
        *,
        identity_map: MigrationIdentityMap,
        required_purpose: str,
        allowed_channels: Iterable[str],
        legacy_allowed_channels: Iterable[str] | None = None,
        jwks: Mapping[str, Any] | None = None,
        http_client: httpx.Client | None = None,
        async_http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if config.issuer != identity_map.issuer or config.token_version != DEFAULT_TOKEN_VERSION:
            raise ValueError("migration mapping must match the issuer and fixed v1 profile")
        self._config = config
        self.identity_map = identity_map
        self._purpose = required_purpose
        self._channels = frozenset(allowed_channels)
        if isinstance(legacy_allowed_channels, (str, bytes)):
            raise ValueError("legacy channel policy must be a collection of channel names")
        legacy_channels = tuple(
            self._channels if legacy_allowed_channels is None else legacy_allowed_channels
        )
        if not legacy_channels or any(not _exact_text(value) for value in legacy_channels):
            raise ValueError("legacy channel policy must contain exact nonempty channel names")
        self._legacy_channels = frozenset(legacy_channels)
        self._legacy = AccessTokenVerifier(
            config, jwks=jwks, http_client=http_client, async_http_client=async_http_client
        )
        self._native = NativeAccessTokenVerifier(
            config,
            expected_feishu_tenant=identity_map.feishu_tenant,
            required_purpose=required_purpose,
            allowed_channels=self._channels,
            jwks=jwks,
            http_client=http_client,
            async_http_client=async_http_client,
        )

    @property
    def config(self) -> LeapAuthConfig:
        return self._config

    @property
    def expected_feishu_tenant(self) -> str:
        return self.identity_map.feishu_tenant

    @property
    def required_purpose(self) -> str:
        return self._purpose

    @property
    def allowed_channels(self) -> frozenset[str]:
        return self._channels

    @property
    def legacy_allowed_channels(self) -> frozenset[str]:
        return self._legacy_channels

    @staticmethod
    def _native_profile(token: object) -> bool:
        return select_native_profile(token)

    def verify(self, token: str) -> TransitionIdentity:
        if self._native_profile(token):
            identity = self._native.verify(token)
            return self._result(identity.person_key, "feishu_native_v2", identity.raw_claims)
        verified = self._legacy.verify_claims(token, policy=RegisteredClaimsPolicy.PYJWT_COMPATIBLE)
        return self._legacy_identity(verified.raw_claims)

    async def verify_async(self, token: str) -> TransitionIdentity:
        if self._native_profile(token):
            identity = await self._native.verify_async(token)
            return self._result(identity.person_key, "feishu_native_v2", identity.raw_claims)
        verified = await self._legacy.verify_claims_async(
            token, policy=RegisteredClaimsPolicy.PYJWT_COMPATIBLE
        )
        return self._legacy_identity(verified.raw_claims)

    def _legacy_identity(self, claims: Mapping[str, Any]) -> TransitionIdentity:
        if (
            claims.get("ver") != DEFAULT_TOKEN_VERSION
            or claims.get("principal_type") != "human"
            or "person" in claims
            or "feishu_tenant" in claims
        ):
            raise ReauthRequired(
                "migration_legacy_profile_rejected", "invalid legacy human profile"
            )
        if claims.get("status", "active") != "active":
            raise Forbidden("access_token_principal_inactive", "principal is not active")
        raw_source = claims.get("source")
        source: Mapping[str, Any] = (
            cast(Mapping[str, Any], raw_source) if isinstance(raw_source, Mapping) else {}
        )
        channel = source.get("channel")
        if (
            claims.get("purpose", "access") != self._purpose
            or not isinstance(channel, str)
            or channel not in self._legacy_channels
        ):
            raise Forbidden(
                "migration_token_policy_rejected", "token purpose or channel is not allowed"
            )
        person = self.identity_map.person_key(claims["sub"])
        return self._result(person, "principal_v1", claims)

    def _result(
        self,
        person: str,
        profile: Literal["principal_v1", "feishu_native_v2"],
        claims: Mapping[str, Any],
    ) -> TransitionIdentity:
        return TransitionIdentity(
            person_key=person,
            issuer=self.config.issuer,
            audience=self.config.audience,
            profile=profile,
            wire_subject=claims["sub"],
            mapping_revision=self.identity_map.revision,
            mapping_tenant=self.identity_map.feishu_tenant,
            expires_at=int(claims["exp"]),
            raw_claims=MappingProxyType(deepcopy(dict(claims))),
        )
