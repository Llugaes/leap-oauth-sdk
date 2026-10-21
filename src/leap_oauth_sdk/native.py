"""Strict Feishu-native v2 identities, isolated from the Principal v1 contract."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import urlsplit

import httpx
import jwt

from .config import LeapAuthConfig
from .errors import Forbidden, InvalidResponse, ReauthRequired, Retryable
from .tokens import AccessTokenVerifier, RegisteredClaimsPolicy

NATIVE_TOKEN_VERSION = "sakamoto_feishu_access_token.v2"
PERSON_KEY_PREFIX = "feishu:user_id:"
_PERSON_FIELDS = frozenset({"user_id", "union_id", "status", "name", "email"})
_CHANNELS = frozenset({"feishu_oauth", "feishu_bot", "obo"})
_PURPOSES = frozenset({"access", "entitlement_probe"})
_V1_FIELDS = frozenset(
    {
        "principal",
        "principal_type",
        "principal_status",
        "subject_id",
        "status",
        "identity",
        "identities",
        "groups",
        "roles",
        "claims",
        "display_name",
        "email",
    }
)


def valid_user_id(value: object) -> bool:
    """Validate without trimming, case folding or Unicode normalization."""
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(unicodedata.category(character) == "Cc" for character in value)
    )


def parse_person_key(person_key: object) -> str:
    """Remove only the fixed prefix; user IDs can themselves contain colons."""
    if not isinstance(person_key, str) or not person_key.startswith(PERSON_KEY_PREFIX):
        raise ValueError("invalid Feishu person key")
    user_id = person_key[len(PERSON_KEY_PREFIX) :]
    if not valid_user_id(user_id):
        raise ValueError("invalid Feishu user ID")
    return user_id


@dataclass(frozen=True, slots=True)
class NativeDisplay:
    """Readable metadata. These values must never select grants."""

    name: str | None
    email: str | None


@dataclass(frozen=True, slots=True)
class NativeIdentity:
    person_key: str
    issuer: str
    audience: str
    user_id: str
    union_id: str | None
    status: str
    client_id: str
    purpose: str
    feishu_tenant: str
    source: Mapping[str, Any]
    display: NativeDisplay
    jti: str
    issued_at: int
    not_before: int
    expires_at: int
    actor: Mapping[str, Any] | None = field(default=None, repr=False)
    raw_claims: Mapping[str, Any] = field(default_factory=lambda: {}, repr=False)

    @property
    def authorization_key(self) -> tuple[str, str]:
        return self.issuer, self.person_key

    @property
    def subject_id(self) -> str:
        """The OAuth sub, for existing browser-session transport helpers."""
        return self.person_key

    @property
    def browser_session_id(self) -> str | None:
        value = self.raw_claims.get("browser_sid")
        return value if isinstance(value, str) and value else None


class NativeAccessTokenVerifier:
    """Reuse the SDK's registered-claims verifier and JWKS cache, never v1 identities."""

    def __init__(
        self,
        config: LeapAuthConfig,
        *,
        expected_feishu_tenant: str,
        required_purpose: str,
        allowed_channels: Iterable[str],
        jwks: Mapping[str, Any] | None = None,
        http_client: httpx.Client | None = None,
        async_http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not expected_feishu_tenant or expected_feishu_tenant != expected_feishu_tenant.strip():
            raise ValueError("expected_feishu_tenant is required without surrounding whitespace")
        if required_purpose not in _PURPOSES:
            raise ValueError("required_purpose must be access or entitlement_probe")
        channels = frozenset(allowed_channels)
        if not channels or not channels <= _CHANNELS:
            raise ValueError("allowed_channels must contain supported native channels")
        if not 0 <= config.leeway_seconds <= 60:
            raise ValueError("native token leeway must be between 0 and 60 seconds")
        if not set(config.allowed_algorithms) <= {"EdDSA", "RS256"}:
            raise ValueError("native token algorithms must be EdDSA or RS256")
        self._config = config
        self._tenant = expected_feishu_tenant
        self._purpose = required_purpose
        self._channels = channels
        self._registered = AccessTokenVerifier(
            config, jwks=jwks, http_client=http_client, async_http_client=async_http_client
        )

    @property
    def config(self) -> LeapAuthConfig:
        return self._config

    @property
    def expected_feishu_tenant(self) -> str:
        return self._tenant

    def verify(self, token: str) -> NativeIdentity:
        self._header(token)
        verified = self._registered.verify_claims(token, policy=RegisteredClaimsPolicy.STRICT)
        return self._identity(verified.raw_claims)

    async def verify_async(self, token: str) -> NativeIdentity:
        self._header(token)
        verified = await self._registered.verify_claims_async(
            token, policy=RegisteredClaimsPolicy.STRICT
        )
        return self._identity(verified.raw_claims)

    def _header(self, token: str) -> None:
        try:
            header: dict[str, Any] = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise _invalid("header") from exc
        if (
            header.get("typ") != "at+jwt"
            or header.get("alg") not in self.config.allowed_algorithms
            or not _text(header.get("kid"))
            or "crit" in header
        ):
            raise _invalid("header")

    def _identity(self, claims: Mapping[str, Any]) -> NativeIdentity:
        if claims.get("ver") != NATIVE_TOKEN_VERSION or _V1_FIELDS.intersection(claims):
            raise _invalid("profile")
        if claims.get("iss") != self.config.issuer or claims.get("aud") != self.config.audience:
            raise _invalid("namespace")
        sub = _required_text(claims.get("sub"), "subject")
        try:
            user_id = parse_person_key(sub)
        except ValueError as exc:
            raise _invalid("subject") from exc
        raw_person = claims.get("person")
        if not isinstance(raw_person, dict):
            raise _invalid("person")
        person = cast(dict[str, Any], raw_person)
        if frozenset(person) != _PERSON_FIELDS or person.get("user_id") != user_id:
            raise _invalid("person")
        status = person.get("status")
        if not isinstance(status, str) or status not in {"active", "inactive", "unknown"}:
            raise _invalid("status")
        if status == "inactive":
            raise Forbidden("native_person_inactive", "Feishu person is inactive")
        union_id = _nullable_text(person.get("union_id"), "union_id", nonempty=True)
        display = NativeDisplay(
            _nullable_text(person.get("name"), "name"), _nullable_text(person.get("email"), "email")
        )
        purpose = _required_text(claims.get("purpose"), "purpose")
        if purpose != self._purpose:
            raise Forbidden(
                "native_token_purpose_rejected", "native token purpose is not accepted here"
            )
        if claims.get("feishu_tenant") != self._tenant:
            raise _invalid("tenant")
        raw_source = claims.get("source")
        if not isinstance(raw_source, dict):
            raise _invalid("source")
        source = cast(dict[str, Any], raw_source)
        channel = source.get("channel")
        if not isinstance(channel, str) or channel not in self._channels:
            raise _invalid("source")
        if "act" in claims and claims["act"] is None:
            raise _invalid("actor")
        actor = _actor(claims.get("act"))
        if channel == "feishu_bot" and (actor is None or actor.get("type") != "trusted_entry"):
            raise _invalid("actor")
        if channel == "obo" and (actor is None or actor.get("type") != "obo"):
            raise _invalid("actor")
        if (
            channel in {"feishu_bot", "obo"}
            and actor is not None
            and actor.get("sub") != claims.get("client_id")
        ):
            raise _invalid("actor_client_binding")
        times: list[int] = []
        for name in ("iat", "nbf", "exp"):
            value = claims.get(name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise _invalid("time")
            times.append(value)
        issued_at, not_before, expires_at = times
        max_ttl = 900 if channel == "feishu_oauth" and purpose == "access" else 300
        if expires_at <= issued_at or not_before >= expires_at or expires_at - issued_at > max_ttl:
            raise _invalid("lifetime")
        return NativeIdentity(
            person_key=sub,
            issuer=self.config.issuer,
            audience=self.config.audience,
            user_id=user_id,
            union_id=union_id,
            status=status,
            client_id=_required_text(claims.get("client_id"), "client_id"),
            purpose=purpose,
            feishu_tenant=self._tenant,
            source=MappingProxyType(deepcopy(source)),
            display=display,
            jti=_required_text(claims.get("jti"), "jti"),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            actor=actor,
            raw_claims=MappingProxyType(deepcopy(dict(claims))),
        )


def verify_native_access_token(
    token: str,
    *,
    issuer: str,
    audience: str,
    jwks: Mapping[str, Any],
    expected_feishu_tenant: str,
    required_purpose: str,
    allowed_channels: Iterable[str],
    leeway_seconds: int = 30,
    allowed_algorithms: tuple[str, ...] = ("EdDSA", "RS256"),
) -> NativeIdentity:
    """Verify the final native profile; every trust boundary is explicit."""
    if issuer != issuer.strip() or audience != audience.strip():
        raise ValueError("issuer and audience must not contain surrounding whitespace")
    return NativeAccessTokenVerifier(
        LeapAuthConfig(
            issuer=issuer,
            audience=audience,
            leeway_seconds=leeway_seconds,
            allowed_algorithms=allowed_algorithms,
        ),
        jwks=jwks,
        expected_feishu_tenant=expected_feishu_tenant,
        required_purpose=required_purpose,
        allowed_channels=allowed_channels,
    ).verify(token)


def grant_matches(subject_ref: str, bound_union_id: str | None, identity: NativeIdentity) -> bool:
    """Match inside the verifier's configured issuer namespace, never by actor or display."""
    try:
        parse_person_key(subject_ref)
    except ValueError:
        return False
    return subject_ref == identity.person_key and (
        bound_union_id is None or bool(bound_union_id) and bound_union_id == identity.union_id
    )


def _actor(value: Any, *, nested: bool = False) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise _invalid("actor")
    actor = cast(dict[str, Any], value)
    _required_text(actor.get("sub"), "actor")
    if actor.get("type") == "trusted_entry":
        if actor.get("auth") not in ("issue_token", "hmac") or "act" in actor:
            raise _invalid("actor")
    elif actor.get("type") == "obo" and not nested:
        _required_text(actor.get("parent_aud"), "actor")
        _required_text(actor.get("parent_jti"), "actor")
        if "act" in actor and actor["act"] is None:
            raise _invalid("actor")
        _actor(actor.get("act"), nested=True)
    else:
        raise _invalid("actor")
    return MappingProxyType(deepcopy(actor))


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _required_text(value: Any, name: str) -> str:
    if not _text(value):
        raise _invalid(name)
    return cast(str, value)


def _nullable_text(value: Any, name: str, *, nonempty: bool = False) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or nonempty and not _text(value):
        raise _invalid(name)
    return value


def _invalid(field_name: str) -> ReauthRequired:
    return ReauthRequired(
        "native_token_invalid_" + field_name, "native access token " + field_name + " is invalid"
    )


@dataclass(frozen=True, slots=True)
class DirectoryDepartment:
    id: str
    name: str | None


@dataclass(frozen=True, slots=True)
class DirectoryPerson:
    person_key: str
    user_id: str
    union_id: str | None
    name: str | None
    email: str | None
    avatar_url: str | None
    department_path: tuple[DirectoryDepartment, ...]
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "person_key": self.person_key,
            "user_id": self.user_id,
            "union_id": self.union_id,
            "name": self.name,
            "email": self.email,
            "avatar_url": self.avatar_url,
            "department_path": [
                {"id": part.id, "name": part.name} for part in self.department_path
            ],
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class GrantPerson:
    person_key: str
    union_id: str | None

    def to_dict(self) -> dict[str, str | None]:
        return {"person_key": self.person_key, "union_id": self.union_id}


@dataclass(frozen=True, slots=True)
class DirectoryBatchResult:
    person_key: str
    state: str
    person: DirectoryPerson | None = None


@dataclass(frozen=True, slots=True)
class DirectorySearchResult:
    items: tuple[DirectoryPerson, ...]
    has_more: bool


class DirectoryClient:
    """Server-held directory_reader client. Locator failures never trigger fallback."""

    def __init__(
        self,
        config: LeapAuthConfig,
        *,
        lookup_token: str,
        api_base_url: str | None = None,
        bound_app_id: str | None = None,
        http_client: httpx.Client | None = None,
        async_http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not _text(lookup_token):
            raise ValueError("lookup_token is required")
        base = api_base_url or config.issuer
        parts = urlsplit(base)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.netloc
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                "directory base URL must be http(s) without credentials, query or fragment"
            )
        if bound_app_id is not None and not _text(bound_app_id):
            raise ValueError("bound_app_id must be nonempty")
        self._base = base.rstrip("/")
        self._credential = lookup_token
        self._bound_app_id = bound_app_id
        self._config = config
        self._http = http_client
        self._async_http = async_http_client

    def resolve(
        self,
        *,
        person_key: str | None = None,
        user_id: str | None = None,
        email: str | None = None,
        union_id: str | None = None,
        open_id: str | None = None,
        app_id: str | None = None,
    ) -> DirectoryPerson:
        locator = self._locator(person_key, user_id, email, union_id, open_id, app_id)
        return _resolved(self._send("POST", "/resolve", body=locator), locator)

    async def resolve_async(
        self,
        *,
        person_key: str | None = None,
        user_id: str | None = None,
        email: str | None = None,
        union_id: str | None = None,
        open_id: str | None = None,
        app_id: str | None = None,
    ) -> DirectoryPerson:
        locator = self._locator(person_key, user_id, email, union_id, open_id, app_id)
        return _resolved(await self._send_async("POST", "/resolve", body=locator), locator)

    def resolve_for_grant(
        self,
        *,
        person_key: str | None = None,
        user_id: str | None = None,
        email: str | None = None,
        union_id: str | None = None,
        open_id: str | None = None,
        app_id: str | None = None,
    ) -> GrantPerson:
        return _grant_person(
            self.resolve(
                person_key=person_key,
                user_id=user_id,
                email=email,
                union_id=union_id,
                open_id=open_id,
                app_id=app_id,
            )
        )

    async def resolve_for_grant_async(
        self,
        *,
        person_key: str | None = None,
        user_id: str | None = None,
        email: str | None = None,
        union_id: str | None = None,
        open_id: str | None = None,
        app_id: str | None = None,
    ) -> GrantPerson:
        return _grant_person(
            await self.resolve_async(
                person_key=person_key,
                user_id=user_id,
                email=email,
                union_id=union_id,
                open_id=open_id,
                app_id=app_id,
            )
        )

    def batch(self, person_keys: Sequence[str]) -> tuple[DirectoryBatchResult, ...]:
        keys = _batch_keys(person_keys)
        if not keys:
            return ()
        return _batch_result(self._send("POST", "/batch", body={"person_keys": keys}), keys)

    async def batch_async(self, person_keys: Sequence[str]) -> tuple[DirectoryBatchResult, ...]:
        keys = _batch_keys(person_keys)
        if not keys:
            return ()
        return _batch_result(
            await self._send_async("POST", "/batch", body={"person_keys": keys}), keys
        )

    def search(self, q: str, *, limit: int = 20) -> DirectorySearchResult:
        params = _search_params(q, limit)
        return _search_result(self._send("GET", "/search", params=params))

    async def search_async(self, q: str, *, limit: int = 20) -> DirectorySearchResult:
        params = _search_params(q, limit)
        return _search_result(await self._send_async("GET", "/search", params=params))

    def _locator(
        self,
        person_key: str | None,
        user_id: str | None,
        email: str | None,
        union_id: str | None,
        open_id: str | None,
        app_id: str | None,
    ) -> dict[str, str]:
        values = {
            "person_key": person_key,
            "user_id": user_id,
            "email": email,
            "union_id": union_id,
            "open_id": open_id,
        }
        locator = {name: value for name, value in values.items() if value is not None}
        if len(locator) != 1 or any(not _text(value) for value in locator.values()):
            raise ValueError("exactly one nonempty locator is required")
        if person_key is not None:
            parse_person_key(person_key)
        if user_id is not None and not valid_user_id(user_id):
            raise ValueError("invalid Feishu user ID")
        if open_id is not None:
            if (
                app_id is not None
                and self._bound_app_id is not None
                and app_id != self._bound_app_id
            ):
                raise ValueError("open_id app_id does not match client binding")
            app_id = app_id if app_id is not None else self._bound_app_id
            if not _text(app_id):
                raise ValueError("open_id requires an explicit app_id")
            locator["app_id"] = cast(str, app_id)
        elif app_id is not None:
            raise ValueError("app_id is only valid with open_id")
        return locator

    def _options(
        self, body: dict[str, Any] | None, params: dict[str, str] | None
    ) -> dict[str, Any]:
        options: dict[str, Any] = {
            "headers": {"Authorization": "Bearer " + self._credential},
            "follow_redirects": False,
        }
        if body is not None:
            options["json"] = body
        if params is not None:
            options["params"] = params
        return options

    def _send(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            url = self._base + "/api/v2/feishu/users" + path
            if self._http is not None:
                response = self._http.request(method, url, **self._options(body, params))
            else:
                with httpx.Client(timeout=self._config.timeout_seconds) as client:
                    response = client.request(method, url, **self._options(body, params))
        except httpx.HTTPError as exc:
            raise Retryable(
                "native_directory_unavailable", "native directory is unavailable"
            ) from exc
        return _directory_payload(response)

    async def _send_async(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            url = self._base + "/api/v2/feishu/users" + path
            if self._async_http is not None:
                response = await self._async_http.request(
                    method, url, **self._options(body, params)
                )
            else:
                async with httpx.AsyncClient(timeout=self._config.timeout_seconds) as client:
                    response = await client.request(method, url, **self._options(body, params))
        except httpx.HTTPError as exc:
            raise Retryable(
                "native_directory_unavailable", "native directory is unavailable"
            ) from exc
        return _directory_payload(response)


def _directory_payload(response: httpx.Response) -> dict[str, Any]:
    if response.status_code == 429 or response.status_code >= 500:
        raise Retryable("native_directory_unavailable", "native directory is unavailable")
    if response.status_code in {401, 403}:
        raise InvalidResponse(
            "native_directory_reader_rejected", "directory credential was rejected"
        )
    if response.status_code in {400, 404, 409, 422}:
        raise Forbidden("native_directory_locator_rejected", "native person locator was rejected")
    if not 200 <= response.status_code < 300 or len(response.content) > 512 * 1024:
        raise _directory_invalid()
    try:
        body: Any = response.json()
    except ValueError as exc:
        raise _directory_invalid() from exc
    if not isinstance(body, dict):
        raise _directory_invalid()
    return cast(dict[str, Any], body)


def _profile(value: Any) -> DirectoryPerson:
    expected = frozenset(
        {
            "person_key",
            "user_id",
            "union_id",
            "name",
            "email",
            "avatar_url",
            "department_path",
            "status",
        }
    )
    if not isinstance(value, dict):
        raise _directory_invalid()
    data = cast(dict[str, Any], value)
    if frozenset(data) != expected:
        raise _directory_invalid()
    try:
        user_id = parse_person_key(data.get("person_key"))
        if user_id != data.get("user_id") or data.get("status") not in (
            "active",
            "inactive",
            "unknown",
        ):
            raise _directory_invalid()
        union_id = _nullable_text(data.get("union_id"), "union_id", nonempty=True)
        name, email = (
            _nullable_text(data.get("name"), "name"),
            _nullable_text(data.get("email"), "email"),
        )
        avatar_url = _nullable_text(data.get("avatar_url"), "avatar_url")
        path = data.get("department_path")
        if not isinstance(path, list):
            raise _directory_invalid()
        departments: list[DirectoryDepartment] = []
        for raw in cast(list[Any], path):
            if not isinstance(raw, dict):
                raise _directory_invalid()
            part = cast(dict[str, Any], raw)
            if frozenset(part) != frozenset({"id", "name"}):
                raise _directory_invalid()
            departments.append(
                DirectoryDepartment(
                    _required_text(part.get("id"), "department"),
                    _nullable_text(part.get("name"), "department"),
                )
            )
    except (ValueError, ReauthRequired) as exc:
        raise _directory_invalid() from exc
    return DirectoryPerson(
        cast(str, data["person_key"]),
        user_id,
        union_id,
        name,
        email,
        avatar_url,
        tuple(departments),
        cast(str, data["status"]),
    )


def _resolved(payload: dict[str, Any], locator: dict[str, str]) -> DirectoryPerson:
    person = _profile(payload.get("person"))
    for name in ("person_key", "user_id", "union_id"):
        if name in locator and getattr(person, name) != locator[name]:
            raise _directory_invalid()
    if (
        "email" in locator
        and (person.email or "").casefold() != locator["email"].strip().casefold()
    ):
        raise _directory_invalid()
    return person


def _grant_person(person: DirectoryPerson) -> GrantPerson:
    if person.status == "inactive":
        raise Forbidden("native_person_inactive", "inactive person cannot receive a grant")
    return GrantPerson(person.person_key, person.union_id)


def _batch_keys(person_keys: Sequence[str]) -> list[str]:
    if isinstance(person_keys, str) or len(person_keys) > 100:
        raise ValueError("batch requires a sequence of at most 100 keys")
    return list(dict.fromkeys(person_keys))


def _batch_result(payload: dict[str, Any], keys: list[str]) -> tuple[DirectoryBatchResult, ...]:
    rows = payload.get("results")
    if not isinstance(rows, list):
        raise _directory_invalid()
    found: dict[str, DirectoryBatchResult] = {}
    for raw in cast(list[Any], rows):
        if not isinstance(raw, dict):
            raise _directory_invalid()
        row = cast(dict[str, Any], raw)
        key, state = row.get("person_key"), row.get("state")
        if (
            not isinstance(key, str)
            or key not in keys
            or key in found
            or state not in ("found", "not_found", "invalid", "conflict")
        ):
            raise _directory_invalid()
        person = _profile(row["person"]) if row.get("person") is not None else None
        if (state == "found" and person is None) or person is not None and person.person_key != key:
            raise _directory_invalid()
        found[key] = DirectoryBatchResult(key, cast(str, state), person)
    if set(found) != set(keys):
        raise _directory_invalid()
    return tuple(found[key] for key in keys)


def _search_params(q: str, limit: int) -> dict[str, str]:
    if not 2 <= len(q) <= 64 or isinstance(limit, bool) or not 1 <= limit <= 30:
        raise ValueError("search requires 2-64 characters and limit 1-30")
    return {"q": q, "limit": str(limit)}


def _search_result(payload: dict[str, Any]) -> DirectorySearchResult:
    rows, has_more = payload.get("items"), payload.get("has_more")
    if not isinstance(rows, list) or not isinstance(has_more, bool):
        raise _directory_invalid()
    return DirectorySearchResult(tuple(_profile(raw) for raw in cast(list[Any], rows)), has_more)


def _directory_invalid() -> InvalidResponse:
    return InvalidResponse(
        "native_directory_response_invalid", "native directory response is invalid"
    )
