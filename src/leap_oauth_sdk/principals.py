"""Principal lookup for admin pages: search, resolve a directory pick, validate, canonicalize.

Only the five read-style lookup endpoints are called, with a service-held lookup token that
never reaches the browser. A rejected lookup token is a configuration fault, so it surfaces
as :class:`InvalidResponse` (alert) and never as ``ReauthRequired``, which would send the
signed-in user into a sign-in loop.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, cast

import httpx

from .config import LeapAuthConfig, _require_http_url  # pyright: ignore[reportPrivateUsage]
from .errors import InvalidResponse, Retryable

PICKER_PATH = "/api/principals/picker/search"
RESOLVE_PATH = "/api/principals/directory/resolve"
VALIDATE_PATH = "/api/principals/validate"

_VALIDATE_BATCH = 100
_MAX_RESPONSE_BYTES = 512 * 1024


@dataclass(frozen=True, slots=True)
class PrincipalCandidate:
    """One picker row. ``subject_id`` is ``None`` for a directory user not yet bound to a
    Principal; pass the candidate to :meth:`PrincipalDirectory.canonicalize` to bind it."""

    source: Literal["principal", "directory"]
    key: str
    subject_id: str | None
    display_name: str | None = None
    email: str | None = None
    department: str | None = None
    status: str | None = None
    directory_user_id: str | None = None
    directory_user: Mapping[str, Any] | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Safe shape for the admin page; send it back unchanged when the admin picks it."""
        data: dict[str, Any] = {
            "source": self.source,
            "key": self.key,
            "subject_id": self.subject_id,
            "display_name": self.display_name,
            "email": self.email,
            "department": self.department,
            "status": self.status,
            "directory_user_id": self.directory_user_id,
        }
        if self.directory_user is not None:
            data["directory_user"] = dict(self.directory_user)
        return data

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PrincipalCandidate:
        """Rebuild a pick posted back by the page. Nothing in it is trusted: subjects are
        validated and directory users are resolved by the authorization server."""
        source = value.get("source")
        if source not in ("principal", "directory"):
            raise PrincipalSelectionError({"?": "candidate_source_invalid"})
        directory_user = value.get("directory_user")
        return cls(
            source=source,
            key=_text(value.get("key")) or "",
            subject_id=_text(value.get("subject_id")),
            directory_user_id=_text(value.get("directory_user_id")),
            directory_user=(
                cast(Mapping[str, Any], directory_user)
                if isinstance(directory_user, Mapping)
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class PickerResult:
    query: str
    candidates: tuple[PrincipalCandidate, ...]
    directory_has_more: bool = False
    #: ``False`` when the directory search failed; Principal matches are still returned.
    directory_available: bool = True


@dataclass(frozen=True, slots=True)
class PrincipalStatus:
    """Validation result for one submitted subject."""

    subject_id: str
    canonical_subject_id: str | None
    state: str
    active: bool
    principal_type: str | None = None
    status: str | None = None
    display_name: str | None = None
    email: str | None = None
    department: str | None = None

    @property
    def effective_subject_id(self) -> str:
        return self.canonical_subject_id or self.subject_id


class PrincipalSelectionError(Exception):
    """The admin picked someone who cannot be stored (inactive, not human, unknown).

    ``rejected`` maps each refused subject or directory user id to a reason code.
    """

    code = "principal_selection_invalid"
    status = 422
    retryable = False

    def __init__(self, rejected: Mapping[str, str]) -> None:
        super().__init__("selection contains principals that cannot be stored")
        self.rejected = dict(rejected)
        self.message = "selection contains principals that cannot be stored"

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.code,
            "message": self.message,
            "retryable": False,
            "rejected": self.rejected,
        }


class PrincipalDirectory:
    """Lookup client bound to one service's lookup token."""

    def __init__(
        self,
        config: LeapAuthConfig,
        *,
        lookup_token: str,
        api_base_url: str | None = None,
        allowed_principal_types: Iterable[str] = ("human",),
        http_client: httpx.Client | None = None,
        async_http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not lookup_token.strip():
            raise ValueError("lookup_token is required")
        if api_base_url is not None:
            _require_http_url(api_base_url.strip(), "api_base_url")
        self._config = config
        self._token = lookup_token.strip()
        self._base = (api_base_url or config.issuer).strip().rstrip("/")
        self._types = frozenset(allowed_principal_types)
        if not self._types:
            raise ValueError("allowed_principal_types must not be empty")
        self._http_client = http_client
        self._async_http_client = async_http_client

    # -- search ------------------------------------------------------------------------

    def search(self, query: str, *, limit: int = 20) -> PickerResult:
        normalized = " ".join(query.split())
        if len(normalized) < 2:
            return PickerResult(query=normalized, candidates=())
        payload = self._send_sync("GET", PICKER_PATH, params=_search_params(normalized, limit))
        return _picker_result(normalized, payload)

    async def search_async(self, query: str, *, limit: int = 20) -> PickerResult:
        normalized = " ".join(query.split())
        if len(normalized) < 2:
            return PickerResult(query=normalized, candidates=())
        payload = await self._send_async(
            "GET", PICKER_PATH, params=_search_params(normalized, limit)
        )
        return _picker_result(normalized, payload)

    # -- validate ----------------------------------------------------------------------

    def validate(self, subject_ids: Iterable[str]) -> dict[str, PrincipalStatus]:
        """Look up every subject; keys are the submitted ids. Batches of 100."""
        result: dict[str, PrincipalStatus] = {}
        for batch in _batches(subject_ids):
            payload = self._send_sync("POST", VALIDATE_PATH, json_body={"subject_ids": batch})
            result.update(_validation(payload))
        return result

    async def validate_async(self, subject_ids: Iterable[str]) -> dict[str, PrincipalStatus]:
        result: dict[str, PrincipalStatus] = {}
        for batch in _batches(subject_ids):
            payload = await self._send_async(
                "POST", VALIDATE_PATH, json_body={"subject_ids": batch}
            )
            result.update(_validation(payload))
        return result

    # -- canonicalize ------------------------------------------------------------------

    def canonicalize(
        self, selection: Sequence[str | PrincipalCandidate]
    ) -> tuple[PrincipalStatus, ...]:
        """Turn a page selection into canonical, active, allowed Principals.

        Directory picks are resolved (which may create the Principal), then everything is
        validated. Raises :class:`PrincipalSelectionError` if any entry is refused; nothing is
        partially accepted.
        """
        subjects: list[str] = []
        rejected: dict[str, str] = {}
        for item in selection:
            body = _pending_resolve(item, subjects, rejected)
            if body is not None:
                try:
                    payload = self._send_sync("POST", RESOLVE_PATH, json_body=body, resolve=True)
                except _ResolveRejected as exc:
                    rejected[body["user_id"]] = exc.code
                    continue
                subjects.append(_resolved_subject(payload))
        return self._accept(subjects, self.validate(subjects) if subjects else {}, rejected)

    async def canonicalize_async(
        self, selection: Sequence[str | PrincipalCandidate]
    ) -> tuple[PrincipalStatus, ...]:
        subjects: list[str] = []
        rejected: dict[str, str] = {}
        for item in selection:
            body = _pending_resolve(item, subjects, rejected)
            if body is not None:
                try:
                    payload = await self._send_async(
                        "POST", RESOLVE_PATH, json_body=body, resolve=True
                    )
                except _ResolveRejected as exc:
                    rejected[body["user_id"]] = exc.code
                    continue
                subjects.append(_resolved_subject(payload))
        statuses = await self.validate_async(subjects) if subjects else {}
        return self._accept(subjects, statuses, rejected)

    def _accept(
        self,
        subjects: list[str],
        statuses: Mapping[str, PrincipalStatus],
        rejected: dict[str, str],
    ) -> tuple[PrincipalStatus, ...]:
        accepted: dict[str, PrincipalStatus] = {}
        for subject_id in subjects:
            status = statuses.get(subject_id)
            if status is None:
                rejected[subject_id] = "not_found"
            elif not status.active:
                rejected[subject_id] = status.state or "inactive"
            elif status.principal_type not in self._types:
                rejected[subject_id] = "principal_type_not_allowed"
            else:
                accepted.setdefault(status.effective_subject_id, status)
        if rejected:
            raise PrincipalSelectionError(rejected)
        if not accepted:
            raise PrincipalSelectionError({"?": "selection_empty"})
        return tuple(accepted.values())

    # -- transport ---------------------------------------------------------------------

    def _options(
        self, params: dict[str, str] | None, json_body: dict[str, Any] | None
    ) -> dict[str, Any]:
        options: dict[str, Any] = {
            "headers": {"Accept": "application/json", "Authorization": "Bearer " + self._token},
            "follow_redirects": False,
        }
        if params is not None:
            options["params"] = params
        if json_body is not None:
            options["json"] = json_body
        return options

    def _send_sync(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        resolve: bool = False,
    ) -> dict[str, Any]:
        options = self._options(params, json_body)
        try:
            if self._http_client is not None:
                response = self._http_client.request(method, self._base + path, **options)
            else:
                with httpx.Client(timeout=self._config.timeout_seconds) as client:
                    response = client.request(method, self._base + path, **options)
        except httpx.HTTPError as exc:
            raise _unavailable() from exc
        return _payload(response, resolve=resolve)

    async def _send_async(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        resolve: bool = False,
    ) -> dict[str, Any]:
        options = self._options(params, json_body)
        try:
            if self._async_http_client is not None:
                response = await self._async_http_client.request(
                    method, self._base + path, **options
                )
            else:
                async with httpx.AsyncClient(timeout=self._config.timeout_seconds) as client:
                    response = await client.request(method, self._base + path, **options)
        except httpx.HTTPError as exc:
            raise _unavailable() from exc
        return _payload(response, resolve=resolve)


class _ResolveRejected(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _payload(response: httpx.Response, *, resolve: bool) -> dict[str, Any]:
    status = response.status_code
    if status == 429 or status >= 500:
        raise _unavailable()
    if status in (401, 403):
        raise InvalidResponse(
            "principal_lookup_unauthorized", "lookup token was rejected; check its configuration"
        )
    if 300 <= status < 400:
        raise InvalidResponse("auth_upstream_redirect", "authorization server redirected")
    body = _json_object(response)
    if 400 <= status < 500:
        if resolve:
            # The picked directory user cannot be bound (not visible, deactivated, invalid).
            detail = (body or {}).get("detail")
            code = (
                _text(cast(Mapping[str, Any], detail).get("code"))
                if isinstance(detail, Mapping)
                else _text(detail)
            )
            raise _ResolveRejected(code or "directory_user_rejected")
        raise InvalidResponse("auth_request_rejected", f"authorization server returned {status}")
    if body is None:
        raise InvalidResponse("principal_response_invalid", "lookup response is not an object")
    return body


def _pending_resolve(
    item: str | PrincipalCandidate, subjects: list[str], rejected: dict[str, str]
) -> dict[str, Any] | None:
    """Record a subject pick directly; return the resolve request body for a directory pick."""
    if not isinstance(item, PrincipalCandidate):
        subject_id = _text(item)
        if subject_id is None:
            rejected["?"] = "subject_missing"
        else:
            subjects.append(subject_id)
        return None
    if item.subject_id is not None:
        subjects.append(item.subject_id)
        return None
    if not item.directory_user_id:
        rejected[item.key or "?"] = "directory_user_missing"
        return None
    body: dict[str, Any] = {"user_id": item.directory_user_id}
    if item.directory_user is not None:
        body["directory_user"] = dict(item.directory_user)
    return body


def _resolved_subject(payload: dict[str, Any]) -> str:
    principal = payload.get("principal")
    subject_id = (
        _text(cast(Mapping[str, Any], principal).get("subject_id"))
        if isinstance(principal, Mapping)
        else None
    )
    if subject_id is None:
        raise InvalidResponse("principal_response_invalid", "resolve returned no subject")
    return subject_id


def _picker_result(query: str, payload: dict[str, Any]) -> PickerResult:
    items: Any = payload.get("items")
    if not isinstance(items, list):
        raise InvalidResponse("principal_response_invalid", "picker items must be a list")
    candidates: list[PrincipalCandidate] = []
    for raw in cast(list[Any], items):
        if isinstance(raw, Mapping):
            candidate = _candidate(cast(Mapping[str, Any], raw))
            if candidate is not None:
                candidates.append(candidate)
    return PickerResult(
        query=query,
        candidates=tuple(candidates),
        directory_has_more=payload.get("directory_has_more") is True,
        directory_available=payload.get("directory_error") is None,
    )


def _candidate(item: Mapping[str, Any]) -> PrincipalCandidate | None:
    directory_user: Any = item.get("directory_user")
    directory = (
        cast(Mapping[str, Any], directory_user) if isinstance(directory_user, Mapping) else None
    )
    subject_id = _text(item.get("subject_id")) or _text(item.get("matched_subject_id"))
    directory_user_id = _text(item.get("feishu_user_id")) or (
        _text(directory.get("user_id")) if directory is not None else None
    )
    if subject_id is None and directory_user_id is None:
        return None
    source: Literal["principal", "directory"] = (
        "principal" if subject_id is not None else "directory"
    )
    return PrincipalCandidate(
        source=source,
        key=_text(item.get("key")) or (subject_id or directory_user_id or ""),
        subject_id=subject_id,
        display_name=_text(item.get("display_name")),
        email=_text(item.get("email")),
        department=_text(item.get("department")),
        status=_text(item.get("status")),
        directory_user_id=directory_user_id,
        directory_user=directory if subject_id is None else None,
    )


def _validation(payload: dict[str, Any]) -> dict[str, PrincipalStatus]:
    subjects: Any = payload.get("subjects")
    if not isinstance(subjects, list):
        raise InvalidResponse("principal_response_invalid", "validate subjects must be a list")
    result: dict[str, PrincipalStatus] = {}
    for raw in cast(list[Any], subjects):
        if not isinstance(raw, Mapping):
            continue
        item = cast(Mapping[str, Any], raw)
        subject_id = _text(item.get("subject_id"))
        if subject_id is None:
            continue
        result[subject_id] = PrincipalStatus(
            subject_id=subject_id,
            canonical_subject_id=_text(item.get("canonical_subject_id")),
            state=_text(item.get("state")) or "invalid",
            active=item.get("active") is True,
            principal_type=_text(item.get("principal_type")),
            status=_text(item.get("status")),
            display_name=_text(item.get("display_name")),
            email=_text(item.get("email")),
            department=_text(item.get("department")),
        )
    return result


def _search_params(query: str, limit: int) -> dict[str, str]:
    return {"q": query, "limit": str(max(1, min(int(limit), 30)))}


def _batches(subject_ids: Iterable[str]) -> list[list[str]]:
    unique = list(dict.fromkeys(s.strip() for s in subject_ids if s and s.strip()))
    return [unique[i : i + _VALIDATE_BATCH] for i in range(0, len(unique), _VALIDATE_BATCH)]


def _json_object(response: httpx.Response) -> dict[str, Any] | None:
    if len(response.content) > _MAX_RESPONSE_BYTES:
        return None
    try:
        payload: Any = json.loads(response.content)
    except ValueError:
        return None
    return cast(dict[str, Any], payload) if isinstance(payload, dict) else None


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _unavailable() -> Retryable:
    return Retryable("auth_upstream_unavailable", "authorization server is unavailable")
