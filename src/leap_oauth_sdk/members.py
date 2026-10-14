"""Admin membership rules shared by every service; storage stays in the service.

Rules enforced here:

- owners come only from configuration; they cannot be stored, added or removed at runtime;
- only owners add or remove members;
- every addition is canonicalized through :class:`PrincipalDirectory` first; without a
  directory, members can be listed and removed but not added;
- writes carry the version the admin saw, and a concurrent change fails instead of
  overwriting;
- each change produces one :class:`MemberChange` audit record for the store to persist.

Role checks read the store on every call; nothing is cached, so a revocation takes effect on
the next request.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import threading
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from .errors import OAuthSDKError
from .principals import PrincipalCandidate, PrincipalDirectory, PrincipalStatus

Role = Literal["owner", "member"]


class MemberError(Exception):
    """A membership request that must be refused. Same ``to_dict`` shape as SDK errors."""

    retryable = False

    def __init__(self, code: str, message: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.code, "message": self.message, "retryable": False}


def _owner_required() -> MemberError:
    return MemberError("member_owner_required", "only owners can change members", 403)


def _owner_protected() -> MemberError:
    return MemberError("member_owner_managed_by_config", "owners are managed in configuration", 409)


def _directory_unavailable() -> MemberError:
    return MemberError("member_directory_unavailable", "principal lookup is not configured", 503)


def version_conflict() -> MemberError:
    """Raise this from :meth:`MemberStore.apply` when ``expected_version`` is stale."""
    return MemberError(
        "member_version_conflict", "members changed since they were loaded; reload", 409
    )


@dataclass(frozen=True, slots=True)
class MemberPolicy:
    owners: frozenset[str]

    def __post_init__(self) -> None:
        owners = frozenset(s.strip() for s in self.owners if s and s.strip())
        if not owners:
            raise ValueError("at least one owner is required")
        object.__setattr__(self, "owners", owners)

    def is_owner(self, subject_id: str) -> bool:
        return subject_id in self.owners


@dataclass(frozen=True, slots=True)
class StoredMembers:
    subject_ids: frozenset[str]
    version: str


@dataclass(frozen=True, slots=True)
class MemberChange:
    """Audit record for one add or remove; the store persists it with the change."""

    at: int
    actor_subject_id: str
    action: Literal["add", "remove"]
    target_subject_ids: tuple[str, ...]
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "actor_subject_id": self.actor_subject_id,
            "action": self.action,
            "target_subject_ids": list(self.target_subject_ids),
            "request_id": self.request_id,
        }


class MemberStore(Protocol):
    """Service-owned storage. Implement both methods atomically for the service's database."""

    def load(self) -> StoredMembers: ...

    def apply(self, change: MemberChange, *, expected_version: str) -> str:
        """Add or remove ``change.target_subject_ids`` and persist ``change`` as audit,
        only if the current version equals ``expected_version`` (else raise
        :func:`version_conflict`). Returns the new version."""
        ...


@dataclass(frozen=True, slots=True)
class Member:
    subject_id: str
    role: Role
    display_name: str | None = None
    email: str | None = None
    department: str | None = None
    #: Principal state from the authorization server; ``None`` when the directory failed.
    state: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "role": self.role,
            "display_name": self.display_name,
            "email": self.email,
            "department": self.department,
            "state": self.state,
            "editable": self.role == "member",
        }


@dataclass(frozen=True, slots=True)
class MemberSnapshot:
    members: tuple[Member, ...]
    version: str
    #: ``False`` when profiles could not be loaded; members can still be removed by id.
    directory_available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "members": [m.to_dict() for m in self.members],
            "version": self.version,
            "directory_available": self.directory_available,
        }


Selection = Sequence[str | PrincipalCandidate]


class MemberService:
    def __init__(
        self, policy: MemberPolicy, store: MemberStore, directory: PrincipalDirectory | None
    ) -> None:
        self._policy = policy
        self._store = store
        self._directory = directory

    @property
    def policy(self) -> MemberPolicy:
        return self._policy

    @property
    def can_add(self) -> bool:
        return self._directory is not None

    def role_for(self, subject_id: str) -> Role | None:
        if self._policy.is_owner(subject_id):
            return "owner"
        return "member" if subject_id in self._store.load().subject_ids else None

    async def role_for_async(self, subject_id: str) -> Role | None:
        if self._policy.is_owner(subject_id):
            return "owner"
        stored = await asyncio.to_thread(self._store.load)
        return "member" if subject_id in stored.subject_ids else None

    def list(self) -> MemberSnapshot:
        stored = self._store.load()
        if self._directory is None:
            return self._snapshot(stored, None)
        try:
            statuses = self._directory.validate(self._all_ids(stored))
        except OAuthSDKError:
            return self._snapshot(stored, None)
        return self._snapshot(stored, statuses)

    async def list_async(self) -> MemberSnapshot:
        stored = await asyncio.to_thread(self._store.load)
        if self._directory is None:
            return self._snapshot(stored, None)
        try:
            statuses = await self._directory.validate_async(self._all_ids(stored))
        except OAuthSDKError:
            return self._snapshot(stored, None)
        return self._snapshot(stored, statuses)

    def add(self, actor_subject_id: str, selection: Selection, *, expected_version: str) -> str:
        """Returns the new version. Owners in the selection are ignored."""
        self._require_owner(actor_subject_id)
        if self._directory is None:
            raise _directory_unavailable()
        accepted = self._directory.canonicalize(selection)
        return self._apply_add(actor_subject_id, accepted, expected_version, self._store.load())

    async def add_async(
        self, actor_subject_id: str, selection: Selection, *, expected_version: str
    ) -> str:
        self._require_owner(actor_subject_id)
        if self._directory is None:
            raise _directory_unavailable()
        accepted = await self._directory.canonicalize_async(selection)
        stored = await asyncio.to_thread(self._store.load)
        change = self._add_change(actor_subject_id, accepted, stored)
        if change is None:
            return stored.version
        return await asyncio.to_thread(self._store.apply, change, expected_version=expected_version)

    def remove(self, actor_subject_id: str, subject_id: str, *, expected_version: str) -> str:
        change = self._remove_change(actor_subject_id, subject_id)
        return self._store.apply(change, expected_version=expected_version)

    async def remove_async(
        self, actor_subject_id: str, subject_id: str, *, expected_version: str
    ) -> str:
        change = self._remove_change(actor_subject_id, subject_id)
        return await asyncio.to_thread(self._store.apply, change, expected_version=expected_version)

    # -- internals -----------------------------------------------------------------------

    def _require_owner(self, actor_subject_id: str) -> None:
        if not self._policy.is_owner(actor_subject_id):
            raise _owner_required()

    def _all_ids(self, stored: StoredMembers) -> list[str]:
        return sorted(self._policy.owners) + sorted(stored.subject_ids - self._policy.owners)

    def _snapshot(
        self, stored: StoredMembers, statuses: Mapping[str, PrincipalStatus] | None
    ) -> MemberSnapshot:
        members: list[Member] = []
        for subject_id in self._all_ids(stored):
            status = (statuses or {}).get(subject_id)
            members.append(
                Member(
                    subject_id=subject_id,
                    role="owner" if self._policy.is_owner(subject_id) else "member",
                    display_name=status.display_name if status else None,
                    email=status.email if status else None,
                    department=status.department if status else None,
                    state=status.state if status else None,
                )
            )
        return MemberSnapshot(tuple(members), stored.version, statuses is not None)

    def _add_change(
        self, actor: str, accepted: Iterable[PrincipalStatus], stored: StoredMembers
    ) -> MemberChange | None:
        targets = tuple(
            dict.fromkeys(
                s.effective_subject_id
                for s in accepted
                if not self._policy.is_owner(s.effective_subject_id)
                and s.effective_subject_id not in stored.subject_ids
            )
        )
        if not targets:
            return None
        return MemberChange(int(time.time()), actor, "add", targets)

    def _apply_add(
        self,
        actor: str,
        accepted: Iterable[PrincipalStatus],
        expected_version: str,
        stored: StoredMembers,
    ) -> str:
        change = self._add_change(actor, accepted, stored)
        if change is None:
            return stored.version
        return self._store.apply(change, expected_version=expected_version)

    def _remove_change(self, actor: str, subject_id: str) -> MemberChange:
        self._require_owner(actor)
        target = subject_id.strip()
        if not target:
            raise MemberError("member_subject_invalid", "subject_id is required", 422)
        if self._policy.is_owner(target):
            raise _owner_protected()
        return MemberChange(int(time.time()), actor, "remove", (target,))


class JsonFileMemberStore:
    """Reference store: one JSON file plus an append-only ``.audit.jsonl`` next to it.

    Suitable for a single-replica service on a persistent volume. Writes are atomic
    (temporary file and rename) and serialized within the process; the version is the
    SHA-256 of the file content.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._audit = self._path.with_name(self._path.name + ".audit.jsonl")
        self._lock = threading.Lock()

    def load(self) -> StoredMembers:
        raw = self._read()
        return StoredMembers(frozenset(_subjects(raw)), _version(raw))

    def apply(self, change: MemberChange, *, expected_version: str) -> str:
        with self._lock:
            raw = self._read()
            if _version(raw) != expected_version:
                raise version_conflict()
            members = set(_subjects(raw))
            if change.action == "add":
                members.update(change.target_subject_ids)
            else:
                members.difference_update(change.target_subject_ids)
            content = json.dumps(
                {"schema_version": 1, "subject_ids": sorted(members)}, indent=2
            ).encode("utf-8")
            self._path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(dir=self._path.parent, prefix=".members-")
            try:
                with os.fdopen(handle, "wb") as file:
                    file.write(content)
                os.replace(temporary, self._path)
            except BaseException:
                Path(temporary).unlink(missing_ok=True)
                raise
            with self._audit.open("a", encoding="utf-8") as audit:
                audit.write(json.dumps(change.to_dict(), ensure_ascii=False) + "\n")
            return _version(content)

    def _read(self) -> bytes:
        try:
            return self._path.read_bytes()
        except FileNotFoundError:
            return b""


def _subjects(raw: bytes) -> list[str]:
    if not raw:
        return []
    data: Any = json.loads(raw)
    values: Any = cast(dict[str, Any], data).get("subject_ids") if isinstance(data, dict) else None
    if not isinstance(values, list):
        raise ValueError("member file must contain a subject_ids list")
    return [v for v in cast(list[Any], values) if isinstance(v, str) and v]


def _version(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
