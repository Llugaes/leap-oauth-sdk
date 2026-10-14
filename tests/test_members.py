from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from leap_oauth_sdk import (
    JsonFileMemberStore,
    MemberError,
    MemberPolicy,
    MemberService,
    PrincipalCandidate,
    PrincipalSelectionError,
    PrincipalStatus,
    Retryable,
)


def _status(subject_id: str, canonical: str | None = None) -> PrincipalStatus:
    return PrincipalStatus(
        subject_id=subject_id,
        canonical_subject_id=canonical,
        state="active",
        active=True,
        principal_type="human",
        display_name=subject_id.upper(),
        email=f"{subject_id}@example.com",
    )


class FakeDirectory:
    """Stands in for PrincipalDirectory; its own behaviour is covered in test_principals."""

    def __init__(self) -> None:
        self.down = False
        self.rejected: set[str] = set()

    def validate(self, subject_ids: Sequence[str]) -> dict[str, PrincipalStatus]:
        if self.down:
            raise Retryable("auth_upstream_unavailable", "down")
        return {s: _status(s) for s in subject_ids}

    def canonicalize(
        self, selection: Sequence[str | PrincipalCandidate]
    ) -> tuple[PrincipalStatus, ...]:
        ids = [s.subject_id if isinstance(s, PrincipalCandidate) else s for s in selection]
        bad = {i: "inactive" for i in ids if i in self.rejected}
        if bad:
            raise PrincipalSelectionError(bad)
        return tuple(
            _status(i or "?", canonical="usr_ann" if i == "usr_alias" else None) for i in ids
        )

    async def validate_async(self, subject_ids: Sequence[str]) -> dict[str, PrincipalStatus]:
        return self.validate(subject_ids)

    async def canonicalize_async(self, selection):
        return self.canonicalize(selection)


@pytest.fixture
def store(tmp_path: Path) -> JsonFileMemberStore:
    return JsonFileMemberStore(tmp_path / "members" / "admins.json")


@pytest.fixture
def directory() -> FakeDirectory:
    return FakeDirectory()


@pytest.fixture
def service(store, directory) -> MemberService:
    return MemberService(MemberPolicy(frozenset({"usr_owner", " "})), store, directory)  # type: ignore[arg-type]


def test_store_versions_atomic_writes_and_audit(store: JsonFileMemberStore, tmp_path: Path) -> None:
    empty = store.load()
    assert empty.subject_ids == frozenset() and empty.version == hashlib.sha256(b"").hexdigest()

    from leap_oauth_sdk import MemberChange

    v1 = store.apply(
        MemberChange(1, "usr_owner", "add", ("usr_b", "usr_a")), expected_version=empty.version
    )
    assert store.load() == type(empty)(frozenset({"usr_a", "usr_b"}), v1)
    path = tmp_path / "members" / "admins.json"
    assert json.loads(path.read_text()) == {"schema_version": 1, "subject_ids": ["usr_a", "usr_b"]}

    with pytest.raises(MemberError) as exc_info:
        store.apply(
            MemberChange(2, "usr_owner", "remove", ("usr_a",)), expected_version=empty.version
        )
    assert (exc_info.value.code, exc_info.value.status) == ("member_version_conflict", 409)

    store.apply(MemberChange(3, "usr_owner", "remove", ("usr_a",)), expected_version=v1)
    assert store.load().subject_ids == frozenset({"usr_b"})
    audit = [
        json.loads(line)
        for line in (path.parent / "admins.json.audit.jsonl").read_text().splitlines()
    ]
    assert [(a["action"], a["target_subject_ids"]) for a in audit] == [
        ("add", ["usr_b", "usr_a"]),
        ("remove", ["usr_a"]),
    ]
    assert not [p for p in path.parent.iterdir() if p.name.startswith(".members-")]

    path.write_text('{"subject_ids": "oops"}')
    with pytest.raises(ValueError):
        store.load()


def test_roles_are_read_on_every_call(service: MemberService, store: JsonFileMemberStore) -> None:
    assert service.role_for("usr_owner") == "owner"
    assert service.role_for("usr_ann") is None
    version = service.add("usr_owner", ["usr_ann"], expected_version=store.load().version)
    assert service.role_for("usr_ann") == "member"
    service.remove("usr_owner", "usr_ann", expected_version=version)
    assert service.role_for("usr_ann") is None, "revocation applies to the next check"


def test_only_owners_change_members_and_owners_are_protected(service: MemberService, store) -> None:
    version = service.add("usr_owner", ["usr_ann"], expected_version=store.load().version)
    for call in (
        lambda: service.add("usr_ann", ["usr_bob"], expected_version=version),
        lambda: service.remove("usr_ann", "usr_ann", expected_version=version),
    ):
        with pytest.raises(MemberError) as exc_info:
            call()
        assert (exc_info.value.code, exc_info.value.status) == ("member_owner_required", 403)
    with pytest.raises(MemberError) as exc_info:
        service.remove("usr_owner", "usr_owner", expected_version=version)
    assert exc_info.value.code == "member_owner_managed_by_config"
    with pytest.raises(MemberError) as exc_info:
        service.remove("usr_owner", " ", expected_version=version)
    assert exc_info.value.status == 422


def test_add_canonicalizes_ignores_owners_and_existing(
    service: MemberService, store, directory
) -> None:
    v0 = store.load().version
    v1 = service.add("usr_owner", ["usr_alias", "usr_owner"], expected_version=v0)
    assert store.load().subject_ids == frozenset({"usr_ann"})
    assert service.add("usr_owner", ["usr_ann"], expected_version=v1) == v1, (
        "no-op keeps the version"
    )

    directory.rejected = {"usr_gone"}
    with pytest.raises(PrincipalSelectionError):
        service.add("usr_owner", ["usr_bob", "usr_gone"], expected_version=v1)
    assert store.load().subject_ids == frozenset({"usr_ann"}), "nothing is partially accepted"

    with pytest.raises(MemberError) as exc_info:
        service.add("usr_owner", ["usr_bob"], expected_version=v0)
    assert exc_info.value.code == "member_version_conflict"


def test_list_marks_owners_and_survives_directory_outage(
    service: MemberService, store, directory
) -> None:
    service.add("usr_owner", ["usr_ann"], expected_version=store.load().version)
    snapshot = service.list()
    assert [(m.subject_id, m.role, m.display_name) for m in snapshot.members] == [
        ("usr_owner", "owner", "USR_OWNER"),
        ("usr_ann", "member", "USR_ANN"),
    ]
    data = snapshot.to_dict()
    assert data["version"] == store.load().version
    assert [m["editable"] for m in data["members"]] == [False, True]

    directory.down = True
    degraded = service.list()
    assert degraded.directory_available is False
    assert [m.subject_id for m in degraded.members] == ["usr_owner", "usr_ann"]
    assert degraded.members[1].display_name is None


async def test_async_variants(service: MemberService, store, directory) -> None:
    v1 = await service.add_async("usr_owner", ["usr_ann"], expected_version=store.load().version)
    assert await service.role_for_async("usr_ann") == "member"
    assert await service.role_for_async("usr_owner") == "owner"
    assert await service.add_async("usr_owner", ["usr_ann"], expected_version=v1) == v1
    assert (await service.list_async()).directory_available
    directory.down = True
    assert (await service.list_async()).directory_available is False
    await service.remove_async("usr_owner", "usr_ann", expected_version=v1)
    assert await service.role_for_async("usr_ann") is None
    with pytest.raises(MemberError):
        await service.add_async("usr_ann", ["usr_x"], expected_version=v1)


def test_policy_requires_an_owner() -> None:
    with pytest.raises(ValueError):
        MemberPolicy(frozenset({" ", ""}))
    assert MemberError("x", "y", 400).to_dict() == {
        "error": "x",
        "message": "y",
        "retryable": False,
    }


async def test_without_directory_members_are_listed_and_removed_but_not_added(store) -> None:
    owner = MemberService(MemberPolicy(frozenset({"usr_owner"})), store, FakeDirectory())  # type: ignore[arg-type]
    version = owner.add("usr_owner", ["usr_ann"], expected_version=store.load().version)
    service = MemberService(MemberPolicy(frozenset({"usr_owner"})), store, None)
    assert not service.can_add and owner.can_add
    snapshot = await service.list_async()
    assert snapshot.directory_available is False
    assert [m.subject_id for m in service.list().members] == ["usr_owner", "usr_ann"]
    for call in (lambda: service.add("usr_owner", ["usr_bob"], expected_version=version),):
        with pytest.raises(MemberError) as exc_info:
            call()
        assert (exc_info.value.code, exc_info.value.status) == ("member_directory_unavailable", 503)
    with pytest.raises(MemberError) as exc_info:
        await service.add_async("usr_owner", ["usr_bob"], expected_version=version)
    assert exc_info.value.code == "member_directory_unavailable"
    with pytest.raises(MemberError) as exc_info:
        service.add("usr_ann", ["usr_bob"], expected_version=version)
    assert exc_info.value.code == "member_owner_required", "permission is checked first"
    await service.remove_async("usr_owner", "usr_ann", expected_version=version)
    assert store.load().subject_ids == frozenset()
