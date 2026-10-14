from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from leap_oauth_sdk import (
    InvalidResponse,
    PrincipalCandidate,
    PrincipalDirectory,
    PrincipalSelectionError,
    Retryable,
)

from .conftest import ISSUER

PICKER = ISSUER + "/api/principals/picker/search"
RESOLVE = ISSUER + "/api/principals/directory/resolve"
VALIDATE = ISSUER + "/api/principals/validate"


def _status(subject_id: str, **overrides: Any) -> dict[str, Any]:
    return {
        "subject_id": subject_id,
        "canonical_subject_id": None,
        "state": "active",
        "exists": True,
        "active": True,
        "expired": False,
        "principal_type": "human",
        "status": "active",
        "display_name": subject_id.upper(),
        "email": f"{subject_id}@example.com",
        "department": "Team",
        **overrides,
    }


def _validate_from(statuses: dict[str, dict[str, Any]]):
    def handler(request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["subject_ids"]
        return httpx.Response(200, json={"subjects": [statuses[i] for i in ids if i in statuses]})

    return handler


@pytest.fixture
def directory(config) -> PrincipalDirectory:
    return PrincipalDirectory(config, lookup_token="lookup-secret")


PICKER_RESPONSE = {
    "query": "ann",
    "items": [
        {
            "source": "principal",
            "key": "principal:usr_ann",
            "subject_id": "usr_ann",
            "display_name": "Ann",
            "email": "ann@example.com",
            "department": "Team A",
            "status": "active",
            "feishu_user_id": "fu_ann",
            "directory_presence": "visible",
        },
        {
            "source": "directory",
            "key": "directory:fu_bob",
            "directory_user": {"user_id": "fu_bob", "name": "Bob", "email": "bob@example.com"},
            "feishu_user_id": "fu_bob",
            "display_name": "Bob",
            "email": "bob@example.com",
            "already_bound": False,
        },
        {"source": "directory", "key": "broken"},
    ],
    "principal_count": 1,
    "directory_count": 2,
    "directory_has_more": True,
    "directory_error": None,
}


@respx.mock
def test_search_returns_principals_and_directory_users(directory) -> None:
    route = respx.get(PICKER).mock(return_value=httpx.Response(200, json=PICKER_RESPONSE))

    result = directory.search("  ann  ", limit=99)

    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer lookup-secret"
    assert request.url.params["q"] == "ann" and request.url.params["limit"] == "30"
    ann, bob = result.candidates
    assert (ann.source, ann.subject_id, ann.display_name) == ("principal", "usr_ann", "Ann")
    assert ann.directory_user is None
    assert (bob.source, bob.subject_id, bob.directory_user_id) == ("directory", None, "fu_bob")
    assert result.directory_has_more and result.directory_available
    assert PrincipalCandidate.from_dict(bob.to_dict()).directory_user == bob.directory_user


@respx.mock
def test_search_short_query_and_directory_outage(directory) -> None:
    route = respx.get(PICKER).mock(
        return_value=httpx.Response(
            200,
            json={
                **PICKER_RESPONSE,
                "items": PICKER_RESPONSE["items"][:1],
                "directory_error": {"code": "x"},
            },
        )
    )
    assert directory.search("a").candidates == ()
    assert not route.called
    result = directory.search("ann")
    assert len(result.candidates) == 1 and result.directory_available is False


@respx.mock
def test_validate_deduplicates_and_batches(directory) -> None:
    ids = [f"usr_{i}" for i in range(250)]
    route = respx.post(VALIDATE).mock(side_effect=_validate_from({i: _status(i) for i in ids}))

    statuses = directory.validate([*ids, *ids[:10], " ", ""])

    assert len(statuses) == 250
    assert [len(json.loads(c.request.content)["subject_ids"]) for c in route.calls] == [
        100,
        100,
        50,
    ]
    assert statuses["usr_7"].display_name == "USR_7"


@respx.mock
def test_canonicalize_resolves_directory_picks_and_follows_aliases(directory) -> None:
    resolve = respx.post(RESOLVE).mock(
        return_value=httpx.Response(
            200, json={"principal": {"subject_id": "usr_bob"}, "directory_user": {}}
        )
    )
    respx.post(VALIDATE).mock(
        side_effect=_validate_from(
            {
                "usr_ann": _status("usr_ann"),
                "usr_bob": _status("usr_bob"),
                "usr_old": _status("usr_old", canonical_subject_id="usr_ann"),
            }
        )
    )
    bob = PrincipalCandidate(
        source="directory",
        key="d",
        subject_id=None,
        directory_user_id="fu_bob",
        directory_user={"user_id": "fu_bob"},
    )

    accepted = directory.canonicalize(["usr_ann", bob, "usr_old"])

    assert [s.effective_subject_id for s in accepted] == ["usr_ann", "usr_bob"]
    assert json.loads(resolve.calls.last.request.content) == {
        "user_id": "fu_bob",
        "directory_user": {"user_id": "fu_bob"},
    }


@respx.mock
def test_canonicalize_rejects_the_whole_selection(directory) -> None:
    respx.post(RESOLVE).mock(
        return_value=httpx.Response(
            422, json={"detail": {"code": "feishu_directory_user_not_visible"}}
        )
    )
    respx.post(VALIDATE).mock(
        side_effect=_validate_from(
            {
                "usr_ok": _status("usr_ok"),
                "usr_gone": _status("usr_gone", active=False, state="inactive", status="departed"),
                "svc_bot": _status("svc_bot", principal_type="service"),
            }
        )
    )
    hidden = PrincipalCandidate(
        source="directory", key="d", subject_id=None, directory_user_id="fu_x"
    )
    nameless = PrincipalCandidate(source="directory", key="k", subject_id=None)

    with pytest.raises(PrincipalSelectionError) as exc_info:
        directory.canonicalize(["usr_ok", "usr_gone", "svc_bot", "usr_missing", hidden, nameless])

    assert exc_info.value.rejected == {
        "usr_gone": "inactive",
        "svc_bot": "principal_type_not_allowed",
        "usr_missing": "not_found",
        "fu_x": "feishu_directory_user_not_visible",
        "k": "directory_user_missing",
    }
    assert exc_info.value.status == 422
    assert exc_info.value.to_dict()["error"] == "principal_selection_invalid"
    with pytest.raises(PrincipalSelectionError):
        directory.canonicalize([])


@pytest.mark.parametrize(
    ("response", "category", "code"),
    [
        (httpx.Response(401), InvalidResponse, "principal_lookup_unauthorized"),
        (httpx.Response(403), InvalidResponse, "principal_lookup_unauthorized"),
        (httpx.Response(503), Retryable, "auth_upstream_unavailable"),
        (httpx.Response(429), Retryable, "auth_upstream_unavailable"),
        (httpx.ConnectError("down"), Retryable, "auth_upstream_unavailable"),
        (httpx.Response(302), InvalidResponse, "auth_upstream_redirect"),
        (httpx.Response(400), InvalidResponse, "auth_request_rejected"),
        (httpx.Response(200, json=["x"]), InvalidResponse, "principal_response_invalid"),
        (
            httpx.Response(200, json={"subjects": "x"}),
            InvalidResponse,
            "principal_response_invalid",
        ),
    ],
)
@respx.mock
def test_lookup_failures_never_ask_the_user_to_sign_in_again(
    directory, response, category, code
) -> None:
    respx.post(VALIDATE).mock(side_effect=[response])
    with pytest.raises(category) as exc_info:
        directory.validate(["usr_1"])
    assert exc_info.value.code == code


@respx.mock
def test_resolve_without_subject_is_invalid(directory) -> None:
    respx.post(RESOLVE).mock(return_value=httpx.Response(200, json={"principal": {}}))
    pick = PrincipalCandidate(
        source="directory", key="d", subject_id=None, directory_user_id="fu_1"
    )
    with pytest.raises(InvalidResponse):
        directory.canonicalize([pick])


@respx.mock
async def test_async_variants(directory) -> None:
    respx.get(PICKER).mock(return_value=httpx.Response(200, json=PICKER_RESPONSE))
    respx.post(RESOLVE).mock(
        side_effect=[
            httpx.Response(200, json={"principal": {"subject_id": "usr_bob"}}),
            httpx.Response(404, json={"detail": "not_found"}),
        ]
    )
    respx.post(VALIDATE).mock(
        side_effect=_validate_from({"usr_ann": _status("usr_ann"), "usr_bob": _status("usr_bob")})
    )

    result = await directory.search_async("ann")
    accepted = await directory.canonicalize_async(list(result.candidates))
    assert {s.subject_id for s in accepted} == {"usr_ann", "usr_bob"}
    assert (await directory.validate_async(["usr_ann"]))["usr_ann"].active
    assert (await directory.search_async("a")).candidates == ()
    with pytest.raises(PrincipalSelectionError) as exc_info:
        await directory.canonicalize_async([result.candidates[1]])
    assert exc_info.value.rejected == {"fu_bob": "not_found"}


def test_configuration_and_untrusted_picks(config) -> None:
    with pytest.raises(ValueError):
        PrincipalDirectory(config, lookup_token=" ")
    with pytest.raises(ValueError):
        PrincipalDirectory(config, lookup_token="t", allowed_principal_types=())
    with pytest.raises(ValueError):
        PrincipalDirectory(config, lookup_token="t", api_base_url="ftp://x")
    with pytest.raises(PrincipalSelectionError):
        PrincipalCandidate.from_dict({"source": "admin", "subject_id": "usr_1"})
    pick = PrincipalCandidate.from_dict(
        {"source": "principal", "subject_id": "usr_1", "display_name": "spoofed"}
    )
    assert pick.subject_id == "usr_1" and pick.display_name is None


@respx.mock
def test_internal_base_url_and_shared_client(config) -> None:
    route = respx.post("http://127.0.0.1:8080/api/principals/validate").mock(
        return_value=httpx.Response(200, json={"subjects": [_status("usr_1")]})
    )
    with httpx.Client() as client:
        directory = PrincipalDirectory(
            config, lookup_token="t", api_base_url="http://127.0.0.1:8080/", http_client=client
        )
        assert directory.validate(["usr_1"])["usr_1"].active
    assert route.called
