from __future__ import annotations

import json

import httpx
import pytest

from leap_oauth_sdk import Forbidden, InvalidResponse, LeapAuthConfig, Retryable


def profile(**changes):
    return {
        "person_key": "feishu:user_id:u1",
        "user_id": "u1",
        "union_id": "on_1",
        "name": "Example",
        "email": "example@example.com",
        "avatar_url": None,
        "department_path": [{"id": "od_data", "name": "Data"}],
        "status": "unknown",
        **changes,
    }


def client(handler, **kwargs):
    from leap_oauth_sdk.native import DirectoryClient

    return DirectoryClient(
        LeapAuthConfig(issuer="https://auth.example.com", audience="business"),
        lookup_token="synthetic-directory-reader",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


def test_all_locators_return_one_exact_person_and_open_id_has_explicit_source():
    requests = []

    def handler(request):
        assert request.headers["authorization"] == "Bearer synthetic-directory-reader"
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"person": profile()})

    directory = client(handler, bound_app_id="cli_central")
    for locator in (
        {"person_key": "feishu:user_id:u1"},
        {"user_id": "u1"},
        {"email": "EXAMPLE@example.com"},
        {"union_id": "on_1"},
        {"open_id": "ou_1"},
    ):
        assert directory.resolve(**locator).person_key == "feishu:user_id:u1"
    assert requests[-1] == {"open_id": "ou_1", "app_id": "cli_central"}
    assert "open_id" not in directory.resolve(user_id="u1").to_dict()
    count = len(requests)
    for locator in (
        {},
        {"user_id": "u1", "email": "example@example.com"},
        {"user_id": " u1"},
        {"open_id": "ou_1", "app_id": "other_app"},
    ):
        with pytest.raises(ValueError):
            directory.resolve(**locator)
    assert len(requests) == count
    with pytest.raises(ValueError):
        client(handler).resolve(open_id="ou_1")


@pytest.mark.parametrize(
    "locator",
    [
        {"user_id": "other"},
        {"person_key": "feishu:user_id:other"},
        {"union_id": "on_other"},
        {"email": "other@example.com"},
    ],
)
def test_locator_source_mismatch_is_not_resolved_using_another_locator(locator):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"person": profile()})

    with pytest.raises(InvalidResponse):
        client(handler).resolve(**locator)
    assert len(requests) == 1


def test_resolve_for_grant_fresh_lookup_returns_only_key_and_union():
    requests = []

    def handler(request):
        requests.append(request.url.path)
        return httpx.Response(
            200,
            json={"items": [profile()], "has_more": False}
            if request.method == "GET"
            else {"person": profile()},
        )

    directory = client(handler)
    directory.search("Example")
    grant = directory.resolve_for_grant(user_id="u1")
    assert grant.to_dict() == {"person_key": "feishu:user_id:u1", "union_id": "on_1"}
    assert requests == ["/api/v2/feishu/users/search", "/api/v2/feishu/users/resolve"]
    directory = client(
        lambda request: httpx.Response(200, json={"person": profile(status="inactive")})
    )
    with pytest.raises(Forbidden):
        directory.resolve_for_grant(user_id="u1")


@pytest.mark.parametrize(
    "status,error",
    [
        (401, InvalidResponse),
        (403, InvalidResponse),
        (404, Forbidden),
        (409, Forbidden),
        (429, Retryable),
        (502, Retryable),
        (503, Retryable),
    ],
)
def test_directory_failures_do_not_fall_back_or_become_user_login(status, error):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(status, json={"detail": {"code": "source_unavailable"}})

    with pytest.raises(error):
        client(handler).resolve(email="example@example.com")
    assert len(requests) == 1


def test_batch_requires_complete_exact_results_and_search_profile_is_closed():
    keys = ["feishu:user_id:u1", "feishu:user_id:missing"]
    good = {
        "results": [
            {"person_key": keys[0], "state": "found", "person": profile()},
            {"person_key": keys[1], "state": "not_found"},
        ]
    }
    results = client(lambda request: httpx.Response(200, json=good)).batch(keys)
    assert [item.state for item in results] == ["found", "not_found"]
    assert results[0].person.person_key == keys[0]
    for bad in (
        {"results": good["results"][:1]},
        {"items": [profile()], "invalid_keys": [keys[1]]},
        {"results": good["results"] * 2},
    ):
        with pytest.raises(InvalidResponse):
            client(lambda request, bad=bad: httpx.Response(200, json=bad)).batch(keys)
    with pytest.raises(InvalidResponse):
        client(
            lambda request: httpx.Response(
                200, json={"items": [profile(open_id="ou_1")], "has_more": False}
            )
        ).search("Example")


@pytest.mark.asyncio
async def test_async_directory_resolve_and_batch():
    from leap_oauth_sdk.native import DirectoryClient

    def handler(request):
        payload = (
            {"person": profile()}
            if request.url.path.endswith("/resolve")
            else {
                "results": [
                    {"person_key": "feishu:user_id:u1", "state": "found", "person": profile()}
                ]
            }
        )
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        directory = DirectoryClient(
            LeapAuthConfig(issuer="https://auth.example.com", audience="business"),
            lookup_token="synthetic",
            async_http_client=http,
        )
        assert (await directory.resolve_async(union_id="on_1")).person_key == "feishu:user_id:u1"
        assert (await directory.batch_async(["feishu:user_id:u1"]))[0].state == "found"


def test_email_changes_only_locate_a_new_person_without_moving_the_old_grant():
    current = [profile()]
    directory = client(lambda request: httpx.Response(200, json={"person": current[0]}))
    original_grant = directory.resolve_for_grant(email="example@example.com")
    current[0] = profile(person_key="feishu:user_id:u2", user_id="u2", union_id="on_2")
    new_selection = directory.resolve_for_grant(email="example@example.com")
    assert original_grant.person_key == "feishu:user_id:u1"
    assert new_selection.person_key == "feishu:user_id:u2"
