from __future__ import annotations

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx

from leap_oauth_sdk import (
    AccessTokenVerifier,
    BrowserClientConfig,
    BrowserSSO,
    Forbidden,
    InvalidResponse,
    LeapAuthConfig,
    OAuthSDKError,
    ReauthRequired,
    Retryable,
)

from .conftest import AUDIENCE, ISSUER, LOGOUT_URL, SESSION_URL, TOKEN_URL


def _form(request: httpx.Request) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(request.content.decode()).items()}


def test_browser_config_and_authorization_url(sso: BrowserSSO, browser_client) -> None:
    assert sso.browser_config() == {
        "enabled": True,
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/api/oauth/authorize",
        "client_id": "web-example",
        "redirect_uri": browser_client.redirect_uri,
        "resource": browser_client.resource,
    }
    url = urlsplit(sso.authorization_url(state="s", code_challenge="c"))
    query = {key: values[0] for key, values in parse_qs(url.query).items()}
    assert url.netloc == "auth.example.com"
    assert query == {
        "response_type": "code",
        "client_id": "web-example",
        "redirect_uri": browser_client.redirect_uri,
        "resource": browser_client.resource,
        "code_challenge": "c",
        "code_challenge_method": "S256",
        "state": "s",
    }
    explicit = parse_qs(
        urlsplit(sso.authorization_url(state="s", code_challenge="c", explicit=True)).query
    )
    assert explicit["allow_login"] == ["1"]


def test_start_authorization_uses_s256(sso: BrowserSSO) -> None:
    request = sso.start_authorization()
    query = parse_qs(urlsplit(request.url).query)
    digest = hashlib.sha256(request.code_verifier.encode()).digest()
    assert query["code_challenge"] == [base64.urlsafe_b64encode(digest).rstrip(b"=").decode()]
    assert query["state"] == [request.state]
    assert "allow_login" not in query
    assert request.code_verifier not in repr(request)


@respx.mock
def test_exchange_code_returns_verified_session(sso: BrowserSSO, token_response) -> None:
    route = respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=token_response()))

    session = sso.exchange_code("code-1", "v" * 43)

    assert session.subject_id == "usr_1"
    assert session.refresh_token == "rt-1"
    assert session.context.browser_session_id == "bsid-1"
    assert session.auth_expires_at is not None
    assert session.access_token not in repr(session) and "rt-1" not in repr(session)
    assert session.to_browser_payload() == {
        "access_token": session.access_token,
        "token_type": "Bearer",
        "expires_at": session.expires_at,
        "refresh_token": "rt-1",
    }
    form = _form(route.calls.last.request)
    assert form == {
        "grant_type": "authorization_code",
        "code": "code-1",
        "code_verifier": "v" * 43,
        "client_id": "web-example",
        "redirect_uri": "https://app.example.com/auth/callback",
        "resource": "https://app.example.com/",
    }


@respx.mock
def test_refresh_sends_refresh_grant_and_checks_subject(sso: BrowserSSO, token_response) -> None:
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=token_response(refresh_token="rt-2"))
    )
    assert sso.refresh("rt-1", expected_subject_id="usr_1").refresh_token == "rt-2"
    assert _form(route.calls.last.request) == {
        "grant_type": "refresh_token",
        "refresh_token": "rt-1",
        "client_id": "web-example",
        "resource": "https://app.example.com/",
    }
    with pytest.raises(ReauthRequired) as exc_info:
        sso.refresh("rt-1", expected_subject_id="usr_other")
    assert exc_info.value.code == "browser_session_subject_changed"


ROTATION = {"error": "temporarily_unavailable", "error_description": "refresh_rotation_in_progress"}


@pytest.mark.parametrize(
    ("response", "category", "code"),
    [
        (httpx.Response(400, json=ROTATION), Retryable, "refresh_rotation_in_progress"),
        (
            httpx.Response(400, json={"error": "temporarily_unavailable"}),
            Retryable,
            "auth_temporarily_unavailable",
        ),
        (httpx.Response(503), Retryable, "auth_upstream_unavailable"),
        (httpx.Response(429), Retryable, "auth_upstream_unavailable"),
        (httpx.ConnectError("down"), Retryable, "auth_upstream_unavailable"),
        (httpx.ReadTimeout("slow"), Retryable, "auth_upstream_unavailable"),
        (
            httpx.Response(400, json={"error": "invalid_grant"}),
            ReauthRequired,
            "browser_session_invalid",
        ),
        (httpx.Response(401), ReauthRequired, "browser_session_invalid"),
        (httpx.Response(403, json={"error": "access_denied"}), Forbidden, "auth_access_denied"),
        (
            httpx.Response(400, json={"error": "invalid_client"}),
            InvalidResponse,
            "auth_request_rejected",
        ),
        (
            httpx.Response(302, headers={"Location": "https://evil.example.com"}),
            InvalidResponse,
            "auth_upstream_redirect",
        ),
        (httpx.Response(200, content=b"not json"), InvalidResponse, "auth_response_invalid"),
        (httpx.Response(200, json={"access_token": "x"}), InvalidResponse, "auth_response_invalid"),
        (
            httpx.Response(
                200, json={"access_token": "x", "refresh_token": "y", "token_type": "mac"}
            ),
            InvalidResponse,
            "auth_response_invalid",
        ),
    ],
)
@respx.mock
def test_token_endpoint_errors_are_classified(sso: BrowserSSO, response, category, code) -> None:
    respx.post(TOKEN_URL).mock(side_effect=[response, response])
    for call in (lambda: sso.exchange_code("code-1", "v" * 43), lambda: sso.refresh("rt-1")):
        with pytest.raises(category) as exc_info:
            call()
        assert exc_info.value.code == code
        assert exc_info.value.status == category.status


@pytest.mark.parametrize(
    ("overrides", "category", "code"),
    [
        ({"aud": "other-service"}, ReauthRequired, "access_token_invalid"),
        ({"status": "disabled"}, Forbidden, "access_token_principal_inactive"),
        ({"browser_sid": None}, InvalidResponse, "browser_session_unbound"),
    ],
)
@respx.mock
def test_exchanged_token_must_verify(
    sso: BrowserSSO, token_response, overrides, category, code
) -> None:
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=token_response(**overrides)))
    with pytest.raises(category) as exc_info:
        sso.exchange_code("code-1", "v" * 43)
    assert exc_info.value.code == code


def test_missing_inputs_fail_before_network(sso: BrowserSSO) -> None:
    with pytest.raises(ReauthRequired):
        sso.exchange_code("", "v" * 43)
    with pytest.raises(ReauthRequired):
        sso.refresh("")
    with pytest.raises(ReauthRequired):
        sso.logout("")
    with pytest.raises(ValueError):
        sso.logout("token", "everything")  # type: ignore[arg-type]


@respx.mock
def test_check_session_verifies_locally_then_online(sso: BrowserSSO, key, claims) -> None:
    token = key.sign(claims(browser_sid="bsid-1"))
    route = respx.post(SESSION_URL).mock(
        return_value=httpx.Response(
            200, json={"active": True, "subject_id": "usr_1", "audience": AUDIENCE}
        )
    )
    assert sso.check_session(token).subject_id == "usr_1"
    assert route.calls.last.request.headers["Authorization"] == "Bearer " + token

    for bad in (
        key.sign(claims(browser_sid="bsid-1", exp=int(time.time()) - 120)),
        key.sign(claims()),  # not a browser sign-in token
    ):
        with pytest.raises(ReauthRequired):
            sso.check_session(bad)
    assert route.call_count == 1


@respx.mock
async def test_check_session_accepts_a_verified_context(sso: BrowserSSO, key, claims) -> None:
    token = key.sign(claims(browser_sid="bsid-1"))
    respx.post(SESSION_URL).mock(
        return_value=httpx.Response(
            200, json={"active": True, "subject_id": "usr_1", "audience": AUDIENCE}
        )
    )
    context = sso.verifier.verify(token)
    assert sso.check_session(token, verified=context) is context
    assert await sso.check_session_async(token, verified=context) is context
    device = sso.verifier.verify(key.sign(claims()))
    with pytest.raises(ReauthRequired):
        sso.check_session(token, verified=device)


@pytest.mark.parametrize(
    ("response", "category", "code"),
    [
        (
            httpx.Response(401, json={"detail": "browser_session_revoked"}),
            ReauthRequired,
            "browser_session_revoked",
        ),
        (httpx.Response(200, json={"active": False}), ReauthRequired, "browser_session_revoked"),
        (
            httpx.Response(200, json={"active": True, "subject_id": "usr_2", "audience": AUDIENCE}),
            InvalidResponse,
            "browser_session_mismatch",
        ),
        (httpx.Response(403), Forbidden, "auth_access_denied"),
        (httpx.Response(503), Retryable, "auth_upstream_unavailable"),
        (httpx.ConnectError("down"), Retryable, "auth_upstream_unavailable"),
    ],
)
@respx.mock
def test_check_session_errors(sso: BrowserSSO, key, claims, response, category, code) -> None:
    respx.post(SESSION_URL).mock(side_effect=[response])
    with pytest.raises(category) as exc_info:
        sso.check_session(key.sign(claims(browser_sid="bsid-1")))
    assert exc_info.value.code == code


@respx.mock
def test_logout_treats_ended_sign_in_as_success(sso: BrowserSSO) -> None:
    route = respx.post(LOGOUT_URL).mock(
        side_effect=[httpx.Response(200, json={"success": True}), httpx.Response(401)]
    )
    sso.logout("token-1")
    sso.logout("token-1", "current")
    assert json.loads(route.calls[0].request.content) == {"scope": "browser"}
    assert json.loads(route.calls[1].request.content) == {"scope": "current"}
    assert route.calls[0].request.headers["Authorization"] == "Bearer token-1"


@pytest.mark.parametrize(
    ("response", "category"),
    [
        (httpx.Response(503), Retryable),
        (httpx.ConnectError("down"), Retryable),
        (httpx.Response(403), Forbidden),
        (httpx.Response(400, json={"detail": "invalid_logout_scope"}), InvalidResponse),
    ],
)
@respx.mock
def test_logout_failures_keep_credentials(sso: BrowserSSO, response, category) -> None:
    respx.post(LOGOUT_URL).mock(side_effect=[response])
    with pytest.raises(category):
        sso.logout("token-1")


@respx.mock
async def test_async_variants(sso: BrowserSSO, token_response, key, claims) -> None:
    respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json=token_response()),
            httpx.Response(200, json=token_response(refresh_token="rt-2")),
            httpx.Response(400, json=ROTATION),
        ]
    )
    respx.post(SESSION_URL).mock(
        return_value=httpx.Response(
            200, json={"active": True, "subject_id": "usr_1", "audience": AUDIENCE}
        )
    )
    logout = respx.post(LOGOUT_URL).mock(return_value=httpx.Response(200, json={"success": True}))

    session = await sso.exchange_code_async("code-1", "v" * 43)
    refreshed = await sso.refresh_async(session.refresh_token, expected_subject_id="usr_1")
    assert refreshed.refresh_token == "rt-2"
    with pytest.raises(Retryable):
        await sso.refresh_async("rt-2")
    assert (await sso.check_session_async(refreshed.access_token)).subject_id == "usr_1"
    await sso.logout_async(refreshed.access_token)
    assert logout.call_count == 1


@respx.mock
def test_backend_calls_use_api_base_url(config, key, token_response) -> None:
    client = BrowserClientConfig(
        client_id="web-example",
        redirect_uri="https://app.example.com/auth/callback",
        resource="https://app.example.com/",
        api_base_url="http://127.0.0.1:8080/",
    )
    sso = BrowserSSO(config, client, AccessTokenVerifier(config, jwks={"keys": [key.jwk]}))
    route = respx.post("http://127.0.0.1:8080/api/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response())
    )
    sso.exchange_code("code-1", "v" * 43)
    assert route.called
    assert sso.authorization_endpoint == ISSUER + "/api/oauth/authorize"


@respx.mock
def test_shared_http_clients_are_used(config, browser_client, key, token_response) -> None:
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=token_response()))
    with httpx.Client() as client:
        sso = BrowserSSO(
            config,
            browser_client,
            AccessTokenVerifier(config, jwks={"keys": [key.jwk]}),
            http_client=client,
        )
        assert sso.exchange_code("code-1", "v" * 43).subject_id == "usr_1"


def test_client_config_validation(config) -> None:
    with pytest.raises(ValueError):
        BrowserClientConfig(
            client_id=" ", redirect_uri="https://a.example.com/", resource="https://a.example.com/"
        )
    with pytest.raises(ValueError):
        BrowserClientConfig(
            client_id="c", redirect_uri="http://a.example.com/", resource="https://a.example.com/"
        )
    with pytest.raises(ValueError):
        BrowserClientConfig(
            client_id="c",
            redirect_uri="https://a.example.com/#x",
            resource="https://a.example.com/",
        )
    with pytest.raises(ValueError):
        BrowserClientConfig(client_id="c", redirect_uri="https://a.example.com/", resource="urn:x")
    local = BrowserClientConfig(
        client_id="c", redirect_uri="http://localhost:3000/cb", resource="http://localhost:3000/"
    )
    assert local.redirect_path == "/cb"
    other = LeapAuthConfig(issuer=ISSUER, audience="other")
    with pytest.raises(ValueError):
        BrowserSSO(config, local, AccessTokenVerifier(other))


def test_error_serialization() -> None:
    retry = Retryable("auth_upstream_unavailable", "unavailable")
    assert retry.to_dict() == {
        "error": "auth_upstream_unavailable",
        "message": "unavailable",
        "retryable": True,
    }
    assert retry.headers == {"Retry-After": "1"}
    denied: OAuthSDKError = Forbidden("auth_access_denied", "denied")
    assert denied.to_dict()["retryable"] is False
    assert denied.headers == {}
