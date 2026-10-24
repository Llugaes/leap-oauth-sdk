from __future__ import annotations

import time
from dataclasses import replace

import httpx
import pytest

from leap_oauth_sdk import (
    BrowserSSO,
    CookieCipher,
    CookieSession,
    CookieSessionManager,
    InvalidResponse,
    OAuthSDKError,
)

from .conftest import AUDIENCE, ISSUER
from .test_transition import PERSON, native_claims, verifier


def browser(config, client, key, handler):
    return BrowserSSO(
        config,
        client,
        verifier(config, key),
        token_profile="transition",
        expected_feishu_tenant="tenant-1",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def token_response(key, payload, native=False):
    return {
        "access_token": key.sign(payload, typ="at+jwt" if native else "JWT"),
        "refresh_token": "same-existing-family",
        "token_type": "Bearer",
    }


def test_existing_browser_subject_refreshes_into_native_without_reauth(
    config, browser_client, key, claims
):
    legacy = claims(browser_sid="same-root", browser_client_id=browser_client.client_id)
    native = native_claims(claims)
    native.update(browser_sid="same-root", client_id=browser_client.client_id)
    bodies = [token_response(key, legacy), token_response(key, native, True)]

    def handler(request):
        return httpx.Response(200, json=bodies.pop(0))

    sso = browser(config, browser_client, key, handler)
    session = sso.exchange_code("code", "pkce")
    assert session.subject_id == PERSON
    assert session.context.wire_subject == "usr_1"
    renewed = sso.refresh(session.refresh_token, expected_subject_id="usr_1")
    assert renewed.subject_id == PERSON
    assert renewed.refresh_token == "same-existing-family"
    assert renewed.context.wire_subject == PERSON


@pytest.mark.parametrize("server_subject", ["usr_1", PERSON])
def test_online_check_accepts_only_the_same_canonical_server_identity(
    config, browser_client, key, claims, server_subject
):
    sso = browser(
        config,
        browser_client,
        key,
        lambda request: httpx.Response(
            200, json={"active": True, "subject_id": server_subject, "audience": AUDIENCE}
        ),
    )
    result = sso.check_session(
        key.sign(claims(browser_sid="same-root", browser_client_id=browser_client.client_id))
    )
    assert result.subject_id == PERSON


def test_online_check_does_not_convert_an_unknown_server_subject_to_another_user(
    config, browser_client, key, claims
):
    sso = browser(
        config,
        browser_client,
        key,
        lambda request: httpx.Response(
            200, json={"active": True, "subject_id": "usr_unknown", "audience": AUDIENCE}
        ),
    )
    with pytest.raises(InvalidResponse):
        sso.check_session(
            key.sign(claims(browser_sid="same-root", browser_client_id=browser_client.client_id))
        )


def test_browser_requires_explicit_mapping_tenant_and_oauth_access_policy(
    config, browser_client, key
):
    check = verifier(config, key)
    with pytest.raises(ValueError):
        BrowserSSO(config, browser_client, check)
    with pytest.raises(ValueError):
        BrowserSSO(config, browser_client, token_profile="transition")
    with pytest.raises(ValueError):
        BrowserSSO(
            config,
            browser_client,
            check,
            token_profile="transition",
            expected_feishu_tenant="wrong-tenant",
        )
    with pytest.raises(ValueError):
        BrowserSSO(
            replace(config, issuer="https://another.example.com"),
            browser_client,
            check,
            token_profile="transition",
            expected_feishu_tenant="tenant-1",
        )


def test_browser_does_not_accept_a_native_ticket_for_another_client(
    config, browser_client, key, claims
):
    payload = native_claims(claims)
    payload.update(browser_sid="same-root", client_id="another-client")
    sso = browser(config, browser_client, key, lambda request: httpx.Response(200, json={}))
    with pytest.raises(OAuthSDKError):
        sso.check_session(key.sign(payload, typ="at+jwt"))


@pytest.mark.asyncio
async def test_async_refresh_and_check_keep_old_cookie_subject(config, browser_client, key, claims):
    payload = native_claims(claims)
    payload.update(browser_sid="same-root", client_id=browser_client.client_id)

    def handler(request):
        if request.url.path.endswith("/session"):
            return httpx.Response(
                200, json={"active": True, "subject_id": PERSON, "audience": AUDIENCE}
            )
        return httpx.Response(200, json=token_response(key, payload, True))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        sso = BrowserSSO(
            config,
            browser_client,
            verifier(config, key),
            token_profile="transition",
            expected_feishu_tenant="tenant-1",
            async_http_client=http,
        )
        session = await sso.refresh_async("same-existing-family", expected_subject_id="usr_1")
        assert session.subject_id == PERSON
        assert (await sso.check_session_async(session.access_token)).authorization_key == (
            ISSUER,
            PERSON,
        )


@pytest.mark.parametrize("refresh", [False, True])
def test_original_encrypted_cookie_is_rewritten_without_changing_the_user_or_root(
    config, browser_client, key, claims, refresh
):
    payload = native_claims(claims)
    payload.update(browser_sid="same-root", client_id=browser_client.client_id)

    def handler(request):
        if request.url.path.endswith("/session"):
            return httpx.Response(
                200, json={"active": True, "subject_id": PERSON, "audience": AUDIENCE}
            )
        return httpx.Response(200, json=token_response(key, payload, True))

    sso = browser(config, browser_client, key, handler)
    manager = CookieSessionManager(sso, CookieCipher("s" * 32))
    original = CookieSession(
        subject_id="usr_1",
        access_token=key.sign(
            claims(browser_sid="same-root", browser_client_id=browser_client.client_id)
        ),
        refresh_token="same-existing-family",
        expires_at=int(time.time()) + (1 if refresh else 300),
        auth_expires_at=int(time.time()) + 3600,
        extra={"keep": "original-context"},
    )
    result = manager.resolve(manager.encode(original))
    assert result.context.subject_id == PERSON
    assert result.session.subject_id == PERSON
    assert result.session.refresh_token == "same-existing-family"
    assert result.session.auth_expires_at == original.auth_expires_at
    assert result.session.extra == original.extra
    assert result.cookie is not None
    assert manager.load(result.cookie).subject_id == PERSON


def test_missing_legacy_browser_client_binding_is_rejected_before_online_call(
    config, browser_client, key, claims
):
    def no_call(request):
        pytest.fail("missing browser-client binding must be rejected locally")

    sso = browser(config, browser_client, key, no_call)
    with pytest.raises(OAuthSDKError):
        sso.check_session(key.sign(claims(browser_sid="same-root")))


def test_verified_context_from_another_mapping_tenant_cannot_skip_verification(
    config, browser_client, key, claims
):
    from leap_oauth_sdk.transition import TransitionAccessTokenVerifier

    from .test_transition import mapping

    original = verifier(config, key).verify(
        key.sign(claims(browser_sid="same-root", browser_client_id=browser_client.client_id))
    )
    second = TransitionAccessTokenVerifier(
        config,
        identity_map=replace(mapping(), feishu_tenant="tenant-2"),
        required_purpose="access",
        allowed_channels=("feishu_oauth",),
        jwks={"keys": [key.jwk]},
    )
    sso = BrowserSSO(
        config,
        browser_client,
        second,
        token_profile="transition",
        expected_feishu_tenant="tenant-2",
    )
    with pytest.raises(OAuthSDKError):
        sso._require_context(original)


def test_native_receiver_accepts_migrated_cookie_without_transition_map(
    config, browser_client, key, claims
):
    from leap_oauth_sdk.native import NativeAccessTokenVerifier

    payload = native_claims(claims)
    payload.update(browser_sid="same-root", client_id=browser_client.client_id)
    response = token_response(key, payload, True)
    transition = browser(
        config, browser_client, key, lambda request: httpx.Response(200, json=response)
    )
    fresh = transition.refresh("same-existing-family", expected_subject_id="usr_1")
    cipher = CookieCipher("s" * 32)
    original_manager = CookieSessionManager(transition, cipher)
    cookie = original_manager.encode(CookieSession.from_browser_session(fresh))
    native = BrowserSSO(
        config,
        browser_client,
        NativeAccessTokenVerifier(
            config,
            jwks={"keys": [key.jwk]},
            expected_feishu_tenant="tenant-1",
            required_purpose="access",
            allowed_channels=("feishu_oauth",),
        ),
        token_profile="feishu_native_v2",
        expected_feishu_tenant="tenant-1",
        http_client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={"active": True, "subject_id": PERSON, "audience": AUDIENCE}
                )
            )
        ),
    )
    result = CookieSessionManager(native, cipher).resolve(cookie)
    assert result.context.subject_id == PERSON
    assert result.session.refresh_token == fresh.refresh_token
