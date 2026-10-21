from __future__ import annotations

import copy

import httpx
import pytest

from leap_oauth_sdk import BrowserSSO, OAuthSDKError

from .conftest import AUDIENCE, ISSUER, SigningKey
from .test_native import VECTORS


def payload(key: SigningKey, client_id: str):
    import time

    claims = copy.deepcopy(VECTORS["base_claims"])
    now = int(time.time())
    claims.update(
        iss=ISSUER,
        aud=AUDIENCE,
        client_id=client_id,
        iat=now,
        nbf=now,
        exp=now + 300,
        browser_sid="native-browser-session",
    )
    return {
        "access_token": key.sign(claims, typ="at+jwt"),
        "refresh_token": "native-refresh",
        "token_type": "Bearer",
    }


def test_explicit_native_browser_exchange_refresh_and_online_check(config, browser_client, key):
    from leap_oauth_sdk.native import NativeAccessTokenVerifier

    verifier = NativeAccessTokenVerifier(
        config,
        jwks={"keys": [key.jwk]},
        expected_feishu_tenant="tenant-test",
        required_purpose="access",
        allowed_channels=["feishu_oauth"],
    )

    def handler(request):
        if request.url.path.endswith("/session"):
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "subject_id": VECTORS["base_claims"]["sub"],
                    "audience": AUDIENCE,
                },
            )
        return httpx.Response(200, json=payload(key, browser_client.client_id))

    sso = BrowserSSO(
        config,
        browser_client,
        verifier,
        token_profile="feishu_native_v2",
        expected_feishu_tenant="tenant-test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    session = sso.exchange_code("one-time-code", "verifier")
    assert session.subject_id == "feishu:user_id:Ab:01"
    assert session.context.display.name == "Example"
    assert (
        sso.refresh(session.refresh_token, expected_subject_id=session.subject_id).subject_id
        == session.subject_id
    )
    assert sso.check_session(session.access_token).person_key == session.subject_id


def test_browser_never_uses_other_profiles_verifier_or_verified_context(
    config, browser_client, key, sso, claims
):
    from leap_oauth_sdk.native import NativeAccessTokenVerifier

    native = NativeAccessTokenVerifier(
        config,
        jwks={"keys": [key.jwk]},
        expected_feishu_tenant="tenant-test",
        required_purpose="access",
        allowed_channels=["feishu_oauth"],
    )
    with pytest.raises(ValueError):
        BrowserSSO(config, browser_client, token_profile="feishu_native_v2")
    with pytest.raises(ValueError):
        BrowserSSO(
            config,
            browser_client,
            sso.verifier,
            token_profile="feishu_native_v2",
            expected_feishu_tenant="tenant-test",
        )
    with pytest.raises(ValueError):
        BrowserSSO(config, browser_client, native)
    native_sso = BrowserSSO(
        config,
        browser_client,
        native,
        token_profile="feishu_native_v2",
        expected_feishu_tenant="tenant-test",
    )
    legacy = sso.verifier.verify(key.sign(claims(browser_sid="old-browser")))
    with pytest.raises(OAuthSDKError):
        native_sso.check_session("unused", verified=legacy)
    final_token = payload(key, browser_client.client_id)["access_token"]
    with pytest.raises(OAuthSDKError):
        sso.check_session(final_token)


@pytest.mark.asyncio
async def test_native_browser_async_and_wrong_client_are_rejected(config, browser_client, key):
    from leap_oauth_sdk.native import NativeAccessTokenVerifier

    verifier = NativeAccessTokenVerifier(
        config,
        jwks={"keys": [key.jwk]},
        expected_feishu_tenant="tenant-test",
        required_purpose="access",
        allowed_channels=["feishu_oauth"],
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=payload(key, "wrong-browser"))
        )
    ) as http:
        sso = BrowserSSO(
            config,
            browser_client,
            verifier,
            token_profile="feishu_native_v2",
            expected_feishu_tenant="tenant-test",
            async_http_client=http,
        )
        with pytest.raises(OAuthSDKError):
            await sso.exchange_code_async("code", "verifier")


@pytest.mark.asyncio
async def test_native_browser_async_success_keeps_verified_identity(config, browser_client, key):
    from leap_oauth_sdk.native import NativeAccessTokenVerifier

    verifier = NativeAccessTokenVerifier(
        config,
        jwks={"keys": [key.jwk]},
        expected_feishu_tenant="tenant-test",
        required_purpose="access",
        allowed_channels=["feishu_oauth"],
    )

    def handler(request):
        if request.url.path.endswith("/session"):
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "subject_id": VECTORS["base_claims"]["sub"],
                    "audience": AUDIENCE,
                },
            )
        return httpx.Response(200, json=payload(key, browser_client.client_id))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        sso = BrowserSSO(
            config,
            browser_client,
            verifier,
            token_profile="feishu_native_v2",
            expected_feishu_tenant="tenant-test",
            async_http_client=http,
        )
        session = await sso.exchange_code_async("code", "verifier")
        renewed = await sso.refresh_async(
            session.refresh_token, expected_subject_id=session.subject_id
        )
        assert (
            await sso.check_session_async(renewed.access_token, verified=renewed.context)
            is renewed.context
        )
