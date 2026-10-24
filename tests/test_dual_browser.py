from __future__ import annotations

from dataclasses import replace

import httpx
import pytest

from leap_oauth_sdk import AccessTokenVerifier, BrowserSSO, OAuthSDKError
from leap_oauth_sdk.browser import DualAccessTokenVerifier
from leap_oauth_sdk.native import NativeAccessTokenVerifier, NativeIdentity
from leap_oauth_sdk.tokens import AccessTokenContext

from .test_native_browser import payload as native_payload
from .test_transition import verifier as transition_verifier


def dual(config, key):
    return DualAccessTokenVerifier(
        legacy=AccessTokenVerifier(config, jwks={"keys": [key.jwk]}),
        native=NativeAccessTokenVerifier(
            config,
            jwks={"keys": [key.jwk]},
            expected_feishu_tenant="tenant-test",
            required_purpose="access",
            allowed_channels=("feishu_oauth",),
        ),
    )


@pytest.mark.parametrize("profile", ["legacy", "native"])
@pytest.mark.parametrize("operation", ["exchange", "refresh"])
def test_dual_returns_original_wire_subject_and_rotated_root(
    config, browser_client, key, token_response, profile, operation
):
    body = (
        token_response(refresh_token="brt1.next")
        if profile == "legacy"
        else {**native_payload(key, browser_client.client_id), "refresh_token": "brt1.next"}
    )
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        sso = BrowserSSO(
            config,
            browser_client,
            dual(config, key),
            token_profile="dual",
            expected_feishu_tenant="tenant-test",
            http_client=client,
        )
        result = (
            sso.exchange_code("code", "a" * 43)
            if operation == "exchange"
            else sso.refresh("brt1.original")
        )
    assert result.refresh_token == "brt1.next"
    assert result.access_token == body["access_token"]
    assert result.auth_expires_at == body.get("auth_expires_at")
    assert isinstance(result.context, AccessTokenContext if profile == "legacy" else NativeIdentity)
    assert result.subject_id == result.context.raw_claims["sub"]
    assert sso.canonical_subject(result.subject_id) == result.subject_id
    assert len(calls) == 1 and calls[0].url.path == "/api/oauth/token"


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["legacy", "native"])
async def test_dual_async_exchange_then_refresh(
    config, browser_client, key, token_response, profile
):
    body = (
        token_response(refresh_token="brt1.next")
        if profile == "legacy"
        else {**native_payload(key, browser_client.client_id), "refresh_token": "brt1.next"}
    )
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        sso = BrowserSSO(
            config,
            browser_client,
            dual(config, key),
            token_profile="dual",
            expected_feishu_tenant="tenant-test",
            async_http_client=client,
        )
        first = await sso.exchange_code_async("code", "a" * 43)
        second = await sso.refresh_async(first.refresh_token)
    assert second.refresh_token == "brt1.next" and len(calls) == 2
    assert all(call.url.path == "/api/oauth/token" for call in calls)


def test_dual_rejects_subject_comparison_before_spending_root(config, browser_client, key):
    def forbidden(request):
        pytest.fail("root must not be spent")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        sso = BrowserSSO(
            config,
            browser_client,
            dual(config, key),
            token_profile="dual",
            expected_feishu_tenant="tenant-test",
            http_client=client,
        )
        with pytest.raises(ValueError, match="compare subjects"):
            sso.refresh("brt1.original", expected_subject_id="usr_1")


@pytest.mark.asyncio
async def test_dual_async_rejects_subject_comparison_before_post(config, browser_client, key):
    def forbidden(request):
        pytest.fail("root must not be spent")

    async with httpx.AsyncClient(transport=httpx.MockTransport(forbidden)) as client:
        sso = BrowserSSO(
            config,
            browser_client,
            dual(config, key),
            token_profile="dual",
            expected_feishu_tenant="tenant-test",
            async_http_client=client,
        )
        with pytest.raises(ValueError, match="compare subjects"):
            await sso.refresh_async("brt1.original", expected_subject_id="usr_1")


@pytest.mark.parametrize("tenant", [None, "", " tenant-test", "tenant-test\n"])
def test_dual_requires_exact_tenant(config, browser_client, key, tenant):
    with pytest.raises(ValueError, match="tenant"):
        BrowserSSO(
            config,
            browser_client,
            dual(config, key),
            token_profile="dual",
            expected_feishu_tenant=tenant,
        )


def test_dual_requires_explicit_nontransition_verifier(config, browser_client, key):
    for verifier in (None, transition_verifier(config, key)):
        with pytest.raises(ValueError):
            BrowserSSO(
                config,
                browser_client,
                verifier,
                token_profile="dual",
                expected_feishu_tenant="tenant-test",
            )
    with pytest.raises(ValueError):
        DualAccessTokenVerifier(
            legacy=AccessTokenVerifier(config, jwks={"keys": [key.jwk]}),
            native=NativeAccessTokenVerifier(
                replace(config, issuer="https://other.example"),
                expected_feishu_tenant="tenant-test",
                required_purpose="access",
                allowed_channels=("feishu_oauth",),
            ),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"client_id": "other"},
        {"feishu_tenant": "other"},
        {"source": {"channel": "obo"}},
        {"purpose": "entitlement_probe"},
    ],
)
def test_dual_native_keeps_original_browser_binding(config, browser_client, key, changes):
    import jwt

    body = native_payload(key, browser_client.client_id)
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    claims.update(changes)
    body["access_token"] = key.sign(claims, typ="at+jwt")
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=body))
    ) as client:
        sso = BrowserSSO(
            config,
            browser_client,
            dual(config, key),
            token_profile="dual",
            expected_feishu_tenant="tenant-test",
            http_client=client,
        )
        with pytest.raises(OAuthSDKError):
            sso.refresh("brt1.original")
