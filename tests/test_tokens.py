from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
import respx

from leap_oauth_sdk import (
    AccessTokenVerifier,
    Forbidden,
    InvalidResponse,
    LeapAuthConfig,
    ReauthRequired,
    Retryable,
)

from .conftest import AUDIENCE, ISSUER, JWKS_URL, FakeClock, SigningKey


def _verifier(config: LeapAuthConfig, key: SigningKey, **kwargs: Any) -> AccessTokenVerifier:
    return AccessTokenVerifier(config, jwks={"keys": [key.jwk]}, **kwargs)


def test_valid_token_returns_context(config, key, claims) -> None:
    context = _verifier(config, key).verify(key.sign(claims(browser_sid="bsid-1")))

    assert context.subject_id == "usr_1"
    assert context.audience == AUDIENCE
    assert context.issuer == ISSUER
    assert context.purpose == "access"
    assert context.source == {"channel": "feishu_oauth"}
    assert context.email == "user@example.com"
    assert context.browser_session_id == "bsid-1"


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"aud": "other-service"}, "access_token_invalid"),
        ({"aud": [AUDIENCE]}, "access_token_invalid"),
        ({"iss": "https://evil.example.com"}, "access_token_invalid"),
        ({"exp": int(time.time()) - 120}, "access_token_invalid"),
        ({"nbf": int(time.time()) + 120}, "access_token_invalid"),
        ({"jti": None}, "access_token_invalid"),
        ({"nbf": None}, "access_token_invalid"),
        ({"ver": "other.v1"}, "access_token_version_rejected"),
        ({"status": None}, "access_token_claim_invalid"),
        ({"principal_type": None}, "access_token_claim_invalid"),
        ({"source": {}}, "access_token_source_invalid"),
        ({"groups": ["ok", 1]}, "access_token_claim_invalid"),
    ],
)
def test_invalid_tokens_require_reauthentication(config, key, claims, overrides, code) -> None:
    with pytest.raises(ReauthRequired) as exc_info:
        _verifier(config, key).verify(key.sign(claims(**overrides)))
    assert exc_info.value.code == code
    assert exc_info.value.status == 401


def test_inactive_principal_is_forbidden(config, key, claims) -> None:
    with pytest.raises(Forbidden) as exc_info:
        _verifier(config, key).verify(key.sign(claims(status="disabled")))
    assert exc_info.value.code == "access_token_principal_inactive"


def test_purpose_must_be_allowed(key, claims) -> None:
    token = key.sign(claims(purpose="entitlement_probe"))
    with pytest.raises(Forbidden) as exc_info:
        _verifier(LeapAuthConfig(issuer=ISSUER, audience=AUDIENCE), key).verify(token)
    assert exc_info.value.code == "access_token_purpose_rejected"

    probe_config = LeapAuthConfig(
        issuer=ISSUER, audience=AUDIENCE, allowed_purposes=("entitlement_probe",)
    )
    assert _verifier(probe_config, key).verify(token).purpose == "entitlement_probe"


def test_header_problems_are_rejected(config, key, claims) -> None:
    verifier = _verifier(config, key)
    for token, code in [
        ("not-a-jwt", "access_token_header_invalid"),
        ("", "access_token_invalid"),
        ("a" * 20000, "access_token_invalid"),
        (key.sign(claims(), kid=""), "access_token_kid_required"),
        (key.sign(claims(), kid="unknown"), "access_token_key_not_found"),
    ]:
        with pytest.raises(ReauthRequired) as exc_info:
            verifier.verify(token)
        assert exc_info.value.code == code


def test_algorithm_allowlist(config, key, claims) -> None:
    rs_config = LeapAuthConfig(issuer=ISSUER, audience=AUDIENCE, allowed_algorithms=("RS256",))
    with pytest.raises(ReauthRequired) as exc_info:
        _verifier(rs_config, key).verify(key.sign(claims()))
    assert exc_info.value.code == "access_token_alg_rejected"


def test_private_key_material_in_jwks_is_rejected(config, key, claims) -> None:
    leaked = {**key.jwk, "d": "secret"}
    verifier = AccessTokenVerifier(config, jwks={"keys": [leaked]})
    with pytest.raises(InvalidResponse) as exc_info:
        verifier.verify(key.sign(claims()))
    assert exc_info.value.code == "access_token_jwk_rejected"


@respx.mock
def test_jwks_is_cached_across_calls_and_refreshed_after_ttl(
    config, key, claims, clock: FakeClock
) -> None:
    route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json={"keys": [key.jwk]}))
    verifier = AccessTokenVerifier(config, clock=clock)

    for _ in range(3):
        verifier.verify(key.sign(claims()))
    assert route.call_count == 1

    clock.now += config.jwks_cache_seconds
    verifier.verify(key.sign(claims()))
    assert route.call_count == 2


@respx.mock
def test_unknown_kid_refetches_once_within_cooldown(config, key, claims, clock: FakeClock) -> None:
    rotated = SigningKey("rotated-2026")
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"keys": [key.jwk]}),
            httpx.Response(200, json={"keys": [key.jwk, rotated.jwk]}),
        ]
    )
    verifier = AccessTokenVerifier(config, clock=clock)
    verifier.verify(key.sign(claims()))

    # Inside the cooldown a forged kid must not trigger another fetch.
    with pytest.raises(ReauthRequired):
        verifier.verify(rotated.sign(claims()))
    assert route.call_count == 1

    clock.now += config.jwks_refresh_cooldown_seconds
    assert verifier.verify(rotated.sign(claims())).subject_id == "usr_1"
    assert route.call_count == 2


@respx.mock
def test_jwks_failures_are_retryable_and_not_cached(config, key, claims, clock: FakeClock) -> None:
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.ConnectError("down"),
            httpx.Response(503),
            httpx.Response(200, content=b"not json"),
            httpx.Response(200, json={"keys": [key.jwk]}),
        ]
    )
    verifier = AccessTokenVerifier(config, clock=clock)
    token = key.sign(claims())

    with pytest.raises(Retryable) as exc_info:
        verifier.verify(token)
    assert exc_info.value.code == "auth_upstream_unavailable"
    assert exc_info.value.status == 503
    with pytest.raises(Retryable):
        verifier.verify(token)
    with pytest.raises(InvalidResponse):
        verifier.verify(token)
    assert verifier.verify(token).subject_id == "usr_1"
    assert route.call_count == 4


@respx.mock
def test_expired_cache_with_failing_fetch_does_not_use_old_keys(
    config, key, claims, clock: FakeClock
) -> None:
    respx.get(JWKS_URL).mock(
        side_effect=[httpx.Response(200, json={"keys": [key.jwk]}), httpx.ConnectError("down")]
    )
    verifier = AccessTokenVerifier(config, clock=clock)
    verifier.verify(key.sign(claims()))

    clock.now += config.jwks_cache_seconds
    with pytest.raises(Retryable):
        verifier.verify(key.sign(claims()))


@respx.mock
def test_jwks_redirects_are_not_followed(config, key, claims) -> None:
    respx.get(JWKS_URL).mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.example.com"})
    )
    with pytest.raises(Retryable):
        AccessTokenVerifier(config).verify(key.sign(claims()))


@respx.mock
async def test_async_verify_shares_cache(config, key, claims, clock: FakeClock) -> None:
    route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json={"keys": [key.jwk]}))
    verifier = AccessTokenVerifier(config, clock=clock)

    assert (await verifier.verify_async(key.sign(claims()))).subject_id == "usr_1"
    assert verifier.verify(key.sign(claims())).subject_id == "usr_1"
    assert route.call_count == 1

    with pytest.raises(Forbidden):
        await verifier.verify_async(key.sign(claims(status="disabled")))
