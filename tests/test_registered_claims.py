from __future__ import annotations

import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import MappingProxyType
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa

import leap_oauth_sdk as sdk
from leap_oauth_sdk import AccessTokenVerifier, InvalidResponse, ReauthRequired, Retryable

from .conftest import AUDIENCE, JWKS_URL, SigningKey


def compatible():
    return sdk.RegisteredClaimsPolicy.PYJWT_COMPATIBLE


def verify(verifier, token):
    return verifier.verify_claims(token, policy=compatible())


def old_decode(token: str, keys: list[dict[str, Any]], config) -> dict[str, Any]:
    """The previous PyJWT public-key selection and registered-claims contract."""
    client = jwt.PyJWKClient(JWKS_URL)
    client.fetch_data = lambda: {"keys": keys}
    alg = jwt.get_unverified_header(token)["alg"]
    assert alg in config.allowed_algorithms
    key = client.get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        key,
        algorithms=[alg],
        issuer=config.issuer,
        audience=config.audience,
        leeway=config.leeway_seconds,
        options={"require": ["exp", "iat", "sub", "aud"]},
    )


def test_public_claims_api_is_explicit_and_strict_by_default(config, key, claims):
    assert hasattr(sdk, "RegisteredClaimsPolicy"), "fixed verification policies must be public"
    assert hasattr(sdk, "VerifiedTokenClaims"), "verified raw claims must have a separate type"
    assert set(sdk.RegisteredClaimsPolicy.__members__) == {"STRICT", "PYJWT_COMPATIBLE"}
    verifier = AccessTokenVerifier(config, jwks={"keys": [key.jwk]})
    payload = claims()
    assert verifier.verify_claims(key.sign(payload)).raw_claims == payload
    with pytest.raises(TypeError):
        verifier.verify_claims(key.sign(payload), policy="pyjwt-compatible")
    with pytest.raises(TypeError):
        verifier.verify(key.sign(payload), policy=compatible())


def test_static_jwks_accepts_readonly_mapping_and_detaches_caller_data(config, key, claims):
    jwk = dict(key.jwk)
    verifier = AccessTokenVerifier(config, jwks=MappingProxyType({"keys": [jwk]}))
    jwk["use"] = "enc"
    assert verifier.verify(key.sign(claims())).subject_id == "usr_1"


@pytest.mark.parametrize("algorithm", ["EdDSA", "RS256"])
@pytest.mark.parametrize("case", ["minimum", "array", "dates", "metadata", "empty_jti"])
def test_compatible_claims_match_legacy_without_fabricating_fields(
    config, key, claims, algorithm, case
):
    config = replace(config, allowed_algorithms=(algorithm,), leeway_seconds=0)
    private = key.private_key
    jwk = key.jwk
    if algorithm == "RS256":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
        jwk.update(kid=key.kid, alg="RS256", use="sig")
    payload = claims()
    if case == "minimum":
        for name in ("nbf", "jti", "source", "principal_type", "status"):
            payload.pop(name)
    elif case == "array":
        payload["aud"] = [AUDIENCE, "other-service"]
    elif case == "dates":
        payload.update(iat=str(payload["iat"]), exp=str(payload["exp"]), nbf=str(payload["nbf"]))
    elif case == "metadata":
        payload.update(status=False, source="legacy", roles=123)
    else:
        payload["jti"] = ""
    token = jwt.encode(payload, private, algorithm=algorithm, headers={"kid": key.kid})
    verifier = AccessTokenVerifier(config, jwks={"keys": [jwk]})
    assert verify(verifier, token).raw_claims == old_decode(token, [jwk], config) == payload
    with pytest.raises((ReauthRequired, sdk.Forbidden)):
        verifier.verify(token)


@pytest.mark.parametrize(
    "patch",
    [
        {"iss": "https://evil.example.com"},
        {"aud": "other"},
        {"aud": ["other"]},
        {"exp": 1},
        {"iat": 4102444800},
        {"nbf": 4102444800},
        {"sub": 123},
        {"jti": 123},
        {"exp": "not-a-number"},
        {"iat": None},
    ],
)
def test_compatible_rejects_invalid_registered_claims(config, key, claims, patch):
    payload = claims(**patch)
    token = key.sign(payload)
    with pytest.raises(jwt.PyJWTError):
        old_decode(token, [key.jwk], config)
    with pytest.raises(ReauthRequired):
        verify(AccessTokenVerifier(config, jwks={"keys": [key.jwk]}), token)


def test_signature_and_algorithm_failures_never_fall_back(config, key, claims):
    verifier = AccessTokenVerifier(config, jwks={"keys": [key.jwk]})
    for token in (
        SigningKey(key.kid).sign(claims()),
        jwt.encode(claims(), "test-secret-long-enough-for-hs256-signing", algorithm="HS256"),
        jwt.encode(claims(), None, algorithm="none"),
    ):
        with pytest.raises(ReauthRequired):
            verify(verifier, token)


@pytest.mark.parametrize("case", ["missing_alg", "exact_kid", "mixed", "duplicate"])
def test_compatible_jwk_selection_matches_pyjwt(config, key, claims, case):
    jwk = dict(key.jwk)
    kid = key.kid
    if case == "missing_alg":
        jwk.pop("alg")
    elif case == "exact_kid":
        kid = jwk["kid"] = " exact kid "
    keys = [jwk]
    if case == "mixed":
        keys.insert(0, {"kty": "RSA", "kid": kid})
    if case == "duplicate":
        keys.append(SigningKey(kid).jwk)
    token = key.sign(claims(), kid=kid)
    assert verify(AccessTokenVerifier(config, jwks={"keys": keys}), token).raw_claims == old_decode(
        token, keys, config
    )


@pytest.mark.parametrize("use", ["enc", "other"])
def test_encryption_key_is_not_accepted_for_strict_signature_verification(config, key, claims, use):
    verifier = AccessTokenVerifier(config, jwks={"keys": [{**key.jwk, "use": use}]})
    with pytest.raises(InvalidResponse):
        verifier.verify(key.sign(claims()))


@pytest.mark.parametrize(
    "keys", [[], [{"kid": "broken", "kty": "RSA"}], [{"use": "enc", "kid": "other"}]]
)
def test_unusable_jwks_is_infrastructure_failure(config, key, claims, keys):
    with pytest.raises(InvalidResponse):
        verify(AccessTokenVerifier(config, jwks={"keys": keys}), key.sign(claims()))


def test_compatible_never_accepts_private_jwk(config, key, claims):
    with pytest.raises(InvalidResponse, match="private"):
        verify(
            AccessTokenVerifier(config, jwks={"keys": [{**key.jwk, "d": "private"}]}),
            key.sign(claims()),
        )


def test_compatible_large_token_does_not_change_strict_limit(config, key, claims):
    payload = claims(extra="x" * 17000)
    token = key.sign(payload)
    verifier = AccessTokenVerifier(config, jwks={"keys": [key.jwk]})
    assert verify(verifier, token).raw_claims == payload
    with pytest.raises(ReauthRequired):
        verifier.verify_claims(token)


@respx.mock
def test_compatible_cache_cannot_bypass_strict_size_or_key_checks(config, key, claims):
    large = {**key.jwk, "comment": "x" * 66000}
    route = respx.get(JWKS_URL).respond(200, json={"keys": [large]})
    verifier = AccessTokenVerifier(config)
    token = key.sign(claims())
    verify(verifier, token)
    with pytest.raises(InvalidResponse, match="large"):
        verifier.verify(token)
    assert route.call_count == 1
    missing_alg = {k: v for k, v in key.jwk.items() if k != "alg"}
    route.respond(200, json={"keys": [missing_alg]})
    verifier = AccessTokenVerifier(config)
    verify(verifier, token)
    with pytest.raises(ReauthRequired):
        verifier.verify(token)


@respx.mock
def test_strict_size_check_precedes_json_and_key_parsing(config, key, claims):
    # An oversized response must be rejected for size before trying to parse its body.
    route = respx.get(JWKS_URL).respond(200, content=b"not-json" * 10000)
    verifier = AccessTokenVerifier(config)
    with pytest.raises(InvalidResponse, match="too large"):
        verifier.verify(key.sign(claims()))
    # The same transport cache is checked under the compatible policy, which sees bad JSON.
    with pytest.raises(InvalidResponse, match="not JSON"):
        verify(verifier, key.sign(claims()))
    assert route.call_count == 1


def test_strict_does_not_skip_first_matching_malformed_key(config, key, claims):
    malformed = {"kid": key.kid, "alg": "EdDSA", "kty": "bad"}
    verifier = AccessTokenVerifier(config, jwks={"keys": [malformed, key.jwk]})
    token = key.sign(claims())
    with pytest.raises(InvalidResponse) as exc_info:
        verifier.verify(token)
    assert exc_info.value.code == "access_token_jwk_invalid"
    assert verify(verifier, token).raw_claims["sub"] == "usr_1"


@respx.mock
def test_strict_oversize_failure_recovers_after_cooldown_not_cache_ttl(config, key, claims, clock):
    route = respx.get(JWKS_URL).respond(200, json={"keys": [{**key.jwk, "padding": "x" * 66000}]})
    verifier = AccessTokenVerifier(config, clock=clock)
    token = key.sign(claims())
    with pytest.raises(InvalidResponse, match="too large"):
        verifier.verify(token)
    assert verify(verifier, token).raw_claims["sub"] == "usr_1"
    route.respond(200, json={"keys": [key.jwk]})
    clock.now += config.jwks_refresh_cooldown_seconds + 1
    assert verifier.verify(token).subject_id == "usr_1"
    assert route.call_count == 2


@pytest.mark.parametrize("broken", [None, {"kty": "RSA", "kid": "other", "e": "AQAB", "n": "AA"}])
def test_compatible_does_not_skip_structurally_broken_keys(config, key, claims, broken):
    verifier = AccessTokenVerifier(config, jwks={"keys": [broken, key.jwk]})
    with pytest.raises(InvalidResponse):
        verify(verifier, key.sign(claims()))


def test_compatible_still_skips_existing_pyjwt_wrapped_key_errors(config, key, claims):
    # OKPAlgorithm already wrapped this ValueError in PyJWT 2.10.1; it is skippable.
    bad = {"kty": "OKP", "crv": "Ed25519", "kid": "other", "x": "AA"}
    keys = [bad, key.jwk]
    token = key.sign(claims())
    assert verify(AccessTokenVerifier(config, jwks={"keys": keys}), token).raw_claims == old_decode(
        token, keys, config
    )


def test_compatible_rejects_bad_payload_before_jwks_network(config, key, claims):
    good = key.sign(claims()).split(".")
    bad = ".".join([good[0], jwt.utils.base64url_encode(b"{").decode(), good[2]])
    calls = []

    def fetch(_request):
        calls.append(1)
        raise httpx.ConnectError("offline")

    with httpx.Client(transport=httpx.MockTransport(fetch)) as client:
        with pytest.raises(ReauthRequired):
            verify(AccessTokenVerifier(config, http_client=client), bad)
    assert calls == []


@respx.mock
def test_compatible_first_miss_refreshes_immediately_then_cools_down(config, key, claims, clock):
    config = replace(config, jwks_refresh_cooldown_seconds=30)
    rotated = SigningKey("rotated")
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"keys": [key.jwk]}),
            httpx.Response(200, json={"keys": [key.jwk, rotated.jwk]}),
        ]
    )
    verifier = AccessTokenVerifier(config, clock=clock)
    verify(verifier, key.sign(claims()))
    verify(verifier, rotated.sign(claims()))
    assert route.call_count == 2
    unknown = key.sign(claims(), kid="unknown")
    with pytest.raises(ReauthRequired):
        verify(verifier, unknown)
    assert route.call_count == 2
    clock.now += 30
    route.respond(200, json={"keys": [key.jwk]})
    with pytest.raises(ReauthRequired):
        verify(verifier, unknown)
    assert route.call_count == 3


@respx.mock
def test_failed_forced_refresh_invalidates_previously_fresh_cache(config, key, claims, clock):
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"keys": [key.jwk]}),
            httpx.ConnectError("offline"),
        ]
    )
    verifier = AccessTokenVerifier(config, clock=clock)
    token = key.sign(claims())
    verify(verifier, token)
    with pytest.raises(Retryable):
        verify(verifier, key.sign(claims(), kid="unknown"))
    with pytest.raises(Retryable):
        verifier.verify(token)
    assert route.call_count == 2
    clock.now += config.jwks_refresh_cooldown_seconds
    route.respond(200, json={"keys": [key.jwk]})
    assert verify(verifier, token).raw_claims["sub"] == "usr_1"


def test_concurrent_sync_miss_is_single_flight(config, key, claims, clock):
    calls = []
    barrier = threading.Barrier(8)

    def fetch(_request):
        calls.append(1)
        time.sleep(0.02)
        return httpx.Response(200, json={"keys": [key.jwk]})

    with httpx.Client(transport=httpx.MockTransport(fetch)) as client:
        verifier = AccessTokenVerifier(config, clock=clock, http_client=client)
        token = key.sign(claims(), kid="unknown")

        def run(_):
            barrier.wait()
            with pytest.raises(ReauthRequired):
                verify(verifier, token)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(run, range(8)))
    assert len(calls) == 2  # initial fetch plus the first immediate miss refresh


async def test_async_claims_and_sync_calls_share_single_flight(config, key, claims):
    calls = []
    started = asyncio.Event()
    release = asyncio.Event()

    async def fetch(_request):
        calls.append(1)
        started.set()
        await release.wait()
        return httpx.Response(200, json={"keys": [key.jwk]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(fetch)) as client:
        verifier = AccessTokenVerifier(config, async_http_client=client)
        token = key.sign(claims())
        task = asyncio.create_task(verifier.verify_claims_async(token, policy=compatible()))
        await started.wait()
        other = asyncio.create_task(asyncio.to_thread(verifier.verify, token))
        release.set()
        raw, context = await asyncio.gather(task, other)
        assert raw.raw_claims["sub"] == context.subject_id == "usr_1"
        assert (await verifier.verify_async(token)).subject_id == "usr_1"
    assert len(calls) == 1


def test_raw_result_does_not_claim_application_authorization(config, key, claims):
    payload = claims(status="disabled", source=None, principal_type=None, purpose="other")
    verifier = AccessTokenVerifier(config, jwks={"keys": [key.jwk]})
    result = verifier.verify_claims(key.sign(payload))
    assert result.raw_claims == payload
    assert "source" not in result.raw_claims
    with pytest.raises(TypeError):
        result.raw_claims["sub"] = "changed"
    with pytest.raises(sdk.Forbidden):
        verifier.verify(key.sign(payload))


def test_raw_default_and_async_default_keep_strict_required_fields(config, key, claims):
    token = key.sign(claims(nbf=None, jti=None))
    verifier = AccessTokenVerifier(config, jwks={"keys": [key.jwk]})
    with pytest.raises(ReauthRequired):
        verifier.verify_claims(token)
    with pytest.raises(ReauthRequired):
        asyncio.run(verifier.verify_claims_async(token))
    assert verify(verifier, token).raw_claims["sub"] == "usr_1"


def test_duplicate_kid_never_retries_signature_with_later_key(config, key, claims):
    other = SigningKey(key.kid)
    keys = [other.jwk, key.jwk]
    token = key.sign(claims())
    with pytest.raises(jwt.InvalidSignatureError):
        old_decode(token, keys, config)
    with pytest.raises(ReauthRequired):
        verify(AccessTokenVerifier(config, jwks={"keys": keys}), token)


def test_compatible_uses_selected_public_key_without_rewriting_its_algorithm(config, key, claims):
    config = replace(config, allowed_algorithms=("RS256",))
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update(kid=key.kid, alg="RS512", use="sig")
    token = jwt.encode(claims(), private, algorithm="RS256", headers={"kid": key.kid})
    verifier = AccessTokenVerifier(config, jwks={"keys": [jwk]})
    assert verify(verifier, token).raw_claims == old_decode(token, [jwk], config)
    with pytest.raises(ReauthRequired):
        verifier.verify(token)


@pytest.mark.parametrize(
    "payload", [{}, {"keys": []}, {"keys": [None]}, {"keys": [{"kty": "RSA"}]}]
)
@respx.mock
def test_bad_jwks_response_is_not_a_credential_failure(config, key, claims, clock, payload):
    route = respx.get(JWKS_URL).respond(200, json=payload)
    verifier = AccessTokenVerifier(config, clock=clock)
    token = key.sign(claims())
    with pytest.raises(InvalidResponse):
        verify(verifier, token)
    with pytest.raises(Retryable):
        verify(verifier, token)
    assert route.call_count == 1
    clock.now += config.jwks_refresh_cooldown_seconds
    route.respond(200, json={"keys": [key.jwk]})
    assert verify(verifier, token).raw_claims["sub"] == "usr_1"


def test_concurrent_failed_fetch_is_single_flight(config, key, claims, clock):
    calls = []
    barrier = threading.Barrier(8)

    def fetch(_request):
        calls.append(1)
        time.sleep(0.02)
        raise httpx.ConnectError("offline")

    with httpx.Client(transport=httpx.MockTransport(fetch)) as client:
        verifier = AccessTokenVerifier(config, clock=clock, http_client=client)
        token = key.sign(claims())

        def run(_):
            barrier.wait()
            with pytest.raises(Retryable):
                verify(verifier, token)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(run, range(8)))
    assert len(calls) == 1


async def test_async_first_miss_and_cancellation_do_not_duplicate_fetch(config, key, claims):
    calls = []
    started = asyncio.Event()
    release = asyncio.Event()

    async def fetch(_request):
        calls.append(1)
        if len(calls) == 1:
            started.set()
            await release.wait()
        return httpx.Response(200, json={"keys": [key.jwk]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(fetch)) as client:
        verifier = AccessTokenVerifier(config, async_http_client=client)
        token = key.sign(claims(), kid="unknown")
        first = asyncio.create_task(verifier.verify_claims_async(token, policy=compatible()))
        await started.wait()
        cancelled = asyncio.create_task(verifier.verify_claims_async(token, policy=compatible()))
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        release.set()
        with pytest.raises(ReauthRequired):
            await first
        assert len(calls) == 2
        assert (await verifier.verify_async(key.sign(claims()))).subject_id == "usr_1"


async def test_cancelled_fetch_owner_releases_waiters_and_can_recover(config, key, claims, clock):
    started = asyncio.Event()
    waiting = asyncio.Event()
    calls = []

    async def fetch(_request):
        calls.append(1)
        if len(calls) == 1:
            started.set()
            await waiting.wait()
        return httpx.Response(200, json={"keys": [key.jwk]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(fetch)) as client:
        verifier = AccessTokenVerifier(config, clock=clock, async_http_client=client)
        token = key.sign(claims())
        first = asyncio.create_task(verifier.verify_async(token))
        await started.wait()
        other = asyncio.create_task(verifier.verify_claims_async(token, policy=compatible()))
        await asyncio.sleep(0)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        with pytest.raises(Retryable):
            await other
        clock.now += config.jwks_refresh_cooldown_seconds
        assert (await verifier.verify_async(token)).subject_id == "usr_1"
        assert len(calls) == 2
