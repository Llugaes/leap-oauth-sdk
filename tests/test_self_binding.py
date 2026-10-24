from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace

import httpx
import pytest

from leap_oauth_sdk import AccessTokenVerifier, RegisteredClaimsPolicy
from leap_oauth_sdk.native import NativeAccessTokenVerifier, NativeIdentity
from leap_oauth_sdk.self_binding import (
    SelfBinding,
    SelfBindingMissing,
    SelfBindingResolver,
    SelfBindingUnavailable,
)
from leap_oauth_sdk.tokens import AccessTokenContext, VerifiedTokenClaims

E1, E2 = "a" * 64, "b" * 64
PERSON = "feishu:user_id:User1"


@pytest.fixture
def setup(config, key, claims, clock):
    legacy = AccessTokenVerifier(config, jwks={"keys": [key.jwk]})
    native = NativeAccessTokenVerifier(
        config,
        expected_feishu_tenant="tenant",
        required_purpose="access",
        allowed_channels={"feishu_oauth", "feishu_bot", "obo"},
        jwks={"keys": [key.jwk]},
    )
    requests = []
    responses = []

    def handler(request):
        requests.append(request)
        return responses.pop(0)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    async_client = httpx.AsyncClient(transport=transport)
    wall_start, mono_start = time.time(), clock()

    def make(**kwargs):
        options = dict(
            legacy_verifier=legacy,
            native_verifier=native,
            http_client=client,
            async_http_client=async_client,
            clock=clock,
            wall_clock=lambda: wall_start + clock() - mono_start,
        )
        options.update(kwargs)
        return SelfBindingResolver(config, **options)

    def v1(**kwargs):
        return key.sign(claims(**{"source": {"channel": "device"}, **kwargs}))

    def nat(**kwargs):
        now = int(time.time())
        payload = dict(
            iss=config.issuer,
            aud=config.audience,
            sub=PERSON,
            iat=now,
            nbf=now,
            exp=now + 300,
            jti="native-jti",
            ver="sakamoto_feishu_access_token.v2",
            client_id="device:original",
            feishu_tenant="tenant",
            purpose="access",
            source={"channel": "feishu_oauth"},
            person=dict(user_id="User1", union_id=None, status="active", name=None, email=None),
        )
        payload.update(kwargs)
        return key.sign(payload, typ="at+jwt")

    def good(*, native=False, legacy="usr_1", person=PERSON, epoch=E1, age=60, generation=1):
        return dict(
            aud=config.audience,
            sub=person if native else legacy,
            legacy_subject=legacy,
            person_key=person,
            epoch=epoch,
            generation=generation,
            max_age_seconds=age,
        )

    yield dict(
        make=make,
        v1=v1,
        nat=nat,
        good=good,
        responses=responses,
        requests=requests,
        legacy=legacy,
        native=native,
        client=client,
        async_client=async_client,
    )
    client.close()


def push(ctx, code=200, payload=None):
    ctx["responses"].append(httpx.Response(code, json=payload or ctx["good"]()))


@pytest.mark.parametrize("policy", list(RegisteredClaimsPolicy))
def test_local_v1_verify_then_same_bearer_and_original_source(setup, policy):
    ctx = setup
    resolver = ctx["make"](legacy_policy=policy)
    token = ctx["v1"]()
    push(ctx)
    result = resolver.resolve(token)
    assert isinstance(result, SelfBinding)
    assert result.profile == "principal_v1" and result.lookup == "legacy"
    assert result.legacy_subject == result.wire_subject == "usr_1"
    assert isinstance(
        result.source,
        AccessTokenContext if policy is RegisteredClaimsPolicy.STRICT else VerifiedTokenClaims,
    )
    assert result.raw_claims is result.source.raw_claims
    assert not hasattr(result, "subject_id") and not hasattr(result, "enrollment")
    request = ctx["requests"][0]
    assert request.headers["authorization"] == "Bearer " + token
    assert request.headers["accept"] == "application/json"
    assert request.method == "GET" and request.url.path == "/api/identity/binding/self"
    assert not request.url.query and not request.content
    assert set(request.extensions["timeout"].values()) == {2.0}
    with pytest.raises(FrozenInstanceError):
        result.generation = 2


@pytest.mark.parametrize("kind", ["service", "subject", "channel", "actor"])
def test_ineligible_legacy_never_calls_cs(setup, kind):
    ctx = setup
    overrides = {
        "service": {"principal_type": "service"},
        "subject": {"sub": "raw-person"},
        "channel": {"source": {"channel": "unknown"}},
        "actor": {"act": {"type": "trusted_entry"}},
    }[kind]
    token = ctx["v1"](**overrides)
    result = ctx["make"]().resolve(token)
    assert isinstance(result, SelfBindingMissing) and result.reason == "source_not_resolvable"
    assert ctx["requests"] == []


@pytest.mark.parametrize("bot", [False, True])
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_native_verified_source_and_canonical_lookup(setup, bot, asynchronous):
    ctx = setup
    options = (
        dict(
            source={"channel": "feishu_bot"},
            act={"type": "trusted_entry", "sub": "bot:test", "auth": "hmac"},
            client_id="bot:test",
            exp=int(time.time()) + 100,
        )
        if bot
        else {}
    )
    token = ctx["nat"](**options)
    push(ctx, payload=ctx["good"](native=True, legacy="usr_canonical"))
    resolver = ctx["make"]()
    result = await resolver.resolve_async(token) if asynchronous else resolver.resolve(token)
    assert isinstance(result, SelfBinding) and isinstance(result.source, NativeIdentity)
    assert result.lookup == "person" and result.legacy_subject == "usr_canonical"
    assert result.wire_subject == PERSON and len(ctx["requests"]) == 1


@pytest.mark.parametrize(
    "field,value", [("aud", "wrong"), ("iss", "https://wrong.example"), ("feishu_tenant", "wrong")]
)
def test_native_wrong_namespace_no_http(setup, field, value):
    ctx = setup
    result = ctx["make"]().resolve(ctx["nat"](**{field: value}))
    assert isinstance(result, SelfBindingMissing) and result.reason == "not_verified"
    assert ctx["requests"] == []


def test_selected_native_failure_never_falls_back_and_profile_missing(setup, monkeypatch):
    ctx = setup

    def never(token):
        raise AssertionError("must not fall back to legacy")

    monkeypatch.setattr(ctx["legacy"], "verify", never)
    bad = ctx["nat"](aud="wrong")
    assert ctx["make"]().resolve(bad).reason == "not_verified"
    assert ctx["make"](native_verifier=None).resolve(bad).reason == "profile_not_configured"
    assert ctx["make"]().resolve("not-a-token").source is None
    assert not ctx["requests"]


@pytest.mark.parametrize(
    "native,field,value",
    [
        (False, "aud", "wrong"),
        (False, "sub", "usr_other"),
        (False, "legacy_subject", "usr_other"),
        (True, "person_key", "feishu:user_id:Other"),
    ],
)
def test_echo_mismatch_never_caches(setup, native, field, value):
    ctx = setup
    payload = ctx["good"](native=native)
    payload[field] = value
    push(ctx, payload=payload)
    result = ctx["make"]().resolve(ctx["nat"]() if native else ctx["v1"]())
    assert isinstance(result, SelfBindingMissing) and result.reason == "echo_mismatch"


@pytest.mark.parametrize(
    "change",
    [
        {"extra": 1},
        {"generation": True},
        {"generation": 0},
        {"generation": "1"},
        {"max_age_seconds": 0},
        {"max_age_seconds": 86401},
        {"legacy_subject": "raw"},
        {"person_key": "bad"},
        {"epoch": " "},
        {"aud": "x" * 513},
        {"sub": "usr_\n"},
    ],
)
def test_response_closed_schema_and_backoff(setup, change):
    ctx = setup
    body = ctx["good"]()
    body.update(change)
    push(ctx, payload=body)
    resolver = ctx["make"]()
    result = resolver.resolve(ctx["v1"]())
    assert isinstance(result, SelfBindingUnavailable) and result.reason == "invalid_response"
    assert resolver.resolve(ctx["v1"](sub="usr_other")).reason == "backoff"
    assert len(ctx["requests"]) == 1


@pytest.mark.parametrize(
    "status,code,expected",
    [
        (400, "identity_binding_bad_request", "rejected"),
        (401, "identity_binding_token_rejected", "rejected"),
        (405, "identity_binding_method_not_allowed", "rejected"),
        (409, "identity_binding_unmapped", "unmapped"),
        (503, "identity_binding_pending", "ledger_not_recording"),
        (503, "identity_binding_revoked", "ledger_not_recording"),
        (503, "identity_binding_breached", "ledger_not_recording"),
        (503, "identity_binding_chain_invalid", "ledger_not_recording"),
        (503, "identity_binding_unavailable", "upstream_unavailable"),
        (500, "identity_binding_unavailable", "invalid_response"),
        (401, "identity_binding_unmapped", "invalid_response"),
        (409, "future", "invalid_response"),
    ],
)
def test_error_status_code_matrix(setup, status, code, expected):
    ctx = setup
    push(ctx, status, {"error": code})
    result = ctx["make"]().resolve(ctx["v1"]())
    assert result.reason == expected


@pytest.mark.parametrize("status", [301, 302, 307])
def test_redirect_never_followed(setup, status):
    ctx = setup
    ctx["responses"].append(
        httpx.Response(status, headers={"location": "https://elsewhere.example"})
    )
    assert ctx["make"]().resolve(ctx["v1"]()).reason == "redirect"
    assert len(ctx["requests"]) == 1


def test_ttl_sent_time_cap_ticket_exp_and_cache_hit_no_renewal(setup, clock):
    ctx = setup
    wall = [float(int(time.time()))]

    def handler(request):
        ctx["requests"].append(request)
        clock.now += 5
        wall[0] += 5
        return httpx.Response(200, json=ctx["good"](age=600))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    resolver = ctx["make"](http_client=client, wall_clock=lambda: wall[0])
    token = ctx["v1"](exp=int(wall[0]) + 20)
    answer = resolver.resolve(token)
    assert answer.expires_at == int(wall[0]) + 15
    clock.now += 10
    wall[0] += 10
    assert resolver.resolve(token).expires_at == answer.expires_at
    assert len(ctx["requests"]) == 1
    client.close()


@pytest.mark.parametrize("metadata", [True, False])
def test_first_409_negative_cache_without_enrollment(setup, metadata, clock):
    ctx = setup
    body = {"error": "identity_binding_unmapped"}
    if metadata:
        body.update(epoch=E1, max_age_seconds=60)
    push(ctx, 409, body)
    push(ctx, 409, body)
    resolver = ctx["make"]()
    assert resolver.resolve(ctx["v1"]()).reason == "unmapped"
    assert resolver.resolve(ctx["v1"]()).reason == "unmapped"
    assert len(ctx["requests"]) == (1 if metadata else 2)
    assert not resolver.epoch_invalidated(E1)
    if metadata:
        clock.now += 31
        assert resolver.resolve(ctx["v1"]()).reason == "unmapped"
        assert len(ctx["requests"]) == 2


@pytest.mark.parametrize("second", [200, 409])
def test_epoch_change_and_old_epoch_sticky(setup, second):
    ctx = setup
    resolver = ctx["make"]()
    push(ctx)
    assert isinstance(resolver.resolve(ctx["v1"]()), SelfBinding)
    push(
        ctx,
        second,
        ctx["good"](legacy="usr_two", epoch=E2)
        if second == 200
        else {"error": "identity_binding_unmapped", "epoch": E2, "max_age_seconds": 60},
    )
    resolver.resolve(ctx["v1"](sub="usr_two"))
    assert resolver.epoch_invalidated(E1)
    push(ctx, payload=ctx["good"](legacy="usr_three"))
    assert resolver.resolve(ctx["v1"](sub="usr_three")).reason == "epoch_invalidated"


def test_state_invalidation_and_unavailable_preserve_cache(setup, clock):
    ctx = setup
    resolver = ctx["make"]()
    push(ctx)
    original = resolver.resolve(ctx["v1"]())
    push(ctx, 503, {"error": "identity_binding_unavailable"})
    assert resolver.resolve(ctx["v1"](sub="usr_other")).reason == "upstream_unavailable"
    assert resolver.resolve(ctx["v1"]()) == original
    clock.now += 6
    push(ctx, 503, {"error": "identity_binding_revoked"})
    assert resolver.resolve(ctx["v1"](sub="usr_other")).reason == "ledger_not_recording"
    assert resolver.epoch_invalidated(E1)
    push(ctx)
    assert resolver.resolve(ctx["v1"]()).reason == "epoch_invalidated"


@pytest.mark.parametrize("reverse", [False, True])
def test_alias_does_not_reverse_native_canonical_key(setup, reverse):
    ctx = setup
    resolver = ctx["make"]()
    items = [
        (ctx["v1"](sub="usr_alias"), ctx["good"](legacy="usr_alias")),
        (ctx["nat"](), ctx["good"](native=True, legacy="usr_canonical")),
    ]
    for token, body in reversed(items) if reverse else items:
        push(ctx, payload=body)
        assert isinstance(resolver.resolve(token), SelfBinding)
    assert resolver.resolve(ctx["nat"]()).legacy_subject == "usr_canonical"
    assert resolver.resolve(ctx["v1"](sub="usr_alias")).legacy_subject == "usr_alias"
    assert len(ctx["requests"]) == 2


@pytest.mark.parametrize("reverse", [False, True])
def test_canonical_conflict_invalidates_whole_epoch(setup, reverse):
    ctx = setup
    resolver = ctx["make"]()
    items = [
        (ctx["nat"](), ctx["good"](native=True)),
        (ctx["v1"](), ctx["good"](person="feishu:user_id:Other")),
    ]
    for index, (token, body) in enumerate(reversed(items) if reverse else items):
        push(ctx, payload=body)
        result = resolver.resolve(token)
        assert (
            isinstance(result, SelfBinding) if index == 0 else result.reason == "binding_conflict"
        )
    assert resolver.epoch_invalidated(E1)


def test_obo_only_reuses_positive_same_source_index_cache(setup, clock):
    ctx = setup
    resolver = ctx["make"]()
    delegated = ctx["nat"](
        source={"channel": "obo"},
        act={
            "type": "obo",
            "sub": "device:original",
            "parent_aud": "source",
            "parent_jti": "parent",
        },
    )
    assert resolver.resolve(delegated).reason == "delegated_uncached"
    push(ctx, payload=ctx["good"](native=True))
    assert isinstance(resolver.resolve(ctx["nat"]()), SelfBinding)
    assert resolver.resolve(delegated).delegated is True
    clock.now += 61
    assert resolver.resolve(delegated).reason == "delegated_uncached"
    legacy_obo = ctx["v1"](source={"channel": "obo"}, act={"type": "obo"})
    assert resolver.resolve(legacy_obo).reason == "delegated_uncached"
    assert len(ctx["requests"]) == 1


async def test_mixed_sync_async_singleflight_uses_each_waiter_ticket_exp(setup):
    ctx = setup
    entered, release = threading.Event(), threading.Event()

    def handler(request):
        ctx["requests"].append(request)
        entered.set()
        assert release.wait(5)
        return httpx.Response(200, json=ctx["good"]())

    client = httpx.Client(transport=httpx.MockTransport(handler))
    resolver = ctx["make"](http_client=client)
    short = ctx["v1"](exp=int(time.time()) + 10)
    with ThreadPoolExecutor(max_workers=50) as pool:
        leader = pool.submit(resolver.resolve, ctx["v1"]())
        assert await asyncio.to_thread(entered.wait, 2)
        syncs = [pool.submit(resolver.resolve, short) for _ in range(49)]
        tasks = [asyncio.create_task(resolver.resolve_async(short)) for _ in range(50)]
        await asyncio.sleep(0.05)
        release.set()
        answers = await asyncio.gather(*tasks)
        answers.extend(future.result() for future in syncs)
        assert isinstance(leader.result(), SelfBinding)
    assert len(answers) == 99 and all(
        answer.expires_at <= int(time.time()) + 10 for answer in answers
    )
    assert len(ctx["requests"]) == 1
    await asyncio.to_thread(client.close)


async def test_async_leader_cancelled_waiter_does_not_cancel_shared_future(setup):
    ctx = setup
    entered, release = asyncio.Event(), asyncio.Event()

    async def handler(request):
        ctx["requests"].append(request)
        entered.set()
        await release.wait()
        return httpx.Response(200, json=ctx["good"]())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resolver = ctx["make"](async_http_client=client)
        leader = asyncio.create_task(resolver.resolve_async(ctx["v1"]()))
        await entered.wait()
        waiter = asyncio.create_task(resolver.resolve_async(ctx["v1"]()))
        await asyncio.sleep(0)
        leader.cancel()
        with pytest.raises(asyncio.CancelledError):
            await leader
        assert (await waiter).reason == "cancelled"
        release.set()
        assert isinstance(await resolver.resolve_async(ctx["v1"]()), SelfBinding)
        assert len(ctx["requests"]) == 2


def test_close_inflight_limit_wait_timeout_and_no_token_storage(setup, caplog):
    ctx = setup
    entered, release = threading.Event(), threading.Event()

    def handler(request):
        entered.set()
        assert release.wait(3)
        return httpx.Response(200, json=ctx["good"]())

    client = httpx.Client(transport=httpx.MockTransport(handler))
    resolver = ctx["make"](http_client=client, timeout_seconds=0.03, max_inflight=1)
    token = ctx["v1"]()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(resolver.resolve, token)
        assert entered.wait(2)
        assert resolver.resolve(token).reason == "wait_timeout"
        assert resolver.resolve(ctx["v1"](sub="usr_other")).reason == "inflight_limit"
        assert token not in repr(vars(resolver)) and token not in caplog.text
        resolver.close()
        release.set()
        assert future.result().reason == "closed"
    assert resolver.resolve(token).reason == "closed"
    assert not client.is_closed
    resolver.close()
    client.close()


class Stream(httpx.SyncByteStream):
    def __init__(self):
        self.reads = 0
        self.closed = False

    def __iter__(self):
        for _ in range(10000):
            self.reads += 1
            yield b"x"

    def close(self):
        self.closed = True


@pytest.mark.parametrize("declared", [False, True])
def test_stream_size_bounded_and_response_always_closed(setup, declared):
    ctx = setup
    stream = Stream()
    response = httpx.Response(
        200, stream=stream, headers={"content-length": "10000"} if declared else {}
    )
    ctx["responses"].append(response)
    assert ctx["make"]().resolve(ctx["v1"]()).reason == "invalid_response"
    assert stream.closed and stream.reads <= (0 if declared else 4097)


@pytest.mark.parametrize(
    "options",
    [
        {"enrollment": "intent"},
        {"legacy_channels": "device"},
        {"legacy_channels": []},
        {"legacy_channels": ["obo"]},
        {"max_entries": 0},
        {"max_inflight": 0},
        {"max_age_cap_seconds": True},
        {"max_age_cap_seconds": 3601},
        {"negative_max_age_cap_seconds": 61},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": 11},
        {"unavailable_backoff_seconds": 301},
        {"max_response_bytes": 1023},
        {"api_base_url": "http://remote.example"},
        {"api_base_url": "https://u:p@host"},
    ],
)
def test_constructor_rejects_invalid_without_io(setup, options):
    with pytest.raises(ValueError):
        setup["make"](**options)
    assert not setup["requests"]


def test_constructor_requires_matching_verifiers_and_no_enrollment_api(setup, config):
    ctx = setup
    with pytest.raises(ValueError):
        ctx["make"](native_verifier=None, legacy_verifier=None)
    other = AccessTokenVerifier(replace(config, audience="other"), jwks={"keys": []})
    with pytest.raises(ValueError):
        ctx["make"](legacy_verifier=other)
    resolver = ctx["make"]()
    assert not hasattr(resolver, "enroll") and not hasattr(resolver, "enroll_async")
    assert not resolver.epoch_invalidated("never-seen")


@pytest.mark.parametrize("error", [[], {}, True, None, 17])
def test_invalid_error_values_are_results_not_exceptions(setup, error):
    push(setup, 503, {"error": error})
    result = setup["make"]().resolve(setup["v1"]())
    assert isinstance(result, SelfBindingUnavailable) and result.reason == "invalid_response"


def test_compatible_nontext_channel_is_ineligible_not_exception(setup):
    ctx = setup
    resolver = ctx["make"](legacy_policy=RegisteredClaimsPolicy.PYJWT_COMPATIBLE)
    result = resolver.resolve(ctx["v1"](source={"channel": []}))
    assert isinstance(result, SelfBindingMissing) and result.reason == "source_not_resolvable"
    assert ctx["requests"] == []


@pytest.mark.parametrize("options", [{"legacy_channels": None}, {"max_age_cap_seconds": "bad"}])
def test_invalid_constructor_types_are_value_error(setup, options):
    with pytest.raises(ValueError):
        setup["make"](**options)


@pytest.mark.parametrize(
    "body", [b"not-json", b"[]", b'{"error":"x","error":"y"}', b'{"generation":NaN}']
)
def test_invalid_json_and_missing_fields_are_unavailable(setup, body):
    ctx = setup
    ctx["responses"].append(httpx.Response(200, content=body))
    assert ctx["make"]().resolve(ctx["v1"]()).reason == "invalid_response"


@pytest.mark.parametrize(
    "payload",
    [
        {"error": "identity_binding_unmapped", "epoch": E1},
        {"error": "identity_binding_unmapped", "epoch": E1, "max_age_seconds": True},
        {
            "error": "identity_binding_unmapped",
            "epoch": E1,
            "max_age_seconds": 60,
            "class": "secret",
        },
    ],
)
def test_409_only_two_closed_shapes(setup, payload):
    push(setup, 409, payload)
    assert setup["make"]().resolve(setup["v1"]()).reason == "invalid_response"


def test_short_server_ttl_no_hit_renewal_and_generation_decrease_not_fork(setup, clock):
    ctx = setup
    resolver = ctx["make"]()
    push(ctx, payload=ctx["good"](age=10, generation=100))
    first = resolver.resolve(ctx["v1"]())
    clock.now += 9
    assert resolver.resolve(ctx["v1"]()).expires_at == first.expires_at
    clock.now += 1
    push(ctx, payload=ctx["good"](age=10, generation=1))
    second = resolver.resolve(ctx["v1"]())
    assert second.generation == 1 and second.expires_at == first.expires_at + 10
    assert not resolver.epoch_invalidated(E1) and len(ctx["requests"]) == 2


def test_shared_lru_budget_and_native_owner_eviction(setup):
    ctx = setup
    resolver = ctx["make"](max_entries=2)
    push(ctx, payload=ctx["good"](legacy="usr_alias"))
    resolver.resolve(ctx["v1"](sub="usr_alias"))
    push(ctx, payload=ctx["good"](native=True, legacy="usr_canonical"))
    resolver.resolve(ctx["nat"]())
    push(ctx, 409, {"error": "identity_binding_unmapped", "epoch": E1, "max_age_seconds": 60})
    resolver.resolve(ctx["v1"](sub="usr_missing"))
    assert len(resolver._by_legacy) + len(resolver._by_person) + len(resolver._negative) == 2
    assert resolver._by_legacy == {}
    push(ctx, payload=ctx["good"](legacy="usr_again"))
    resolver.resolve(ctx["v1"](sub="usr_again"))
    assert resolver._by_person == {} and resolver._canonical_owner == {}


def test_invalidated_epoch_capacity_disables_instance(setup):
    ctx = setup
    resolver = ctx["make"]()
    for index in range(34):
        epoch = f"epoch-{index}"
        subject = f"usr_{index}"
        push(ctx, payload=ctx["good"](legacy=subject, epoch=epoch))
        result = resolver.resolve(ctx["v1"](sub=subject))
    assert isinstance(result, SelfBindingUnavailable) and result.reason == "closed"
    assert len(resolver._invalidated) == 32 and resolver.epoch_invalidated("unknown")
    assert resolver.resolve(ctx["v1"]()).reason == "closed"


def test_verifier_unavailable_is_not_a_login_exception(setup, monkeypatch, caplog):
    from leap_oauth_sdk import Retryable

    ctx = setup
    token = ctx["v1"]()

    def unavailable(value):
        raise Retryable("jwks_unavailable", value)

    monkeypatch.setattr(ctx["legacy"], "verify", unavailable)
    result = ctx["make"]().resolve(token)
    assert isinstance(result, SelfBindingUnavailable) and result.reason == "verifier_unavailable"
    assert token not in repr(result) and token not in caplog.text and not ctx["requests"]


@pytest.mark.parametrize("timeout", [True, False])
def test_network_failure_backoff_keeps_existing_positive_cache(setup, timeout):
    ctx = setup
    fail = [False]

    def handler(request):
        ctx["requests"].append(request)
        if fail[0]:
            error = httpx.ReadTimeout if timeout else httpx.ConnectError
            raise error("synthetic network failure", request=request)
        return httpx.Response(200, json=ctx["good"]())

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        resolver = ctx["make"](http_client=client)
        original = resolver.resolve(ctx["v1"]())
        fail[0] = True
        assert resolver.resolve(ctx["v1"](sub="usr_other")).reason == "network"
        assert resolver.resolve(ctx["v1"]()) == original
        assert resolver.resolve(ctx["v1"](sub="usr_third")).reason == "backoff"
        assert len(ctx["requests"]) == 2


def test_late_old_epoch_response_cannot_restore_cache(setup):
    ctx = setup
    entered, release = threading.Event(), threading.Event()
    slow = ctx["v1"](sub="usr_slow")

    def handler(request):
        if request.headers["authorization"] == "Bearer " + slow:
            entered.set()
            assert release.wait(3)
            payload = ctx["good"](legacy="usr_slow")
        else:
            payload = ctx["good"](legacy="usr_new", epoch=E2)
        return httpx.Response(200, json=payload)

    push(ctx)
    resolver = ctx["make"]()
    resolver.resolve(ctx["v1"]())
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        resolver._http = client
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(resolver.resolve, slow)
            assert entered.wait(2)
            assert resolver.resolve(ctx["v1"](sub="usr_new")).epoch == E2
            release.set()
            assert future.result().reason == "epoch_invalidated"
        assert resolver._current_epoch == E2 and resolver.epoch_invalidated(E1)


async def test_cancelled_async_waiter_does_not_cancel_leader(setup):
    ctx = setup
    entered, release = asyncio.Event(), asyncio.Event()

    async def handler(request):
        ctx["requests"].append(request)
        entered.set()
        await release.wait()
        return httpx.Response(200, json=ctx["good"]())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resolver = ctx["make"](async_http_client=client)
        leader = asyncio.create_task(resolver.resolve_async(ctx["v1"]()))
        await entered.wait()
        waiter = asyncio.create_task(resolver.resolve_async(ctx["v1"]()))
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        release.set()
        assert isinstance(await leader, SelfBinding) and len(ctx["requests"]) == 1
        resolver.close()
        assert not client.is_closed


class AsyncStream(httpx.AsyncByteStream):
    def __init__(self, *, fail=False):
        self.closed = False
        self.reads = 0
        self.fail = fail

    async def __aiter__(self):
        for _ in range(10000):
            self.reads += 1
            if self.fail:
                raise httpx.ReadError("synthetic read error")
            yield b"x"

    async def aclose(self):
        self.closed = True


@pytest.mark.parametrize("fail", [False, True])
async def test_async_stream_always_closed_and_budgeted(setup, fail):
    ctx = setup
    stream = AsyncStream(fail=fail)
    ctx["responses"].append(httpx.Response(200, stream=stream))
    result = await ctx["make"]().resolve_async(ctx["v1"]())
    assert result.reason == ("network" if fail else "invalid_response")
    assert stream.closed and stream.reads <= 4097


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_implicit_per_call_clients_are_closed(setup, monkeypatch, asynchronous):
    from leap_oauth_sdk import self_binding as module

    ctx = setup
    created = []
    original = httpx.AsyncClient if asynchronous else httpx.Client

    def factory():
        client = original(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=ctx["good"]()))
        )
        created.append(client)
        return client

    monkeypatch.setattr(module.httpx, "AsyncClient" if asynchronous else "Client", factory)
    resolver = ctx["make"](http_client=None, async_http_client=None)
    result = (
        await resolver.resolve_async(ctx["v1"]()) if asynchronous else resolver.resolve(ctx["v1"]())
    )
    assert isinstance(result, SelfBinding) and len(created) == 1 and created[0].is_closed


@pytest.mark.parametrize("native", [False, True])
def test_tampered_signature_and_v1_wrong_audience_are_local_missing(setup, native):
    ctx = setup
    token = ctx["nat"]() if native else ctx["v1"]()
    parts = token.split(".")
    parts[-1] = ("A" if parts[-1][0] != "A" else "B") + parts[-1][1:]
    result = ctx["make"]().resolve(".".join(parts))
    assert isinstance(result, SelfBindingMissing) and result.reason == "not_verified"
    assert ctx["make"]().resolve(ctx["v1"](aud="other")).reason == "not_verified"
    assert ctx["requests"] == []


def test_compatible_missing_optional_status_and_zero_negative_cap(setup):
    ctx = setup
    resolver = ctx["make"](
        legacy_policy=RegisteredClaimsPolicy.PYJWT_COMPATIBLE, negative_max_age_cap_seconds=0
    )
    for _ in range(2):
        push(ctx, 409, {"error": "identity_binding_unmapped", "epoch": E1, "max_age_seconds": 60})
        assert resolver.resolve(ctx["v1"](status=None)).reason == "unmapped"
    assert resolver._current_epoch == E1 and resolver._negative == {} and len(ctx["requests"]) == 2


def test_new_exports_are_available_without_enrollment():
    import leap_oauth_sdk as sdk

    for name in (
        "SelfBindingResolver",
        "SelfBinding",
        "SelfBindingMissing",
        "SelfBindingUnavailable",
        "SelfBindingResult",
    ):
        assert name in sdk.__all__ and hasattr(sdk, name)
    assert not hasattr(sdk, "SelfBindingEnrollment")


def test_closed_injected_transport_is_unavailable_not_runtime_exception(setup):
    ctx = setup
    resolver = ctx["make"]()
    ctx["client"].close()
    result = resolver.resolve(ctx["v1"]())
    assert isinstance(result, SelfBindingUnavailable) and result.reason == "network"


@pytest.mark.parametrize(
    "field",
    ["aud", "sub", "epoch", "person_key", "legacy_subject", "generation", "max_age_seconds"],
)
def test_each_missing_200_field_is_invalid_response(setup, field):
    payload = setup["good"]()
    payload.pop(field)
    push(setup, payload=payload)
    assert setup["make"]().resolve(setup["v1"]()).reason == "invalid_response"


def test_v1_delegated_cache_uses_own_exp_and_never_calls_cs(setup):
    ctx = setup
    resolver = ctx["make"]()
    push(ctx)
    resolver.resolve(ctx["v1"]())
    deadline = int(time.time()) + 10
    delegated = ctx["v1"](source={"channel": "obo"}, act={"type": "obo"}, exp=deadline)
    result = resolver.resolve(delegated)
    assert isinstance(result, SelfBinding) and result.delegated and result.lookup == "legacy"
    assert result.expires_at <= deadline and len(ctx["requests"]) == 1


def test_injected_client_defaults_cannot_replace_or_add_credentials(setup):
    ctx = setup

    def handler(request):
        ctx["requests"].append(request)
        return httpx.Response(200, json=ctx["good"]())

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        auth=("service", "secret"),
        cookies={"session": "unrelated"},
        headers={"X-Extra": "unrelated"},
        follow_redirects=True,
        timeout=9,
    ) as client:
        token = ctx["v1"]()
        result = ctx["make"](http_client=client).resolve(token)
        assert isinstance(result, SelfBinding)
    request = ctx["requests"][0]
    assert set(request.headers) == {"host", "authorization", "accept"}
    assert request.headers["authorization"] == "Bearer " + token
    assert set(request.extensions["timeout"].values()) == {2.0}
