"""本人映射；Missing 按无映射处理，Unavailable 可重试，两者都不得清登录凭据。

业务先用自己的入口策略接受 token，再调用 resolve；解析器会再验同一张票。
此模块不创建后台任务、不缓存 Bearer，也不执行 enrollment。
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import threading
import time
import unicodedata
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import CancelledError as FutureCancelledError
from concurrent.futures import Future, InvalidStateError
from dataclasses import dataclass, field
from typing import Any, Literal, cast
from urllib.parse import urlsplit

import httpx

# Reuse the URL contract specified by the approved design.
from .config import (
    DEFAULT_TOKEN_VERSION,
    LeapAuthConfig,
    _require_http_url,  # pyright: ignore[reportPrivateUsage]
)
from .errors import OAuthSDKError, Retryable
from .native import NativeAccessTokenVerifier, NativeIdentity, parse_person_key
from .tokens import (
    AccessTokenContext,
    AccessTokenVerifier,
    RegisteredClaimsPolicy,
    VerifiedTokenClaims,
)
from .transition import select_native_profile

logger = logging.getLogger(__name__)
Profile = Literal["principal_v1", "feishu_native_v2"]
Lookup = Literal["legacy", "person"]
type VerifiedSource = AccessTokenContext | VerifiedTokenClaims | NativeIdentity
MissingReason = Literal[
    "not_verified",
    "profile_not_configured",
    "source_not_resolvable",
    "delegated_uncached",
    "unmapped",
    "rejected",
    "echo_mismatch",
    "ledger_not_recording",
    "epoch_invalidated",
    "binding_conflict",
]
UnavailableReason = Literal[
    "closed",
    "verifier_unavailable",
    "backoff",
    "upstream_unavailable",
    "redirect",
    "invalid_response",
    "network",
    "inflight_limit",
    "wait_timeout",
    "cancelled",
]


@dataclass(frozen=True, slots=True)
class SelfBinding:
    profile: Profile
    wire_subject: str
    legacy_subject: str
    person_key: str
    lookup: Lookup
    epoch: str
    generation: int
    delegated: bool
    expires_at: int
    source: VerifiedSource = field(repr=False)

    @property
    def raw_claims(self) -> Mapping[str, Any]:
        return self.source.raw_claims


@dataclass(frozen=True, slots=True)
class SelfBindingMissing:
    reason: MissingReason
    profile: Profile
    wire_subject: str
    source: VerifiedSource | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class SelfBindingUnavailable:
    reason: UnavailableReason
    source: VerifiedSource | None = field(repr=False)


type SelfBindingResult = SelfBinding | SelfBindingMissing | SelfBindingUnavailable


@dataclass(frozen=True, slots=True)
class _Verified:
    profile: Profile
    lookup: Lookup
    subject: str
    exp: int
    delegated: bool
    source: VerifiedSource = field(repr=False)


@dataclass(frozen=True, slots=True)
class _Bound:
    legacy: str
    person: str
    epoch: str
    generation: int
    expires: float


@dataclass(frozen=True, slots=True)
class _Outcome:
    kind: Literal["bound", "missing", "unavailable"]
    reason: MissingReason | UnavailableReason | None = None
    bound: _Bound | None = None
    epoch: str | None = None


@dataclass(frozen=True, slots=True)
class _Reply:
    status: int = 0
    payload: Mapping[str, Any] | None = None
    failure: UnavailableReason | None = None


def _missing(reason: MissingReason, epoch: str | None = None) -> _Outcome:
    return _Outcome("missing", reason=reason, epoch=epoch)


def _unavailable(reason: UnavailableReason) -> _Outcome:
    return _Outcome("unavailable", reason=reason)


def _exact_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(unicodedata.category(char) == "Cc" for char in value)
    )


def _integer(value: object, minimum: int, maximum: object) -> bool:
    return type(value) is int and type(maximum) is int and minimum <= value <= maximum


def _verifier_type(value: object, *, native: bool) -> bool:
    return isinstance(value, NativeAccessTokenVerifier if native else AccessTokenVerifier)


def _number(value: object, low: float, high: float, exclusive: bool) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and value <= high
        and (value > low if exclusive else value >= low)
    )


def _unique(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("invalid self binding response")
        result[key] = value
    return result


def _nonfinite(_value: str) -> None:
    raise ValueError("invalid self binding response")


def _json_object(content: bytes) -> Mapping[str, Any] | None:
    try:
        value: object = json.loads(
            content.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite
        )
        return cast(dict[str, Any], value) if isinstance(value, dict) else None
    except (ValueError, UnicodeError, RecursionError):
        return None


class SelfBindingResolver:
    """本地再验票后查询 C-S；Missing→无映射，Unavailable→503，均不能变为401。

    resolver 不接受调用方拼装的 verified 对象。两个缓存索引按原票来源分开，
    legacy alias 不能反推 native canonical 键；结果必须在 expires_at 前使用。
    """

    def __init__(
        self,
        config: LeapAuthConfig,
        *,
        native_verifier: NativeAccessTokenVerifier | None = None,
        legacy_verifier: AccessTokenVerifier | None = None,
        legacy_policy: RegisteredClaimsPolicy = RegisteredClaimsPolicy.STRICT,
        legacy_channels: Iterable[str] = ("device", "bot", "feishu_oauth", "feishu_bot"),
        api_base_url: str | None = None,
        http_client: httpx.Client | None = None,
        async_http_client: httpx.AsyncClient | None = None,
        enrollment: Literal["off"] = "off",
        max_age_cap_seconds: int = 60,
        negative_max_age_cap_seconds: int = 30,
        max_entries: int = 10_000,
        max_inflight: int = 256,
        timeout_seconds: float = 2.0,
        unavailable_backoff_seconds: float = 5.0,
        max_response_bytes: int = 4096,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if enrollment != "off":
            raise ValueError("self-binding enrollment is not available in this SDK release")
        if native_verifier is None and legacy_verifier is None:
            raise ValueError("at least one self-binding verifier is required")
        for verifier in (native_verifier, legacy_verifier):
            if verifier is not None and (verifier.config.issuer, verifier.config.audience) != (
                config.issuer,
                config.audience,
            ):
                raise ValueError("self-binding verifiers must match issuer and audience")
        if (
            native_verifier is not None
            and not _verifier_type(native_verifier, native=True)
            or legacy_verifier is not None
            and not _verifier_type(legacy_verifier, native=False)
        ):
            raise ValueError("self-binding requires original profile verifiers")
        if legacy_policy not in (
            RegisteredClaimsPolicy.STRICT,
            RegisteredClaimsPolicy.PYJWT_COMPATIBLE,
        ):
            raise ValueError("invalid self-binding legacy policy")
        if isinstance(legacy_channels, (str, bytes)):
            raise ValueError("legacy channels must be a collection")
        try:
            channels = tuple(legacy_channels)
        except TypeError as exc:
            raise ValueError("legacy channels must be a collection") from exc
        if not channels or any(
            not _exact_text(item) or item not in {"device", "bot", "feishu_oauth", "feishu_bot"}
            for item in channels
        ):
            raise ValueError("unsupported self-binding legacy channels")
        base = config.issuer if api_base_url is None else api_base_url
        _require_http_url(base, "api_base_url")
        try:
            httpx.URL(base)
        except httpx.InvalidURL as exc:
            raise ValueError("invalid self-binding API URL") from exc
        parsed = urlsplit(base)
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("self-binding API must use https outside loopback")
        if not all(
            (
                _integer(max_age_cap_seconds, 1, 3600),
                _integer(negative_max_age_cap_seconds, 0, max_age_cap_seconds),
                _integer(max_entries, 1, 1_000_000),
                _integer(max_inflight, 1, 10_000),
                _integer(max_response_bytes, 1024, 65536),
            )
        ):
            raise ValueError("invalid self-binding cache or response limit")
        for number, low, high, exclusive in (
            (timeout_seconds, 0, config.timeout_seconds, True),
            (unavailable_backoff_seconds, 0, 300, False),
        ):
            if not _number(number, low, high, exclusive):
                raise ValueError("invalid self-binding timeout or backoff")
        self._config, self._native, self._legacy = config, native_verifier, legacy_verifier
        self._policy, self._channels = legacy_policy, frozenset(channels)
        self._url = base.rstrip("/") + "/api/identity/binding/self"
        self._http, self._async_http = http_client, async_http_client
        self._cap, self._negative_cap = max_age_cap_seconds, negative_max_age_cap_seconds
        self._max_entries, self._max_inflight = max_entries, max_inflight
        self._timeout, self._backoff, self._max_bytes = (
            timeout_seconds,
            unavailable_backoff_seconds,
            max_response_bytes,
        )
        self._clock, self._wall = clock, wall_clock
        self._lock = threading.Lock()
        self._closed, self._disabled = False, False
        self._current_epoch: str | None = None
        self._invalidated: OrderedDict[str, None] = OrderedDict()
        self._by_legacy: dict[tuple[str, str], _Bound] = {}
        self._by_person: dict[tuple[str, str], _Bound] = {}
        self._canonical_owner: dict[tuple[str, str], str] = {}
        self._negative: dict[tuple[str, str, str], float] = {}
        self._lru: OrderedDict[tuple[str, str, str], None] = OrderedDict()
        self._backoff_until = 0.0
        self._inflight: dict[tuple[Lookup, str], Future[_Outcome]] = {}

    def epoch_invalidated(self, epoch: str) -> bool:
        """只说明本实例是否已见失效；False 不证明 epoch 当前有效。"""
        with self._lock:
            return self._disabled or epoch in self._invalidated

    def _clear(self) -> None:
        self._by_legacy.clear()
        self._by_person.clear()
        self._negative.clear()
        self._canonical_owner.clear()
        self._lru.clear()

    def close(self) -> None:
        """幂等；不关闭调用方注入的 client，不创建或取消后台任务。"""
        with self._lock:
            self._closed = True
            self._clear()
            self._current_epoch = None
            waiting = tuple(self._inflight.values())
            self._inflight.clear()
        for future in waiting:
            self._set_result(future, _unavailable("closed"))

    def _mark_invalid(self, epoch: str) -> None:
        if epoch not in self._invalidated:
            if len(self._invalidated) >= 32:
                self._disabled = True
            else:
                self._invalidated[epoch] = None
            logger.warning(
                "Self-binding epoch invalidated epoch=%s count=%s",
                epoch[:12],
                len(self._invalidated),
            )

    def _adopt(self, epoch: str) -> _Outcome | None:
        if epoch in self._invalidated:
            return _missing("epoch_invalidated", epoch)
        if self._current_epoch is not None and epoch != self._current_epoch:
            self._mark_invalid(self._current_epoch)
            self._clear()
        self._current_epoch = epoch
        return _unavailable("closed") if self._disabled else None

    def _drop(self, key: tuple[str, str, str]) -> None:
        self._lru.pop(key, None)
        index, epoch, subject = key
        if index == "legacy":
            self._by_legacy.pop((epoch, subject), None)
        elif index == "person":
            item = self._by_person.pop((epoch, subject), None)
            if item is not None:
                self._canonical_owner.pop((epoch, item.legacy), None)
        else:
            self._negative.pop((epoch, index.removeprefix("negative:"), subject), None)

    def _touch(self, key: tuple[str, str, str]) -> None:
        self._lru[key] = None
        self._lru.move_to_end(key)
        while len(self._lru) > self._max_entries:
            self._drop(next(iter(self._lru)))

    def _cache_get(self, verified: _Verified) -> _Outcome | None:
        epoch = self._current_epoch
        if epoch is None or epoch in self._invalidated:
            return None
        index = self._by_legacy if verified.lookup == "legacy" else self._by_person
        entry = index.get((epoch, verified.subject))
        if entry is not None and entry.expires > self._clock():
            self._touch((verified.lookup, epoch, verified.subject))
            return _Outcome("bound", bound=entry, epoch=epoch)
        if not verified.delegated:
            expiry = self._negative.get((epoch, verified.lookup, verified.subject))
            if expiry is not None and expiry > self._clock():
                self._touch(("negative:" + verified.lookup, epoch, verified.subject))
                return _missing("unmapped", epoch)
        return None

    def _prepare(self, source: VerifiedSource, native: bool) -> _Verified | SelfBindingMissing:
        profile: Profile = "feishu_native_v2" if native else "principal_v1"
        lookup: Lookup = "person" if native else "legacy"
        claims = source.raw_claims
        subject = claims.get("sub")
        subject = subject if isinstance(subject, str) else ""
        failure = SelfBindingMissing("source_not_resolvable", profile, subject, source)
        raw_source = claims.get("source")
        channel = (
            cast(Mapping[str, Any], raw_source).get("channel")
            if isinstance(raw_source, Mapping)
            else None
        )
        actor = claims.get("act")
        actor_map = cast(Mapping[str, Any], actor) if isinstance(actor, Mapping) else None
        if not isinstance(channel, str):
            return failure
        delegated = bool(
            channel == "obo" or actor_map is not None and actor_map.get("type") == "obo"
        )
        if native:
            if channel not in {"feishu_oauth", "feishu_bot", "obo"}:
                return failure
        else:
            if (
                claims.get("ver") != DEFAULT_TOKEN_VERSION
                or claims.get("principal_type") != "human"
                or not subject.startswith("usr_")
                or len(subject) <= 4
                or claims.get("status", "active") != "active"
                or claims.get("purpose", "access") != "access"
                or (channel not in self._channels and not (delegated and channel == "obo"))
                or (
                    "act" in claims
                    and (
                        not isinstance(actor, Mapping) or not delegated and channel != "feishu_bot"
                    )
                )
            ):
                return failure
        try:
            expiry = int(claims["exp"])
        except (KeyError, ValueError, TypeError, OverflowError):
            return SelfBindingMissing("not_verified", profile, subject, None)
        return _Verified(profile, lookup, subject, expiry, delegated, source)

    def _selected(self, token: str) -> bool | SelfBindingMissing:
        try:
            native = select_native_profile(token)
        except OAuthSDKError:
            return SelfBindingMissing("not_verified", "principal_v1", "", None)
        if self._native is None if native else self._legacy is None:
            return SelfBindingMissing(
                "profile_not_configured", "feishu_native_v2" if native else "principal_v1", "", None
            )
        return native

    def _verify_error(self, error: OAuthSDKError, native: bool) -> SelfBindingResult:
        if isinstance(error, Retryable):
            return SelfBindingUnavailable("verifier_unavailable", None)
        return SelfBindingMissing(
            "not_verified", "feishu_native_v2" if native else "principal_v1", "", None
        )

    def _acquire(self, verified: _Verified) -> tuple[Future[_Outcome], bool] | _Outcome:
        key = (verified.lookup, verified.subject)
        with self._lock:
            if self._closed or self._disabled:
                return _unavailable("closed")
            hit = self._cache_get(verified)
            if hit is not None:
                return hit
            if verified.delegated:
                return _missing("delegated_uncached")
            if self._clock() < self._backoff_until:
                return _unavailable("backoff")
            if key in self._inflight:
                return self._inflight[key], False
            if len(self._inflight) >= self._max_inflight:
                return _unavailable("inflight_limit")
            future: Future[_Outcome] = Future()
            self._inflight[key] = future
            return future, True

    def _materialize(self, outcome: _Outcome, verified: _Verified) -> SelfBindingResult:
        with self._lock:
            if self._closed or self._disabled:
                return SelfBindingUnavailable("closed", verified.source)
            if outcome.kind == "bound":
                bound = outcome.bound
                assert bound is not None
                if bound.epoch in self._invalidated or bound.epoch != self._current_epoch:
                    return SelfBindingMissing(
                        "epoch_invalidated", verified.profile, verified.subject, verified.source
                    )
                expires = math.floor(
                    min(verified.exp, self._wall() + bound.expires - self._clock())
                )
                return SelfBinding(
                    verified.profile,
                    verified.subject,
                    bound.legacy,
                    bound.person,
                    verified.lookup,
                    bound.epoch,
                    bound.generation,
                    verified.delegated,
                    expires,
                    verified.source,
                )
            if outcome.kind == "unavailable":
                return SelfBindingUnavailable(
                    cast(UnavailableReason, outcome.reason), verified.source
                )
            reason = cast(MissingReason, outcome.reason)
            if reason == "unmapped" and outcome.epoch in self._invalidated:
                reason = "epoch_invalidated"
            return SelfBindingMissing(reason, verified.profile, verified.subject, verified.source)

    @staticmethod
    def _set_result(future: Future[_Outcome], outcome: _Outcome) -> None:
        try:
            future.set_result(outcome)
        except InvalidStateError:
            pass  # close / cancellation may already have completed this flight.

    def _finish(
        self, verified: _Verified, future: Future[_Outcome], outcome: _Outcome
    ) -> SelfBindingResult:
        with self._lock:
            key = (verified.lookup, verified.subject)
            if self._inflight.get(key) is future:
                self._inflight.pop(key)
            if self._closed or self._disabled:
                outcome = _unavailable("closed")
        self._set_result(future, outcome)
        return self._materialize(outcome, verified)

    def _cancel(self, verified: _Verified, future: Future[_Outcome]) -> None:
        with self._lock:
            key = (verified.lookup, verified.subject)
            if self._inflight.get(key) is future:
                self._inflight.pop(key)
        future.cancel()

    def resolve(self, token: str) -> SelfBindingResult:
        """业务先验票/授权；这里再验同一张票，映射失败不抛重新登录异常。"""
        with self._lock:
            if self._closed or self._disabled:
                return SelfBindingUnavailable("closed", None)
        native = self._selected(token)
        if isinstance(native, SelfBindingMissing):
            return native
        try:
            if native:
                assert self._native is not None
                source: VerifiedSource = self._native.verify(token)
            else:
                assert self._legacy is not None
                source = (
                    self._legacy.verify(token)
                    if self._policy is RegisteredClaimsPolicy.STRICT
                    else self._legacy.verify_claims(token, policy=self._policy)
                )
        except OAuthSDKError as exc:
            return self._verify_error(exc, native)
        verified = self._prepare(source, native)
        if isinstance(verified, SelfBindingMissing):
            return verified
        flight = self._acquire(verified)
        if isinstance(flight, _Outcome):
            return self._materialize(flight, verified)
        future, leader = flight
        if not leader:
            try:
                outcome = future.result(timeout=self._timeout)
            except TimeoutError:
                outcome = _unavailable("wait_timeout")
            except FutureCancelledError:
                outcome = _unavailable("cancelled")
            return self._materialize(outcome, verified)
        try:
            sent = self._clock()
            return self._finish(verified, future, self._apply(self._send(token), verified, sent))
        except BaseException:
            self._cancel(verified, future)
            raise

    async def resolve_async(self, token: str) -> SelfBindingResult:
        """与 resolve 共用索引/单飞；取消 waiter 不会取消 leader。"""
        with self._lock:
            if self._closed or self._disabled:
                return SelfBindingUnavailable("closed", None)
        native = self._selected(token)
        if isinstance(native, SelfBindingMissing):
            return native
        try:
            if native:
                assert self._native is not None
                source: VerifiedSource = await self._native.verify_async(token)
            else:
                assert self._legacy is not None
                source = (
                    await self._legacy.verify_async(token)
                    if self._policy is RegisteredClaimsPolicy.STRICT
                    else await self._legacy.verify_claims_async(token, policy=self._policy)
                )
        except OAuthSDKError as exc:
            return self._verify_error(exc, native)
        verified = self._prepare(source, native)
        if isinstance(verified, SelfBindingMissing):
            return verified
        flight = self._acquire(verified)
        if isinstance(flight, _Outcome):
            return self._materialize(flight, verified)
        future, leader = flight
        if not leader:
            try:
                outcome = await asyncio.wait_for(
                    asyncio.shield(asyncio.wrap_future(future)), self._timeout
                )
            except TimeoutError:
                outcome = _unavailable("wait_timeout")
            except asyncio.CancelledError:
                if not future.cancelled():
                    raise
                outcome = _unavailable("cancelled")
            return self._materialize(outcome, verified)
        try:
            sent = self._clock()
            reply = await self._send_async(token)
            return self._finish(verified, future, self._apply(reply, verified, sent))
        except BaseException:
            self._cancel(verified, future)
            raise

    def _request(self, token: str) -> httpx.Request:
        return httpx.Request(
            "GET",
            self._url,
            headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
            extensions={"timeout": httpx.Timeout(self._timeout).as_dict()},
        )

    def _length_allowed(self, response: httpx.Response) -> bool:
        try:
            length = response.headers.get("content-length")
            return length is None or 0 <= int(length) <= self._max_bytes
        except ValueError:
            return False

    def _read(self, response: httpx.Response) -> _Reply:
        if 300 <= response.status_code < 400:
            return _Reply(failure="redirect")
        if not self._length_allowed(response):
            return _Reply(failure="invalid_response")
        content = bytearray()
        for chunk in response.iter_bytes(chunk_size=self._max_bytes + 1):
            content.extend(chunk[: self._max_bytes + 1 - len(content)])
            if len(content) > self._max_bytes:
                return _Reply(failure="invalid_response")
        return _Reply(response.status_code, _json_object(bytes(content)))

    async def _read_async(self, response: httpx.Response) -> _Reply:
        if 300 <= response.status_code < 400:
            return _Reply(failure="redirect")
        if not self._length_allowed(response):
            return _Reply(failure="invalid_response")
        content = bytearray()
        async for chunk in response.aiter_bytes(chunk_size=self._max_bytes + 1):
            content.extend(chunk[: self._max_bytes + 1 - len(content)])
            if len(content) > self._max_bytes:
                return _Reply(failure="invalid_response")
        return _Reply(response.status_code, _json_object(bytes(content)))

    def _send_with(self, client: httpx.Client, token: str) -> _Reply:
        response = client.send(self._request(token), stream=True, follow_redirects=False, auth=None)
        try:
            return self._read(response)
        finally:
            response.close()

    async def _send_with_async(self, client: httpx.AsyncClient, token: str) -> _Reply:
        response = await client.send(
            self._request(token), stream=True, follow_redirects=False, auth=None
        )
        try:
            return await self._read_async(response)
        finally:
            await response.aclose()

    def _send(self, token: str) -> _Reply:
        try:
            if self._http is not None:
                return self._send_with(self._http, token)
            with httpx.Client() as client:
                return self._send_with(client, token)
        except (httpx.HTTPError, RuntimeError):
            return _Reply(failure="network")

    async def _send_async(self, token: str) -> _Reply:
        try:
            if self._async_http is not None:
                return await self._send_with_async(self._async_http, token)
            async with httpx.AsyncClient() as client:
                return await self._send_with_async(client, token)
        except (httpx.HTTPError, RuntimeError):
            return _Reply(failure="network")

    def _bad_reply(self, reason: UnavailableReason) -> _Outcome:
        self._backoff_until = self._clock() + self._backoff
        return _unavailable(reason)

    def _store(self, verified: _Verified, bound: _Bound) -> _Outcome:
        epoch, legacy, person = bound.epoch, bound.legacy, bound.person
        owner = self._canonical_owner.get((epoch, legacy))
        known_legacy = self._by_legacy.get((epoch, legacy))
        known_person = self._by_person.get((epoch, person))
        conflict = owner is not None and owner != person
        if verified.lookup == "legacy":
            conflict |= known_legacy is not None and known_legacy.person != person
        else:
            conflict |= (
                known_person is not None
                and known_person.legacy != legacy
                or known_legacy is not None
                and known_legacy.person != person
            )
        if conflict:
            logger.warning("Self-binding conflict epoch=%s count=%s", epoch[:12], len(self._lru))
            self._mark_invalid(epoch)
            self._clear()
            self._current_epoch = None
            return _missing("binding_conflict", epoch)
        if verified.lookup == "legacy":
            self._by_legacy[(epoch, legacy)] = bound
        else:
            self._by_person[(epoch, person)] = bound
            self._canonical_owner[(epoch, legacy)] = person
        self._drop(("negative:" + verified.lookup, epoch, verified.subject))
        self._touch((verified.lookup, epoch, verified.subject))
        return _Outcome("bound", bound=bound, epoch=epoch)

    def _apply(self, reply: _Reply, verified: _Verified, sent: float) -> _Outcome:
        with self._lock:
            if self._closed or self._disabled:
                return _unavailable("closed")
            if reply.failure is not None:
                return self._bad_reply(reply.failure)
            payload = reply.payload
            if payload is None:
                return self._bad_reply("invalid_response")
            if reply.status == 200:
                if set(payload) != {
                    "aud",
                    "sub",
                    "legacy_subject",
                    "person_key",
                    "epoch",
                    "generation",
                    "max_age_seconds",
                }:
                    return self._bad_reply("invalid_response")
                if (
                    any(
                        not _exact_text(payload[name]) or len(str(payload[name])) > 512
                        for name in ("aud", "sub", "epoch")
                    )
                    or not _exact_text(payload["legacy_subject"])
                    or not str(payload["legacy_subject"]).startswith("usr_")
                    or len(str(payload["legacy_subject"])) <= 4
                    or type(payload["generation"]) is not int
                    or payload["generation"] < 1
                    or not _integer(payload["max_age_seconds"], 1, 86400)
                ):
                    return self._bad_reply("invalid_response")
                try:
                    parse_person_key(payload["person_key"])
                except ValueError:
                    return self._bad_reply("invalid_response")
                if (
                    payload["aud"] != self._config.audience
                    or payload["sub"] != verified.subject
                    or payload["legacy_subject" if verified.lookup == "legacy" else "person_key"]
                    != verified.subject
                ):
                    return _missing("echo_mismatch")
                epoch = cast(str, payload["epoch"])
                rejected = self._adopt(epoch)
                if rejected is not None:
                    return rejected
                bound = _Bound(
                    cast(str, payload["legacy_subject"]),
                    cast(str, payload["person_key"]),
                    epoch,
                    payload["generation"],
                    sent + min(payload["max_age_seconds"], self._cap),
                )
                return self._store(verified, bound)
            if reply.status == 409 and payload.get("error") == "identity_binding_unmapped":
                if set(payload) == {"error"}:
                    return _missing("unmapped")
                if (
                    set(payload) != {"error", "epoch", "max_age_seconds"}
                    or not _exact_text(payload.get("epoch"))
                    or len(str(payload["epoch"])) > 512
                    or not _integer(payload.get("max_age_seconds"), 1, 86400)
                ):
                    return self._bad_reply("invalid_response")
                epoch = cast(str, payload["epoch"])
                rejected = self._adopt(epoch)
                if rejected is not None:
                    return rejected
                if self._negative_cap:
                    self._negative[(epoch, verified.lookup, verified.subject)] = sent + min(
                        payload["max_age_seconds"], self._negative_cap
                    )
                    self._touch(("negative:" + verified.lookup, epoch, verified.subject))
                return _missing("unmapped", epoch)
            if set(payload) != {"error"} or not isinstance(payload["error"], str):
                return self._bad_reply("invalid_response")
            if (reply.status, payload["error"]) in {
                (400, "identity_binding_bad_request"),
                (401, "identity_binding_token_rejected"),
                (405, "identity_binding_method_not_allowed"),
            }:
                return _missing("rejected")
            if reply.status == 503:
                if payload["error"] in {
                    "identity_binding_pending",
                    "identity_binding_revoked",
                    "identity_binding_breached",
                    "identity_binding_chain_invalid",
                }:
                    if self._current_epoch is not None:
                        self._mark_invalid(self._current_epoch)
                    self._clear()
                    self._current_epoch = None
                    return _missing("ledger_not_recording")
                if payload["error"] == "identity_binding_unavailable":
                    return self._bad_reply("upstream_unavailable")
            return self._bad_reply("invalid_response")
