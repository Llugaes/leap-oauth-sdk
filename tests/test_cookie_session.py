from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx
from cryptography.fernet import Fernet

from leap_oauth_sdk import (
    BrowserSSO,
    CookieCipher,
    CookieSession,
    CookieSessionManager,
    InvalidResponse,
    ReauthRequired,
    Retryable,
)

from .conftest import AUDIENCE, LOGOUT_URL, SESSION_URL, TOKEN_URL, FakeClock

SECRET = "s" * 32
ACTIVE = {"active": True, "subject_id": "usr_1", "audience": AUDIENCE}


def test_cipher_round_trip_and_rejections() -> None:
    cipher = CookieCipher(SECRET)
    value = cipher.encrypt({"a": 1, "名": "值"})
    assert cipher.decrypt(value) == {"a": 1, "名": "值"}
    assert cipher.decrypt(value, max_age_seconds=60) == {"a": 1, "名": "值"}
    assert cipher.decrypt(None) is None
    assert cipher.decrypt(value[:-4] + "AAAA") is None
    assert cipher.decrypt("not-a-token") is None
    assert CookieCipher(SECRET, context="other").decrypt(value) is None
    assert cipher.decrypt(Fernet(Fernet.generate_key()).encrypt(b"{}").decode()) is None
    with pytest.raises(ValueError):
        CookieCipher("short")
    with pytest.raises(ValueError):
        CookieCipher(SECRET, previous_secrets=["short"])
    with pytest.raises(ValueError):
        CookieCipher(SECRET, context="")


def test_cipher_rotation_and_key_derivation() -> None:
    old = CookieCipher("o" * 32, context="example.cookie.v2")
    rotated = CookieCipher(SECRET, context="example.cookie.v2", previous_secrets=["o" * 32])
    assert rotated.decrypt(old.encrypt({"k": "v"})) == {"k": "v"}

    # Key = SHA-256(context + NUL + secret), so services with an existing Fernet cookie can
    # keep their format by passing the same context.
    digest = hashlib.sha256(b"example.cookie.v2\0" + SECRET.encode()).digest()
    existing = Fernet(base64.urlsafe_b64encode(digest)).encrypt(json.dumps({"k": 1}).encode())
    assert CookieCipher(SECRET, context="example.cookie.v2").decrypt(existing.decode()) == {"k": 1}
    not_object = Fernet(base64.urlsafe_b64encode(digest)).encrypt(b'["list"]').decode()
    assert CookieCipher(SECRET, context="example.cookie.v2").decrypt(not_object) is None


@pytest.fixture
def mono() -> FakeClock:
    return FakeClock()


@pytest.fixture
def manager(sso: BrowserSSO, mono: FakeClock) -> CookieSessionManager:
    return CookieSessionManager(sso, CookieCipher(SECRET), monotonic=mono)


@pytest.fixture
def cookie(manager: CookieSessionManager, key, claims) -> Callable[..., str]:
    def build(expires_in: int = 300, refresh_token: str = "rt-1", **extra: str) -> str:
        exp = int(time.time()) + expires_in
        token = key.sign(claims(browser_sid="bsid-1", exp=exp))
        return manager.encode(
            CookieSession(
                subject_id="usr_1",
                access_token=token,
                refresh_token=refresh_token,
                expires_at=exp,
                auth_expires_at=int(time.time()) + 3600,
                extra=extra,
            )
        )

    return build


@respx.mock
def test_fresh_cookie_is_checked_online_without_refresh(manager, cookie) -> None:
    token_route = respx.post(TOKEN_URL)
    session_route = respx.post(SESSION_URL).mock(return_value=httpx.Response(200, json=ACTIVE))

    result = manager.resolve(cookie(csrf="c1"))

    assert result.context.subject_id == "usr_1"
    assert result.cookie is None
    assert result.session.extra == {"csrf": "c1"}
    assert session_route.call_count == 1 and not token_route.called
    assert 3500 < manager.max_age(result.session) <= 3600


@respx.mock
def test_expiring_cookie_refreshes_and_rewrites(manager, cookie, token_response) -> None:
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=token_response(refresh_token="rt-2"))
    )
    respx.post(SESSION_URL).mock(return_value=httpx.Response(200, json=ACTIVE))

    result = manager.resolve(cookie(expires_in=30, csrf="c1"))

    assert result.cookie is not None
    reloaded = manager.load(result.cookie)
    assert reloaded is not None
    assert reloaded.refresh_token == "rt-2"
    assert reloaded.extra == {"csrf": "c1"}


@respx.mock
def test_concurrent_requests_share_one_refresh(manager, cookie, token_response, mono) -> None:
    def slow_refresh(_: httpx.Request) -> httpx.Response:
        time.sleep(0.2)
        return httpx.Response(200, json=token_response(refresh_token="rt-2"))

    token_route = respx.post(TOKEN_URL).mock(side_effect=slow_refresh)
    respx.post(SESSION_URL).mock(return_value=httpx.Response(200, json=ACTIVE))
    old = cookie(expires_in=30)
    results: list[Any] = []
    threads = [
        threading.Thread(target=lambda: results.append(manager.resolve(old))) for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert token_route.call_count == 1
    assert {manager.load(r.cookie).refresh_token for r in results} == {"rt-2"}

    # A late request with the old cookie inside the reuse window gets the same result.
    manager.resolve(old)
    assert token_route.call_count == 1
    mono.now += 10
    manager.resolve(old)
    assert token_route.call_count == 2


@respx.mock
def test_failed_refresh_is_not_cached(manager, cookie, token_response) -> None:
    token_route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, json=token_response(refresh_token="rt-2")),
        ]
    )
    respx.post(SESSION_URL).mock(return_value=httpx.Response(200, json=ACTIVE))
    old = cookie(expires_in=30)
    with pytest.raises(Retryable):
        manager.resolve(old)
    assert manager.resolve(old).cookie is not None
    assert token_route.call_count == 2


@respx.mock
async def test_async_requests_share_one_refresh(manager, cookie, token_response, mono) -> None:
    async def slow_refresh(_: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        return httpx.Response(200, json=token_response(refresh_token="rt-2"))

    token_route = respx.post(TOKEN_URL).mock(side_effect=slow_refresh)
    respx.post(SESSION_URL).mock(return_value=httpx.Response(200, json=ACTIVE))
    old = cookie(expires_in=30)

    results = await asyncio.gather(*(manager.resolve_async(old) for _ in range(4)))

    assert token_route.call_count == 1
    assert {manager.load(r.cookie).refresh_token for r in results} == {"rt-2"}
    await manager.resolve_async(old)
    assert token_route.call_count == 1
    mono.now += 10
    await manager.resolve_async(old)
    assert token_route.call_count == 2


@respx.mock
async def test_async_failed_refresh_is_not_cached(manager, cookie, token_response) -> None:
    token_route = respx.post(TOKEN_URL).mock(
        side_effect=[httpx.Response(400, json={"error": "invalid_grant"}), httpx.Response(503)]
    )
    old = cookie(expires_in=30)
    with pytest.raises(ReauthRequired):
        await manager.resolve_async(old)
    with pytest.raises(Retryable):
        await manager.resolve_async(old)
    assert token_route.call_count == 2


def test_missing_invalid_or_expired_cookie_requires_sign_in(manager, key, claims) -> None:
    for value in (None, "", "garbage", CookieCipher("x" * 32).encrypt({"v": 1})):
        with pytest.raises(ReauthRequired) as exc_info:
            manager.resolve(value)
        assert exc_info.value.code == "browser_session_missing"
    wrong_version = CookieCipher(SECRET).encrypt({"v": 99})
    assert manager.load(wrong_version) is None
    broken = CookieCipher(SECRET).encrypt(
        {"v": 1, "sub": "usr_1", "at": "a", "rt": "r", "exp": "soon"}
    )
    assert manager.load(broken) is None

    expired = manager.encode(
        CookieSession(
            "usr_1",
            "a",
            "r",
            expires_at=int(time.time()) + 300,
            auth_expires_at=int(time.time()) - 1,
        )
    )
    with pytest.raises(ReauthRequired) as exc_info:
        manager.resolve(expired)
    assert exc_info.value.code == "browser_session_expired"


@respx.mock
def test_session_check_subject_must_match_cookie(manager, key, claims) -> None:
    respx.post(SESSION_URL).mock(
        return_value=httpx.Response(200, json={**ACTIVE, "subject_id": "usr_2"})
    )
    exp = int(time.time()) + 300
    value = manager.encode(
        CookieSession("usr_2", key.sign(claims(browser_sid="bsid-1", exp=exp)), "r", expires_at=exp)
    )
    with pytest.raises(InvalidResponse):
        manager.resolve(value)  # token says usr_1, server says usr_2

    respx.post(SESSION_URL).mock(return_value=httpx.Response(200, json=ACTIVE))
    with pytest.raises(ReauthRequired) as exc_info:
        manager.resolve(value)  # token and server say usr_1, cookie says usr_2
    assert exc_info.value.code == "browser_session_subject_changed"


@respx.mock
def test_legacy_cookie_is_migrated(sso, mono, cookie) -> None:
    respx.post(SESSION_URL).mock(return_value=httpx.Response(200, json=ACTIVE))
    current = CookieSessionManager(sso, CookieCipher(SECRET), monotonic=mono)
    session = current.load(cookie())
    assert session is not None

    migrating = CookieSessionManager(
        sso,
        CookieCipher("n" * 32),
        legacy_loader=lambda value: session if value == "legacy-format" else None,
        monotonic=mono,
    )
    result = migrating.resolve("legacy-format")
    assert result.cookie is not None and migrating.load(result.cookie) == session
    with pytest.raises(ReauthRequired):
        migrating.resolve("unknown-format")


@respx.mock
def test_logout_refreshes_expiring_token_first(manager, cookie, token_response) -> None:
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=token_response(refresh_token="rt-2"))
    )
    logout = respx.post(LOGOUT_URL).mock(return_value=httpx.Response(200, json={"success": True}))
    manager.logout(cookie(expires_in=30))
    manager.logout(cookie(), "current")
    assert logout.call_count == 2
    assert json.loads(logout.calls[1].request.content) == {"scope": "current"}
    with pytest.raises(ReauthRequired):
        manager.logout(None)


@respx.mock
async def test_async_logout(manager, cookie, token_response) -> None:
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=token_response(refresh_token="rt-2"))
    )
    logout = respx.post(LOGOUT_URL).mock(
        side_effect=[httpx.Response(200, json={}), httpx.Response(503)]
    )
    await manager.logout_async(cookie(expires_in=30))
    with pytest.raises(Retryable):
        await manager.logout_async(cookie())
    assert logout.call_count == 2


def test_oversized_cookie_and_options(manager, sso) -> None:
    with pytest.raises(InvalidResponse):
        manager.encode(CookieSession("usr_1", "a" * 4000, "r", expires_at=int(time.time()) + 300))
    with pytest.raises(ValueError):
        CookieSessionManager(sso, CookieCipher(SECRET), refresh_margin_seconds=-1)
