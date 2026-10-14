"""Encrypted HttpOnly cookie sessions for services that keep tokens out of the browser.

The cookie holds the access and refresh tokens, encrypted and authenticated with a server
secret. :class:`CookieSessionManager` refreshes shortly before expiry and checks the sign-in
online on every request. Concurrent requests carrying the same old cookie share one refresh
inside the process, so a rotation is never replayed by the same replica.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future
from dataclasses import dataclass, field, replace
from typing import Any, cast

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .browser import BrowserSession, BrowserSSO, LogoutScope
from .errors import InvalidResponse, ReauthRequired
from .tokens import AccessTokenContext

DEFAULT_COOKIE_CONTEXT = "leap-oauth-sdk.cookie.v1"
#: Browsers drop cookies above ~4 KiB including name and attributes.
MAX_COOKIE_VALUE_BYTES = 3800
_PAYLOAD_VERSION = 1


class CookieCipher:
    """Authenticated encryption for cookie values.

    The key is ``SHA-256(context + NUL + secret)``. ``context`` separates cookies of different
    purposes that share a secret. ``previous_secrets`` are still accepted for decryption so the
    secret can be rotated without signing everyone out.
    """

    def __init__(
        self,
        secret: str,
        *,
        context: str = DEFAULT_COOKIE_CONTEXT,
        previous_secrets: Sequence[str] = (),
    ) -> None:
        if not context:
            raise ValueError("context is required")
        for value in (secret, *previous_secrets):
            if len(value) < 32:
                raise ValueError("cookie secrets must be at least 32 characters")
        self._fernet = MultiFernet(
            [_fernet(context, value) for value in (secret, *previous_secrets)]
        )

    def encrypt(self, payload: Mapping[str, Any]) -> str:
        data = json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        return self._fernet.encrypt(data.encode("utf-8")).decode("ascii")

    def decrypt(
        self, value: str | None, *, max_age_seconds: int | None = None
    ) -> dict[str, Any] | None:
        """Return the payload, or ``None`` when missing, tampered, expired or not an object."""
        if not value:
            return None
        try:
            if max_age_seconds is None:
                raw = self._fernet.decrypt(value.encode("ascii"))
            else:
                raw = self._fernet.decrypt(value.encode("ascii"), ttl=max_age_seconds)
            payload: Any = json.loads(raw)
        except (InvalidToken, ValueError, UnicodeError):
            return None
        return cast(dict[str, Any], payload) if isinstance(payload, dict) else None


@dataclass(frozen=True, slots=True)
class CookieSession:
    """Decrypted cookie contents. ``extra`` carries small business values (CSRF token,
    display name); it is encrypted with the tokens but is not verified identity."""

    subject_id: str
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_at: int
    auth_expires_at: int | None = None
    extra: Mapping[str, str] = field(default_factory=lambda: {})

    @classmethod
    def from_browser_session(
        cls, session: BrowserSession, *, extra: Mapping[str, str] | None = None
    ) -> CookieSession:
        return cls(
            subject_id=session.subject_id,
            access_token=session.access_token,
            refresh_token=session.refresh_token,
            expires_at=session.expires_at,
            auth_expires_at=session.auth_expires_at,
            extra=dict(extra or {}),
        )


@dataclass(frozen=True, slots=True)
class CookieResolution:
    """Result of one protected request. When ``cookie`` is not ``None`` the session was
    refreshed or migrated: set it on the response with :meth:`CookieSessionManager.max_age`."""

    context: AccessTokenContext
    session: CookieSession
    cookie: str | None = field(default=None, repr=False)


LegacyLoader = Callable[[str], CookieSession | None]


class CookieSessionManager:
    """Load, refresh, check and end cookie sessions for one browser client."""

    def __init__(
        self,
        sso: BrowserSSO,
        cipher: CookieCipher,
        *,
        refresh_margin_seconds: int = 60,
        rotation_reuse_seconds: float = 10.0,
        legacy_loader: LegacyLoader | None = None,
        now: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if refresh_margin_seconds < 0 or rotation_reuse_seconds < 0:
            raise ValueError("refresh_margin_seconds and rotation_reuse_seconds must be >= 0")
        self._sso = sso
        self._cipher = cipher
        self._margin = refresh_margin_seconds
        self._reuse = rotation_reuse_seconds
        self._legacy_loader = legacy_loader
        self._now = now
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._flights: dict[str, tuple[float, Future[BrowserSession]]] = {}
        self._async_flights: dict[str, tuple[float, asyncio.Future[BrowserSession]]] = {}

    # -- encoding ------------------------------------------------------------------------

    def encode(self, session: CookieSession) -> str:
        value = self._cipher.encrypt(
            {
                "v": _PAYLOAD_VERSION,
                "sub": session.subject_id,
                "at": session.access_token,
                "rt": session.refresh_token,
                "exp": session.expires_at,
                "aexp": session.auth_expires_at,
                "x": dict(session.extra),
            }
        )
        if len(value) > MAX_COOKIE_VALUE_BYTES:
            raise InvalidResponse("browser_cookie_too_large", "session cookie would be too large")
        return value

    def issue(self, session: BrowserSession, *, extra: Mapping[str, str] | None = None) -> str:
        """Cookie value right after :meth:`BrowserSSO.exchange_code`."""
        return self.encode(CookieSession.from_browser_session(session, extra=extra))

    def load(self, value: str | None) -> CookieSession | None:
        payload = self._cipher.decrypt(value)
        if payload is None or payload.get("v") != _PAYLOAD_VERSION:
            return None
        extra: Any = payload.get("x") or {}
        auth_expires_at = payload.get("aexp")
        try:
            session = CookieSession(
                subject_id=_text(payload["sub"]),
                access_token=_text(payload["at"]),
                refresh_token=_text(payload["rt"]),
                expires_at=_integer(payload["exp"]),
                auth_expires_at=None if auth_expires_at is None else _integer(auth_expires_at),
                extra={str(k): str(v) for k, v in cast(dict[Any, Any], extra).items()},
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
        return session

    def max_age(self, session: CookieSession) -> int:
        """Cookie ``Max-Age``: until the root sign-in (or the token) expires."""
        until = session.auth_expires_at or session.expires_at
        return max(1, int(until - self._now()))

    # -- per request ---------------------------------------------------------------------

    def resolve(self, value: str | None) -> CookieResolution:
        session, rewrite = self._load_for_request(value)
        if self._needs_refresh(session):
            session = self._refreshed(session, self._refresh_sync(session))
            rewrite = True
        context = self._sso.check_session(session.access_token)
        return self._resolution(context, session, rewrite)

    async def resolve_async(self, value: str | None) -> CookieResolution:
        session, rewrite = self._load_for_request(value)
        if self._needs_refresh(session):
            session = self._refreshed(session, await self._refresh_async(session))
            rewrite = True
        context = await self._sso.check_session_async(session.access_token)
        return self._resolution(context, session, rewrite)

    def logout(self, value: str | None, scope: LogoutScope = "browser") -> None:
        """End the sign-in upstream. Clear the cookie only after this returns."""
        session, _ = self._load_for_request(value)
        if self._needs_refresh(session):
            session = self._refreshed(session, self._refresh_sync(session))
        self._sso.logout(session.access_token, scope)

    async def logout_async(self, value: str | None, scope: LogoutScope = "browser") -> None:
        session, _ = self._load_for_request(value)
        if self._needs_refresh(session):
            session = self._refreshed(session, await self._refresh_async(session))
        await self._sso.logout_async(session.access_token, scope)

    # -- internals -----------------------------------------------------------------------

    def _load_for_request(self, value: str | None) -> tuple[CookieSession, bool]:
        session = self.load(value)
        rewrite = False
        if session is None and value and self._legacy_loader is not None:
            session = self._legacy_loader(value)
            rewrite = session is not None
        if session is None:
            raise ReauthRequired("browser_session_missing", "no valid session cookie")
        if session.auth_expires_at is not None and session.auth_expires_at <= self._now():
            raise ReauthRequired("browser_session_expired", "browser sign-in has expired")
        return session, rewrite

    def _needs_refresh(self, session: CookieSession) -> bool:
        return session.expires_at - self._now() <= self._margin

    @staticmethod
    def _refreshed(session: CookieSession, fresh: BrowserSession) -> CookieSession:
        return replace(
            session,
            access_token=fresh.access_token,
            refresh_token=fresh.refresh_token,
            expires_at=fresh.expires_at,
            auth_expires_at=fresh.auth_expires_at or session.auth_expires_at,
        )

    def _resolution(
        self, context: AccessTokenContext, session: CookieSession, rewrite: bool
    ) -> CookieResolution:
        if context.subject_id != session.subject_id:
            raise ReauthRequired("browser_session_subject_changed", "cookie subject mismatch")
        return CookieResolution(context, session, self.encode(session) if rewrite else None)

    def _refresh_sync(self, session: CookieSession) -> BrowserSession:
        key = _flight_key(session.refresh_token)
        with self._lock:
            self._prune()
            entry = self._flights.get(key)
            owner = entry is None
            future: Future[BrowserSession] = Future() if entry is None else entry[1]
            if owner:
                self._flights[key] = (float("inf"), future)
        if owner:
            try:
                result = self._sso.refresh(
                    session.refresh_token, expected_subject_id=session.subject_id
                )
            except BaseException as exc:
                with self._lock:
                    self._flights.pop(key, None)
                future.set_exception(exc)
                raise
            with self._lock:
                # Keep the result briefly: requests still carrying the old cookie reuse it
                # instead of replaying the spent refresh token.
                self._flights[key] = (self._monotonic() + self._reuse, future)
            future.set_result(result)
        return future.result()

    async def _refresh_async(self, session: CookieSession) -> BrowserSession:
        key = _flight_key(session.refresh_token)
        with self._lock:
            self._prune()
            entry = self._async_flights.get(key)
            if entry is None:
                task = asyncio.ensure_future(
                    self._sso.refresh_async(
                        session.refresh_token, expected_subject_id=session.subject_id
                    )
                )
                self._async_flights[key] = (float("inf"), task)
                task.add_done_callback(lambda done: self._async_done(key, done))
            else:
                task = entry[1]
        return await asyncio.shield(task)

    def _async_done(self, key: str, task: asyncio.Future[BrowserSession]) -> None:
        with self._lock:
            if task.cancelled() or task.exception() is not None:
                self._async_flights.pop(key, None)
            else:
                self._async_flights[key] = (self._monotonic() + self._reuse, task)

    def _prune(self) -> None:
        now = self._monotonic()
        self._flights = {k: v for k, v in self._flights.items() if v[0] > now}
        self._async_flights = {k: v for k, v in self._async_flights.items() if v[0] > now}


def _fernet(context: str, secret: str) -> Fernet:
    digest = hashlib.sha256(context.encode("utf-8") + b"\0" + secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _flight_key(refresh_token: str) -> str:
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("expected a non-empty string")
    return value


def _integer(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("expected an integer")
    return value
