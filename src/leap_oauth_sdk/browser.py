"""Server side of browser sign-in: code exchange, refresh, online session check and logout.

The browser runs authorization code + PKCE with a top-level redirect (see ``leap-sso.js``)
and hands the code to this service; tokens are exchanged backend-to-backend and never put in
URLs. Every call is classified into the four error categories of :mod:`leap_oauth_sdk.errors`.
Blocking and ``async`` variants are provided.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Literal, cast
from urllib.parse import urlencode

import httpx

from .config import BrowserClientConfig, LeapAuthConfig
from .errors import Forbidden, InvalidResponse, OAuthSDKError, ReauthRequired, Retryable
from .tokens import AccessTokenContext, AccessTokenVerifier

LogoutScope = Literal["browser", "current"]

AUTHORIZE_PATH = "/api/oauth/authorize"
TOKEN_PATH = "/api/oauth/token"
SESSION_PATH = "/api/identity/browser/session"
LOGOUT_PATH = "/api/identity/browser/logout"

#: ``error_description`` returned while a concurrent refresh of the same credential is
#: finishing. The credential is still valid; the caller should retry, not sign in again.
ROTATION_IN_PROGRESS = "refresh_rotation_in_progress"

_MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """Authorization redirect prepared on the server (cookie-mode services)."""

    url: str
    state: str
    code_verifier: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class BrowserSession:
    """Tokens of one browser sign-in, already verified."""

    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    #: Access token expiry, epoch seconds.
    expires_at: int
    #: Root sign-in expiry, epoch seconds. Refreshing never extends past it.
    auth_expires_at: int | None
    context: AccessTokenContext

    @property
    def subject_id(self) -> str:
        return self.context.subject_id

    def to_browser_payload(self) -> dict[str, Any]:
        """Response body for ``{endpoint}/exchange`` and ``/refresh`` in bearer mode."""
        return {
            "access_token": self.access_token,
            "token_type": "Bearer",
            "expires_at": self.expires_at,
            "refresh_token": self.refresh_token,
        }


class BrowserSSO:
    """Backend calls for one registered browser client."""

    def __init__(
        self,
        config: LeapAuthConfig,
        client: BrowserClientConfig,
        verifier: AccessTokenVerifier | None = None,
        *,
        http_client: httpx.Client | None = None,
        async_http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if verifier is not None and verifier.config.audience != config.audience:
            raise ValueError("verifier audience does not match config audience")
        self._config = config
        self._client = client
        self._verifier = verifier or AccessTokenVerifier(config)
        self._http_client = http_client
        self._async_http_client = async_http_client
        self._api_base = (client.api_base_url or config.issuer).strip().rstrip("/")

    @property
    def config(self) -> LeapAuthConfig:
        return self._config

    @property
    def client(self) -> BrowserClientConfig:
        return self._client

    @property
    def verifier(self) -> AccessTokenVerifier:
        return self._verifier

    @property
    def authorization_endpoint(self) -> str:
        return self._config.issuer.rstrip("/") + AUTHORIZE_PATH

    def browser_config(self) -> dict[str, Any]:
        """Response body for ``{endpoint}/config``; contains no secrets."""
        return {
            "enabled": True,
            "issuer": self._config.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "client_id": self._client.client_id,
            "redirect_uri": self._client.redirect_uri,
            "resource": self._client.resource,
        }

    def authorization_url(self, *, state: str, code_challenge: str, explicit: bool = False) -> str:
        """Top-level redirect target. ``explicit`` lets the user sign in interactively; an
        automatic attempt only reuses an existing sign-in."""
        params = {
            "response_type": "code",
            "client_id": self._client.client_id,
            "redirect_uri": self._client.redirect_uri,
            "resource": self._client.resource,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        if explicit:
            params["allow_login"] = "1"
        return self.authorization_endpoint + "?" + urlencode(params)

    def start_authorization(self, *, explicit: bool = False) -> AuthorizationRequest:
        """Generate state and PKCE on the server. Keep ``state`` and ``code_verifier`` in an
        encrypted, short-lived cookie until the callback."""
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        url = self.authorization_url(state=state, code_challenge=challenge, explicit=explicit)
        return AuthorizationRequest(url=url, state=state, code_verifier=verifier)

    # -- token endpoint ----------------------------------------------------------------

    def exchange_code(self, code: str, code_verifier: str) -> BrowserSession:
        payload = self._token_payload(self._send_sync(self._code_request(code, code_verifier)))
        return self._session(payload, self._verifier.verify(payload["access_token"]), None)

    async def exchange_code_async(self, code: str, code_verifier: str) -> BrowserSession:
        response = await self._send_async(self._code_request(code, code_verifier))
        payload = self._token_payload(response)
        context = await self._verifier.verify_async(payload["access_token"])
        return self._session(payload, context, None)

    def refresh(
        self, refresh_token: str, *, expected_subject_id: str | None = None
    ) -> BrowserSession:
        """Rotate the refresh credential. The old ``refresh_token`` is spent afterwards."""
        payload = self._token_payload(self._send_sync(self._refresh_request(refresh_token)))
        context = self._verifier.verify(payload["access_token"])
        return self._session(payload, context, expected_subject_id)

    async def refresh_async(
        self, refresh_token: str, *, expected_subject_id: str | None = None
    ) -> BrowserSession:
        response = await self._send_async(self._refresh_request(refresh_token))
        payload = self._token_payload(response)
        context = await self._verifier.verify_async(payload["access_token"])
        return self._session(payload, context, expected_subject_id)

    # -- online session check and logout -----------------------------------------------

    def check_session(
        self, access_token: str, *, verified: AccessTokenContext | None = None
    ) -> AccessTokenContext:
        """Verify locally, then ask the server whether the sign-in is still live.

        Call on every protected request and do not cache the result, so that a logout
        elsewhere takes effect on the next request. Pass ``verified`` when the same token was
        just verified with this service's verifier, to skip verifying it twice.
        """
        context = _require_browser_binding(verified or self._verifier.verify(access_token))
        response = self._send_sync(self._bearer_request(SESSION_PATH, access_token, None))
        return self._session_result(response, context)

    async def check_session_async(
        self, access_token: str, *, verified: AccessTokenContext | None = None
    ) -> AccessTokenContext:
        context = _require_browser_binding(
            verified or await self._verifier.verify_async(access_token)
        )
        response = await self._send_async(self._bearer_request(SESSION_PATH, access_token, None))
        return self._session_result(response, context)

    def logout(self, access_token: str, scope: LogoutScope = "browser") -> None:
        """``browser`` ends the sign-in for every service in this browser; ``current`` only
        ends this service's refresh chain. An already-ended sign-in counts as success."""
        _logout_result(self._send_sync(self._logout_request(access_token, scope)))

    async def logout_async(self, access_token: str, scope: LogoutScope = "browser") -> None:
        _logout_result(await self._send_async(self._logout_request(access_token, scope)))

    # -- requests ----------------------------------------------------------------------

    def _code_request(self, code: str, code_verifier: str) -> _Request:
        if not code or not code_verifier:
            raise ReauthRequired("browser_callback_invalid", "authorization code is missing")
        return _Request(
            TOKEN_PATH,
            form={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": code_verifier,
                "client_id": self._client.client_id,
                "redirect_uri": self._client.redirect_uri,
                "resource": self._client.resource,
            },
        )

    def _refresh_request(self, refresh_token: str) -> _Request:
        if not refresh_token:
            raise ReauthRequired("browser_session_invalid", "refresh token is missing")
        return _Request(
            TOKEN_PATH,
            form={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self._client.client_id,
                "resource": self._client.resource,
            },
        )

    def _logout_request(self, access_token: str, scope: str) -> _Request:
        if scope not in ("browser", "current"):
            raise ValueError("scope must be 'browser' or 'current'")
        return self._bearer_request(LOGOUT_PATH, access_token, {"scope": scope})

    @staticmethod
    def _bearer_request(path: str, access_token: str, body: dict[str, Any] | None) -> _Request:
        if not access_token:
            raise ReauthRequired("browser_session_invalid", "access token is missing")
        return _Request(path, json_body=body or {}, bearer=access_token)

    def _send_sync(self, request: _Request) -> httpx.Response:
        try:
            if self._http_client is not None:
                return self._http_client.post(self._api_base + request.path, **request.options())
            with httpx.Client(timeout=self._config.timeout_seconds) as client:
                return client.post(self._api_base + request.path, **request.options())
        except httpx.HTTPError as exc:
            raise _unavailable() from exc

    async def _send_async(self, request: _Request) -> httpx.Response:
        try:
            if self._async_http_client is not None:
                return await self._async_http_client.post(
                    self._api_base + request.path, **request.options()
                )
            async with httpx.AsyncClient(timeout=self._config.timeout_seconds) as client:
                return await client.post(self._api_base + request.path, **request.options())
        except httpx.HTTPError as exc:
            raise _unavailable() from exc

    # -- responses ---------------------------------------------------------------------

    @staticmethod
    def _token_payload(response: httpx.Response) -> dict[str, Any]:
        error = classify_response(response, rejected="browser_session_invalid")
        if error is not None:
            raise error
        payload = _json_object(response)
        if payload is None:
            raise InvalidResponse("auth_response_invalid", "token response is not a JSON object")
        token_type = payload.get("token_type", "Bearer")
        if (
            not _non_empty(payload.get("access_token"))
            or not _non_empty(payload.get("refresh_token"))
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
        ):
            raise InvalidResponse("auth_response_invalid", "token response is missing tokens")
        return payload

    @staticmethod
    def _session(
        payload: dict[str, Any], context: AccessTokenContext, expected_subject_id: str | None
    ) -> BrowserSession:
        _require_browser_binding(context, missing=InvalidResponse)
        if expected_subject_id is not None and context.subject_id != expected_subject_id:
            raise ReauthRequired(
                "browser_session_subject_changed", "refreshed token belongs to another subject"
            )
        auth_expires_at = payload.get("auth_expires_at")
        if isinstance(auth_expires_at, bool) or not isinstance(auth_expires_at, int):
            auth_expires_at = None
        return BrowserSession(
            access_token=payload["access_token"],
            refresh_token=payload["refresh_token"],
            expires_at=context.expires_at,
            auth_expires_at=auth_expires_at,
            context=context,
        )

    def _session_result(
        self, response: httpx.Response, context: AccessTokenContext
    ) -> AccessTokenContext:
        error = classify_response(response, rejected="browser_session_revoked")
        if error is not None:
            raise error
        payload = _json_object(response) or {}
        if payload.get("active") is not True:
            raise ReauthRequired("browser_session_revoked", "browser sign-in is no longer active")
        if (
            payload.get("subject_id") != context.subject_id
            or payload.get("audience") != self._config.audience
        ):
            raise InvalidResponse(
                "browser_session_mismatch", "session check returned another identity"
            )
        return context


def classify_response(response: httpx.Response, *, rejected: str) -> OAuthSDKError | None:
    """Map a non-2xx authorization server response to an error category.

    ``rejected`` is the ``code`` used when the credential itself was refused (401 or
    ``invalid_grant``). Returns ``None`` for 2xx.
    """
    status = response.status_code
    if 200 <= status < 300:
        return None
    payload = _json_object(response) or {}
    error = payload.get("error")
    if error == "temporarily_unavailable":
        if payload.get("error_description") == ROTATION_IN_PROGRESS:
            return Retryable(ROTATION_IN_PROGRESS, "a concurrent refresh is finishing; retry")
        return Retryable("auth_temporarily_unavailable", "authorization server asked to retry")
    if status == 429 or status >= 500:
        return _unavailable()
    if 300 <= status < 400:
        return InvalidResponse("auth_upstream_redirect", "authorization server redirected")
    if status == 401 or error == "invalid_grant":
        return ReauthRequired(rejected, "credential was rejected; sign in again")
    if status == 403:
        return Forbidden("auth_access_denied", "access denied by the authorization server")
    return InvalidResponse("auth_request_rejected", f"authorization server returned {status}")


@dataclass(frozen=True, slots=True)
class _Request:
    path: str
    form: dict[str, str] | None = None
    json_body: dict[str, Any] | None = None
    bearer: str | None = field(default=None, repr=False)

    def options(self) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self.bearer:
            headers["Authorization"] = "Bearer " + self.bearer
        options: dict[str, Any] = {"headers": headers, "follow_redirects": False}
        if self.form is not None:
            options["data"] = self.form
        else:
            options["json"] = self.json_body or {}
        return options


def _logout_result(response: httpx.Response) -> None:
    if response.status_code == 401:
        return  # the sign-in is already gone
    error = classify_response(response, rejected="browser_session_revoked")
    if error is not None:
        raise error


def _require_browser_binding(
    context: AccessTokenContext, *, missing: type[OAuthSDKError] = ReauthRequired
) -> AccessTokenContext:
    if context.browser_session_id is None:
        raise missing("browser_session_unbound", "token is not bound to a browser sign-in")
    return context


def _json_object(response: httpx.Response) -> dict[str, Any] | None:
    if len(response.content) > _MAX_RESPONSE_BYTES:
        return None
    try:
        payload: Any = json.loads(response.content)
    except ValueError:
        return None
    return cast(dict[str, Any], payload) if isinstance(payload, dict) else None


def _non_empty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _unavailable() -> Retryable:
    return Retryable("auth_upstream_unavailable", "authorization server is unavailable")
