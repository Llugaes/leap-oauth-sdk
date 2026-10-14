"""Error taxonomy shared by every SDK call.

Callers only need to handle four categories. Each carries a stable ``code`` for logs and
API responses, and a suggested local HTTP ``status``. Messages never contain tokens,
response bodies or other credential material.
"""

from __future__ import annotations


class OAuthSDKError(Exception):
    """Base class. Prefer catching one of the four categories below."""

    status: int = 500
    retryable: bool = False

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"

    def to_dict(self) -> dict[str, str | bool]:
        """JSON body for the service's own error response; read by ``leap-sso.js``."""
        return {"error": self.code, "message": self.message, "retryable": self.retryable}

    @property
    def headers(self) -> dict[str, str]:
        """Suggested response headers (``Retry-After`` for retryable errors)."""
        return {"Retry-After": "1"} if self.retryable else {}


class Retryable(OAuthSDKError):
    """Temporary upstream condition: keep credentials and retry later (HTTP 503)."""

    status = 503
    retryable = True


class ReauthRequired(OAuthSDKError):
    """Credentials are invalid, expired or revoked: clear them and sign in again (HTTP 401)."""

    status = 401


class Forbidden(OAuthSDKError):
    """Identity is known but not allowed here: show a permission error, not a re-login (403)."""

    status = 403


class InvalidResponse(OAuthSDKError):
    """Upstream answered with an unexpected shape, or the SDK is misconfigured (HTTP 502)."""

    status = 502
