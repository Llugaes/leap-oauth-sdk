"""Business-side SDK for services that accept Leap Auth OAuth access tokens."""

from pathlib import Path

from .browser import (
    ROTATION_IN_PROGRESS,
    AuthorizationRequest,
    BrowserSession,
    BrowserSSO,
    LogoutScope,
    classify_response,
)
from .config import DEFAULT_TOKEN_VERSION, BrowserClientConfig, LeapAuthConfig
from .cookie_session import (
    CookieCipher,
    CookieResolution,
    CookieSession,
    CookieSessionManager,
)
from .errors import Forbidden, InvalidResponse, OAuthSDKError, ReauthRequired, Retryable
from .tokens import AccessTokenContext, AccessTokenVerifier

__version__ = "0.1.0"


def static_dir() -> Path:
    """Directory holding ``leap-sso.js``; mount it as static files in your web framework."""
    return Path(__file__).with_name("static")


__all__ = [
    "DEFAULT_TOKEN_VERSION",
    "ROTATION_IN_PROGRESS",
    "AccessTokenContext",
    "AccessTokenVerifier",
    "AuthorizationRequest",
    "BrowserClientConfig",
    "BrowserSSO",
    "BrowserSession",
    "CookieCipher",
    "CookieResolution",
    "CookieSession",
    "CookieSessionManager",
    "Forbidden",
    "InvalidResponse",
    "LeapAuthConfig",
    "LogoutScope",
    "OAuthSDKError",
    "ReauthRequired",
    "Retryable",
    "__version__",
    "classify_response",
    "static_dir",
]
