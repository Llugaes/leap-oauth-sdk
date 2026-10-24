"""Explicit configuration. The SDK never reads environment variables or ships default hosts."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

STRICT_ACCESS_TOKEN_MAX_BYTES = 16 * 1024

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: Protocol identifier carried in the ``ver`` claim of every Leap Auth access token.
DEFAULT_TOKEN_VERSION = "sakamoto_access_token.v1"


@dataclass(frozen=True, slots=True)
class LeapAuthConfig:
    """Settings a business service passes in from its own configuration layer.

    ``issuer`` must match the ``iss`` claim exactly; it is not normalised.
    ``audience`` is this service's own audience. ``jwks_url`` defaults to
    ``{issuer}/.well-known/jwks.json``.
    """

    issuer: str
    audience: str
    jwks_url: str | None = None
    allowed_algorithms: tuple[str, ...] = ("EdDSA",)
    #: Accepted ``purpose`` claim values. A token without ``purpose`` is treated as ``access``.
    allowed_purposes: tuple[str, ...] = ("access",)
    token_version: str = DEFAULT_TOKEN_VERSION
    leeway_seconds: int = 30
    timeout_seconds: float = 10.0
    jwks_cache_seconds: int = 300
    #: Minimum interval between forced JWKS refetches triggered by an unknown ``kid``.
    jwks_refresh_cooldown_seconds: int = 10

    def __post_init__(self) -> None:
        issuer = self.issuer.strip()
        audience = self.audience.strip()
        if not issuer:
            raise ValueError("issuer is required")
        if not audience:
            raise ValueError("audience is required")
        _require_http_url(issuer, "issuer")
        if self.jwks_url is not None:
            _require_http_url(self.jwks_url.strip(), "jwks_url")
        if not self.allowed_algorithms:
            raise ValueError("allowed_algorithms must not be empty")
        if any(alg.upper().startswith("HS") or alg == "none" for alg in self.allowed_algorithms):
            raise ValueError("symmetric or unsigned algorithms are not allowed")
        if not self.allowed_purposes:
            raise ValueError("allowed_purposes must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not 0 <= self.leeway_seconds <= 300:
            raise ValueError("leeway_seconds must be between 0 and 300")
        if self.jwks_cache_seconds < 1:
            raise ValueError("jwks_cache_seconds must be at least 1")
        if self.jwks_refresh_cooldown_seconds < 0:
            raise ValueError("jwks_refresh_cooldown_seconds must not be negative")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "audience", audience)

    @property
    def resolved_jwks_url(self) -> str:
        if self.jwks_url:
            return self.jwks_url.strip()
        return self.issuer.rstrip("/") + "/.well-known/jwks.json"


@dataclass(frozen=True, slots=True)
class BrowserClientConfig:
    """Registration of one browser sign-in client (one per service and environment).

    ``redirect_uri`` and ``resource`` must match the registration exactly. ``api_base_url`` is
    where this service calls the authorization server from the backend; it defaults to the
    public ``issuer`` and only differs when an internal address is available. Browsers are
    always sent to ``issuer``.
    """

    client_id: str
    redirect_uri: str
    resource: str
    api_base_url: str | None = None

    def __post_init__(self) -> None:
        client_id = self.client_id.strip()
        if not client_id:
            raise ValueError("client_id is required")
        _require_http_url(self.redirect_uri, "redirect_uri")
        parts = urlsplit(self.redirect_uri)
        if parts.scheme != "https" and parts.hostname not in _LOOPBACK_HOSTS:
            raise ValueError("redirect_uri must use https outside loopback development")
        _require_http_url(self.resource, "resource")
        if self.api_base_url is not None:
            _require_http_url(self.api_base_url.strip(), "api_base_url")
        object.__setattr__(self, "client_id", client_id)

    @property
    def redirect_path(self) -> str:
        return urlsplit(self.redirect_uri).path or "/"


def _require_http_url(value: str, name: str) -> None:
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError(f"{name} must be an http(s) URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(f"{name} must not contain credentials, query or fragment")
