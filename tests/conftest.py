from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from leap_oauth_sdk import AccessTokenVerifier, BrowserClientConfig, BrowserSSO, LeapAuthConfig

ISSUER = "https://auth.example.com"
AUDIENCE = "example-service"
JWKS_URL = ISSUER + "/.well-known/jwks.json"


class SigningKey:
    def __init__(self, kid: str) -> None:
        self.kid = kid
        self.private_key = Ed25519PrivateKey.generate()
        public = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(self.private_key.public_key()))
        self.jwk: dict[str, Any] = {**public, "kid": kid, "alg": "EdDSA", "use": "sig"}

    def sign(self, claims: dict[str, Any], **header: Any) -> str:
        return jwt.encode(
            claims, self.private_key, algorithm="EdDSA", headers={"kid": self.kid, **header}
        )


@pytest.fixture
def key() -> SigningKey:
    return SigningKey("test-2026")


@pytest.fixture
def config() -> LeapAuthConfig:
    return LeapAuthConfig(issuer=ISSUER, audience=AUDIENCE)


@pytest.fixture
def claims() -> Callable[..., dict[str, Any]]:
    def build(**overrides: Any) -> dict[str, Any]:
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": ISSUER,
            "sub": "usr_1",
            "aud": AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": "jti-1",
            "ver": "sakamoto_access_token.v1",
            "status": "active",
            "principal_type": "human",
            "source": {"channel": "feishu_oauth"},
            "email": "user@example.com",
            "display_name": "User One",
        }
        payload.update(overrides)
        return {name: value for name, value in payload.items() if value is not None}

    return build


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


TOKEN_URL = ISSUER + "/api/oauth/token"
SESSION_URL = ISSUER + "/api/identity/browser/session"
LOGOUT_URL = ISSUER + "/api/identity/browser/logout"


@pytest.fixture
def browser_client() -> BrowserClientConfig:
    return BrowserClientConfig(
        client_id="web-example",
        redirect_uri="https://app.example.com/auth/callback",
        resource="https://app.example.com/",
    )


@pytest.fixture
def sso(config: LeapAuthConfig, browser_client: BrowserClientConfig, key: SigningKey) -> BrowserSSO:
    verifier = AccessTokenVerifier(config, jwks={"keys": [key.jwk]})
    return BrowserSSO(config, browser_client, verifier)


@pytest.fixture
def token_response(
    key: SigningKey, claims: Callable[..., dict[str, Any]]
) -> Callable[..., dict[str, Any]]:
    def build(refresh_token: str = "rt-1", **overrides: Any) -> dict[str, Any]:
        payload = claims(**{"browser_sid": "bsid-1", **overrides})
        return {
            "access_token": key.sign(payload),
            "token_type": "Bearer",
            "expires_in": payload.get("exp", 0) - int(time.time()),
            "refresh_token": refresh_token,
            "auth_expires_at": int(time.time()) + 3600,
            "scope": "",
        }

    return build
