from __future__ import annotations

import pytest

from leap_oauth_sdk import LeapAuthConfig


def test_jwks_url_defaults_to_issuer_well_known() -> None:
    config = LeapAuthConfig(issuer=" https://auth.example.com ", audience=" svc ")
    assert config.issuer == "https://auth.example.com"
    assert config.audience == "svc"
    assert config.resolved_jwks_url == "https://auth.example.com/.well-known/jwks.json"
    assert config.allowed_algorithms == ("EdDSA",)


def test_explicit_jwks_url_is_used() -> None:
    config = LeapAuthConfig(
        issuer="https://auth.example.com", audience="svc", jwks_url="http://127.0.0.1:8080/jwks"
    )
    assert config.resolved_jwks_url == "http://127.0.0.1:8080/jwks"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": "", "audience": "svc"},
        {"issuer": "https://auth.example.com", "audience": ""},
        {"issuer": "auth.example.com", "audience": "svc"},
        {"issuer": "https://user:pw@auth.example.com", "audience": "svc"},
        {"issuer": "https://auth.example.com", "audience": "svc", "jwks_url": "ftp://x/jwks"},
        {"issuer": "https://auth.example.com", "audience": "svc", "allowed_algorithms": ("HS256",)},
        {"issuer": "https://auth.example.com", "audience": "svc", "allowed_algorithms": ("none",)},
        {"issuer": "https://auth.example.com", "audience": "svc", "allowed_algorithms": ()},
        {"issuer": "https://auth.example.com", "audience": "svc", "timeout_seconds": 0},
        {"issuer": "https://auth.example.com", "audience": "svc", "leeway_seconds": 301},
    ],
)
def test_invalid_config_is_rejected(kwargs) -> None:
    with pytest.raises(ValueError):
        LeapAuthConfig(**kwargs)
