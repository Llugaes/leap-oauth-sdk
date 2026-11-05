"""Platform Owner is a verified direct-user capability, never an identity lookup."""

import time

import pytest

from leap_oauth_sdk import LeapAuthConfig
from leap_oauth_sdk.native import NativeAccessTokenVerifier

from .conftest import AUDIENCE, ISSUER


def native(key, **changes):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "feishu:user_id:owner8",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": "synthetic-platform-owner",
        "ver": "sakamoto_feishu_access_token.v2",
        "feishu_tenant": "tenant-test",
        "person": {
            "user_id": "owner8",
            "union_id": None,
            "name": None,
            "email": None,
            "status": "active",
        },
        "client_id": "direct-user",
        "purpose": "access",
        "source": {"channel": "feishu_oauth"},
        "sakamoto_platform_owner": True,
    }
    claims.update(changes)
    verifier = NativeAccessTokenVerifier(
        LeapAuthConfig(issuer=ISSUER, audience=AUDIENCE),
        expected_feishu_tenant="tenant-test",
        required_purpose=claims["purpose"],
        allowed_channels=["feishu_oauth", "feishu_bot", "obo"],
        jwks={"keys": [key.jwk]},
    )
    return verifier, verifier.verify(key.sign(claims, typ="at+jwt"))


def test_signed_direct_user_owns_only_the_verifiers_resource(key):
    verifier, identity = native(key)
    assert verifier.is_platform_owner(identity)
    assert not verifier.is_platform_owner(dict(identity.raw_claims))
    other = NativeAccessTokenVerifier(
        LeapAuthConfig(issuer=ISSUER, audience="other-service"),
        expected_feishu_tenant="tenant-test",
        required_purpose="access",
        allowed_channels=["feishu_oauth"],
        jwks={"keys": [key.jwk]},
    )
    assert not other.is_platform_owner(identity)


@pytest.mark.parametrize("value", [None, False, 1, "true", {}, []])
def test_platform_owner_needs_exact_boolean_true(key, value):
    verifier, identity = native(key, sakamoto_platform_owner=value)
    assert not verifier.is_platform_owner(identity)


def test_platform_owner_does_not_apply_to_probe_or_stale_context(key, monkeypatch):
    verifier, probe = native(key, purpose="entitlement_probe")
    assert not verifier.is_platform_owner(probe)
    verifier, identity = native(key)
    monkeypatch.setattr("leap_oauth_sdk.native.time.time", lambda: identity.expires_at + 61)
    assert not verifier.is_platform_owner(identity)


@pytest.mark.parametrize(
    "channel,actor",
    [
        (
            "obo",
            {
                "type": "obo",
                "sub": "direct-user",
                "parent_aud": "hub",
                "parent_jti": "original-parent",
            },
        ),
        ("feishu_bot", {"type": "trusted_entry", "sub": "direct-user", "auth": "issue_token"}),
        ("feishu_oauth", {"type": "trusted_entry", "sub": "direct-user", "auth": "issue_token"}),
    ],
)
def test_delegated_or_bot_identity_does_not_become_owner_even_if_marked(key, channel, actor):
    verifier, identity = native(key, source={"channel": channel}, act=actor)
    assert not verifier.is_platform_owner(identity)


def test_owner_identity_cannot_cross_tenant_or_restricted_channel_verifier(key):
    _, identity = native(key)
    for tenant, channels in [("different-tenant", ["feishu_oauth"]), ("tenant-test", ["obo"])]:
        verifier = NativeAccessTokenVerifier(
            LeapAuthConfig(issuer=ISSUER, audience=AUDIENCE),
            expected_feishu_tenant=tenant,
            required_purpose="access",
            allowed_channels=channels,
            jwks={"keys": [key.jwk]},
        )
        assert not verifier.is_platform_owner(identity)
