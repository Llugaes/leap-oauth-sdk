"""Owner installation eligibility never becomes delegated business access."""

import time

import pytest

from leap_oauth_sdk import LeapAuthConfig
from leap_oauth_sdk.native import NativeAccessTokenVerifier

from .conftest import AUDIENCE, ISSUER
from .test_platform_owner import native


def probe(key, **changes):
    verifier, identity = native(
        key,
        purpose="entitlement_probe",
        source={"channel": "obo"},
        act={"type": "obo", "sub": "direct-user", "parent_aud": "hub", "parent_jti": "parent"},
    )
    claims = dict(identity.raw_claims)
    claims.pop("sakamoto_platform_owner")
    claims["sakamoto_platform_owner_probe"] = True
    claims.update(changes)
    return verifier, verifier.verify(key.sign(claims, typ="at+jwt"))


def test_signed_owner_probe_is_only_installation_eligibility(key):
    verifier, identity = probe(key)
    assert verifier.is_platform_owner_probe(identity)
    assert not verifier.is_platform_owner(identity)
    assert not verifier.is_platform_owner_probe(dict(identity.raw_claims))


@pytest.mark.parametrize("value", [None, False, 1, "true", {}, []])
def test_owner_probe_requires_exact_boolean_true(key, value):
    verifier, identity = probe(key, sakamoto_platform_owner_probe=value)
    assert not verifier.is_platform_owner_probe(identity)


@pytest.mark.parametrize(
    "changes",
    [
        {"sakamoto_platform_owner": True},
        {"sakamoto_platform_owner": False},
        {"source": {"channel": "feishu_oauth"}},
        {
            "source": {"channel": "feishu_bot"},
            "act": {"type": "trusted_entry", "sub": "direct-user", "auth": "issue_token"},
        },
        {
            "act": {
                "type": "obo",
                "sub": "direct-user",
                "parent_aud": "hub",
                "parent_jti": "parent",
                "act": {"type": "trusted_entry", "sub": "bot", "auth": "issue_token"},
            }
        },
    ],
)
def test_access_owner_or_bot_provenance_cannot_grant_owner_probe(key, changes):
    verifier, identity = probe(key, **changes)
    assert not verifier.is_platform_owner_probe(identity)


def test_owner_probe_cannot_cross_verifier_namespace_or_purpose(key):
    _, identity = probe(key)
    for issuer, audience, tenant, purpose, channels in [
        ("https://other.test", AUDIENCE, "tenant-test", "entitlement_probe", ["obo"]),
        (ISSUER, "other", "tenant-test", "entitlement_probe", ["obo"]),
        (ISSUER, AUDIENCE, "other", "entitlement_probe", ["obo"]),
        (ISSUER, AUDIENCE, "tenant-test", "access", ["obo"]),
        (ISSUER, AUDIENCE, "tenant-test", "entitlement_probe", ["feishu_oauth"]),
    ]:
        verifier = NativeAccessTokenVerifier(
            LeapAuthConfig(issuer=issuer, audience=audience),
            expected_feishu_tenant=tenant,
            required_purpose=purpose,
            allowed_channels=channels,
            jwks={"keys": [key.jwk]},
        )
        assert not verifier.is_platform_owner_probe(identity)
    direct, access = native(key, sakamoto_platform_owner_probe=True)
    assert not direct.is_platform_owner_probe(access)


def test_owner_probe_expiry_does_not_survive_cached_context(key, monkeypatch):
    verifier, identity = probe(key)
    assert verifier.is_platform_owner_probe(identity)
    monkeypatch.setattr(time, "time", lambda: identity.expires_at + 61)
    assert not verifier.is_platform_owner_probe(identity)
