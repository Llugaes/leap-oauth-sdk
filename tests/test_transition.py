from __future__ import annotations

import base64
import copy
import json
from dataclasses import replace

import pytest

from leap_oauth_sdk import Forbidden, OAuthSDKError

from .conftest import ISSUER

PERSON = "feishu:user_id:Exact-User"


def mapping(values=None, **kw):
    from leap_oauth_sdk.transition import MigrationIdentityMap

    return MigrationIdentityMap(
        issuer=ISSUER,
        feishu_tenant="tenant-1",
        revision="mapping-1",
        legacy_to_person={"usr_1": PERSON} if values is None else values,
        **kw,
    )


def verifier(config, key, **kw):
    from leap_oauth_sdk.transition import TransitionAccessTokenVerifier

    return TransitionAccessTokenVerifier(
        config,
        identity_map=mapping(),
        required_purpose="access",
        allowed_channels=("feishu_oauth",),
        jwks={"keys": [key.jwk]},
        **kw,
    )


def native_claims(claims):
    old = claims()
    return {
        **{k: old[k] for k in ("iss", "aud", "iat", "nbf", "exp", "jti")},
        "sub": PERSON,
        "ver": "sakamoto_feishu_access_token.v2",
        "person": {
            "user_id": "Exact-User",
            "union_id": "union-1",
            "status": "unknown",
            "name": "User",
            "email": "same@example.com",
        },
        "client_id": "client-1",
        "purpose": "access",
        "feishu_tenant": "tenant-1",
        "source": {"channel": "feishu_oauth"},
    }


def test_both_verified_profiles_have_one_key_without_fabricating_native_claims(config, key, claims):
    check = verifier(config, key)
    old_claims = claims()
    old = check.verify(key.sign(old_claims))
    new_claims = native_claims(claims)
    new = check.verify(key.sign(new_claims, typ="at+jwt"))
    assert old.authorization_key == new.authorization_key == (ISSUER, PERSON)
    assert old.subject_id == new.subject_id == PERSON
    assert old.wire_subject == "usr_1"
    assert new.wire_subject == PERSON
    assert old.profile == "principal_v1"
    assert new.profile == "feishu_native_v2"
    assert old.mapping_revision == new.mapping_revision == "mapping-1"
    assert dict(old.raw_claims) == old_claims
    assert "person" not in old.raw_claims
    assert dict(new.raw_claims) == new_claims


def test_single_storage_format_uses_exact_reverse_map_and_never_falls_back():
    ids = mapping()
    assert ids.storage_subject(PERSON, "principal_v1") == "usr_1"
    assert ids.storage_subject(PERSON, "feishu_native_v2") == PERSON
    with pytest.raises(Forbidden):
        ids.storage_subject("feishu:user_id:exact-user", "principal_v1")
    with pytest.raises(ValueError):
        ids.storage_subject(PERSON, "both")
    with pytest.raises(Forbidden):
        ids.person_key("usr_1 ")
    with pytest.raises(Forbidden):
        ids.person_key("USR_1")


@pytest.mark.parametrize(
    "values",
    [
        {"usr_1": PERSON, "usr_2": PERSON},
        {"usr_1 ": PERSON},
        {"machine_1": PERSON},
        {"usr_1": "same@example.com"},
        {"usr_1": "feishu:user_id: Exact-User"},
    ],
)
def test_mapping_rejects_ambiguous_or_noncanonical_input(values):
    with pytest.raises(ValueError):
        mapping(values)


def test_mapping_and_verified_claims_are_detached_from_mutable_inputs(config, key, claims):
    values = {"usr_1": PERSON}
    ids = mapping(values)
    values["usr_1"] = "feishu:user_id:other"
    assert ids.person_key("usr_1") == PERSON
    with pytest.raises(TypeError):
        ids.legacy_to_person["usr_1"] = "feishu:user_id:other"
    result = verifier(config, key).verify(key.sign(claims()))
    with pytest.raises(TypeError):
        result.raw_claims["sub"] = "usr_2"


@pytest.mark.parametrize(
    "change",
    [
        {"sub": "usr_unknown"},
        {"sub": PERSON},
        {"principal_type": "service"},
        {"principal_type": None},
        {"status": "disabled"},
        {"purpose": "entitlement_probe"},
        {"source": {"channel": "feishu_bot"}},
        {"source": {"channel": []}},
        {"iss": "https://another.example.com"},
        {"aud": "another-service"},
        {"ver": "unknown"},
        {"person": {"user_id": "Exact-User"}},
    ],
)
def test_legacy_rejects_invalid_profile_and_cannot_authorize_by_display(
    config, key, claims, change
):
    with pytest.raises(OAuthSDKError):
        verifier(config, key).verify(key.sign(claims(**change)))


@pytest.mark.parametrize(
    "change",
    [
        {"feishu_tenant": "another-tenant"},
        {"purpose": "entitlement_probe"},
        {"person": {"user_id": "Exact-User"}},
        {"status": "active"},
        {"aud": "another-service"},
        {"iss": "https://another.example.com"},
    ],
)
def test_native_rejection_never_retries_legacy(config, key, claims, change, monkeypatch):
    check = verifier(config, key)
    payload = {**native_claims(claims), **copy.deepcopy(change)}

    def forbidden_retry(*a, **kw):
        pytest.fail("native failure must not retry the legacy verifier")

    monkeypatch.setattr(check._legacy, "verify_claims", forbidden_retry)
    with pytest.raises(OAuthSDKError):
        check.verify(key.sign(payload, typ="at+jwt"))


def test_signature_and_profile_header_are_checked(config, key, claims):
    from .conftest import SigningKey

    wrong_key = SigningKey(key.kid)
    check = verifier(config, key)
    for token in (
        wrong_key.sign(claims()),
        wrong_key.sign(native_claims(claims), typ="at+jwt"),
        key.sign(native_claims(claims), typ="JWT"),
        key.sign(claims(), typ="at+jwt"),
        "not-a-jwt",
        "x" * 16385,
    ):
        with pytest.raises(OAuthSDKError):
            check.verify(token)


def test_mapping_namespace_and_purpose_configuration_are_explicit(config, key):
    from leap_oauth_sdk.transition import TransitionAccessTokenVerifier

    with pytest.raises(ValueError):
        TransitionAccessTokenVerifier(
            replace(config, issuer="https://another.example.com"),
            identity_map=mapping(),
            required_purpose="access",
            allowed_channels=("feishu_oauth",),
        )
    with pytest.raises(ValueError):
        verifier(replace(config, token_version="custom-v1"), key)


@pytest.mark.asyncio
async def test_async_verification_preserves_the_same_key(config, key, claims):
    check = verifier(config, key)
    old = await check.verify_async(key.sign(claims()))
    new = await check.verify_async(key.sign(native_claims(claims), typ="at+jwt"))
    assert old.authorization_key == new.authorization_key == (ISSUER, PERSON)


def test_legacy_compatible_registered_claims_are_not_fabricated(config, key, claims):
    payload = claims(nbf=None, jti=None)
    result = verifier(config, key).verify(key.sign(payload))
    assert result.subject_id == PERSON
    assert "nbf" not in result.raw_claims
    assert "jti" not in result.raw_claims


def test_legacy_compatible_size_policy_does_not_break_existing_valid_tickets(config, key, claims):
    payload = claims(display_name="x" * 17000)
    result = verifier(config, key).verify(key.sign(payload))
    assert result.subject_id == PERSON
    assert result.raw_claims["display_name"] == payload["display_name"]


def test_expired_tokens_and_invalid_unicode_are_credential_errors(config, key, claims):
    payload = native_claims(claims)
    payload["exp"] = 1
    for token in (key.sign(claims(exp=1)), key.sign(payload, typ="at+jwt"), "\ud800"):
        with pytest.raises(OAuthSDKError):
            verifier(config, key).verify(token)


def test_large_native_and_malformed_header_are_rejected_before_jwt_parses_full_token(
    config, key, monkeypatch
):
    header = base64.urlsafe_b64encode(json.dumps({"typ": "at+jwt"}).encode()).rstrip(b"=").decode()
    check = verifier(config, key)

    def must_not_parse(*a, **kw):
        pytest.fail("large original token reached PyJWT before the size check")

    monkeypatch.setattr("jwt.get_unverified_header", must_not_parse)
    for token in (
        header + "." + "e" * (1024 * 1024) + ".signature",
        "e" * (1024 * 1024) + ".",
        base64.urlsafe_b64encode(b"[" * 3000).decode() + ".e30.signature",
    ):
        with pytest.raises(OAuthSDKError):
            check.verify(token)


@pytest.mark.parametrize("change", [{"sub": None}, {"exp": None}, {"exp": "not-a-time"}])
def test_compatible_verifier_requires_sub_and_exp_before_identity_mapping(
    config, key, claims, change, monkeypatch
):
    check = verifier(config, key)

    def no_identity(*a, **kw):
        pytest.fail("invalid registered claims reached the identity mapping")

    monkeypatch.setattr(check, "_legacy_identity", no_identity)
    with pytest.raises(OAuthSDKError):
        check.verify(key.sign(claims(**change)))
