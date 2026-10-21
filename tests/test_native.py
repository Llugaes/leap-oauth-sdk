from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import jwt
import pytest

from leap_oauth_sdk import OAuthSDKError

from .conftest import SigningKey

VECTORS = json.loads(
    (Path(__file__).parents[1] / "testdata/feishu_native_v2_vectors.json").read_text(
        encoding="utf-8"
    )
)


@pytest.fixture
def vector_clock(monkeypatch):
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(VECTORS["now"], tz=tz or UTC)

    monkeypatch.setattr(jwt.api_jwt, "datetime", FixedDatetime)


def verify_vector(vector):
    from leap_oauth_sdk.native import verify_native_access_token

    key = SigningKey("native-vector-key")
    header = {**vector["header"], "typ": vector["header"].get("typ")}
    algorithm = header["alg"]
    token = jwt.encode(
        vector["claims"],
        "synthetic-long-hmac-secret-123456789" if algorithm == "HS256" else key.private_key,
        algorithm=algorithm,
        headers=header,
    )
    if vector.get("signature") == "tampered":
        parts = token.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        token = ".".join(parts)
    return verify_native_access_token(
        token,
        issuer=VECTORS["issuer"],
        audience=VECTORS["audience"],
        jwks={"keys": [key.jwk]},
        expected_feishu_tenant=VECTORS["expected_feishu_tenant"],
        required_purpose=vector.get("required_purpose", "access"),
        allowed_channels=VECTORS["allowed_channels"],
    )


@pytest.mark.parametrize("vector", VECTORS["token_vectors"], ids=lambda value: value["id"])
def test_shared_token_vectors(vector, vector_clock):
    if vector["accept"]:
        identity = verify_vector(vector)
        assert identity.person_key == vector["claims"]["sub"]
        assert identity.authorization_key == (VECTORS["issuer"], vector["claims"]["sub"])
        assert identity.display.name == vector["claims"]["person"]["name"]
        assert not hasattr(identity, "principal_type")
    else:
        with pytest.raises(OAuthSDKError):
            verify_vector(vector)


@pytest.mark.parametrize("vector", VECTORS["user_id_vectors"])
def test_exact_user_id_and_person_key_rules(vector):
    from leap_oauth_sdk.native import parse_person_key, valid_user_id

    assert valid_user_id(vector["value"]) is vector["valid"]
    key = "feishu:user_id:" + vector["value"]
    if vector["valid"]:
        assert parse_person_key(key) == vector["value"]
    else:
        with pytest.raises(ValueError):
            parse_person_key(key)


@pytest.mark.parametrize("vector", VECTORS["grant_vectors"], ids=lambda value: value["id"])
def test_grants_only_match_exact_person_and_optional_union_fingerprint(vector, vector_clock):
    from leap_oauth_sdk.native import grant_matches

    token_vector = copy.deepcopy(VECTORS["token_vectors"][0])
    token_vector["claims"]["sub"] = "feishu:user_id:" + vector["identity_user_id"]
    token_vector["claims"]["person"].update(
        user_id=vector["identity_user_id"], union_id=vector["identity_union_id"]
    )
    identity = verify_vector(token_vector)
    assert (
        grant_matches(vector["subject_ref"], vector["bound_union_id"], identity) is vector["match"]
    )


def test_native_configuration_never_inherits_v1_purpose_defaults():
    from leap_oauth_sdk.native import verify_native_access_token

    kwargs = dict(
        issuer=VECTORS["issuer"],
        audience=VECTORS["audience"],
        jwks={"keys": []},
        expected_feishu_tenant="tenant-test",
        required_purpose="access",
        allowed_channels=["feishu_oauth"],
    )
    with pytest.raises(TypeError):
        verify_native_access_token(
            "invalid", **{k: v for k, v in kwargs.items() if k != "required_purpose"}
        )
    for changes in (
        {"expected_feishu_tenant": ""},
        {"required_purpose": ""},
        {"leeway_seconds": 61},
    ):
        with pytest.raises(ValueError):
            verify_native_access_token("invalid", **{**kwargs, **changes})


def test_rsa_key_can_be_enabled_explicitly_and_other_algorithms_remain_rejected(vector_clock):
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

    from leap_oauth_sdk.native import verify_native_access_token

    private = generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public.update(kid="rsa-test", alg="RS256", use="sig")
    token = jwt.encode(
        VECTORS["base_claims"],
        private,
        algorithm="RS256",
        headers={"kid": "rsa-test", "typ": "at+jwt"},
    )
    kwargs = dict(
        issuer=VECTORS["issuer"],
        audience=VECTORS["audience"],
        jwks={"keys": [public]},
        expected_feishu_tenant=VECTORS["expected_feishu_tenant"],
        required_purpose="access",
        allowed_channels=["feishu_oauth"],
    )
    assert (
        verify_native_access_token(token, **kwargs, allowed_algorithms=("RS256",)).person_key
        == VECTORS["base_claims"]["sub"]
    )
    with pytest.raises(OAuthSDKError):
        verify_native_access_token(token, **kwargs, allowed_algorithms=("EdDSA",))
