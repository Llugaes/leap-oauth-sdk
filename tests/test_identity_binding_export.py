"""C-X component verifier; shared bytes come from the actual AS producer."""

from __future__ import annotations

import ast
import gzip
import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
import respx


def stream_response(status: int, body: bytes = b"", **kwargs: Any) -> httpx.Response:
    return httpx.Response(status, stream=httpx.ByteStream(body), **kwargs)


def test_public_cx_module_and_six_exports() -> None:
    import leap_oauth_sdk as sdk
    from leap_oauth_sdk import identity_binding_export as module

    names = {
        "EXPORT_TYP",
        "EXPORT_VER",
        "EXPORT_MAX_ITEMS",
        "IdentityBindingExportRejected",
        "VerifiedExport",
        "verify_identity_binding_export",
    }
    assert names <= set(sdk.__all__)
    assert all(getattr(sdk, name) is getattr(module, name) for name in names)


def vectors() -> list[dict[str, Any]]:
    path = Path(__file__).parents[1] / "testdata/identity_binding_export_vectors.json"
    data = json.loads(path.read_bytes())
    assert data["schema"] == "sakamoto.identity_binding.export.shared_vectors.v1"
    assert data["as_commit"] == "3b499cdc09a50d267cd797d60910c747c577e6ce"
    return cast(list[dict[str, Any]], data["vectors"])


def good_vector() -> dict[str, Any]:
    return next(vector for vector in vectors() if vector["name"] == "EdDSA-producer-valid")


def test_shared_as_producer_vectors() -> None:
    from leap_oauth_sdk import identity_binding_export as module

    cases = vectors()
    assert {case["alg"] for case in cases} == {"EdDSA", "RS256"}
    for case in cases:
        arguments = {name: case[name] for name in ("issuer", "request_subjects", "jwks")}
        if case["expect"] == "reject":
            with pytest.raises(
                module.IdentityBindingExportRejected, match="^identity binding export rejected$"
            ):
                module.verify_identity_binding_export(case["jws"], **arguments)
        else:
            result = module.verify_identity_binding_export(case["jws"], **arguments)
            assert {
                "epoch": result.epoch,
                "generation": result.generation,
                "chain": result.chain,
                "payload_sha256": result.payload_sha256,
                "items": dict(result.items),
                "not_exportable_count": result.not_exportable_count,
                "absent_count": result.absent_count,
            } == case["verified"], case["name"]
            with pytest.raises(TypeError):
                cast(Any, result.items)["new"] = "changed"
            with pytest.raises(FrozenInstanceError):
                result.generation = 9


@respx.mock
def test_url_get_five_seconds_without_redirect_or_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    from leap_oauth_sdk import identity_binding_export as module

    case = good_vector()
    url = "https://auth.example.com/.well-known/jwks.json"
    route = respx.get(url).mock(
        return_value=stream_response(200, json.dumps(case["jwks"]).encode())
    )
    actual = httpx.Client
    constructions = []

    def client(**kwargs: Any) -> httpx.Client:
        constructions.append(kwargs)
        return actual(**kwargs)

    monkeypatch.setattr(module.httpx, "Client", client)
    for _ in range(2):
        module.verify_identity_binding_export(
            case["jws"],
            issuer=case["issuer"],
            request_subjects=case["request_subjects"],
            jwks_url=url,
        )
    assert route.call_count == 2
    assert constructions == [{"timeout": 5.0, "follow_redirects": False}] * 2
    assert all(
        call.request.method == "GET" and call.request.headers["Accept"] == "application/json"
        for call in route.calls
    )
    for call in route.calls:
        assert set(call.request.extensions["timeout"].values()) == {5.0}
        assert call.request.headers["Accept-Encoding"] == "identity"
        assert "Authorization" not in call.request.headers


@pytest.mark.parametrize(
    "response",
    [
        stream_response(302, headers={"Location": "https://evil.example.com/jwks"}),
        stream_response(500),
        stream_response(200, b"not-json"),
        stream_response(200, b"\xff"),
        stream_response(200, b"[]"),
        stream_response(200, '{"keys":[]}'.encode("utf-16")),
    ],
)
@respx.mock
def test_url_errors_reject_whole_export_no_redirect_or_stale(response: httpx.Response) -> None:
    from leap_oauth_sdk import identity_binding_export as module

    case = good_vector()
    url = "https://auth.example.com/jwks"
    route = respx.get(url).mock(return_value=response)
    with pytest.raises(
        module.IdentityBindingExportRejected, match="^identity binding export rejected$"
    ):
        module.verify_identity_binding_export(
            case["jws"],
            issuer=case["issuer"],
            request_subjects=case["request_subjects"],
            jwks_url=url,
        )
    assert route.call_count == 1 and len(respx.calls) == 1


@respx.mock
def test_url_timeout_rejected_without_second_attempt() -> None:
    from leap_oauth_sdk import identity_binding_export as module

    case = good_vector()
    route = respx.get("https://auth.example.com/jwks").mock(
        side_effect=httpx.ReadTimeout("test only")
    )
    with pytest.raises(module.IdentityBindingExportRejected):
        module.verify_identity_binding_export(
            case["jws"],
            issuer=case["issuer"],
            request_subjects=case["request_subjects"],
            jwks_url="https://auth.example.com/jwks",
        )
    assert route.call_count == 1


def test_exactly_one_jwks_source_without_io(monkeypatch: pytest.MonkeyPatch) -> None:
    from leap_oauth_sdk import identity_binding_export as module

    case = good_vector()
    monkeypatch.setattr(
        module.httpx, "Client", lambda **_: pytest.fail("invalid source selection attempted IO")
    )
    for arguments in (
        {},
        {"jwks": case["jwks"], "jwks_url": "https://auth.example.com/jwks"},
        {"jwks_url": ""},
    ):
        with pytest.raises(module.IdentityBindingExportRejected):
            module.verify_identity_binding_export(
                case["jws"],
                issuer=case["issuer"],
                request_subjects=case["request_subjects"],
                **arguments,
            )


@respx.mock
def test_url_requires_status_200_even_with_valid_jwks() -> None:
    from leap_oauth_sdk import identity_binding_export as module

    case = good_vector()
    route = respx.get("https://auth.example.com/jwks").mock(
        return_value=stream_response(201, json.dumps(case["jwks"]).encode())
    )
    with pytest.raises(module.IdentityBindingExportRejected):
        module.verify_identity_binding_export(
            case["jws"],
            issuer=case["issuer"],
            request_subjects=case["request_subjects"],
            jwks_url="https://auth.example.com/jwks",
        )
    assert route.call_count == 1


@pytest.mark.parametrize("extra", [0, 1])
@respx.mock
def test_url_stream_body_exact_64k_boundary(extra: int) -> None:
    from leap_oauth_sdk import identity_binding_export as module

    case = good_vector()
    body = json.dumps(case["jwks"]).encode()
    body += b" " * (65536 + extra - len(body))
    route = respx.get("https://auth.example.com/jwks").mock(return_value=stream_response(200, body))
    kwargs = dict(
        issuer=case["issuer"],
        request_subjects=case["request_subjects"],
        jwks_url="https://auth.example.com/jwks",
    )
    if extra:
        with pytest.raises(module.IdentityBindingExportRejected):
            module.verify_identity_binding_export(case["jws"], **kwargs)
    else:
        assert (
            module.verify_identity_binding_export(case["jws"], **kwargs).epoch
            == case["verified"]["epoch"]
        )
    assert route.call_count == 1


@pytest.mark.parametrize(
    "url",
    [
        "file:///fixture.json",
        "ftp://auth.example.com/jwks",
        "https:///jwks",
        "https://user@auth.example.com/jwks",
        "https://user:pass@auth.example.com/jwks",
        "https://auth.example.com/jwks?key=value",
        "https://auth.example.com/jwks#fragment",
    ],
)
def test_invalid_url_rejected_before_client(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    from leap_oauth_sdk import identity_binding_export as module

    case = good_vector()
    monkeypatch.setattr(module.httpx, "Client", lambda **_: pytest.fail("invalid URL attempted IO"))
    with pytest.raises(module.IdentityBindingExportRejected):
        module.verify_identity_binding_export(
            case["jws"],
            issuer=case["issuer"],
            request_subjects=case["request_subjects"],
            jwks_url=url,
        )


@respx.mock
def test_raw_http_body_not_implicitly_gzip_decoded() -> None:
    from leap_oauth_sdk import identity_binding_export as module

    case = good_vector()
    body = gzip.compress(json.dumps(case["jwks"]).encode())
    respx.get("https://auth.example.com/jwks").mock(
        return_value=stream_response(200, body, headers={"Content-Encoding": "gzip"})
    )
    with pytest.raises(module.IdentityBindingExportRejected):
        module.verify_identity_binding_export(
            case["jws"],
            issuer=case["issuer"],
            request_subjects=case["request_subjects"],
            jwks_url="https://auth.example.com/jwks",
        )


def test_unexpected_input_exception_is_fixed_rejection_without_catching_interrupt() -> None:
    from leap_oauth_sdk import identity_binding_export as module

    case = good_vector()

    class BadKeys(dict[str, Any]):
        def get(self, *_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("untrusted input detail")

    with pytest.raises(
        module.IdentityBindingExportRejected, match="^identity binding export rejected$"
    ):
        module.verify_identity_binding_export(
            case["jws"],
            issuer=case["issuer"],
            request_subjects=case["request_subjects"],
            jwks=BadKeys(),
        )

    class InterruptedKeys(dict[str, Any]):
        def get(self, *_args: Any, **_kwargs: Any) -> Any:
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        module.verify_identity_binding_export(
            case["jws"],
            issuer=case["issuer"],
            request_subjects=case["request_subjects"],
            jwks=InterruptedKeys(),
        )


@pytest.mark.parametrize("token", ["", "a.b.c.d", "!.e30.aaa", "e30.e30.aaa"])
def test_malformed_jws_does_not_construct_http_client(
    monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    from leap_oauth_sdk import identity_binding_export as module

    monkeypatch.setattr(
        module.httpx, "Client", lambda **_: pytest.fail("malformed JWS attempted IO")
    )
    with pytest.raises(module.IdentityBindingExportRejected):
        module.verify_identity_binding_export(
            token,
            issuer="https://auth.example.com",
            request_subjects=["usr_one"],
            jwks_url="https://auth.example.com/jwks",
        )


def test_no_as_import_cache_or_access_verifier_state() -> None:
    from leap_oauth_sdk import identity_binding_export as module

    text = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(text)
    assert "sakamoto_auth" not in text
    assert "AccessTokenVerifier" not in text
    assert not any(
        isinstance(node, ast.ImportFrom) and node.module and node.module.endswith("server")
        for node in ast.walk(tree)
    )
