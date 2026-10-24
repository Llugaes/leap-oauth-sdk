"""Verify a bounded C-X export envelope independently of access tokens."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, cast

import httpx
import jwt

from .config import _require_http_url  # pyright: ignore[reportPrivateUsage]
from .tokens import _MAX_JWKS_BYTES, _PRIVATE_JWK_FIELDS  # pyright: ignore[reportPrivateUsage]

EXPORT_TYP = "sakamoto-identity-binding-export+jws"
EXPORT_VER = "sakamoto.identity_binding.export.v1"
EXPORT_MAX_ITEMS = 5000
_PAYLOAD_FIELDS = frozenset(
    {
        "ver",
        "iss",
        "epoch",
        "generation",
        "chain",
        "request_sha256",
        "requested_count",
        "items",
        "not_exportable_count",
        "absent_count",
    }
)


class IdentityBindingExportRejected(ValueError):
    """The whole export is untrusted; no partial result is available."""

    def __init__(self) -> None:
        super().__init__("identity binding export rejected")


@dataclass(frozen=True, slots=True)
class VerifiedExport:
    epoch: str
    generation: int
    chain: str
    payload_sha256: str
    items: Mapping[str, str]
    not_exportable_count: int
    absent_count: int


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IdentityBindingExportRejected()
        result[key] = value
    return result


def _nonfinite(_value: str) -> Any:
    raise IdentityBindingExportRejected()


def _json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite)


def _segment(value: str) -> bytes:
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise IdentityBindingExportRejected()
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise IdentityBindingExportRejected()
    return raw


def _exact(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _sha(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def verify_identity_binding_export(
    jws: str,
    *,
    issuer: str,
    request_subjects: Sequence[str],
    jwks: Mapping[str, Any] | None = None,
    jwks_url: str | None = None,
) -> VerifiedExport:
    """Verify signature, closed canonical payload, request binding and counts."""
    try:
        return _verify(
            jws, issuer=issuer, request_subjects=request_subjects, jwks=jwks, jwks_url=jwks_url
        )
    except IdentityBindingExportRejected:
        raise
    except (
        httpx.HTTPError,
        jwt.PyJWTError,
        TimeoutError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise IdentityBindingExportRejected() from exc
    except Exception as exc:
        # Caller-owned Mapping/Sequence implementations may fail outside the JSON error set.
        # Interrupts inherit BaseException and deliberately remain visible to the caller.
        raise IdentityBindingExportRejected() from exc


def _fetch_jwks(url: str, timeout: float) -> dict[str, Any]:
    _require_http_url(url, "jwks_url")
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        with client.stream(
            "GET",
            url,
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
            auth=None,
        ) as response:
            if response.status_code != 200:
                raise IdentityBindingExportRejected()
            raw = bytearray()
            for chunk in response.iter_raw(chunk_size=8192):
                raw.extend(chunk)
                if len(raw) > _MAX_JWKS_BYTES:
                    raise IdentityBindingExportRejected()
            value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise IdentityBindingExportRejected()
    return cast(dict[str, Any], value)


def _key_matches(key: Any, kid: str, alg: str) -> bool:
    return (
        isinstance(key, dict)
        and cast(dict[str, Any], key).get("kid") == kid
        and cast(dict[str, Any], key).get("alg") == alg
    )


def _verify(
    jws: Any, *, issuer: Any, request_subjects: Any, jwks: Any, jwks_url: Any
) -> VerifiedExport:
    if (
        not _exact(issuer)
        or not isinstance(request_subjects, Sequence)
        or isinstance(request_subjects, (str, bytes, bytearray))
        or not 1 <= len(cast(Sequence[Any], request_subjects)) <= EXPORT_MAX_ITEMS
    ):
        raise IdentityBindingExportRejected()
    # Copy once so the request and verified result share no caller-owned containers.
    subjects = tuple(cast(Sequence[str], request_subjects))
    if any(not _exact(subject) or len(subject) > 191 for subject in subjects) or len(
        set(subjects)
    ) != len(subjects):
        raise IdentityBindingExportRejected()
    if (jwks is None) == (jwks_url is None):
        raise IdentityBindingExportRejected()
    if not isinstance(jws, str) or len(parts := jws.split(".")) != 3:
        raise IdentityBindingExportRejected()
    header_raw, payload_raw, _ = (_segment(part) for part in parts)
    raw_header = _json(header_raw)
    if not isinstance(raw_header, dict):
        raise IdentityBindingExportRejected()
    header = cast(dict[str, Any], raw_header)
    if (
        set(header) != {"alg", "kid", "typ"}
        or header["typ"] != EXPORT_TYP
        or not isinstance(header["alg"], str)
        or header["alg"] not in {"EdDSA", "RS256"}
        or not isinstance(header["kid"], str)
        or not header["kid"]
    ):
        raise IdentityBindingExportRejected()
    alg, kid = header["alg"], header["kid"]
    if jwks is None:
        if not isinstance(jwks_url, str) or not jwks_url:
            raise IdentityBindingExportRejected()
        jwks = _fetch_jwks(jwks_url, 5.0)
    if not isinstance(jwks, Mapping):
        raise IdentityBindingExportRejected()
    keys = cast(Mapping[str, Any], jwks).get("keys")
    if not isinstance(keys, list):
        raise IdentityBindingExportRejected()
    keys = cast(list[Any], keys)
    if sum(_key_matches(key, kid, alg) for key in keys) != 1:
        raise IdentityBindingExportRejected()
    selected = cast(dict[str, Any], next(key for key in keys if _key_matches(key, kid, alg)))
    if _PRIVATE_JWK_FIELDS.intersection(selected):
        raise IdentityBindingExportRejected()
    # Reuse the SDK's existing PyJWT conversion primitive, without token-policy use filtering.
    key = jwt.PyJWK.from_dict(selected).key
    decoded = jwt.PyJWS().decode_complete(jws, key, algorithms=[alg])
    if decoded["payload"] != payload_raw:
        raise IdentityBindingExportRejected()
    raw_value = _json(payload_raw)
    if not isinstance(raw_value, dict):
        raise IdentityBindingExportRejected()
    value = cast(dict[str, Any], raw_value)
    if (
        frozenset(value) != _PAYLOAD_FIELDS
        or _canonical(value) != payload_raw
        or value["ver"] != EXPORT_VER
        or value["iss"] != issuer
        or not _sha(value["epoch"])
        or not _sha(value["chain"])
        or any(
            not _integer(value[name])
            for name in ("generation", "requested_count", "not_exportable_count", "absent_count")
        )
        or value["requested_count"] != len(subjects)
        or value["request_sha256"] != hashlib.sha256(_canonical(sorted(subjects))).hexdigest()
        or not isinstance(value["items"], list)
    ):
        raise IdentityBindingExportRejected()
    items: dict[str, str] = {}
    requested = frozenset(subjects)
    previous: str | None = None
    for raw_item in cast(list[Any], value["items"]):
        if not isinstance(raw_item, dict):
            raise IdentityBindingExportRejected()
        item = cast(dict[str, Any], raw_item)
        if set(item) != {"legacy_subject", "person_key"}:
            raise IdentityBindingExportRejected()
        subject, person = item["legacy_subject"], item["person_key"]
        if (
            not isinstance(subject, str)
            or subject not in requested
            or (previous is not None and subject <= previous)
            or not isinstance(person, str)
            or not person.startswith("feishu:user_id:")
            or not person[len("feishu:user_id:") :]
        ):
            raise IdentityBindingExportRejected()
        items[subject] = person
        previous = subject
    if (
        len(items) + value["not_exportable_count"] + value["absent_count"]
        != value["requested_count"]
        or len(items) + value["not_exportable_count"] > value["generation"]
    ):
        raise IdentityBindingExportRejected()
    return VerifiedExport(
        value["epoch"],
        value["generation"],
        value["chain"],
        hashlib.sha256(payload_raw).hexdigest(),
        MappingProxyType(items),
        value["not_exportable_count"],
        value["absent_count"],
    )


__all__ = [
    "EXPORT_TYP",
    "EXPORT_VER",
    "EXPORT_MAX_ITEMS",
    "IdentityBindingExportRejected",
    "VerifiedExport",
    "verify_identity_binding_export",
]
