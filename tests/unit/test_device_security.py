"""Tests for device enrollment and signed-decision canonicalization."""

import base64
from datetime import UTC, datetime
from uuid import uuid4, uuid7

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from soffortbackend.device_security import (
    canonical_uuid7,
    decision_message,
    enrollment_message,
    jwk_thumbprint,
    normalize_display_name,
    parse_public_jwk,
    require_fresh_issued_at,
    validate_apns_token,
    verify_signature,
)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def make_device_key() -> tuple[ec.EllipticCurvePrivateKey, dict[str, str]]:
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    return private, {
        "kty": "EC",
        "crv": "P-256",
        "x": _encode(numbers.x.to_bytes(32, "big")),
        "y": _encode(numbers.y.to_bytes(32, "big")),
    }


def test_profile_name_normalizes_unicode_and_rejects_controls() -> None:
    assert normalize_display_name("  A\u0301lphonse  ") == "Álphonse"
    for value in ("", " " * 3, "x" * 101, "bad\nname", 42):
        with pytest.raises(ValueError):
            normalize_display_name(value)


def test_uuid7_and_apns_tokens_are_canonical() -> None:
    identifier = "01890f3e-7b4a-7cc0-8000-000000000000"
    assert canonical_uuid7(identifier, "id") == identifier
    assert validate_apns_token("ab" * 32) == "ab" * 32
    for value in (identifier.upper(), "not-a-uuid", str(uuid4())):
        with pytest.raises(ValueError):
            canonical_uuid7(value, "id")
    for value in ("AB" * 32, "ab" * 31, "gg" * 32, None):
        with pytest.raises(ValueError):
            validate_apns_token(value)


def test_public_jwk_thumbprint_and_signatures_round_trip() -> None:
    private, jwk = make_device_key()
    canonical, public = parse_public_jwk(jwk)
    assert public.public_numbers() == private.public_key().public_numbers()
    thumbprint = jwk_thumbprint(canonical)
    issued_at = int(datetime.now(UTC).timestamp())
    enrollment = enrollment_message(
        tenant_id="tenant",
        object_id="object",
        device_id=str(uuid7()),
        challenge_id=str(uuid7()),
        nonce="nonce",
        thumbprint=thumbprint,
        issued_at=issued_at,
    )
    signature = private.sign(enrollment, ec.ECDSA(hashes.SHA256()))
    verify_signature(jwk, enrollment, _encode(signature))

    decision = decision_message(
        tenant_id="tenant",
        object_id="object",
        device_id=str(uuid7()),
        approval_id=str(uuid7()),
        nonce="nonce",
        tool_name="hello_world",
        arguments_hash="hash",
        decision="approved",
        issued_at=issued_at,
    )
    verify_signature(jwk, decision, _encode(private.sign(decision, ec.ECDSA(hashes.SHA256()))))

    with pytest.raises(ValueError, match="invalid"):
        verify_signature(jwk, decision + b"tampered", _encode(signature))


@pytest.mark.parametrize(
    "jwk",
    [
        {},
        {"kty": "RSA", "crv": "P-256", "x": "x", "y": "y"},
        {"kty": "EC", "crv": "P-256", "x": "bad=", "y": "bad"},
        {"kty": "EC", "crv": "P-256", "x": _encode(b"x" * 32), "y": _encode(b"y" * 32)},
    ],
)
def test_malformed_public_keys_fail_closed(jwk: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        parse_public_jwk(jwk)


def test_proof_timestamp_is_bounded() -> None:
    now = int(datetime.now(UTC).timestamp())
    assert require_fresh_issued_at(now) == now
    for value in (now - 31, now + 31, "now", True):
        with pytest.raises(ValueError):
            require_fresh_issued_at(value)
