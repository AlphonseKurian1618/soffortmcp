"""Canonical device-proof verification shared by enrollment and decisions."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

APNS_TOKEN_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def normalize_display_name(value: object) -> str:
    """Normalize a user-authored name while rejecting invisible controls."""
    if not isinstance(value, str):
        raise ValueError("display_name must be a string")
    normalized = unicodedata.normalize("NFC", value.strip())
    if not 1 <= len(normalized) <= 100:
        raise ValueError("display_name must contain 1 to 100 characters")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise ValueError("display_name cannot contain control characters")
    return normalized


def normalize_purpose(value: object) -> str:
    """Normalize bounded request context before it is shown on the phone."""
    if not isinstance(value, str):
        raise ValueError("purpose must be a string")
    normalized = unicodedata.normalize("NFC", value.strip())
    if not 1 <= len(normalized) <= 200:
        raise ValueError("purpose must contain 1 to 200 characters")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise ValueError("purpose cannot contain control characters")
    return normalized


def canonical_uuid7(value: object, field: str) -> str:
    """Require a lowercase canonical UUIDv7 identifier."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a UUIDv7 string")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise ValueError(f"{field} must be a UUIDv7 string") from error
    if parsed.version != 7 or str(parsed) != value:
        raise ValueError(f"{field} must be a lowercase canonical UUIDv7")
    return value


def validate_apns_token(value: object) -> str:
    """Validate Apple's current opaque 32-byte hexadecimal device token."""
    if not isinstance(value, str) or APNS_TOKEN_PATTERN.fullmatch(value) is None:
        raise ValueError("apns_token must be 64 lowercase hexadecimal characters")
    return value


def parse_public_jwk(value: object) -> tuple[dict[str, str], ec.EllipticCurvePublicKey]:
    """Parse the exact public P-256 JWK shape accepted for device possession."""
    if not isinstance(value, dict):
        raise ValueError("public_jwk must contain exactly kty, crv, x, and y")
    raw = cast(dict[object, object], value)
    if set(raw) != {"kty", "crv", "x", "y"}:
        raise ValueError("public_jwk must contain exactly kty, crv, x, and y")
    if raw.get("kty") != "EC" or raw.get("crv") != "P-256":
        raise ValueError("public_jwk must be an EC P-256 key")
    x_value = raw.get("x")
    y_value = raw.get("y")
    x = _decode_b64url(x_value, "public_jwk.x", expected_length=32)
    y = _decode_b64url(y_value, "public_jwk.y", expected_length=32)
    try:
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    except ValueError as error:
        raise ValueError("public_jwk is not a valid P-256 point") from error
    canonical = {"kty": "EC", "crv": "P-256", "x": str(x_value), "y": str(y_value)}
    return canonical, key


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """Return the RFC 7638-style SHA-256 thumbprint for a P-256 JWK."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return _encode_b64url(hashlib.sha256(canonical).digest())


def enrollment_message(
    *,
    tenant_id: str,
    object_id: str,
    device_id: str,
    challenge_id: str,
    nonce: str,
    thumbprint: str,
    issued_at: int,
) -> bytes:
    """Build the versioned enrollment bytes signed by the iPhone."""
    return (
        "soffort-device-enrollment-v1\n"
        f"{tenant_id}\n{object_id}\n{device_id}\n{challenge_id}\n{nonce}\n"
        f"{thumbprint}\n{issued_at}"
    ).encode()


def decision_message(
    *,
    tenant_id: str,
    object_id: str,
    device_id: str,
    approval_id: str,
    nonce: str,
    tool_name: str,
    arguments_hash: str,
    decision: str,
    result_hash: str,
    issued_at: int,
) -> bytes:
    """Build the exact v2 consent bytes signed after local authentication."""
    return (
        "soffort-consent-decision-v2\n"
        f"{tenant_id}\n{object_id}\n{device_id}\n{approval_id}\n{nonce}\n"
        f"{tool_name}\n{arguments_hash}\n{decision}\n{result_hash}\n{issued_at}"
    ).encode()


def verify_signature(public_jwk: dict[str, str], message: bytes, signature: object) -> None:
    """Verify one bounded DER-encoded ECDSA/SHA-256 signature."""
    _, key = parse_public_jwk(public_jwk)
    decoded = _decode_b64url(signature, "signature", max_length=96)
    try:
        key.verify(decoded, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as error:
        raise ValueError("device proof signature is invalid") from error


def require_fresh_issued_at(value: object, *, maximum_skew_seconds: int = 30) -> int:
    """Require a whole-second proof timestamp near the server clock."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("issued_at must be an integer Unix timestamp")
    now = int(datetime.now(UTC).timestamp())
    if abs(now - value) > maximum_skew_seconds:
        raise ValueError("issued_at is outside the accepted clock window")
    return value


def _decode_b64url(
    value: object,
    field: str,
    *,
    expected_length: int | None = None,
    max_length: int | None = None,
) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or len(value) > 256:
        raise ValueError(f"{field} must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise ValueError(f"{field} must be unpadded base64url") from error
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(f"{field} has the wrong length")
    if max_length is not None and len(decoded) > max_length:
        raise ValueError(f"{field} is too long")
    if _encode_b64url(decoded) != value:
        raise ValueError(f"{field} is not canonical base64url")
    return decoded


def _encode_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
