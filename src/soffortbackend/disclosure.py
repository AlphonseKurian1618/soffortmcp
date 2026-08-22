"""JWE boundary that keeps approved vault values encrypted in Cosmos."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from azure.identity.aio import DefaultAzureCredential
from azure.keyvault.keys.aio import KeyClient
from azure.keyvault.keys.crypto import EncryptionAlgorithm
from azure.keyvault.keys.crypto.aio import CryptographyClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from soffortbackend.models import Approval, PropertyMetadata
from soffortbackend.settings import Settings


class DisclosureError(Exception):
    """A ciphertext could not be safely mapped to the approved request."""


@dataclass(frozen=True, slots=True)
class DisclosureKey:
    """Public RSA JWK served only to the authenticated Concentrey app."""

    kid: str
    n: str
    e: str

    def as_json(self) -> dict[str, str]:
        """Return the exact public JWK shape accepted by iOS."""
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "enc",
            "alg": "RSA-OAEP-256",
            "n": self.n,
            "e": self.e,
        }


@dataclass(frozen=True, slots=True)
class DisclosedProperty:
    """One approved plaintext value held only during the MCP response."""

    key: str
    value: str


class DisclosureDecryptor(Protocol):
    """Lifecycle and crypto surface used by the consent service."""

    @property
    def ready(self) -> bool:
        """Return whether a current public key is available."""
        ...

    async def start(self) -> None:
        """Load current public key metadata."""
        ...

    async def close(self) -> None:
        """Release Azure clients."""
        ...

    async def current_key(self) -> DisclosureKey:
        """Return the current versioned public JWK."""
        ...

    async def decrypt(self, approval: Approval) -> tuple[DisclosedProperty, ...]:
        """Decrypt and validate an approved disclosure."""
        ...


class FakeDisclosureDecryptor:
    """Deterministic test adapter that never exercises Azure."""

    ready = True

    def __init__(self) -> None:
        """Create an empty fixture value map."""
        self.values: dict[str, tuple[DisclosedProperty, ...]] = {}

    async def start(self) -> None:
        """Match the production lifecycle."""

    async def close(self) -> None:
        """Match the production lifecycle."""

    async def current_key(self) -> DisclosureKey:
        """Return a syntactically valid fixture JWK."""
        return DisclosureKey(kid="fixture-key", n=_encode(b"n" * 256), e=_encode(b"\x01\x00\x01"))

    async def decrypt(self, approval: Approval) -> tuple[DisclosedProperty, ...]:
        """Return values registered by approval ID."""
        try:
            return self.values[approval.approval_id]
        except KeyError as error:
            raise DisclosureError("fixture disclosure is unavailable") from error


class KeyVaultDisclosureDecryptor:
    """Use a non-exportable versioned Key Vault RSA key for JWE decryption."""

    def __init__(self, settings: Settings) -> None:
        """Configure versioned key access through the workload identity."""
        if settings.key_vault_url is None or settings.azure_workload_client_id is None:
            raise ValueError("Key Vault workload identity configuration is required")
        self._credential = DefaultAzureCredential(
            managed_identity_client_id=str(settings.azure_workload_client_id)
        )
        self._keys = KeyClient(str(settings.key_vault_url), self._credential)
        self._key_name = settings.disclosure_key_name
        self._current: DisclosureKey | None = None

    @property
    def ready(self) -> bool:
        """Return whether startup resolved a current key version."""
        return self._current is not None

    async def start(self) -> None:
        """Resolve the current key without exporting private material."""
        try:
            key = await self._keys.get_key(self._key_name)
            raw_key = cast(Any, key.key)
            modulus = cast(bytes | None, getattr(raw_key, "n", None))
            exponent = cast(bytes | None, getattr(raw_key, "e", None))
            if modulus is None or exponent is None:
                raise DisclosureError("disclosure key has no RSA public members")
            version = key.properties.version
            if not version:
                raise DisclosureError("disclosure key has no immutable version")
            self._current = DisclosureKey(version, _encode(modulus), _encode(exponent))
        except Exception as error:
            raise DisclosureError("disclosure key is unavailable") from error

    async def close(self) -> None:
        """Forget cached metadata and close workload-identity clients."""
        self._current = None
        await self._keys.close()
        await self._credential.close()

    async def current_key(self) -> DisclosureKey:
        """Return the immutable current public key version."""
        if self._current is None:
            raise DisclosureError("disclosure key is unavailable")
        return self._current

    async def decrypt(self, approval: Approval) -> tuple[DisclosedProperty, ...]:
        """Remotely decrypt the CEK, then validate authenticated local plaintext."""
        compact = approval.compact_jwe
        if compact is None or len(compact) > 96_000:
            raise DisclosureError("disclosure ciphertext is missing or too large")
        segments = compact.split(".")
        if len(segments) != 5:
            raise DisclosureError("disclosure must be compact JWE")
        protected_segment, encrypted_key_segment, iv_segment, ciphertext_segment, tag_segment = (
            segments
        )
        header = _json_object(_decode(protected_segment, 4_096))
        _require_exact(
            header,
            {
                "alg",
                "enc",
                "kid",
                "typ",
                "request_id",
                "decision_id",
                "approved_keys_hash",
                "expires_at",
            },
        )
        if header["alg"] != "RSA-OAEP-256" or header["enc"] != "A256GCM":
            raise DisclosureError("disclosure algorithms are not accepted")
        if header["typ"] != "permi-disclosure+jwe":
            raise DisclosureError("disclosure type is not accepted")
        if (
            header["request_id"] != approval.approval_id
            or header["decision_id"] != approval.decision_id
        ):
            raise DisclosureError("disclosure is bound to another decision")
        if header["approved_keys_hash"] != approved_keys_hash(approval.approved_keys):
            raise DisclosureError("approved property manifest does not match")
        expires_at = _parse_time(header["expires_at"])
        if expires_at > approval.expires_at or datetime.now(UTC) >= expires_at:
            raise DisclosureError("disclosure has expired")
        kid = header["kid"]
        if not isinstance(kid, str) or not kid or len(kid) > 128:
            raise DisclosureError("disclosure key version is invalid")
        key = await self._keys.get_key(self._key_name, kid)
        crypto = CryptographyClient(key, credential=self._credential)
        try:
            unwrapped = await crypto.decrypt(
                EncryptionAlgorithm.rsa_oaep_256,
                _decode(encrypted_key_segment, 512),
            )
        finally:
            await crypto.close()
        if len(unwrapped.plaintext) != 32:
            raise DisclosureError("content encryption key has the wrong size")
        iv = _decode(iv_segment, 12)
        tag = _decode(tag_segment, 16)
        ciphertext = _decode(ciphertext_segment, 65_536)
        try:
            plaintext = AESGCM(unwrapped.plaintext).decrypt(
                iv,
                ciphertext + tag,
                protected_segment.encode(),
            )
        except Exception as error:
            raise DisclosureError("disclosure authentication failed") from error
        return _validate_plaintext(approval, plaintext, expires_at)


def approved_keys_hash(keys: tuple[str, ...]) -> str:
    """Hash the ordered approved manifest using one cross-language encoding."""
    encoded = json.dumps(
        {"approved_keys": list(keys), "schema_version": 1},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return _encode(hashlib.sha256(encoded).digest())


def result_manifest_hash(
    *,
    available_keys: tuple[str, ...],
    approved_keys: tuple[str, ...],
    denied_keys: tuple[str, ...],
    unavailable_keys: tuple[str, ...],
    property_metadata: tuple[PropertyMetadata, ...],
    compact_jwe: str | None,
) -> str:
    """Bind the signed decision to exact metadata and ciphertext bytes."""
    manifest = {
        "approved_keys": list(approved_keys),
        "available_keys": list(available_keys),
        "compact_jwe_sha256": _encode(hashlib.sha256((compact_jwe or "").encode()).digest()),
        "denied_keys": list(denied_keys),
        "property_metadata_sha256": _encode(
            hashlib.sha256(
                json.dumps(
                    [
                        {
                            "key": item.key,
                            "display_name": item.display_name,
                            "value_type": item.value_type,
                            "sensitivity": item.sensitivity,
                        }
                        for item in property_metadata
                    ],
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            ).digest()
        ),
        "unavailable_keys": list(unavailable_keys),
    }
    encoded = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
    return _encode(hashlib.sha256(encoded).digest())


def _validate_plaintext(
    approval: Approval,
    encoded: bytes,
    expires_at: datetime,
) -> tuple[DisclosedProperty, ...]:
    payload = _json_object(encoded)
    _require_exact(
        payload,
        {
            "schema_version",
            "request_id",
            "decision_id",
            "approved_fields",
            "created_at",
            "expires_at",
        },
    )
    if payload["schema_version"] != 1 or payload["request_id"] != approval.approval_id:
        raise DisclosureError("disclosure payload is bound to another request")
    if (
        payload["decision_id"] != approval.decision_id
        or _parse_time(payload["expires_at"]) != expires_at
    ):
        raise DisclosureError("disclosure payload is bound to another decision")
    created_at = _parse_time(payload["created_at"])
    if created_at < approval.created_at or created_at >= expires_at:
        raise DisclosureError("disclosure creation time is invalid")
    raw_fields = payload["approved_fields"]
    if not isinstance(raw_fields, list):
        raise DisclosureError("disclosure fields must be an array")
    fields = cast(list[object], raw_fields)
    if len(fields) != len(approval.approved_keys):
        raise DisclosureError("disclosure field count does not match")
    output: list[DisclosedProperty] = []
    metadata_by_key = {item.key: item for item in approval.property_metadata}
    for expected, raw in zip(approval.approved_keys, fields, strict=True):
        if not isinstance(raw, dict):
            raise DisclosureError("disclosure field is malformed")
        field = cast(dict[str, Any], raw)
        _require_exact(field, {"key", "value_type", "value"})
        metadata = metadata_by_key.get(expected)
        if metadata is None:
            raise DisclosureError("approved property metadata is missing")
        value = field["value"]
        if field["key"] != expected or field["value_type"] != metadata.value_type:
            raise DisclosureError("disclosure property metadata does not match")
        if not isinstance(value, str) or not 1 <= len(value) <= 4_096:
            raise DisclosureError("disclosure value has an invalid size")
        output.append(DisclosedProperty(expected, value))
    return tuple(output)


def _json_object(encoded: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in values:
            if key in output:
                raise DisclosureError("JSON contains duplicate members")
            output[key] = value
        return output

    try:
        value = json.loads(encoded, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DisclosureError("disclosure JSON is malformed") from error
    if not isinstance(value, dict):
        raise DisclosureError("disclosure JSON must be an object")
    return cast(dict[str, Any], value)


def _require_exact(value: dict[str, Any], members: set[str]) -> None:
    if set(value) != members:
        raise DisclosureError("disclosure JSON members do not match the contract")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise DisclosureError("disclosure timestamp is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DisclosureError("disclosure timestamp is malformed") from error
    if parsed.tzinfo is None:
        raise DisclosureError("disclosure timestamp requires an offset")
    return parsed.astimezone(UTC)


def _decode(value: str, maximum: int) -> bytes:
    if not value or "=" in value or len(value) > maximum * 2:
        raise DisclosureError("JWE segment is malformed")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise DisclosureError("JWE segment is malformed") from error
    if len(decoded) > maximum or _encode(decoded) != value:
        raise DisclosureError("JWE segment is not canonical")
    return decoded


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
