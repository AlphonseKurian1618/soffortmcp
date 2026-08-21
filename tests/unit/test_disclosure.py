"""Tests for result hashing and the Key Vault-backed compact JWE boundary."""

import base64
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid7

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import soffortbackend.disclosure as module
from soffortbackend.disclosure import (
    DisclosureError,
    KeyVaultDisclosureDecryptor,
    approved_keys_hash,
    result_manifest_hash,
)
from soffortbackend.models import Approval, ApprovalStatus
from soffortbackend.settings import Settings


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _approval() -> Approval:
    now = datetime.now(UTC)
    return Approval(
        partition_key="tenant:subject",
        approval_id=str(uuid7()),
        event_id=str(uuid7()),
        nonce="nonce",
        tool_name="request_properties",
        arguments_hash="arguments-hash",
        requester="VS Code",
        purpose="Send a fictional receipt",
        requested_keys=("contact.personalEmail",),
        created_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=1),
        status=ApprovalStatus.APPROVED,
        decision_id=str(uuid7()),
        approved_keys=("contact.personalEmail",),
    )


def _compact(approval: Approval, *, cek: bytes, overrides=None, payload_overrides=None) -> str:
    expires_at = approval.expires_at - timedelta(seconds=1)
    header = {
        "alg": "RSA-OAEP-256",
        "enc": "A256GCM",
        "kid": "key-version",
        "typ": "permi-disclosure+jwe",
        "request_id": approval.approval_id,
        "decision_id": approval.decision_id,
        "approved_keys_hash": approved_keys_hash(approval.approved_keys),
        "expires_at": _iso(expires_at),
    }
    header.update(overrides or {})
    protected = _encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload = {
        "schema_version": 1,
        "request_id": approval.approval_id,
        "decision_id": approval.decision_id,
        "approved_fields": [
            {
                "key": "contact.personalEmail",
                "value_type": "email",
                "value": "fictional@example.test",
            }
        ],
        "created_at": _iso(approval.created_at + timedelta(milliseconds=1)),
        "expires_at": _iso(expires_at),
    }
    payload.update(payload_overrides or {})
    iv = os.urandom(12)
    encrypted = AESGCM(cek).encrypt(
        iv,
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        protected.encode(),
    )
    return ".".join(
        (
            protected,
            _encode(b"wrapped-key"),
            _encode(iv),
            _encode(encrypted[:-16]),
            _encode(encrypted[-16:]),
        )
    )


class _Keys:
    async def get_key(self, name, version=None):
        assert name == "permi-disclosure"
        return SimpleNamespace(
            key=SimpleNamespace(n=b"n", e=b"\x01\x00\x01"),
            properties=SimpleNamespace(version=version or "key-version"),
        )

    async def close(self):
        return None


class _Credential:
    async def close(self):
        return None


class _Crypto:
    cek = b"c" * 32

    def __init__(self, key, credential):
        assert key and credential

    async def decrypt(self, algorithm, ciphertext):
        assert algorithm and ciphertext == b"wrapped-key"
        return SimpleNamespace(plaintext=self.cek)

    async def close(self):
        return None


def _decryptor(monkeypatch: pytest.MonkeyPatch) -> KeyVaultDisclosureDecryptor:
    monkeypatch.setattr(module, "CryptographyClient", _Crypto)
    decryptor = object.__new__(KeyVaultDisclosureDecryptor)
    decryptor._keys = _Keys()
    decryptor._credential = _Credential()
    decryptor._key_name = "permi-disclosure"
    decryptor._current = None
    return decryptor


@pytest.mark.asyncio
async def test_valid_jwe_decrypts_and_preserves_catalog_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval = _approval()
    approval = replace(approval, compact_jwe=_compact(approval, cek=_Crypto.cek))
    decryptor = _decryptor(monkeypatch)
    await decryptor.start()
    assert decryptor.ready
    assert (await decryptor.current_key()).as_json()["kid"] == "key-version"
    values = await decryptor.decrypt(approval)
    assert [(item.key.value, item.value) for item in values] == [
        ("contact.personalEmail", "fictional@example.test")
    ]
    await decryptor.close()
    assert not decryptor.ready
    with pytest.raises(DisclosureError, match="unavailable"):
        await decryptor.current_key()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"alg": "RSA1_5"}, "algorithms"),
        ({"typ": "JWT"}, "type"),
        ({"request_id": str(uuid7())}, "another decision"),
        ({"approved_keys_hash": "wrong"}, "manifest"),
        ({"kid": ""}, "key version"),
    ],
)
async def test_jwe_header_tampering_fails_closed(monkeypatch, overrides, match) -> None:
    approval = _approval()
    compact = _compact(approval, cek=_Crypto.cek, overrides=overrides)
    approval = replace(approval, compact_jwe=compact)
    with pytest.raises(DisclosureError, match=match):
        await _decryptor(monkeypatch).decrypt(approval)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload_overrides", "match"),
    [
        ({"schema_version": 2}, "another request"),
        ({"decision_id": str(uuid7())}, "another decision"),
        ({"approved_fields": []}, "count"),
        ({"approved_fields": "bad"}, "array"),
        (
            {
                "approved_fields": [
                    {"key": "contact.personalEmail", "value_type": "text", "value": "x"}
                ]
            },
            "metadata",
        ),
        (
            {
                "approved_fields": [
                    {"key": "contact.personalEmail", "value_type": "email", "value": ""}
                ]
            },
            "invalid size",
        ),
    ],
)
async def test_jwe_plaintext_tampering_fails_closed(monkeypatch, payload_overrides, match) -> None:
    approval = _approval()
    compact = _compact(approval, cek=_Crypto.cek, payload_overrides=payload_overrides)
    approval = replace(approval, compact_jwe=compact)
    with pytest.raises(DisclosureError, match=match):
        await _decryptor(monkeypatch).decrypt(approval)


@pytest.mark.asyncio
async def test_malformed_and_authenticated_ciphertext_fail_closed(monkeypatch) -> None:
    decryptor = _decryptor(monkeypatch)
    approval = _approval()
    for compact in (None, "one.two", "=bad.a.b.c.d"):
        malformed = replace(approval, compact_jwe=compact)
        with pytest.raises(DisclosureError):
            await decryptor.decrypt(malformed)
    compact = _compact(approval, cek=_Crypto.cek)
    segments = compact.split(".")
    segments[3] = _encode(b"tampered")
    tampered = replace(approval, compact_jwe=".".join(segments))
    with pytest.raises(DisclosureError, match="authentication"):
        await decryptor.decrypt(tampered)

    _Crypto.cek = b"short"
    wrong_cek = replace(approval, compact_jwe=_compact(approval, cek=b"c" * 32))
    with pytest.raises(DisclosureError, match="wrong size"):
        await decryptor.decrypt(wrong_cek)
    _Crypto.cek = b"c" * 32


def test_hashes_and_strict_json_are_deterministic() -> None:
    assert approved_keys_hash(("a", "b")) != approved_keys_hash(("b", "a"))
    assert result_manifest_hash(
        available_keys=(),
        approved_keys=("a",),
        denied_keys=(),
        unavailable_keys=(),
        compact_jwe="one",
    ) != result_manifest_hash(
        available_keys=(),
        approved_keys=("a",),
        denied_keys=(),
        unavailable_keys=(),
        compact_jwe="two",
    )
    with pytest.raises(DisclosureError, match="duplicate"):
        module._json_object(b'{"a":1,"a":2}')
    with pytest.raises(DisclosureError, match="object"):
        module._json_object(b"[]")
    with pytest.raises(DisclosureError, match="malformed"):
        module._parse_time("not-a-time")
    with pytest.raises(DisclosureError, match="offset"):
        module._parse_time("2026-01-01T00:00:00")
    with pytest.raises(DisclosureError, match="timestamp"):
        module._parse_time(42)
    with pytest.raises(DisclosureError, match="malformed"):
        module._json_object(b"not-json")
    with pytest.raises(DisclosureError, match="members"):
        module._require_exact({"one": 1}, {"two"})
    for segment in ("", "YWJj=", "*", "YQ"):
        with pytest.raises(DisclosureError):
            module._decode(segment, 0 if segment == "YQ" else 8)


@pytest.mark.asyncio
async def test_fake_decryptor_requires_registered_fixture() -> None:
    fake = module.FakeDisclosureDecryptor()
    await fake.start()
    await fake.close()
    assert fake.ready
    assert (await fake.current_key()).kid == "fixture-key"
    with pytest.raises(DisclosureError, match="unavailable"):
        await fake.decrypt(_approval())


def test_production_decryptor_requires_workload_identity(settings: Settings) -> None:
    with pytest.raises(ValueError, match="workload identity"):
        KeyVaultDisclosureDecryptor(
            settings.model_copy(update={"key_vault_url": None, "azure_workload_client_id": None})
        )
