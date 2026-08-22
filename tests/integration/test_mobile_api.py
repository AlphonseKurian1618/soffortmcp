"""HTTP integration tests for the authenticated Concentrey consent surface."""

import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid7

import httpx
import pytest
from conftest import EMAIL_KEY, OBJECT_ID, TENANT_ID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from soffortbackend.app import create_app
from soffortbackend.device_security import decision_message, enrollment_message, jwk_thumbprint
from soffortbackend.disclosure import result_manifest_hash
from soffortbackend.models import Approval, ApprovalStatus
from soffortbackend.notifications import FakeApprovalNotifier
from soffortbackend.settings import Settings
from soffortbackend.store import InMemoryApprovalStore


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _device_key() -> tuple[ec.EllipticCurvePrivateKey, dict[str, str]]:
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    return private, {
        "kty": "EC",
        "crv": "P-256",
        "x": _encode(numbers.x.to_bytes(32, "big")),
        "y": _encode(numbers.y.to_bytes(32, "big")),
    }


@pytest.mark.asyncio
async def test_mobile_auth_and_removed_profile_surface(settings: Settings, fake_verifier) -> None:
    app = create_app(settings, token_verifier=fake_verifier)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            metadata = await client.get("/.well-known/oauth-protected-resource/v1")
            missing = await client.post("/v1/devices/enrollment-challenges")
            wrong_client = await client.post(
                "/v1/devices/enrollment-challenges",
                headers={"Authorization": "Bearer valid-test-token"},
            )
            challenge = await client.post(
                "/v1/devices/enrollment-challenges",
                headers={"Authorization": "Bearer valid-mobile-token"},
            )
            removed_profile = await client.get(
                "/v1/me/profile",
                headers={"Authorization": "Bearer valid-mobile-token"},
            )

    assert metadata.status_code == 200
    assert metadata.json()["scopes_supported"] == [settings.mobile_scope_uri]
    assert missing.status_code == 401
    assert "oauth-protected-resource/v1" in missing.headers["www-authenticate"]
    assert wrong_client.status_code == 403
    assert challenge.status_code == 201
    assert removed_profile.status_code == 404


@pytest.mark.asyncio
async def test_device_enrollment_pending_recovery_and_signed_decision(
    settings: Settings, fake_verifier
) -> None:
    store = InMemoryApprovalStore()
    app = create_app(
        settings,
        token_verifier=fake_verifier,
        approval_store=store,
        notifier=FakeApprovalNotifier(),
    )
    headers = {"Authorization": "Bearer valid-mobile-token"}
    private, public_jwk = _device_key()
    device_id = str(uuid7())
    partition_key = f"{TENANT_ID}:{OBJECT_ID}"

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
            headers=headers,
        ) as client:
            challenge = (await client.post("/v1/devices/enrollment-challenges")).json()
            issued_at = int(datetime.now(UTC).timestamp())
            enrollment = enrollment_message(
                tenant_id=str(TENANT_ID),
                object_id=OBJECT_ID,
                device_id=device_id,
                challenge_id=challenge["challenge_id"],
                nonce=challenge["nonce"],
                thumbprint=jwk_thumbprint(public_jwk),
                issued_at=issued_at,
            )
            enrolled = await client.put(
                f"/v1/devices/{device_id}",
                json={
                    "challenge_id": challenge["challenge_id"],
                    "public_jwk": public_jwk,
                    "apns_token": "ab" * 32,
                    "apns_environment": "sandbox",
                    "notifications_enabled": True,
                    "issued_at": issued_at,
                    "signature": _encode(private.sign(enrollment, ec.ECDSA(hashes.SHA256()))),
                },
            )
            assert enrolled.status_code == 201, enrolled.text

            indexed = await client.put(
                "/v1/property-index",
                json={
                    "properties": [
                        {
                            "key": EMAIL_KEY,
                            "display_name": "Personal · Email",
                            "value_type": "email",
                            "sensitivity": "moderate",
                        }
                    ]
                },
            )
            assert indexed.status_code == 200, indexed.text
            assert indexed.json()["property_count"] == 1
            assert (await store.get_property_index(partition_key)).properties[0].key == EMAIL_KEY

            now = datetime.now(UTC)
            approval = Approval(
                partition_key=partition_key,
                approval_id=str(uuid7()),
                event_id=str(uuid7()),
                nonce="approval-nonce",
                tool_name="list_available_properties",
                arguments_hash="fixture-arguments-hash",
                requester="VS Code",
                purpose="List the properties currently available in this Concentrey vault.",
                requested_keys=(),
                created_at=now,
                expires_at=now + timedelta(seconds=60),
            )
            await store.create_approval(approval)
            fetched = await client.get(f"/v1/approvals/{approval.approval_id}")
            pending = await client.get("/v1/approvals")
            assert fetched.json()["contract_version"] == 3
            assert fetched.json()["disclosure_key"] is None
            assert [item["approval_id"] for item in pending.json()["requests"]] == [
                approval.approval_id
            ]

            decision_id = str(uuid7())
            decision_at = int(datetime.now(UTC).timestamp())
            manifest = {
                "available_keys": [],
                "approved_keys": [],
                "denied_keys": [],
                "unavailable_keys": [],
                "property_metadata": [],
                "compact_jwe": None,
            }
            result_hash = result_manifest_hash(
                available_keys=(),
                approved_keys=(),
                denied_keys=(),
                unavailable_keys=(),
                property_metadata=(),
                compact_jwe=None,
            )
            signed = decision_message(
                tenant_id=str(TENANT_ID),
                object_id=OBJECT_ID,
                device_id=device_id,
                approval_id=approval.approval_id,
                nonce=approval.nonce,
                tool_name=approval.tool_name,
                arguments_hash=approval.arguments_hash,
                decision="denied",
                result_hash=result_hash,
                issued_at=decision_at,
            )
            body = {
                "device_id": device_id,
                "decision_id": decision_id,
                "decision": "denied",
                "result": manifest,
                "result_hash": result_hash,
                "issued_at": decision_at,
                "signature": _encode(private.sign(signed, ec.ECDSA(hashes.SHA256()))),
            }
            decided = await client.post(
                f"/v1/approvals/{approval.approval_id}/decisions", json=body
            )
            replay = await client.post(f"/v1/approvals/{approval.approval_id}/decisions", json=body)
            deleted = await client.delete(f"/v1/devices/{device_id}")

    assert decided.status_code == 200
    assert decided.json()["status"] == ApprovalStatus.DENIED.value
    assert replay.status_code == 200
    assert deleted.status_code == 204
    assert await store.get_device(partition_key, device_id) is None
