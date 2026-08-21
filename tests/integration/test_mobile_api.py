"""HTTP integration tests for the authenticated iPhone approval surface."""

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid7

import httpx
import pytest
from conftest import OBJECT_ID, TENANT_ID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from soffortbackend.app import create_app
from soffortbackend.device_security import (
    decision_message,
    enrollment_message,
    jwk_thumbprint,
)
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
async def test_mobile_auth_profile_and_body_boundaries(settings: Settings, fake_verifier) -> None:
    store = InMemoryApprovalStore()
    app = create_app(
        settings,
        token_verifier=fake_verifier,
        approval_store=store,
        notifier=FakeApprovalNotifier(),
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            metadata = await client.get("/.well-known/oauth-protected-resource/v1")
            missing = await client.get("/v1/me/profile")
            wrong_client = await client.get(
                "/v1/me/profile",
                headers={"Authorization": "Bearer valid-test-token"},
            )
            created = await client.put(
                "/v1/me/profile",
                headers={"Authorization": "Bearer valid-mobile-token"},
                json={"display_name": "  A\u0301lphonse  "},
            )
            fetched = await client.get(
                "/v1/me/profile",
                headers={"Authorization": "Bearer valid-mobile-token"},
            )
            malformed = await client.put(
                "/v1/me/profile",
                headers={"Authorization": "Bearer valid-mobile-token"},
                json={"display_name": "Name", "unexpected": True},
            )
            oversized = await client.put(
                "/v1/me/profile",
                headers={
                    "Authorization": "Bearer valid-mobile-token",
                    "Content-Type": "application/json",
                },
                content=b"x" * (64 * 1024 + 1),
            )

    assert metadata.status_code == 200
    assert metadata.json()["scopes_supported"] == [settings.mobile_scope_uri]
    assert missing.status_code == 401
    assert "oauth-protected-resource/v1" in missing.headers["www-authenticate"]
    assert wrong_client.status_code == 403
    assert created.status_code == 200
    assert created.json()["display_name"] == "Álphonse"
    assert fetched.json()["version"] == 1
    assert malformed.status_code == 400
    assert oversized.status_code == 413


@pytest.mark.asyncio
async def test_device_enrollment_fetch_and_signed_decision(
    settings: Settings, fake_verifier
) -> None:
    store = InMemoryApprovalStore()
    notifier = FakeApprovalNotifier()
    app = create_app(
        settings,
        token_verifier=fake_verifier,
        approval_store=store,
        notifier=notifier,
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
            profile_required = await client.post("/v1/devices/enrollment-challenges")
            assert profile_required.status_code == 409
            await client.put("/v1/me/profile", json={"display_name": "Alphonse"})
            challenge_response = await client.post("/v1/devices/enrollment-challenges")
            challenge = challenge_response.json()
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

            now = datetime.now(UTC)
            approval = Approval(
                partition_key=partition_key,
                approval_id=str(uuid7()),
                event_id=str(uuid7()),
                nonce="approval-nonce",
                tool_name="hello_world",
                arguments_hash=_encode(hashlib.sha256(b"{}").digest()),
                requester="VS Code",
                display_name_snapshot="Alphonse",
                profile_version=1,
                created_at=now,
                expires_at=now + timedelta(seconds=60),
            )
            await store.create_approval(approval)
            fetched = await client.get(f"/v1/approvals/{approval.approval_id}")
            assert fetched.status_code == 200
            assert fetched.json()["tool_name"] == "hello_world"

            decision_id = str(uuid7())
            decision_at = int(datetime.now(UTC).timestamp())
            decision = decision_message(
                tenant_id=str(TENANT_ID),
                object_id=OBJECT_ID,
                device_id=device_id,
                approval_id=approval.approval_id,
                nonce=approval.nonce,
                tool_name=approval.tool_name,
                arguments_hash=approval.arguments_hash,
                decision="approved",
                issued_at=decision_at,
            )
            decided = await client.post(
                f"/v1/approvals/{approval.approval_id}/decisions",
                json={
                    "device_id": device_id,
                    "decision_id": decision_id,
                    "decision": "approved",
                    "issued_at": decision_at,
                    "signature": _encode(private.sign(decision, ec.ECDSA(hashes.SHA256()))),
                },
            )
            replay = await client.post(
                f"/v1/approvals/{approval.approval_id}/decisions",
                json={
                    "device_id": device_id,
                    "decision_id": decision_id,
                    "decision": "approved",
                    "issued_at": decision_at,
                    "signature": _encode(private.sign(decision, ec.ECDSA(hashes.SHA256()))),
                },
            )
            deleted = await client.delete(f"/v1/devices/{device_id}")

    assert decided.status_code == 200
    assert decided.json()["status"] == ApprovalStatus.APPROVED.value
    assert replay.status_code == 200
    assert deleted.status_code == 204
    assert await store.get_device(partition_key, device_id) is None
