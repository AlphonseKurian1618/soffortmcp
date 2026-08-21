"""Tests for the durable phone-approval application service."""

import asyncio
import base64
from datetime import UTC, datetime
from uuid import uuid7

import pytest
from conftest import OBJECT_ID, TENANT_ID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from soffortbackend.approval import ApprovalError, ApprovalErrorCode, ApprovalService
from soffortbackend.device_security import decision_message
from soffortbackend.models import ApprovalStatus, Device, Principal, StoreConflict
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


def _principal(settings: Settings) -> Principal:
    return Principal(
        tenant_id=str(TENANT_ID),
        object_id=OBJECT_ID,
        client_id=str(settings.entra_vscode_client_id),
        client_kind="vscode",
    )


async def _configured_service(
    settings: Settings, *, notifier_accepts: bool = True
) -> tuple[
    ApprovalService,
    InMemoryApprovalStore,
    FakeApprovalNotifier,
    Principal,
    ec.EllipticCurvePrivateKey,
    Device,
]:
    store = InMemoryApprovalStore()
    notifier = FakeApprovalNotifier(accept=notifier_accepts)
    service = ApprovalService(settings, store, notifier)
    principal = _principal(settings)
    await store.put_profile(principal.partition_key, "Alphonse")
    private, public_jwk = _device_key()
    device = Device(
        partition_key=principal.partition_key,
        device_id=str(uuid7()),
        public_jwk=public_jwk,
        apns_token="ab" * 32,
        apns_environment="sandbox",
        notifications_enabled=True,
        updated_at=datetime.now(UTC),
    )
    store.devices[(principal.partition_key, device.device_id)] = device
    return service, store, notifier, principal, private, device


async def _wait_for_delivery(notifier: FakeApprovalNotifier) -> None:
    for _ in range(100):
        if notifier.deliveries:
            return
        await asyncio.sleep(0.001)
    raise AssertionError("approval notification was not attempted")


def _signed_decision(
    private: ec.EllipticCurvePrivateKey,
    principal: Principal,
    device: Device,
    approval,
    decision: str,
) -> tuple[int, str]:
    issued_at = int(datetime.now(UTC).timestamp())
    message = decision_message(
        tenant_id=principal.tenant_id,
        object_id=principal.object_id,
        device_id=device.device_id,
        approval_id=approval.approval_id,
        nonce=approval.nonce,
        tool_name=approval.tool_name,
        arguments_hash=approval.arguments_hash,
        decision=decision,
        issued_at=issued_at,
    )
    return issued_at, _encode(private.sign(message, ec.ECDSA(hashes.SHA256())))


@pytest.mark.asyncio
async def test_phone_approval_returns_profile_snapshot_and_is_idempotent(
    settings: Settings,
) -> None:
    service, store, notifier, principal, private, device = await _configured_service(settings)
    pending = asyncio.create_task(service.request_hello_world(principal))
    await _wait_for_delivery(notifier)
    approval = notifier.deliveries[0][0]
    persisted = await store.get_approval(principal.partition_key, approval.approval_id)
    assert persisted is not None
    issued_at, signature = _signed_decision(private, principal, device, persisted, "approved")
    decision_id = str(uuid7())

    decided = await service.decide(
        principal,
        approval_id=approval.approval_id,
        device_id=device.device_id,
        decision_id=decision_id,
        decision="approved",
        issued_at=issued_at,
        signature=signature,
    )
    replay = await service.decide(
        principal,
        approval_id=approval.approval_id,
        device_id=device.device_id,
        decision_id=decision_id,
        decision="approved",
        issued_at=issued_at,
        signature=signature,
    )

    assert decided.status is ApprovalStatus.APPROVED
    assert replay == decided
    assert await pending == "Alphonse"
    with pytest.raises(StoreConflict):
        await service.decide(
            principal,
            approval_id=approval.approval_id,
            device_id=device.device_id,
            decision_id=str(uuid7()),
            decision="denied",
            issued_at=issued_at,
            signature=signature,
        )


@pytest.mark.asyncio
async def test_denial_returns_closed_mcp_error(settings: Settings) -> None:
    service, store, notifier, principal, private, device = await _configured_service(settings)
    pending = asyncio.create_task(service.request_hello_world(principal))
    await _wait_for_delivery(notifier)
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None
    issued_at, signature = _signed_decision(private, principal, device, approval, "denied")
    await service.decide(
        principal,
        approval_id=approval.approval_id,
        device_id=device.device_id,
        decision_id=str(uuid7()),
        decision="denied",
        issued_at=issued_at,
        signature=signature,
    )
    with pytest.raises(ApprovalError) as raised:
        await pending
    assert raised.value.code is ApprovalErrorCode.APPROVAL_DENIED


@pytest.mark.asyncio
async def test_missing_profile_phone_and_delivery_fail_closed(settings: Settings) -> None:
    principal = _principal(settings)
    empty = InMemoryApprovalStore()
    with pytest.raises(ApprovalError) as missing_profile:
        await ApprovalService(settings, empty, FakeApprovalNotifier()).request_hello_world(
            principal
        )
    assert missing_profile.value.code is ApprovalErrorCode.PROFILE_REQUIRED

    await empty.put_profile(principal.partition_key, "Alphonse")
    with pytest.raises(ApprovalError) as missing_phone:
        await ApprovalService(settings, empty, FakeApprovalNotifier()).request_hello_world(
            principal
        )
    assert missing_phone.value.code is ApprovalErrorCode.PHONE_NOT_LINKED

    service, _, _, principal, _, _ = await _configured_service(settings, notifier_accepts=False)
    with pytest.raises(ApprovalError) as delivery:
        await service.request_hello_world(principal)
    assert delivery.value.code is ApprovalErrorCode.NOTIFICATIONS_UNAVAILABLE


@pytest.mark.asyncio
async def test_timeout_and_cancellation_close_pending_approvals(settings: Settings) -> None:
    fast = settings.model_copy(
        update={"approval_timeout_seconds": 0.03, "approval_poll_interval_seconds": 0.005}
    )
    service, store, notifier, principal, _, _ = await _configured_service(fast)
    with pytest.raises(ApprovalError) as timed_out:
        await service.request_hello_world(principal)
    assert timed_out.value.code is ApprovalErrorCode.APPROVAL_TIMED_OUT
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None and approval.status is ApprovalStatus.EXPIRED

    slower = settings.model_copy(
        update={"approval_timeout_seconds": 1, "approval_poll_interval_seconds": 0.01}
    )
    service, store, notifier, principal, _, _ = await _configured_service(slower)
    task = asyncio.create_task(service.request_hello_world(principal))
    await _wait_for_delivery(notifier)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None and approval.status is ApprovalStatus.CANCELLED


@pytest.mark.asyncio
async def test_wrong_device_signature_is_rejected(settings: Settings) -> None:
    service, store, notifier, principal, _, device = await _configured_service(settings)
    pending = asyncio.create_task(service.request_hello_world(principal))
    await _wait_for_delivery(notifier)
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None
    with pytest.raises(ValueError, match="invalid"):
        await service.decide(
            principal,
            approval_id=approval.approval_id,
            device_id=device.device_id,
            decision_id=str(uuid7()),
            decision="approved",
            issued_at=int(datetime.now(UTC).timestamp()),
            signature=_encode(b"invalid"),
        )
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
