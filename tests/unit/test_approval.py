"""Tests for the durable, result-bound phone consent service."""

import asyncio
import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest
from conftest import (
    EMAIL_KEY,
    EMAIL_METADATA,
    NAME_KEY,
    NAME_METADATA,
    OBJECT_ID,
    TENANT_ID,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from soffortbackend.approval import ApprovalError, ApprovalErrorCode, ApprovalService
from soffortbackend.device_security import decision_message
from soffortbackend.disclosure import (
    DisclosedProperty,
    FakeDisclosureDecryptor,
    result_manifest_hash,
)
from soffortbackend.models import (
    Approval,
    ApprovalStatus,
    Device,
    Principal,
    PropertyMetadata,
    StoreConflict,
)
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
    FakeDisclosureDecryptor,
    Principal,
    ec.EllipticCurvePrivateKey,
    Device,
]:
    store = InMemoryApprovalStore()
    notifier = FakeApprovalNotifier(accept=notifier_accepts)
    disclosure = FakeDisclosureDecryptor()
    service = ApprovalService(settings, store, notifier, disclosure)
    principal = _principal(settings)
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
    return service, store, notifier, disclosure, principal, private, device


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
    *,
    decision: str,
    available_keys: tuple[str, ...] = (),
    approved_keys: tuple[str, ...] = (),
    denied_keys: tuple[str, ...] = (),
    unavailable_keys: tuple[str, ...] = (),
    property_metadata: tuple[PropertyMetadata, ...] = (),
    compact_jwe: str | None = None,
) -> tuple[int, str, str]:
    result_hash = result_manifest_hash(
        available_keys=available_keys,
        approved_keys=approved_keys,
        denied_keys=denied_keys,
        unavailable_keys=unavailable_keys,
        property_metadata=property_metadata,
        compact_jwe=compact_jwe,
    )
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
        result_hash=result_hash,
        issued_at=issued_at,
    )
    signature = _encode(private.sign(message, ec.ECDSA(hashes.SHA256())))
    return issued_at, signature, result_hash


async def _decide(service, principal, device, approval, private, *, decision, **result):
    issued_at, signature, result_hash = _signed_decision(
        private, principal, device, approval, decision=decision, **result
    )
    return await service.decide(
        principal,
        approval_id=approval.approval_id,
        device_id=device.device_id,
        decision_id=str(uuid7()),
        decision=decision,
        result_hash=result_hash,
        issued_at=issued_at,
        signature=signature,
        **result,
    )


@pytest.mark.asyncio
async def test_discovery_returns_only_available_manifest(settings: Settings) -> None:
    service, store, notifier, _, principal, private, device = await _configured_service(settings)
    pending = asyncio.create_task(service.request_available_properties(principal))
    await _wait_for_delivery(notifier)
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None
    keys = (EMAIL_KEY, NAME_KEY)
    await _decide(
        service,
        principal,
        device,
        approval,
        private,
        decision="approved",
        available_keys=keys,
        approved_keys=(),
        denied_keys=(),
        unavailable_keys=(),
        property_metadata=(EMAIL_METADATA, NAME_METADATA),
        compact_jwe=None,
    )
    assert (await pending).available_keys == keys


@pytest.mark.asyncio
async def test_denial_is_a_structured_business_outcome(settings: Settings) -> None:
    service, store, notifier, _, principal, private, device = await _configured_service(settings)
    pending = asyncio.create_task(service.request_available_properties(principal))
    await _wait_for_delivery(notifier)
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None
    await _decide(
        service,
        principal,
        device,
        approval,
        private,
        decision="denied",
        available_keys=(),
        approved_keys=(),
        denied_keys=(),
        unavailable_keys=(),
        property_metadata=(),
        compact_jwe=None,
    )
    assert (await pending).status is ApprovalStatus.DENIED


@pytest.mark.asyncio
async def test_request_decrypts_only_approved_properties(settings: Settings) -> None:
    service, store, notifier, disclosure, principal, private, device = await _configured_service(
        settings
    )
    requested = (EMAIL_KEY, NAME_KEY)
    pending = asyncio.create_task(
        service.request_properties(principal, requested, "Send my receipt")
    )
    await _wait_for_delivery(notifier)
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None
    disclosure.values[approval.approval_id] = (DisclosedProperty(EMAIL_KEY, "person@example.test"),)
    await _decide(
        service,
        principal,
        device,
        approval,
        private,
        decision="approved",
        available_keys=(),
        approved_keys=(EMAIL_KEY,),
        denied_keys=(NAME_KEY,),
        unavailable_keys=(),
        property_metadata=(EMAIL_METADATA, NAME_METADATA),
        compact_jwe="fixture",
    )
    result, values = await pending
    assert result.approved_keys == (EMAIL_KEY,)
    assert values == disclosure.values[approval.approval_id]


@pytest.mark.asyncio
async def test_missing_phone_and_delivery_fail_closed(settings: Settings) -> None:
    principal = _principal(settings)
    disclosure = FakeDisclosureDecryptor()
    with pytest.raises(ApprovalError) as missing_phone:
        await ApprovalService(
            settings, InMemoryApprovalStore(), FakeApprovalNotifier(), disclosure
        ).request_available_properties(principal)
    assert missing_phone.value.code is ApprovalErrorCode.PHONE_NOT_LINKED

    service, _, _, _, principal, _, _ = await _configured_service(settings, notifier_accepts=False)
    with pytest.raises(ApprovalError) as delivery:
        await service.request_available_properties(principal)
    assert delivery.value.code is ApprovalErrorCode.NOTIFICATIONS_UNAVAILABLE


@pytest.mark.asyncio
async def test_timeout_and_cancellation_close_pending_approvals(settings: Settings) -> None:
    fast = settings.model_copy(
        update={"approval_timeout_seconds": 0.03, "approval_poll_interval_seconds": 0.005}
    )
    service, store, notifier, _, principal, _, _ = await _configured_service(fast)
    with pytest.raises(ApprovalError) as timed_out:
        await service.request_available_properties(principal)
    assert timed_out.value.code is ApprovalErrorCode.APPROVAL_TIMED_OUT
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None and approval.status is ApprovalStatus.EXPIRED

    slower = settings.model_copy(
        update={"approval_timeout_seconds": 1, "approval_poll_interval_seconds": 0.01}
    )
    service, store, notifier, _, principal, _, _ = await _configured_service(slower)
    task = asyncio.create_task(service.request_available_properties(principal))
    await _wait_for_delivery(notifier)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None and approval.status is ApprovalStatus.CANCELLED


@pytest.mark.asyncio
async def test_result_tampering_and_replay_are_rejected(settings: Settings) -> None:
    service, store, notifier, _, principal, private, device = await _configured_service(settings)
    pending = asyncio.create_task(service.request_available_properties(principal))
    await _wait_for_delivery(notifier)
    approval = await store.get_approval(
        principal.partition_key, notifier.deliveries[0][0].approval_id
    )
    assert approval is not None
    with pytest.raises(ValueError, match="result_hash"):
        await service.decide(
            principal,
            approval_id=approval.approval_id,
            device_id=device.device_id,
            decision_id=str(uuid7()),
            decision="approved",
            available_keys=(),
            approved_keys=(),
            denied_keys=(),
            unavailable_keys=(),
            property_metadata=(),
            compact_jwe=None,
            result_hash="tampered",
            issued_at=int(datetime.now(UTC).timestamp()),
            signature="invalid",
        )
    decided = await _decide(
        service,
        principal,
        device,
        approval,
        private,
        decision="denied",
        available_keys=(),
        approved_keys=(),
        denied_keys=(),
        unavailable_keys=(),
        property_metadata=(),
        compact_jwe=None,
    )
    assert (await pending).status is ApprovalStatus.DENIED
    with pytest.raises(StoreConflict):
        await _decide(
            service,
            principal,
            device,
            decided,
            private,
            decision="approved",
            available_keys=(),
            approved_keys=(),
            denied_keys=(),
            unavailable_keys=(),
            property_metadata=(),
            compact_jwe=None,
        )


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"available_keys": (EMAIL_KEY,) * 2}, "duplicate"),
        ({"available_keys": ("unknown",)}, "invalid"),
        ({"decision": "denied", "available_keys": (EMAIL_KEY,)}, "denial"),
        (
            {"tool_name": "list_available_properties", "approved_keys": (EMAIL_KEY,)},
            "availability",
        ),
        ({"approved_keys": (), "denied_keys": ()}, "partition"),
        (
            {
                "requested_keys": (EMAIL_KEY, NAME_KEY),
                "approved_keys": (NAME_KEY, EMAIL_KEY),
            },
            "preserve request order",
        ),
        ({"approved_keys": (EMAIL_KEY,), "compact_jwe": None}, "encrypted"),
    ],
)
def test_consent_result_shape_fails_closed(settings: Settings, changes, match) -> None:
    now = datetime.now(UTC)
    values = {
        "tool_name": "request_properties",
        "decision": "approved",
        "requested_keys": (EMAIL_KEY,),
        "available_keys": (),
        "approved_keys": (EMAIL_KEY,),
        "denied_keys": (),
        "unavailable_keys": (),
        "property_metadata": (EMAIL_METADATA,),
        "compact_jwe": "fixture",
    }
    values.update(changes)
    approval = Approval(
        partition_key="tenant:subject",
        approval_id=str(uuid7()),
        event_id=str(uuid7()),
        nonce="nonce",
        tool_name=values.pop("tool_name"),
        arguments_hash="hash",
        requester="VS Code",
        purpose="Test",
        requested_keys=values.pop("requested_keys"),
        created_at=now,
        expires_at=now + timedelta(minutes=2),
    )
    service = ApprovalService(
        settings, InMemoryApprovalStore(), FakeApprovalNotifier(), FakeDisclosureDecryptor()
    )
    with pytest.raises(ValueError, match=match):
        service._validate_result(approval, **values)
