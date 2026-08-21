"""Application service coordinating MCP calls, devices, APNs, and decisions."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import uuid7

from soffortbackend.device_security import decision_message, verify_signature
from soffortbackend.models import Approval, ApprovalStatus, Principal, StoreConflict
from soffortbackend.notifications import ApprovalNotifier, NotificationUnavailable
from soffortbackend.settings import Settings
from soffortbackend.store import ApprovalStore


class ApprovalErrorCode(StrEnum):
    """Stable, value-free outcomes safe to expose to an MCP caller."""

    PROFILE_REQUIRED = "profile_required"
    PHONE_NOT_LINKED = "phone_not_linked"
    NOTIFICATIONS_UNAVAILABLE = "notifications_unavailable"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_TIMED_OUT = "approval_timed_out"
    APPROVAL_UNAVAILABLE = "approval_unavailable"


class ApprovalError(Exception):
    """Expected approval failure carrying only a public reason code."""

    def __init__(self, code: ApprovalErrorCode) -> None:
        """Create an expected failure from its stable public code."""
        self.code = code
        super().__init__(code.value)


class ApprovalService:
    """Coordinate a single-use phone approval without process-local sessions."""

    def __init__(
        self,
        settings: Settings,
        store: ApprovalStore,
        notifier: ApprovalNotifier,
    ) -> None:
        """Bind the workflow to validated settings and shared adapters."""
        self.settings = settings
        self.store = store
        self.notifier = notifier

    async def request_hello_world(self, principal: Principal) -> str:
        """Wait for an iPhone decision and return the approved profile snapshot."""
        approval: Approval | None = None
        try:
            profile = await self.store.get_profile(principal.partition_key)
            if profile is None:
                raise ApprovalError(ApprovalErrorCode.PROFILE_REQUIRED)
            devices = await self.store.list_active_devices(principal.partition_key)
            if not devices:
                raise ApprovalError(ApprovalErrorCode.PHONE_NOT_LINKED)

            now = datetime.now(UTC)
            arguments_hash = _hash_arguments({})
            approval = Approval(
                partition_key=principal.partition_key,
                approval_id=str(uuid7()),
                event_id=str(uuid7()),
                nonce=_random_nonce(),
                tool_name="hello_world",
                arguments_hash=arguments_hash,
                requester="VS Code",
                display_name_snapshot=profile.display_name,
                profile_version=profile.version,
                created_at=now,
                expires_at=now + timedelta(seconds=self.settings.approval_timeout_seconds),
            )
            await self.store.create_approval(approval)
            persisted = await self.store.get_approval(principal.partition_key, approval.approval_id)
            if persisted is None:
                raise ApprovalError(ApprovalErrorCode.APPROVAL_UNAVAILABLE)
            approval = persisted
            try:
                delivery = await self.notifier.send_approval(approval, devices)
            except NotificationUnavailable as error:
                await self._best_effort_close(approval, ApprovalStatus.CANCELLED)
                raise ApprovalError(ApprovalErrorCode.NOTIFICATIONS_UNAVAILABLE) from error
            for device_id in delivery.invalid_device_ids:
                await self.store.disable_device(principal.partition_key, device_id)
            if not delivery.accepted_device_ids:
                await self._best_effort_close(approval, ApprovalStatus.CANCELLED)
                raise ApprovalError(ApprovalErrorCode.NOTIFICATIONS_UNAVAILABLE)
            return await self._wait_for_decision(approval)
        except ApprovalError:
            raise
        except asyncio.CancelledError:
            if approval is not None:
                await self._best_effort_close(approval, ApprovalStatus.CANCELLED)
            raise
        except Exception as error:
            # Transport details, Cosmos bodies, device IDs, and profile names
            # remain server-only. The caller receives one closed failure code.
            raise ApprovalError(ApprovalErrorCode.APPROVAL_UNAVAILABLE) from error

    async def decide(
        self,
        principal: Principal,
        *,
        approval_id: str,
        device_id: str,
        decision_id: str,
        decision: str,
        issued_at: int,
        signature: str,
    ) -> Approval:
        """Verify a device-bound decision and conditionally commit the first one."""
        approval = await self.store.get_approval(principal.partition_key, approval_id)
        device = await self.store.get_device(principal.partition_key, device_id)
        if approval is None or device is None or not device.notifications_enabled:
            raise StoreConflict("approval or active device does not exist")
        desired = ApprovalStatus.APPROVED if decision == "approved" else ApprovalStatus.DENIED
        if approval.status is not ApprovalStatus.PENDING:
            if (
                approval.status is desired
                and approval.decision_id == decision_id
                and approval.decided_by_device_id == device_id
            ):
                return approval
            raise StoreConflict("approval was already decided")
        if approval.expired:
            await self._best_effort_close(approval, ApprovalStatus.EXPIRED)
            raise StoreConflict("approval expired")

        message = decision_message(
            tenant_id=principal.tenant_id,
            object_id=principal.object_id,
            device_id=device_id,
            approval_id=approval_id,
            nonce=approval.nonce,
            tool_name=approval.tool_name,
            arguments_hash=approval.arguments_hash,
            decision=decision,
            issued_at=issued_at,
        )
        verify_signature(device.public_jwk, message, signature)
        return await self.store.decide_approval(
            approval,
            status=desired,
            device_id=device_id,
            decision_id=decision_id,
            decided_at=datetime.now(UTC),
        )

    async def _wait_for_decision(self, approval: Approval) -> str:
        deadline = time.monotonic() + self.settings.approval_timeout_seconds
        while time.monotonic() < deadline:
            current = await self.store.get_approval(approval.partition_key, approval.approval_id)
            if current is None:
                raise ApprovalError(ApprovalErrorCode.APPROVAL_UNAVAILABLE)
            if current.status is ApprovalStatus.APPROVED:
                return current.display_name_snapshot
            if current.status is ApprovalStatus.DENIED:
                raise ApprovalError(ApprovalErrorCode.APPROVAL_DENIED)
            if current.status in {ApprovalStatus.CANCELLED, ApprovalStatus.EXPIRED}:
                raise ApprovalError(ApprovalErrorCode.APPROVAL_TIMED_OUT)
            await asyncio.sleep(self.settings.approval_poll_interval_seconds)
        latest = await self.store.get_approval(approval.partition_key, approval.approval_id)
        if latest is not None:
            if latest.status is ApprovalStatus.APPROVED:
                return latest.display_name_snapshot
            if latest.status is ApprovalStatus.DENIED:
                raise ApprovalError(ApprovalErrorCode.APPROVAL_DENIED)
            await self._best_effort_close(latest, ApprovalStatus.EXPIRED)
        raise ApprovalError(ApprovalErrorCode.APPROVAL_TIMED_OUT)

    async def _best_effort_close(self, approval: Approval, status: ApprovalStatus) -> None:
        try:
            await self.store.close_approval(approval, status=status)
        except Exception:
            # A concurrent phone decision is authoritative. Cleanup is TTL-backed,
            # so a store outage here must not replace the original caller outcome.
            return


def _hash_arguments(arguments: dict[str, object]) -> str:
    encoded = json.dumps(arguments, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(encoded).digest()).rstrip(b"=").decode()


def _random_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
