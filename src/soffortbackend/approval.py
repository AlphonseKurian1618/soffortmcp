"""Application service coordinating MCP consent, APNs, and signed decisions."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
import unicodedata
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import uuid7

from soffortbackend.catalog import MAX_AVAILABLE_PROPERTIES, PROPERTY_KEY_PATTERN
from soffortbackend.device_security import decision_message, verify_signature
from soffortbackend.disclosure import (
    DisclosedProperty,
    DisclosureDecryptor,
    result_manifest_hash,
)
from soffortbackend.models import (
    Approval,
    ApprovalStatus,
    Principal,
    PropertyMetadata,
    StoreConflict,
)
from soffortbackend.notifications import ApprovalNotifier, NotificationUnavailable
from soffortbackend.settings import Settings
from soffortbackend.store import ApprovalStore

LIST_TOOL = "list_available_properties"
REQUEST_TOOL = "request_properties"


class ApprovalErrorCode(StrEnum):
    """Stable, value-free failures safe to expose to an MCP caller."""

    PHONE_NOT_LINKED = "phone_not_linked"
    NOTIFICATIONS_UNAVAILABLE = "notifications_unavailable"
    APPROVAL_TIMED_OUT = "approval_timed_out"
    APPROVAL_UNAVAILABLE = "approval_unavailable"
    DISCLOSURE_INVALID = "disclosure_invalid"


class ApprovalError(Exception):
    """Expected consent failure carrying only a public reason code."""

    def __init__(self, code: ApprovalErrorCode) -> None:
        """Create an expected failure from its stable public code."""
        self.code = code
        super().__init__(code.value)


class ApprovalService:
    """Coordinate one-time phone decisions without process-local sessions."""

    def __init__(
        self,
        settings: Settings,
        store: ApprovalStore,
        notifier: ApprovalNotifier,
        disclosure: DisclosureDecryptor,
    ) -> None:
        """Bind the workflow to shared storage, push, and disclosure adapters."""
        self.settings = settings
        self.store = store
        self.notifier = notifier
        self.disclosure = disclosure

    async def request_available_properties(self, principal: Principal) -> Approval:
        """Ask the phone to disclose its populated value-free field manifest."""
        return await self._request(
            principal,
            tool_name=LIST_TOOL,
            purpose="List the properties currently available in this Consentary vault.",
            requested_keys=(),
            arguments={},
        )

    async def request_properties(
        self,
        principal: Principal,
        requested_keys: tuple[str, ...],
        purpose: str,
    ) -> tuple[Approval, tuple[DisclosedProperty, ...]]:
        """Ask for selected local values and decrypt only an approved JWE."""
        raw_keys = requested_keys
        approval = await self._request(
            principal,
            tool_name=REQUEST_TOOL,
            purpose=purpose,
            requested_keys=raw_keys,
            arguments={"properties": list(raw_keys), "purpose": purpose},
        )
        if approval.status is ApprovalStatus.DENIED or not approval.approved_keys:
            return approval, ()
        try:
            values = await self.disclosure.decrypt(approval)
        except Exception as error:
            # Azure/provider details and ciphertext never become MCP text.
            raise ApprovalError(ApprovalErrorCode.DISCLOSURE_INVALID) from error
        return approval, values

    async def _request(
        self,
        principal: Principal,
        *,
        tool_name: str,
        purpose: str,
        requested_keys: tuple[str, ...],
        arguments: dict[str, object],
    ) -> Approval:
        approval: Approval | None = None
        try:
            devices = await self.store.list_active_devices(principal.partition_key)
            if not devices:
                raise ApprovalError(ApprovalErrorCode.PHONE_NOT_LINKED)
            now = datetime.now(UTC)
            approval = Approval(
                partition_key=principal.partition_key,
                approval_id=str(uuid7()),
                event_id=str(uuid7()),
                nonce=_random_nonce(),
                tool_name=tool_name,
                arguments_hash=_hash_arguments(arguments),
                requester="VS Code",
                purpose=purpose,
                requested_keys=requested_keys,
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
            raise ApprovalError(ApprovalErrorCode.APPROVAL_UNAVAILABLE) from error

    async def decide(
        self,
        principal: Principal,
        *,
        approval_id: str,
        device_id: str,
        decision_id: str,
        decision: str,
        available_keys: tuple[str, ...],
        approved_keys: tuple[str, ...],
        denied_keys: tuple[str, ...],
        unavailable_keys: tuple[str, ...],
        property_metadata: tuple[PropertyMetadata, ...],
        compact_jwe: str | None,
        result_hash: str,
        issued_at: int,
        signature: str,
    ) -> Approval:
        """Verify a result-bound device decision and commit the first writer."""
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
                and approval.result_hash == result_hash
            ):
                return approval
            raise StoreConflict("approval was already decided")
        if approval.expired:
            await self._best_effort_close(approval, ApprovalStatus.EXPIRED)
            raise StoreConflict("approval expired")
        self._validate_result(
            approval,
            decision=decision,
            available_keys=available_keys,
            approved_keys=approved_keys,
            denied_keys=denied_keys,
            unavailable_keys=unavailable_keys,
            property_metadata=property_metadata,
            compact_jwe=compact_jwe,
        )
        expected_hash = result_manifest_hash(
            available_keys=available_keys,
            approved_keys=approved_keys,
            denied_keys=denied_keys,
            unavailable_keys=unavailable_keys,
            property_metadata=property_metadata,
            compact_jwe=compact_jwe,
        )
        if result_hash != expected_hash:
            raise ValueError("result_hash does not match the consent manifest")
        message = decision_message(
            tenant_id=principal.tenant_id,
            object_id=principal.object_id,
            device_id=device_id,
            approval_id=approval_id,
            nonce=approval.nonce,
            tool_name=approval.tool_name,
            arguments_hash=approval.arguments_hash,
            decision=decision,
            result_hash=result_hash,
            issued_at=issued_at,
        )
        verify_signature(device.public_jwk, message, signature)
        return await self.store.decide_approval(
            approval,
            status=desired,
            device_id=device_id,
            decision_id=decision_id,
            decided_at=datetime.now(UTC),
            available_keys=available_keys,
            approved_keys=approved_keys,
            denied_keys=denied_keys,
            unavailable_keys=unavailable_keys,
            property_metadata=property_metadata,
            compact_jwe=compact_jwe,
            result_hash=result_hash,
        )

    def _validate_result(
        self,
        approval: Approval,
        *,
        decision: str,
        available_keys: tuple[str, ...],
        approved_keys: tuple[str, ...],
        denied_keys: tuple[str, ...],
        unavailable_keys: tuple[str, ...],
        property_metadata: tuple[PropertyMetadata, ...],
        compact_jwe: str | None,
    ) -> None:
        all_lists = (available_keys, approved_keys, denied_keys, unavailable_keys)
        if any(len(values) != len(set(values)) for values in all_lists):
            raise ValueError("consent result contains duplicate property keys")
        if any(
            PROPERTY_KEY_PATTERN.fullmatch(key) is None for values in all_lists for key in values
        ):
            raise ValueError("consent result contains an invalid property key")
        self._validate_metadata(property_metadata)
        if decision == "denied":
            if any(all_lists) or property_metadata or compact_jwe is not None:
                raise ValueError("denial cannot include property metadata or ciphertext")
            return
        if approval.tool_name == LIST_TOOL:
            if approved_keys or denied_keys or unavailable_keys or compact_jwe is not None:
                raise ValueError("availability response has an invalid shape")
            if len(available_keys) > MAX_AVAILABLE_PROPERTIES:
                raise ValueError("availability response contains too many properties")
            if tuple(item.key for item in property_metadata) != available_keys:
                raise ValueError("availability metadata must match property order")
            return
        requested = approval.requested_keys
        combined = approved_keys + denied_keys + unavailable_keys
        if len(combined) != len(set(combined)) or set(combined) != set(requested):
            raise ValueError("request result must partition every requested property")
        if tuple(key for key in requested if key in set(approved_keys)) != approved_keys:
            raise ValueError("approved properties must preserve request order")
        locally_available = tuple(key for key in requested if key not in set(unavailable_keys))
        if tuple(item.key for item in property_metadata) != locally_available:
            raise ValueError("request metadata must match locally available property order")
        if bool(approved_keys) != bool(compact_jwe):
            raise ValueError("approved properties require exactly one encrypted disclosure")

    @staticmethod
    def _validate_metadata(metadata: tuple[PropertyMetadata, ...]) -> None:
        """Validate bounded phone-authored labels without accepting values."""
        allowed_types = {
            "text",
            "long_text",
            "identifier",
            "email",
            "phone",
            "url",
            "date",
            "date_time",
            "integer",
            "decimal",
            "boolean",
            "choice",
            "country_region",
            "money",
            "measurement",
        }
        allowed_sensitivity = {"low", "moderate", "sensitive", "highly_sensitive"}
        if len({item.key for item in metadata}) != len(metadata):
            raise ValueError("property metadata contains duplicate keys")
        for item in metadata:
            display_name = unicodedata.normalize("NFC", item.display_name.strip())
            if (
                PROPERTY_KEY_PATTERN.fullmatch(item.key) is None
                # Item titles (120) and custom field labels (80) are both
                # locally bounded; allow their separator without truncation.
                or not 1 <= len(display_name) <= 240
                or display_name != item.display_name
                or any(
                    unicodedata.category(character).startswith("C") for character in display_name
                )
                or item.value_type not in allowed_types
                or item.sensitivity not in allowed_sensitivity
            ):
                raise ValueError("property metadata is invalid")

    async def _wait_for_decision(self, approval: Approval) -> Approval:
        deadline = time.monotonic() + self.settings.approval_timeout_seconds
        while time.monotonic() < deadline:
            current = await self.store.get_approval(approval.partition_key, approval.approval_id)
            if current is None:
                raise ApprovalError(ApprovalErrorCode.APPROVAL_UNAVAILABLE)
            if current.status in {ApprovalStatus.APPROVED, ApprovalStatus.DENIED}:
                return current
            if current.status in {ApprovalStatus.CANCELLED, ApprovalStatus.EXPIRED}:
                raise ApprovalError(ApprovalErrorCode.APPROVAL_TIMED_OUT)
            await asyncio.sleep(self.settings.approval_poll_interval_seconds)
        latest = await self.store.get_approval(approval.partition_key, approval.approval_id)
        if latest is not None:
            if latest.status in {ApprovalStatus.APPROVED, ApprovalStatus.DENIED}:
                return latest
            await self._best_effort_close(latest, ApprovalStatus.EXPIRED)
        raise ApprovalError(ApprovalErrorCode.APPROVAL_TIMED_OUT)

    async def _best_effort_close(self, approval: Approval, status: ApprovalStatus) -> None:
        try:
            await self.store.close_approval(approval, status=status)
        except Exception:
            return


def _hash_arguments(arguments: dict[str, object]) -> str:
    encoded = json.dumps(arguments, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(encoded).digest()).rstrip(b"=").decode()


def _random_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
