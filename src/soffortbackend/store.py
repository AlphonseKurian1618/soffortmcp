"""Shared approval persistence with in-memory and Azure Cosmos implementations."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import asdict, replace
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from azure.core import MatchConditions
from azure.cosmos.aio import CosmosClient
from azure.cosmos.exceptions import (
    CosmosAccessConditionFailedError,
    CosmosHttpResponseError,
    CosmosResourceNotFoundError,
)
from azure.identity.aio import DefaultAzureCredential

from soffortbackend.models import (
    Approval,
    ApprovalStatus,
    Device,
    EnrollmentChallenge,
    Profile,
    PropertyMetadata,
    StoreConflict,
    StoreUnavailable,
)
from soffortbackend.settings import Settings


class ApprovalStore(Protocol):
    """Durable operations needed by the MCP and iPhone surfaces."""

    @property
    def ready(self) -> bool:
        """Return whether point operations can be attempted."""
        ...

    async def start(self) -> None:
        """Initialize network resources and validate the target container."""
        ...

    async def close(self) -> None:
        """Release network resources."""
        ...

    async def get_profile(self, partition_key: str) -> Profile | None:
        """Read the account profile by point key."""
        ...

    async def put_profile(self, partition_key: str, display_name: str) -> Profile:
        """Create or replace the account profile."""
        ...

    async def create_challenge(self, challenge: EnrollmentChallenge) -> None:
        """Persist a one-use enrollment challenge."""
        ...

    async def get_challenge(
        self, partition_key: str, challenge_id: str
    ) -> EnrollmentChallenge | None:
        """Read an enrollment challenge by point key."""
        ...

    async def register_device(self, challenge: EnrollmentChallenge, device: Device) -> Device:
        """Consume a challenge and persist the proven device."""
        ...

    async def get_device(self, partition_key: str, device_id: str) -> Device | None:
        """Read one enrolled device."""
        ...

    async def list_active_devices(self, partition_key: str) -> Sequence[Device]:
        """List notification-enabled devices for one account."""
        ...

    async def delete_device(self, partition_key: str, device_id: str) -> None:
        """Remove one enrolled device idempotently."""
        ...

    async def disable_device(self, partition_key: str, device_id: str) -> None:
        """Stop routing pushes to a provider-rejected device."""
        ...

    async def create_approval(self, approval: Approval) -> None:
        """Create an immutable pending approval identity."""
        ...

    async def get_approval(self, partition_key: str, approval_id: str) -> Approval | None:
        """Read an approval by point key."""
        ...

    async def list_pending_approvals(self, partition_key: str) -> Sequence[Approval]:
        """List the bounded, unexpired inbox for one phone account."""
        ...

    async def decide_approval(
        self,
        approval: Approval,
        *,
        status: ApprovalStatus,
        device_id: str,
        decision_id: str,
        decided_at: datetime,
        available_keys: tuple[str, ...],
        approved_keys: tuple[str, ...],
        denied_keys: tuple[str, ...],
        unavailable_keys: tuple[str, ...],
        property_metadata: tuple[PropertyMetadata, ...],
        compact_jwe: str | None,
        result_hash: str,
    ) -> Approval:
        """Conditionally commit the first signed phone decision."""
        ...

    async def close_approval(self, approval: Approval, *, status: ApprovalStatus) -> Approval:
        """Conditionally cancel or expire a pending approval."""
        ...


class InMemoryApprovalStore:
    """Deterministic concurrency-safe store used by unit and integration tests."""

    ready = True

    def __init__(self) -> None:
        """Create empty deterministic fixture collections."""
        self.profiles: dict[str, Profile] = {}
        self.challenges: dict[tuple[str, str], EnrollmentChallenge] = {}
        self.devices: dict[tuple[str, str], Device] = {}
        self.approvals: dict[tuple[str, str], Approval] = {}
        self._versions: dict[tuple[str, str], int] = {}
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Match the production lifecycle without external resources."""

    async def close(self) -> None:
        """Match the production lifecycle without external resources."""

    async def get_profile(self, partition_key: str) -> Profile | None:
        """Read a fixture profile."""
        return self.profiles.get(partition_key)

    async def put_profile(self, partition_key: str, display_name: str) -> Profile:
        """Create or version a fixture profile."""
        async with self._lock:
            prior = self.profiles.get(partition_key)
            profile = Profile(
                partition_key=partition_key,
                display_name=display_name,
                version=1 if prior is None else prior.version + 1,
                updated_at=datetime.now(UTC),
            )
            self.profiles[partition_key] = profile
            return profile

    async def create_challenge(self, challenge: EnrollmentChallenge) -> None:
        """Create a unique fixture challenge."""
        async with self._lock:
            key = (challenge.partition_key, challenge.challenge_id)
            if key in self.challenges:
                raise StoreConflict("challenge already exists")
            self.challenges[key] = replace(challenge, etag="1")

    async def register_device(self, challenge: EnrollmentChallenge, device: Device) -> Device:
        """Atomically consume a fixture challenge and register its device."""
        async with self._lock:
            key = (challenge.partition_key, challenge.challenge_id)
            stored = self.challenges.get(key)
            if stored is None or stored.consumed or stored.expires_at <= datetime.now(UTC):
                raise StoreConflict("challenge unavailable")
            if challenge.etag is not None and stored.etag != challenge.etag:
                raise StoreConflict("challenge changed")
            self.challenges[key] = replace(stored, consumed=True, etag="2")
            self.devices[(device.partition_key, device.device_id)] = device
            return device

    async def get_challenge(
        self, partition_key: str, challenge_id: str
    ) -> EnrollmentChallenge | None:
        """Read a fixture challenge."""
        return self.challenges.get((partition_key, challenge_id))

    async def get_device(self, partition_key: str, device_id: str) -> Device | None:
        """Read a fixture device."""
        return self.devices.get((partition_key, device_id))

    async def list_active_devices(self, partition_key: str) -> Sequence[Device]:
        """List active fixture devices."""
        return [
            device
            for (key, _), device in self.devices.items()
            if key == partition_key and device.notifications_enabled
        ]

    async def delete_device(self, partition_key: str, device_id: str) -> None:
        """Delete a fixture device idempotently."""
        self.devices.pop((partition_key, device_id), None)

    async def disable_device(self, partition_key: str, device_id: str) -> None:
        """Disable fixture push routing."""
        async with self._lock:
            key = (partition_key, device_id)
            device = self.devices.get(key)
            if device is not None:
                self.devices[key] = replace(
                    device, notifications_enabled=False, updated_at=datetime.now(UTC)
                )

    async def create_approval(self, approval: Approval) -> None:
        """Create a unique fixture approval."""
        async with self._lock:
            key = (approval.partition_key, approval.approval_id)
            if key in self.approvals:
                raise StoreConflict("approval already exists")
            self._versions[key] = 1
            self.approvals[key] = approval.with_etag("1")

    async def get_approval(self, partition_key: str, approval_id: str) -> Approval | None:
        """Read a fixture approval."""
        return self.approvals.get((partition_key, approval_id))

    async def list_pending_approvals(self, partition_key: str) -> Sequence[Approval]:
        """List at most 20 pending fixture approvals newest first."""
        values = [
            approval
            for (key, _), approval in self.approvals.items()
            if key == partition_key
            and approval.status is ApprovalStatus.PENDING
            and not approval.expired
        ]
        return sorted(values, key=lambda item: item.created_at, reverse=True)[:20]

    async def decide_approval(
        self,
        approval: Approval,
        *,
        status: ApprovalStatus,
        device_id: str,
        decision_id: str,
        decided_at: datetime,
        available_keys: tuple[str, ...],
        approved_keys: tuple[str, ...],
        denied_keys: tuple[str, ...],
        unavailable_keys: tuple[str, ...],
        property_metadata: tuple[PropertyMetadata, ...],
        compact_jwe: str | None,
        result_hash: str,
    ) -> Approval:
        """Commit the first fixture decision under a lock."""
        async with self._lock:
            key = (approval.partition_key, approval.approval_id)
            current = self.approvals.get(key)
            if (
                current is None
                or current.status is not ApprovalStatus.PENDING
                or current.expired
                or current.etag != approval.etag
            ):
                raise StoreConflict("approval is no longer pending")
            version = self._versions[key] + 1
            updated = replace(
                current,
                status=status,
                decided_at=decided_at,
                decided_by_device_id=device_id,
                decision_id=decision_id,
                available_keys=available_keys,
                approved_keys=approved_keys,
                denied_keys=denied_keys,
                unavailable_keys=unavailable_keys,
                property_metadata=property_metadata,
                compact_jwe=compact_jwe,
                result_hash=result_hash,
                etag=str(version),
            )
            self._versions[key] = version
            self.approvals[key] = updated
            return updated

    async def close_approval(self, approval: Approval, *, status: ApprovalStatus) -> Approval:
        """Close a pending fixture approval under a lock."""
        async with self._lock:
            key = (approval.partition_key, approval.approval_id)
            current = self.approvals.get(key)
            if current is None:
                raise StoreConflict("approval does not exist")
            if current.status is not ApprovalStatus.PENDING:
                return current
            version = self._versions[key] + 1
            updated = replace(current, status=status, etag=str(version))
            self._versions[key] = version
            self.approvals[key] = updated
            return updated


class CosmosApprovalStore:
    """Cosmos implementation using point reads and conditional replacements."""

    def __init__(self, settings: Settings) -> None:
        """Create credential and client objects without opening the network."""
        if settings.cosmos_endpoint is None or settings.azure_workload_client_id is None:
            raise ValueError("Cosmos workload identity configuration is required")
        self._credential = DefaultAzureCredential(
            managed_identity_client_id=str(settings.azure_workload_client_id)
        )
        self._client = CosmosClient(str(settings.cosmos_endpoint), credential=self._credential)
        self._database_name = settings.cosmos_database
        self._container_name = settings.cosmos_container
        self._container: Any | None = None

    @property
    def ready(self) -> bool:
        """Return whether the configured Cosmos container was resolved."""
        return self._container is not None

    async def start(self) -> None:
        """Resolve the Bicep-owned container and prove it is reachable."""
        try:
            database = self._client.get_database_client(self._database_name)
            container = database.get_container_client(self._container_name)
            await container.read()
            self._container = container
        except CosmosHttpResponseError as error:
            raise StoreUnavailable("Cosmos approval container is unavailable") from error

    async def close(self) -> None:
        """Close Cosmos and workload-identity clients."""
        await self._client.close()
        await self._credential.close()

    def _require_container(self) -> Any:
        if self._container is None:
            raise StoreUnavailable("Cosmos approval container is not ready")
        return self._container

    async def _read(self, item_id: str, partition_key: str) -> dict[str, Any] | None:
        try:
            result = await self._require_container().read_item(item_id, partition_key)
            return cast(dict[str, Any], result)
        except CosmosResourceNotFoundError:
            return None
        except CosmosHttpResponseError as error:
            raise StoreUnavailable("Cosmos point read failed") from error

    async def get_profile(self, partition_key: str) -> Profile | None:
        """Read the profile document."""
        document = await self._read("profile", partition_key)
        return _profile_from_document(document) if document is not None else None

    async def put_profile(self, partition_key: str, display_name: str) -> Profile:
        """Upsert a versioned profile document."""
        prior = await self.get_profile(partition_key)
        profile = Profile(
            partition_key=partition_key,
            display_name=display_name,
            version=1 if prior is None else prior.version + 1,
            updated_at=datetime.now(UTC),
        )
        try:
            await self._require_container().upsert_item(_profile_document(profile))
            return profile
        except CosmosHttpResponseError as error:
            raise StoreUnavailable("Cosmos profile write failed") from error

    async def create_challenge(self, challenge: EnrollmentChallenge) -> None:
        """Create a TTL-bound enrollment challenge."""
        try:
            await self._require_container().create_item(_challenge_document(challenge))
        except CosmosHttpResponseError as error:
            if error.status_code == 409:
                raise StoreConflict("challenge already exists") from error
            raise StoreUnavailable("Cosmos challenge write failed") from error

    async def get_challenge(
        self, partition_key: str, challenge_id: str
    ) -> EnrollmentChallenge | None:
        """Read a TTL-bound enrollment challenge."""
        document = await self._read(f"challenge:{challenge_id}", partition_key)
        return _challenge_from_document(document) if document is not None else None

    async def register_device(self, challenge: EnrollmentChallenge, device: Device) -> Device:
        """Conditionally consume the challenge before writing the device."""
        if challenge.etag is None:
            raise StoreConflict("challenge has no concurrency token")
        document = _challenge_document(replace(challenge, consumed=True))
        try:
            await self._require_container().replace_item(
                item=f"challenge:{challenge.challenge_id}",
                body=document,
                etag=challenge.etag,
                match_condition=MatchConditions.IfNotModified,
            )
            await self._require_container().upsert_item(_device_document(device))
            return device
        except CosmosAccessConditionFailedError as error:
            raise StoreConflict("challenge was already consumed") from error
        except CosmosHttpResponseError as error:
            raise StoreUnavailable("Cosmos device enrollment failed") from error

    async def get_device(self, partition_key: str, device_id: str) -> Device | None:
        """Read one device document."""
        document = await self._read(f"device:{device_id}", partition_key)
        return _device_from_document(document) if document is not None else None

    async def list_active_devices(self, partition_key: str) -> Sequence[Device]:
        """Query active devices inside one logical partition."""
        query = "SELECT * FROM c WHERE c.kind = 'device' AND c.notifications_enabled = true"
        try:
            iterator = self._require_container().query_items(
                query=query, partition_key=partition_key
            )
            return [_device_from_document(item) async for item in iterator]
        except CosmosHttpResponseError as error:
            raise StoreUnavailable("Cosmos device query failed") from error

    async def delete_device(self, partition_key: str, device_id: str) -> None:
        """Delete one device document idempotently."""
        try:
            await self._require_container().delete_item(f"device:{device_id}", partition_key)
        except CosmosResourceNotFoundError:
            return
        except CosmosHttpResponseError as error:
            raise StoreUnavailable("Cosmos device deletion failed") from error

    async def disable_device(self, partition_key: str, device_id: str) -> None:
        """Disable push routing after a terminal APNs rejection."""
        device = await self.get_device(partition_key, device_id)
        if device is None:
            return
        disabled = replace(device, notifications_enabled=False, updated_at=datetime.now(UTC))
        try:
            await self._require_container().upsert_item(_device_document(disabled))
        except CosmosHttpResponseError as error:
            raise StoreUnavailable("Cosmos device update failed") from error

    async def create_approval(self, approval: Approval) -> None:
        """Create a TTL-bound pending approval."""
        try:
            await self._require_container().create_item(_approval_document(approval))
        except CosmosHttpResponseError as error:
            if error.status_code == 409:
                raise StoreConflict("approval already exists") from error
            raise StoreUnavailable("Cosmos approval write failed") from error

    async def get_approval(self, partition_key: str, approval_id: str) -> Approval | None:
        """Read one approval document."""
        document = await self._read(f"approval:{approval_id}", partition_key)
        return _approval_from_document(document) if document is not None else None

    async def list_pending_approvals(self, partition_key: str) -> Sequence[Approval]:
        """Query the bounded subject inbox without exposing another partition."""
        # Sort after the partition-local query so the development container does
        # not require a paid-for/custom composite index merely for the inbox.
        query = "SELECT * FROM c WHERE c.kind = 'approval' AND c.status = 'pending'"
        try:
            iterator = self._require_container().query_items(
                query=query, partition_key=partition_key
            )
            values = [_approval_from_document(item) async for item in iterator]
            active = [item for item in values if not item.expired]
            return sorted(active, key=lambda item: item.created_at, reverse=True)[:20]
        except CosmosHttpResponseError as error:
            raise StoreUnavailable("Cosmos approval inbox query failed") from error

    async def decide_approval(
        self,
        approval: Approval,
        *,
        status: ApprovalStatus,
        device_id: str,
        decision_id: str,
        decided_at: datetime,
        available_keys: tuple[str, ...],
        approved_keys: tuple[str, ...],
        denied_keys: tuple[str, ...],
        unavailable_keys: tuple[str, ...],
        property_metadata: tuple[PropertyMetadata, ...],
        compact_jwe: str | None,
        result_hash: str,
    ) -> Approval:
        """Conditionally replace a pending approval with a phone decision."""
        if (
            approval.etag is None
            or approval.status is not ApprovalStatus.PENDING
            or approval.expired
        ):
            raise StoreConflict("approval is no longer pending")
        updated = replace(
            approval,
            status=status,
            decided_at=decided_at,
            decided_by_device_id=device_id,
            decision_id=decision_id,
            available_keys=available_keys,
            approved_keys=approved_keys,
            denied_keys=denied_keys,
            unavailable_keys=unavailable_keys,
            property_metadata=property_metadata,
            compact_jwe=compact_jwe,
            result_hash=result_hash,
            etag=None,
        )
        return await self._replace_approval(approval, updated)

    async def close_approval(self, approval: Approval, *, status: ApprovalStatus) -> Approval:
        """Conditionally cancel or expire a pending approval."""
        if approval.status is not ApprovalStatus.PENDING:
            return approval
        return await self._replace_approval(approval, replace(approval, status=status, etag=None))

    async def _replace_approval(self, prior: Approval, updated: Approval) -> Approval:
        if prior.etag is None:
            raise StoreConflict("approval has no concurrency token")
        try:
            result = await self._require_container().replace_item(
                item=f"approval:{prior.approval_id}",
                body=_approval_document(updated),
                etag=prior.etag,
                match_condition=MatchConditions.IfNotModified,
            )
            return _approval_from_document(cast(dict[str, Any], result))
        except CosmosAccessConditionFailedError as error:
            raise StoreConflict("approval decision lost the first-writer race") from error
        except CosmosHttpResponseError as error:
            raise StoreUnavailable("Cosmos approval update failed") from error


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise StoreUnavailable("Cosmos document timestamp is malformed")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise StoreUnavailable("Cosmos document timestamp is malformed") from error


def _profile_document(profile: Profile) -> dict[str, Any]:
    return {
        "id": "profile",
        "kind": "profile",
        "partition_key": profile.partition_key,
        "display_name": profile.display_name,
        "version": profile.version,
        "updated_at": _iso(profile.updated_at),
    }


def _profile_from_document(document: dict[str, Any]) -> Profile:
    return Profile(
        partition_key=str(document["partition_key"]),
        display_name=str(document["display_name"]),
        version=int(document["version"]),
        updated_at=_datetime(document["updated_at"]),
    )


def _challenge_document(challenge: EnrollmentChallenge) -> dict[str, Any]:
    return {
        "id": f"challenge:{challenge.challenge_id}",
        "kind": "challenge",
        "partition_key": challenge.partition_key,
        "challenge_id": challenge.challenge_id,
        "nonce": challenge.nonce,
        "expires_at": _iso(challenge.expires_at),
        "consumed": challenge.consumed,
        "ttl": 300,
    }


def _challenge_from_document(document: dict[str, Any]) -> EnrollmentChallenge:
    return EnrollmentChallenge(
        partition_key=str(document["partition_key"]),
        challenge_id=str(document["challenge_id"]),
        nonce=str(document["nonce"]),
        expires_at=_datetime(document["expires_at"]),
        consumed=bool(document["consumed"]),
        etag=str(document.get("_etag")) if document.get("_etag") else None,
    )


def _device_document(device: Device) -> dict[str, Any]:
    document = asdict(device)
    document.update(
        {
            "id": f"device:{device.device_id}",
            "kind": "device",
            "updated_at": _iso(device.updated_at),
        }
    )
    return document


def _device_from_document(document: dict[str, Any]) -> Device:
    return Device(
        partition_key=str(document["partition_key"]),
        device_id=str(document["device_id"]),
        public_jwk={str(key): str(value) for key, value in document["public_jwk"].items()},
        apns_token=str(document["apns_token"]),
        apns_environment=str(document["apns_environment"]),
        notifications_enabled=bool(document["notifications_enabled"]),
        updated_at=_datetime(document["updated_at"]),
    )


def _approval_document(approval: Approval) -> dict[str, Any]:
    return {
        "id": f"approval:{approval.approval_id}",
        "kind": "approval",
        "partition_key": approval.partition_key,
        "approval_id": approval.approval_id,
        "event_id": approval.event_id,
        "nonce": approval.nonce,
        "tool_name": approval.tool_name,
        "arguments_hash": approval.arguments_hash,
        "requester": approval.requester,
        "purpose": approval.purpose,
        "requested_keys": list(approval.requested_keys),
        "created_at": _iso(approval.created_at),
        "expires_at": _iso(approval.expires_at),
        "status": approval.status.value,
        "decided_at": _iso(approval.decided_at) if approval.decided_at else None,
        "decided_by_device_id": approval.decided_by_device_id,
        "decision_id": approval.decision_id,
        "available_keys": list(approval.available_keys),
        "approved_keys": list(approval.approved_keys),
        "denied_keys": list(approval.denied_keys),
        "unavailable_keys": list(approval.unavailable_keys),
        "property_metadata": [asdict(item) for item in approval.property_metadata],
        "compact_jwe": approval.compact_jwe,
        "result_hash": approval.result_hash,
        # Logical expiry is enforced in code; TTL only removes stale metadata.
        "ttl": 300,
    }


def _approval_from_document(document: dict[str, Any]) -> Approval:
    return Approval(
        partition_key=str(document["partition_key"]),
        approval_id=str(document["approval_id"]),
        event_id=str(document["event_id"]),
        nonce=str(document["nonce"]),
        tool_name=str(document["tool_name"]),
        arguments_hash=str(document["arguments_hash"]),
        requester=str(document["requester"]),
        purpose=str(document["purpose"]),
        requested_keys=tuple(str(value) for value in document["requested_keys"]),
        created_at=_datetime(document["created_at"]),
        expires_at=_datetime(document["expires_at"]),
        status=ApprovalStatus(str(document["status"])),
        decided_at=_datetime(document["decided_at"]) if document.get("decided_at") else None,
        decided_by_device_id=(
            str(document["decided_by_device_id"]) if document.get("decided_by_device_id") else None
        ),
        decision_id=str(document["decision_id"]) if document.get("decision_id") else None,
        available_keys=tuple(str(value) for value in document.get("available_keys", [])),
        approved_keys=tuple(str(value) for value in document.get("approved_keys", [])),
        denied_keys=tuple(str(value) for value in document.get("denied_keys", [])),
        unavailable_keys=tuple(str(value) for value in document.get("unavailable_keys", [])),
        property_metadata=tuple(
            PropertyMetadata(
                key=str(item["key"]),
                display_name=str(item["display_name"]),
                value_type=str(item["value_type"]),
                sensitivity=str(item["sensitivity"]),
            )
            for item in document.get("property_metadata", [])
        ),
        compact_jwe=str(document["compact_jwe"]) if document.get("compact_jwe") else None,
        result_hash=str(document["result_hash"]) if document.get("result_hash") else None,
        etag=str(document.get("_etag")) if document.get("_etag") else None,
    )
