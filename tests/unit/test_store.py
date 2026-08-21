"""Tests for in-memory and Cosmos approval persistence transitions."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid7

import pytest

from soffortbackend.models import (
    Approval,
    ApprovalStatus,
    Device,
    EnrollmentChallenge,
    StoreConflict,
)
from soffortbackend.settings import Settings
from soffortbackend.store import CosmosApprovalStore, InMemoryApprovalStore


class FakeCredential:
    """Minimal async workload-identity fixture."""

    def __init__(self, **_: object) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class FakeContainer:
    """Point-operation-compatible Cosmos container fixture."""

    def __init__(self) -> None:
        self.documents: dict[tuple[str, str], dict[str, Any]] = {}
        self.version = 0

    async def read(self) -> dict[str, str]:
        return {"id": "approval"}

    async def read_item(self, item: str, partition_key: str) -> dict[str, Any]:
        from azure.cosmos.exceptions import CosmosResourceNotFoundError

        try:
            return dict(self.documents[(partition_key, item)])
        except KeyError as error:
            raise CosmosResourceNotFoundError(status_code=404, message="missing") from error

    def _store(self, body: dict[str, Any]) -> dict[str, Any]:
        self.version += 1
        stored = dict(body)
        stored["_etag"] = str(self.version)
        self.documents[(str(body["partition_key"]), str(body["id"]))] = stored
        return dict(stored)

    async def create_item(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._store(body)

    async def upsert_item(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._store(body)

    async def replace_item(
        self,
        *,
        item: str,
        body: dict[str, Any],
        etag: str,
        match_condition: object,
    ) -> dict[str, Any]:
        assert item == body["id"]
        assert etag
        assert match_condition
        return self._store(body)

    def query_items(self, *, query: str, partition_key: str):

        async def iterate():
            for (key, _), document in self.documents.items():
                is_active_device = (
                    document.get("kind") == "device"
                    and document.get("notifications_enabled") is True
                    and "notifications_enabled" in query
                )
                is_pending_approval = (
                    document.get("kind") == "approval"
                    and document.get("status") == "pending"
                    and "status = 'pending'" in query
                )
                if key == partition_key and (is_active_device or is_pending_approval):
                    yield dict(document)

        return iterate()

    async def delete_item(self, item: str, partition_key: str) -> None:
        from azure.cosmos.exceptions import CosmosResourceNotFoundError

        if self.documents.pop((partition_key, item), None) is None:
            raise CosmosResourceNotFoundError(status_code=404, message="missing")


class FakeDatabase:
    """Return one configured container."""

    def __init__(self, container: FakeContainer) -> None:
        self.container = container

    def get_container_client(self, _: str) -> FakeContainer:
        return self.container


class FakeCosmosClient:
    """Return one configured database and record closure."""

    container = FakeContainer()

    def __init__(self, *_: object, **__: object) -> None:
        self.closed = False

    def get_database_client(self, _: str) -> FakeDatabase:
        return FakeDatabase(self.container)

    async def close(self) -> None:
        self.closed = True


def _settings(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "cosmos_endpoint": "https://cosmos.example",
            "azure_workload_client_id": settings.entra_ios_client_id,
        }
    )


def _approval(partition_key: str) -> Approval:
    now = datetime.now(UTC)
    return Approval(
        partition_key=partition_key,
        approval_id=str(uuid7()),
        event_id=str(uuid7()),
        nonce="nonce",
        tool_name="list_available_properties",
        arguments_hash="hash",
        requester="VS Code",
        purpose="List available properties",
        requested_keys=(),
        created_at=now,
        expires_at=now + timedelta(seconds=60),
    )


@pytest.mark.asyncio
async def test_cosmos_store_normal_lifecycle(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeCosmosClient.container = FakeContainer()
    monkeypatch.setattr("soffortbackend.store.DefaultAzureCredential", FakeCredential)
    monkeypatch.setattr("soffortbackend.store.CosmosClient", FakeCosmosClient)
    store = CosmosApprovalStore(_settings(settings))
    assert store.ready is False
    await store.start()
    assert store.ready is True
    partition = "tenant:object"

    assert await store.get_profile(partition) is None
    first_profile = await store.put_profile(partition, "Alphonse")
    second_profile = await store.put_profile(partition, "Alphonse K")
    assert first_profile.version == 1
    assert second_profile.version == 2
    assert (await store.get_profile(partition)).display_name == "Alphonse K"

    challenge = EnrollmentChallenge(
        partition_key=partition,
        challenge_id=str(uuid7()),
        nonce="nonce",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    await store.create_challenge(challenge)
    persisted_challenge = await store.get_challenge(partition, challenge.challenge_id)
    assert persisted_challenge is not None
    device = Device(
        partition_key=partition,
        device_id=str(uuid7()),
        public_jwk={"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        apns_token="ab" * 32,
        apns_environment="sandbox",
        notifications_enabled=True,
        updated_at=datetime.now(UTC),
    )
    await store.register_device(persisted_challenge, device)
    assert (await store.get_device(partition, device.device_id)).device_id == device.device_id
    assert [item.device_id for item in await store.list_active_devices(partition)] == [
        device.device_id
    ]
    await store.disable_device(partition, device.device_id)
    assert await store.list_active_devices(partition) == []

    approval = _approval(partition)
    await store.create_approval(approval)
    persisted = await store.get_approval(partition, approval.approval_id)
    assert persisted is not None
    decided = await store.decide_approval(
        persisted,
        status=ApprovalStatus.APPROVED,
        device_id=device.device_id,
        decision_id=str(uuid7()),
        decided_at=datetime.now(UTC),
        available_keys=("contact.personalEmail",),
        approved_keys=(),
        denied_keys=(),
        unavailable_keys=(),
        compact_jwe=None,
        result_hash="fixture-result-hash",
    )
    assert decided.status is ApprovalStatus.APPROVED
    assert await store.close_approval(decided, status=ApprovalStatus.EXPIRED) == decided

    pending = _approval(partition)
    await store.create_approval(pending)
    assert [item.approval_id for item in await store.list_pending_approvals(partition)] == [
        pending.approval_id
    ]
    persisted_pending = await store.get_approval(partition, pending.approval_id)
    assert persisted_pending is not None
    closed = await store.close_approval(persisted_pending, status=ApprovalStatus.CANCELLED)
    assert closed.status is ApprovalStatus.CANCELLED

    await store.delete_device(partition, device.device_id)
    await store.delete_device(partition, device.device_id)
    assert await store.get_device(partition, device.device_id) is None
    await store.close()


@pytest.mark.asyncio
async def test_in_memory_store_rejects_replayed_challenge_and_stale_approval() -> None:
    store = InMemoryApprovalStore()
    partition = "tenant:object"
    challenge = EnrollmentChallenge(
        partition_key=partition,
        challenge_id=str(uuid7()),
        nonce="nonce",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    await store.create_challenge(challenge)
    persisted = await store.get_challenge(partition, challenge.challenge_id)
    assert persisted is not None
    device = Device(
        partition_key=partition,
        device_id=str(uuid7()),
        public_jwk={},
        apns_token="ab" * 32,
        apns_environment="sandbox",
        notifications_enabled=True,
        updated_at=datetime.now(UTC),
    )
    await store.register_device(persisted, device)
    with pytest.raises(StoreConflict):
        await store.register_device(persisted, device)

    approval = _approval(partition)
    await store.create_approval(approval)
    current = await store.get_approval(partition, approval.approval_id)
    assert current is not None
    stale = current.with_etag("stale")
    with pytest.raises(StoreConflict):
        await store.decide_approval(
            stale,
            status=ApprovalStatus.APPROVED,
            device_id=device.device_id,
            decision_id=str(uuid7()),
            decided_at=datetime.now(UTC),
            available_keys=(),
            approved_keys=(),
            denied_keys=(),
            unavailable_keys=(),
            compact_jwe=None,
            result_hash="fixture-result-hash",
        )


@pytest.mark.asyncio
async def test_in_memory_store_conflicts_and_idempotent_closure() -> None:
    store = InMemoryApprovalStore()
    partition = "tenant:subject"
    assert await store.get_profile(partition) is None
    first = await store.put_profile(partition, "Legacy")
    second = await store.put_profile(partition, "Legacy Two")
    assert (first.version, second.version) == (1, 2)

    challenge = EnrollmentChallenge(
        partition_key=partition,
        challenge_id=str(uuid7()),
        nonce="nonce",
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    await store.create_challenge(challenge)
    with pytest.raises(StoreConflict, match="already exists"):
        await store.create_challenge(challenge)

    device = Device(
        partition_key=partition,
        device_id=str(uuid7()),
        public_jwk={},
        apns_token="ab" * 32,
        apns_environment="sandbox",
        notifications_enabled=True,
        updated_at=datetime.now(UTC),
    )
    store.devices[(partition, device.device_id)] = device
    await store.disable_device(partition, "missing-device")
    await store.disable_device(partition, device.device_id)
    disabled = await store.get_device(partition, device.device_id)
    assert disabled is not None and not disabled.notifications_enabled

    approval = _approval(partition)
    await store.create_approval(approval)
    with pytest.raises(StoreConflict, match="already exists"):
        await store.create_approval(approval)
    current = await store.get_approval(partition, approval.approval_id)
    assert current is not None
    closed = await store.close_approval(current, status=ApprovalStatus.CANCELLED)
    assert await store.close_approval(closed, status=ApprovalStatus.EXPIRED) == closed
    with pytest.raises(StoreConflict, match="does not exist"):
        await store.close_approval(_approval(partition), status=ApprovalStatus.CANCELLED)
