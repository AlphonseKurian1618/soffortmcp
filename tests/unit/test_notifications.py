"""Tests for direct APNs token creation and provider response handling."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid7

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from soffortbackend.models import Approval, Device
from soffortbackend.notifications import APNsApprovalNotifier, NotificationUnavailable
from soffortbackend.settings import Settings


class FakeCredential:
    """Closed-state-only workload credential fixture."""

    def __init__(self, **_: object) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class FakeSecrets:
    """Key Vault fixture returning one configured secret value."""

    value: str | None = None
    error: Exception | None = None

    def __init__(self, **_: object) -> None:
        self.closed = False

    async def get_secret(self, *_: object) -> SimpleNamespace:
        if self.error is not None:
            raise self.error
        return SimpleNamespace(value=self.value)

    async def close(self) -> None:
        self.closed = True


class FakeHttp:
    """Ordered APNs response fixture."""

    responses: list[httpx.Response] = []

    def __init__(self, **_: object) -> None:
        self.closed = False
        self.requests: list[tuple[str, dict[str, str]]] = []

    async def post(self, url: str, *, content: bytes, headers: dict[str, str]) -> httpx.Response:
        assert content
        self.requests.append((url, headers))
        return self.responses.pop(0)

    async def aclose(self) -> None:
        self.closed = True


def _settings(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "key_vault_url": "https://vault.example",
            "azure_workload_client_id": settings.entra_ios_client_id,
            "apns_key_id": "ABCDEFGHIJ",
        }
    )


def _approval_and_devices() -> tuple[Approval, list[Device]]:
    now = datetime.now(UTC)
    approval = Approval(
        partition_key="partition",
        approval_id=str(uuid7()),
        event_id=str(uuid7()),
        nonce="nonce",
        tool_name="hello_world",
        arguments_hash="hash",
        requester="VS Code",
        display_name_snapshot="Alphonse",
        profile_version=1,
        created_at=now,
        expires_at=now + timedelta(seconds=60),
    )
    devices = [
        Device(
            partition_key="partition",
            device_id=str(uuid7()),
            public_jwk={},
            apns_token=("ab" if index == 0 else "cd") * 32,
            apns_environment="sandbox",
            notifications_enabled=True,
            updated_at=now,
        )
        for index in range(2)
    ]
    return approval, devices


@pytest.mark.asyncio
async def test_apns_accepts_devices_disables_invalid_and_reuses_token(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = ec.generate_private_key(ec.SECP256R1())
    FakeSecrets.value = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    FakeSecrets.error = None
    FakeHttp.responses = [
        httpx.Response(200),
        httpx.Response(410, json={"reason": "Unregistered"}),
        httpx.Response(200),
        httpx.Response(200),
    ]
    monkeypatch.setattr("soffortbackend.notifications.DefaultAzureCredential", FakeCredential)
    monkeypatch.setattr("soffortbackend.notifications.SecretClient", FakeSecrets)
    monkeypatch.setattr("soffortbackend.notifications.httpx.AsyncClient", FakeHttp)
    notifier = APNsApprovalNotifier(_settings(settings))
    await notifier.start()
    approval, devices = _approval_and_devices()

    result = await notifier.send_approval(approval, devices)
    token = notifier._provider_token
    second = await notifier.send_approval(approval, devices)

    assert result.accepted_device_ids == (devices[0].device_id,)
    assert result.invalid_device_ids == (devices[1].device_id,)
    assert second.accepted_device_ids == (devices[0].device_id, devices[1].device_id)
    assert notifier._provider_token == token
    assert notifier._http.requests[0][0].startswith("https://api.sandbox.push.apple.com/")
    assert notifier._http.requests[0][1]["apns-topic"] == "com.soffort.aivault"
    await notifier.close()
    assert notifier.ready is False


@pytest.mark.asyncio
async def test_apns_start_and_transient_failures_are_closed(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("soffortbackend.notifications.DefaultAzureCredential", FakeCredential)
    monkeypatch.setattr("soffortbackend.notifications.SecretClient", FakeSecrets)
    monkeypatch.setattr("soffortbackend.notifications.httpx.AsyncClient", FakeHttp)
    FakeSecrets.value = "not-a-private-key"
    FakeSecrets.error = None
    notifier = APNsApprovalNotifier(_settings(settings))
    with pytest.raises(NotificationUnavailable, match="format"):
        await notifier.start()

    private = ec.generate_private_key(ec.SECP256R1())
    FakeSecrets.value = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    notifier = APNsApprovalNotifier(_settings(settings))
    await notifier.start()
    approval, devices = _approval_and_devices()
    FakeHttp.responses = [httpx.Response(503), httpx.Response(503)]
    with pytest.raises(NotificationUnavailable):
        await notifier.send_approval(approval, devices)
    await notifier.close()

    FakeSecrets.error = RuntimeError("vault unavailable")
    notifier = APNsApprovalNotifier(_settings(settings))
    with pytest.raises(NotificationUnavailable, match="unavailable"):
        await notifier.start()
