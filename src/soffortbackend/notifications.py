"""Direct, privacy-minimal Apple Push Notification delivery."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

import httpx
import jwt
from azure.identity.aio import DefaultAzureCredential
from azure.keyvault.secrets.aio import SecretClient

from soffortbackend.models import Approval, Device
from soffortbackend.settings import Settings


class NotificationUnavailable(Exception):
    """APNs credentials or provider connectivity cannot safely deliver a request."""


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """Provider acceptance summary without exposing device tokens or bodies."""

    accepted_device_ids: tuple[str, ...]
    invalid_device_ids: tuple[str, ...]


class ApprovalNotifier(Protocol):
    """Lifecycle and delivery surface used by the approval service."""

    @property
    def ready(self) -> bool:
        """Return whether notification delivery may be attempted."""
        ...

    async def start(self) -> None:
        """Initialize provider resources."""
        ...

    async def close(self) -> None:
        """Release provider resources."""
        ...

    async def send_approval(self, approval: Approval, devices: Sequence[Device]) -> DeliveryResult:
        """Deliver an opaque approval event to eligible devices."""
        ...


class FakeApprovalNotifier:
    """Inspectable provider used by tests without network or credentials."""

    ready = True

    def __init__(self, *, accept: bool = True) -> None:
        """Configure whether fixture deliveries are accepted."""
        self.accept = accept
        self.deliveries: list[tuple[Approval, tuple[Device, ...]]] = []

    async def start(self) -> None:
        """Match the production lifecycle."""

    async def close(self) -> None:
        """Match the production lifecycle."""

    async def send_approval(self, approval: Approval, devices: Sequence[Device]) -> DeliveryResult:
        """Record a deterministic fixture delivery."""
        self.deliveries.append((approval, tuple(devices)))
        accepted = tuple(device.device_id for device in devices) if self.accept else ()
        return DeliveryResult(accepted_device_ids=accepted, invalid_device_ids=())


class APNsApprovalNotifier:
    """Send generic approval wake-ups through Apple's HTTP/2 provider API."""

    def __init__(self, settings: Settings) -> None:
        """Configure Key Vault credential loading and the APNs HTTP/2 pool."""
        if (
            settings.key_vault_url is None
            or settings.azure_workload_client_id is None
            or settings.apns_key_id is None
        ):
            raise ValueError("APNs Key Vault workload configuration is required")
        self._settings = settings
        self._credential = DefaultAzureCredential(
            managed_identity_client_id=str(settings.azure_workload_client_id)
        )
        self._secrets = SecretClient(
            vault_url=str(settings.key_vault_url), credential=self._credential
        )
        self._http = httpx.AsyncClient(
            http2=True,
            timeout=httpx.Timeout(8.0, connect=3.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._private_key: str | None = None
        self._provider_token: str | None = None
        self._provider_token_created_at = 0
        self._token_lock = asyncio.Lock()

    @property
    def ready(self) -> bool:
        """Return whether the APNs signing key is resident in memory."""
        return self._private_key is not None

    async def start(self) -> None:
        """Load the immutable APNs private-key version into process memory."""
        try:
            secret = await self._secrets.get_secret(
                self._settings.apns_private_key_secret_name,
                self._settings.apns_private_key_secret_version,
            )
        except Exception as error:  # Azure SDK exposes several credential/HTTP subclasses.
            raise NotificationUnavailable("APNs signing key is unavailable") from error
        if not secret.value or "BEGIN PRIVATE KEY" not in secret.value:
            raise NotificationUnavailable("APNs signing key has an invalid format")
        self._private_key = secret.value

    async def close(self) -> None:
        """Clear key material and close provider clients."""
        self._private_key = None
        self._provider_token = None
        await self._http.aclose()
        await self._secrets.close()
        await self._credential.close()

    async def send_approval(self, approval: Approval, devices: Sequence[Device]) -> DeliveryResult:
        """Send one opaque event to every currently active device."""
        token = await self._get_provider_token()
        results = await asyncio.gather(
            *(self._send_one(token, approval, device) for device in devices),
            return_exceptions=True,
        )
        accepted: list[str] = []
        invalid: list[str] = []
        transient_failure = False
        for device, result in zip(devices, results, strict=True):
            if result is True:
                accepted.append(device.device_id)
            elif result == "invalid":
                invalid.append(device.device_id)
            else:
                transient_failure = True
        if not accepted and transient_failure:
            raise NotificationUnavailable("APNs did not accept an approval notification")
        return DeliveryResult(tuple(accepted), tuple(invalid))

    async def _get_provider_token(self) -> str:
        async with self._token_lock:
            now = int(time.time())
            # Apple asks providers to reuse a token for at least 20 minutes and
            # rejects it after one hour. Fifty minutes keeps both constraints.
            if self._provider_token and now - self._provider_token_created_at < 3_000:
                return self._provider_token
            if self._private_key is None or self._settings.apns_key_id is None:
                raise NotificationUnavailable("APNs notifier is not ready")
            encoded = jwt.encode(
                {"iss": self._settings.apns_team_id, "iat": now},
                self._private_key,
                algorithm="ES256",
                headers={"kid": self._settings.apns_key_id},
            )
            self._provider_token = encoded
            self._provider_token_created_at = now
            return encoded

    async def _send_one(
        self, provider_token: str, approval: Approval, device: Device
    ) -> bool | str:
        if device.apns_environment != self._settings.apns_environment:
            return "invalid"
        host = (
            "api.sandbox.push.apple.com"
            if device.apns_environment == "sandbox"
            else "api.push.apple.com"
        )
        payload = {
            "aps": {
                "alert": {
                    "title": "Concentrey request",
                    "body": "Open Concentrey to review which information was requested.",
                },
                "sound": "default",
            },
            "event_id": approval.event_id,
            "event_type": "mcp_approval_requested",
            "approval_id": approval.approval_id,
        }
        try:
            response = await self._http.post(
                f"https://{host}/3/device/{device.apns_token}",
                content=json.dumps(payload, separators=(",", ":")).encode(),
                headers={
                    "authorization": f"bearer {provider_token}",
                    "apns-topic": self._settings.apns_topic,
                    "apns-push-type": "alert",
                    "apns-priority": "10",
                    "apns-expiration": str(int(approval.expires_at.timestamp())),
                    "apns-id": approval.event_id,
                    "apns-collapse-id": approval.approval_id,
                    "content-type": "application/json",
                },
            )
        except httpx.HTTPError:
            return "transient"
        if response.status_code == 200:
            return True
        if response.status_code in {400, 410}:
            try:
                reason = response.json().get("reason")
            except ValueError, AttributeError:
                reason = None
            if reason in {"BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"}:
                return "invalid"
        return "transient"
