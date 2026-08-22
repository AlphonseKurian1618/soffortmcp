"""Value-free domain models for device-mediated MCP approval."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum

from mcp.server.auth.provider import AccessToken


class ApprovalStatus(StrEnum):
    """Closed approval states persisted by the shared store."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class Principal:
    """One customer identity correlated across approved Entra applications."""

    tenant_id: str
    object_id: str
    client_id: str
    client_kind: str

    @property
    def partition_key(self) -> str:
        """Return an opaque, tenant-scoped Cosmos partition key."""
        return f"{self.tenant_id}:{self.object_id}"

    @classmethod
    def from_access_token(cls, token: AccessToken) -> Principal | None:
        """Build a principal only from verifier-authenticated claims."""
        claims = token.claims or {}
        tenant_id = claims.get("tid")
        object_id = claims.get("oid")
        client_kind = claims.get("client_kind")
        if not isinstance(tenant_id, str) or not tenant_id:
            return None
        if not isinstance(object_id, str) or not object_id:
            return None
        if not isinstance(client_kind, str) or not client_kind:
            return None
        return cls(
            tenant_id=tenant_id,
            object_id=object_id,
            client_id=token.client_id,
            client_kind=client_kind,
        )


@dataclass(frozen=True, slots=True)
class Profile:
    """Server-held display profile used only after explicit approval."""

    partition_key: str
    display_name: str
    version: int
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class EnrollmentChallenge:
    """Short-lived nonce proving a device owns its submitted public key."""

    partition_key: str
    challenge_id: str
    nonce: str
    expires_at: datetime
    consumed: bool = False
    etag: str | None = None


@dataclass(frozen=True, slots=True)
class Device:
    """One enrolled iPhone and its APNs/device-possession routing material."""

    partition_key: str
    device_id: str
    public_jwk: dict[str, str]
    apns_token: str
    apns_environment: str
    notifications_enabled: bool
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PropertyMetadata:
    """Phone-approved, value-free metadata for one dynamic vault property."""

    key: str
    display_name: str
    value_type: str
    sensitivity: str


@dataclass(frozen=True, slots=True)
class Approval:
    """One time-bounded consent request bound to an exact MCP invocation."""

    partition_key: str
    approval_id: str
    event_id: str
    nonce: str
    tool_name: str
    arguments_hash: str
    requester: str
    purpose: str
    requested_keys: tuple[str, ...]
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_at: datetime | None = None
    decided_by_device_id: str | None = None
    decision_id: str | None = None
    available_keys: tuple[str, ...] = ()
    approved_keys: tuple[str, ...] = ()
    denied_keys: tuple[str, ...] = ()
    unavailable_keys: tuple[str, ...] = ()
    property_metadata: tuple[PropertyMetadata, ...] = ()
    compact_jwe: str | None = None
    result_hash: str | None = None
    etag: str | None = None

    @property
    def expired(self) -> bool:
        """Return whether the logical deadline has passed."""
        return datetime.now(UTC) >= self.expires_at

    def with_etag(self, etag: str | None) -> Approval:
        """Copy the record with its storage concurrency token."""
        return replace(self, etag=etag)


class StoreConflict(Exception):
    """A conditional write lost a race or attempted an invalid transition."""


class StoreUnavailable(Exception):
    """The durable approval store could not safely serve a request."""
