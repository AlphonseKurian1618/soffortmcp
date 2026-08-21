# ADR 0005: device-mediated MCP approval

## Status

Accepted for development.

## Decision

Every `hello_world()` call requires a new iPhone decision. A serverless Cosmos DB container coordinates replicas and conditional first-writer-wins decisions. Direct APNs wakes all active phones; notification content is opaque. The iPhone authenticates through the same External ID user flow as VS Code and signs enrollment and decisions with a non-exportable Secure Enclave P-256 key after user presence.

We identify accounts only by verified `tid` and `oid`. Apple and email sign-in records are not merged. The profile name is required and snapshotted when the approval is created so a concurrent profile update cannot change an already reviewed result.

## Consequences

- The MCP transport remains stateless and needs no affinity.
- A phone, notification permission, profile, APNs availability, and a decision within 60 seconds are required.
- Cosmos serverless, Key Vault Standard, and direct APNs add small usage-based cost while avoiding always-on Redis, Service Bus, Notification Hubs, or a third-party push service.
- Key possession is not App Attest. Device-attestation policy remains a production hardening item.
- The development APNs key is sandbox-only and distinct from the Sign in with Apple federation key.
