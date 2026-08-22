# ADR 0005: phone-mediated Permi vault disclosure

## Status

Accepted for development.

## Decision

The MCP server exposes only `list_available_properties` and `request_properties`. Every invocation creates a two-minute iPhone consent request. Cosmos coordinates replicas and first-writer-wins decisions; direct APNs is only an opaque wake-up. The phone authenticates through External ID and signs exact request/result bindings with its non-exportable Secure Enclave P-256 key after user presence.

Vault values never synchronize to the service. Approved values are compact `RSA-OAEP-256`/`A256GCM` JWE addressed to a non-exportable 2048-bit Key Vault RSA key. Pods unwrap through workload identity and decrypt AES-GCM only in memory. Old key versions remain enabled for requests already issued with their `kid`.

The iPhone projects every populated ontology field—including custom fields and repeated composed instances—to a stable opaque digest handle. Phone-authored display name, value type, and sensitivity are part of the signed result manifest. The server therefore needs no persistent copy of the vault schema, and local record/component identifiers do not cross the boundary.

Accounts are identified only by verified `tid` and `oid`. Apple and email records are not guessed or merged using email addresses.

## Consequences

- MCP and mobile HTTP remain stateless across two replicas with no affinity.
- A linked phone, APNs delivery or inbox polling, local authentication, and a timely decision are required.
- Denial/unavailable fields are structured results; crypto, delivery, and timeout faults fail closed.
- Cosmos retains only short-lived metadata/ciphertext; cleartext is never persisted or logged.
- Key possession is not App Attest; device attestation remains production hardening work.
- This reuses existing Cosmos and Key Vault resources and adds negligible usage cost.
