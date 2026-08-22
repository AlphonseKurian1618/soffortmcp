# ADR 0005: phone-mediated Consentary vault disclosure

## Status

Accepted for development.

## Decision

The MCP server exposes only `list_available_properties` and `request_properties`. Discovery reads a subject-scoped, value-free property index and never prompts the phone. Value requests create a two-minute iPhone consent request. Cosmos coordinates replicas and first-writer-wins decisions; direct APNs is only an opaque wake-up. The phone authenticates through External ID and signs exact value-request/result bindings with its non-exportable Secure Enclave P-256 key after user presence.

Vault values never synchronize to the service. Approved values are compact `RSA-OAEP-256`/`A256GCM` JWE addressed to a non-exportable 2048-bit Key Vault RSA key. Pods unwrap through workload identity and decrypt AES-GCM only in memory. Old key versions remain enabled for requests already issued with their `kid`.

The iPhone projects every populated ontology field—including custom fields and repeated composed instances—to a stable opaque digest handle. It replaces a server-side index containing only handle, display name, value type, and sensitivity whenever the local vault is refreshed. Local record/component identifiers and values do not cross this discovery boundary.

Accounts are identified only by verified `tid` and `oid`. Apple and email records are not guessed or merged using email addresses.

## Consequences

- MCP and mobile HTTP remain stateless across two replicas with no affinity.
- A linked phone, APNs delivery or inbox polling, local authentication, and a timely decision are required only for values.
- Denial/unavailable fields are structured results; crypto, delivery, and timeout faults fail closed.
- Cosmos retains the latest value-free property index plus short-lived consent metadata/ciphertext; cleartext is never persisted or logged.
- Key possession is not App Attest; device attestation remains production hardening work.
- This reuses existing Cosmos and Key Vault resources and adds negligible usage cost.
