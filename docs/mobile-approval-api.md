# Permi vault consent protocol

The VS Code token authenticates the MCP caller; it never substitutes for the iPhone owner's decision. Apple and email identities remain distinct unless External ID itself returns the same verified `tid` and `oid`.

## Sequence

1. The server validates the caller and exact tool arguments, then writes a two-minute pending request to Cosmos.
2. APNs sends only `event_id`, `event_type=mcp_approval_requested`, and `approval_id`.
3. The app authenticates with `soffortbackend.mobile` and fetches authoritative request data. `GET /v1/approvals` recovers requests after missed pushes.
4. Every field begins unselected. Missing fields are disabled. The phone signs a decision binding request, nonce, tool, argument hash, decision ID, result hash, and expiry. Protocol contract v3 also binds the exact phone-authored metadata manifest.
5. For approved values, the phone creates compact `RSA-OAEP-256`/`A256GCM` JWE using the advertised non-exportable Key Vault public key. The server verifies the signed manifest and decrypts only in memory.
6. Cosmos conditional replacement makes the first valid decision final. Request metadata and ciphertext have a five-minute TTL.

## Mobile endpoints

All `/v1` routes require the iOS public client, exact tenant, API audience, and `soffortbackend.mobile`. Bodies reject unknown members and are capped at 1 MiB so a bounded 1,024-field discovery manifest can be submitted.

| Method and path | Purpose |
|---|---|
| `POST /v1/devices/enrollment-challenges` | Create a five-minute, one-use nonce |
| `PUT /v1/devices/{uuidv7}` | Enroll APNs token and Secure Enclave P-256 public JWK |
| `DELETE /v1/devices/{uuidv7}` | Unlink the phone |
| `GET /v1/approvals` | List this subject's live pending requests |
| `GET /v1/approvals/{uuidv7}` | Fetch authoritative request and disclosure public key |
| `POST /v1/approvals/{uuidv7}/decisions` | Submit a signed result manifest |

Enrollment and decision signatures are DER ECDSA/SHA-256 with unpadded base64url. Canonical messages live in `device_security.py` and have cross-language test vectors. Any protocol change must update backend and iOS together.

Property keys are `vault.` plus a 43-character base64url SHA-256 digest derived locally from the record, component, and semantic field identity. They are stable for that field instance but reveal no local UUID. Discovery is capped at 1,024 populated fields and selective requests at 100 handles. User-authored labels are returned only after phone approval, retained with the request's short TTL, and never logged.

## Failure boundary

Denial and missing fields are successful structured tool outcomes. `phone_not_linked`, `notifications_unavailable`, `approval_timed_out`, `approval_unavailable`, and `disclosure_invalid` are stable, value-free MCP errors. Invalid or replayed decisions receive bounded HTTP errors and never alter the first accepted result.

Cosmos uses `tid:oid` only as an internal partition key. No vault value is stored unencrypted by the service. Plaintext exists only during final response construction and is never written to storage or logs.
