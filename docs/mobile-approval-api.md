# iPhone approval contract

`hello_world()` is an authenticated VS Code call and a separate, device-bound user decision. The VS Code token proves who is calling; it does not approve the call.

## Sequence

1. VS Code obtains `soffortbackend.access` and calls `POST /mcp`.
2. The server identifies the user by the verified External ID `tid` and `oid` claims, loads the required profile and active devices, and stores a pending 60-second approval in Cosmos DB.
3. Direct APNs sends only `event_id`, `event_type=mcp_approval_requested`, and `approval_id`. The notification contains no name, token, decision, URL, or tool result.
4. The iPhone obtains `soffortbackend.mobile` with the same External ID provider/account, fetches the authoritative approval, and shows the tool and requester.
5. Face ID or the device passcode unlocks the Secure Enclave P-256 signing key. The phone signs the exact tenant, object, device, approval, nonce, tool, argument hash, decision, and timestamp.
6. The first valid conditional decision wins. On approval, the MCP request returns the profile snapshot; denial, expiry, cancellation, and conflicts fail closed.

Apple and email identities are intentionally separate accounts. A user who signs into VS Code with Apple and the iPhone with email receives `phone_not_linked`; the server never guesses identity from email.

## Mobile endpoints

All `/v1` routes require an Entra access token issued to the registered iOS client with `soffortbackend.mobile`. Bodies reject unknown members and are capped at 64 KiB.

| Method and path | Purpose |
|---|---|
| `GET /v1/me/profile` | Read the current profile |
| `PUT /v1/me/profile` | Set normalized `display_name` (1–100 characters) |
| `POST /v1/devices/enrollment-challenges` | Create a five-minute, one-use nonce |
| `PUT /v1/devices/{uuidv7}` | Enroll an APNs token and P-256 public JWK with a signed proof |
| `DELETE /v1/devices/{uuidv7}` | Unlink the phone |
| `GET /v1/approvals/{uuidv7}` | Fetch authoritative pending metadata |
| `POST /v1/approvals/{uuidv7}/decisions` | Submit a signed `approved` or `denied` decision |

Enrollment and decision signatures are DER-encoded ECDSA/SHA-256 and unpadded base64url. The canonical strings live in `device_security.py`; changing them requires synchronized backend and iOS test vectors.

## Failure contract

Expected MCP failures are stable codes: `profile_required`, `phone_not_linked`, `notifications_unavailable`, `approval_denied`, `approval_timed_out`, and `approval_unavailable`. They intentionally contain no profile, device, provider, or storage details.

Cosmos records use `tid:oid` only as an internal partition key. Challenges and approvals have a five-minute storage TTL in addition to their shorter logical deadlines. Device tokens, names, signed bodies, and bearer tokens are never logged.
