# Consentary vault end-to-end runbook

This runbook proves Entra authentication, MCP authorization, physical-iPhone consent, selective disclosure, and the absence of server-side vault storage. Use fictional values only.

## Fixed development identifiers

- Subscription: `86dfb8ca-2e38-4abb-9072-e8d077af295a`
- Resource group / cluster: `rg-soffortbackend-dev-wus2` / `aks-soffortbackend-dev-wus2`
- MCP endpoint: `https://consentary.com/mcp`
- External tenant: `85685fcd-3fc0-4032-982c-92ddd6efc37b`
- VS Code public client: `9cea70e5-8b4c-4f37-bf6f-2d789ae49492`
- iOS public client: `dcae2fbc-315f-41b0-9c47-17482098cbab`
- API audience: `387b7862-7ab6-4139-af73-b54f535ded29`

Never record tokens, OTPs, real vault values, Apple subjects, private-relay emails, APNs tokens, or screenshots containing sensitive data.

## 1. Verify build and deployment

```bash
uv sync --extra dev --frozen
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
az aks show -g rg-soffortbackend-dev-wus2 -n aks-soffortbackend-dev-wus2 \
  --query powerState.code -o tsv
```

If stopped, use the manual **cluster lifecycle** GitHub workflow. The hourly cost job stops AKS after 19:00 America/Los_Angeles; it never starts it in the morning.

Confirm Flux and the immutable image digest through the private API command channel:

```bash
az aks command invoke -g rg-soffortbackend-dev-wus2 -n aks-soffortbackend-dev-wus2 \
  --command "kubectl -n soffortbackend get pods; kubectl -n soffortbackend get helmrelease; kubectl -n soffortbackend get deploy soffortbackend -o jsonpath='{.spec.template.spec.containers[0].image}'"
```

Expected: two Ready app pods, Ready HelmRelease, and an `acr.../soffortbackend@sha256:...` image.

## 2. Verify public boundary

```bash
dig +short consentary.com A
curl --fail --silent https://consentary.com/.well-known/oauth-protected-resource/mcp
curl --include --request POST https://consentary.com/mcp \
  --header 'content-type: application/json' --data '{}'
curl --include https://consentary.com/livez
```

Expected: apex resolves to `4.242.124.73`; metadata resource is exactly `https://consentary.com/mcp`; unauthenticated MCP returns 401 with the RFC 9728 metadata challenge; health is not publicly routed. Inspect the certificate in a browser and require a trusted, unexpired chain.

## 3. Update and prepare the iPhone

1. Open `/Users/alphonsekurian/Code/VaultBackend2/AIVaultApp/Consentary.xcodeproj` and run the
   `Consentary` scheme on the registered physical iPhone. Because `com.consentary.app` is a new app
   identity, authenticate and enroll this installation as a new device.
2. Sign in using the same External ID method/account used by VS Code. Test Apple first; repeat the authentication gate with email OTP separately.
3. Allow notifications and confirm Settings says **This iPhone is linked**.
4. In **Vault**, add fictional values:
   - Personal email: `ava.test@example.invalid`
   - Preferred name: `Ava Example`
5. Authenticate to edit, reveal, and delete. Confirm a reveal disappears after 15 seconds and whenever the app backgrounds.
6. Sign out and sign back into the same account; confirm the vault remains. Do not delete the vault yet.

## 4. Connect VS Code

Use VS Code 1.123+ and the committed `.vscode/mcp.json`. Start `soffortbackend`; the browser should identify the managed `ciamlogin.com` tenant and complete Apple or email sign-in. If an old token is cached, run **MCP: Reset Cached Tools** and restart the server.

Confirm `tools/list` contains exactly:

```text
list_available_properties
request_properties
```

No removed or legacy tool is acceptable.

## 5. Discovery test

1. Call `list_available_properties` with `{}`.
2. Confirm no phone notification or approval card appears.
3. Require `status: available` with metadata for every populated built-in and custom field.
4. Confirm no `value` member and no fictional plaintext appears anywhere in the result.
5. Add or remove a vault field on the phone, then repeat and confirm the index reflects the change.

## 6. Selective disclosure test

Copy exact opaque keys from the approved discovery result, preserving their order, then call `request_properties` with:

```json
{
  "properties": [
    "vault.<email-handle-from-discovery>",
    "vault.<preferred-name-handle-from-discovery>"
  ],
  "purpose": "Populate a fictional onboarding form"
}
```

On iPhone, verify the purpose is verbatim and all toggles initially are off. Select only Personal email and approve. For the unavailable case, repeat with one syntactically valid `vault.` handle that is not present on the phone.

Expected structured result:

```json
{
  "status": "partially_approved",
  "properties": [
    {
      "key": "vault.<email-handle-from-discovery>",
      "display_name": "Personal · Email",
      "value_type": "email",
      "value": "ava.test@example.invalid"
    }
  ],
  "denied_properties": ["vault.<preferred-name-handle-from-discovery>"],
  "unavailable_properties": []
}
```

The text content must contain only a count/status summary. Verify request order is preserved.

## 7. Failure and recovery matrix

| Test | Expected result |
|---|---|
| Deny every requested field | Structured `denied`; no tool exception |
| Request only an unstored field and approve | Structured `unavailable` |
| Unknown or duplicate key | Immediate MCP input error; no phone notification |
| Purpose empty, >200, or containing a control character | Immediate MCP input error |
| Ignore request for two minutes | Clear `approval_timed_out` tool error |
| Force-quit app, send request, reopen app | Requests tab recovers it from `GET /v1/approvals` |
| Disable notifications | Clear notification error, or inbox recovery when APNs was accepted before disabling |
| Submit decision twice/from two phones | First valid decision remains authoritative |
| Tamper result/signature/JWE/`kid` in an integration fixture | Rejected, no plaintext, no successful output |
| Alternate backend replica between create/poll/decision | Same result; no sticky session dependency |

Repeat authentication using email OTP. The iPhone and VS Code must use the same resulting External ID account; the service never links accounts using an email string.

## 8. Privacy and cleanup

Inspect application logs only for request IDs, status, timing, and error codes. Search for the fictional values and require no matches. Cosmos approval records may contain short-lived compact ciphertext, but never cleartext; they disappear after TTL.

After all gates pass, remove legacy profile documents in two bounded steps:

```bash
uv run python scripts/cleanup-profiles.py --endpoint <cosmos-endpoint>
uv run python scripts/cleanup-profiles.py --endpoint <cosmos-endpoint> \
  --apply --expected-count <dry-run-count>
```

The command prints counts only and deletes exclusively `kind=profile`. It does not touch devices, challenges, or consent records.

## 9. Rollback

Revert the digest-only deployment commit and merge it; Flux restores the prior immutable image. If the iOS update must be rolled back, install the previous signed build. Do not rotate/delete the Key Vault disclosure key version while any two-minute request may still reference its `kid`; disable old versions only after the request/TTL window and a verified new-key E2E.

Record only: date, tester, VS Code/Xcode/iOS versions, Git commits, deployed digest, pass/fail per section, p95/error-rate load-test summary, and sanitized failure codes.
