# Consentary MCP server

The Consentary MCP server (internally packaged as `soffortbackend` for in-place deployment
compatibility) serves the iPhone vault at `https://consentary.com/mcp` and exposes exactly two tools:

- `list_available_properties()` reads value-free metadata for every populated vault field without an approval prompt.
- `request_properties(properties, purpose)` asks the phone to selectively release fields identified by the opaque handles returned from discovery.

Every call requires a Microsoft Entra External ID access token. Only value disclosure requires a fresh, signed iPhone decision. Entra federates Apple and email OTP authentication; Apple tokens, email codes, and passwords never reach this service. Approved values remain encrypted from the phone to an Azure Key Vault RSA key and are decrypted only in pod memory.

## Public interfaces

| Path | Access | Purpose |
|---|---|---|
| `POST /mcp` | `soffortbackend.access` | Stateless Streamable HTTP MCP |
| `GET /.well-known/oauth-protected-resource/mcp` | Public | RFC 9728 discovery |
| `GET /.well-known/oauth-protected-resource/v1` | Public | iPhone API OAuth discovery |
| `/v1/devices/*`, `/v1/property-index`, `/v1/approvals*` | `soffortbackend.mobile` | Device enrollment, value-free index updates, inbox recovery, signed decisions |
| `GET /livez`, `GET /readyz` | Cluster only | Kubernetes probes |

The server has no copy of the user's values. The iPhone publishes a subject-scoped, value-free index containing stable opaque handles and bounded presentation metadata for populated built-in, composed, repeated, or custom fields. Malformed and duplicate handles fail before storage. Values still require a signed phone decision; denial and unavailable values are structured business outcomes. Notification failure, timeout, bad signatures, and invalid ciphertext are value-free MCP errors. See [the mobile protocol](docs/mobile-approval-api.md).

## Local validation

```bash
uv sync --extra dev --frozen
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
```

Copy `.env.example` to `.env` and supply real Entra, Cosmos, APNs, workload identity, and Key Vault settings to run `uv run soffortbackend`. There is intentionally no authentication bypass.

## Deployment

Development uses AKS Free in West US 2, two scheduled PAYG ARM64 nodes, ACR Basic, direct Traefik ingress, cert-manager, serverless Cosmos DB, Standard Key Vault, and Flux. GoDaddy remains authoritative for `consentary.com`. Azure Front Door, WAF, and private origin are production TODOs and are not provisioned.

```bash
az account set --subscription 86dfb8ca-2e38-4abb-9072-e8d077af295a
./scripts/preflight.sh
./scripts/bootstrap-azure.sh --budget-email you@example.com
```

GitHub Actions publishes a scanned multi-architecture image. A digest-only pull request drives Flux; rollback is a digest commit revert. See [the operator runbook](docs/operator-runbook.md) and [the physical E2E runbook](docs/e2e-test-runbook.md).

## VS Code and privacy

`.vscode/mcp.json` contains the non-secret public client ID. VS Code 1.123+ opens the managed External ID sign-in flow. The service accepts only exact-issuer, audience-, client-, tenant-, and scope-bound Entra tokens.

Vault values, vault ownership identifiers, bearer tokens, request/response bodies, and plaintext are never logged. The encrypted vault remains solely on the iPhone and survives sign-out; switching accounts requires the current owner to authenticate and crypto-shred it.

The target development spend is USD $95–130/month with scheduled shutdown. Azure budget alerts do not enforce a hard cap; leaving both nodes running continuously can exceed $200.
