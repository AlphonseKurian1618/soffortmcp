# soffortbackend

`soffortbackend` is a production-shaped [Model Context Protocol](https://modelcontextprotocol.io/) resource server. It publishes one authenticated `hello_world` tool at `https://soffort.com/mcp`. Every invocation creates a fresh, 60-second iPhone approval and returns the user's server profile name only after the enrolled phone signs an approval.

Microsoft Entra External ID is configured for Apple and passwordless email one-time passcodes.
Apple is the verified development path; the managed email provider page has a known issue recorded
in `docs/identity-runbook.md`. The server accepts only short-lived Entra API access tokens; it never
receives Apple tokens, the Apple private key, an email OTP, or an end-user password.

## API contract

| Path | Exposure | Purpose |
|---|---|---|
| `POST /mcp` | Public, bearer token required | Stateless Streamable HTTP MCP |
| `GET /.well-known/oauth-protected-resource/mcp` | Public | RFC 9728 discovery |
| `GET /.well-known/oauth-protected-resource/v1` | Public | iPhone API OAuth discovery |
| `/v1/me/profile`, `/v1/devices/*`, `/v1/approvals/*` | Public, iOS bearer token required | Profile, phone enrollment, and signed decisions |
| `GET /livez` and `GET /readyz` | Cluster-only | Kubernetes probes |

The only tool is `hello_world()`; it has no arguments. A successful approved call returns both MCP text content and this structured result:

```json
{"message":"Hello, Alphonse!","user_name":"Alphonse","server":"soffortbackend"}
```

Without a profile, enrolled phone, APNs delivery, or timely approval, the tool fails closed with a stable value-free code. Apple tokens and notification payloads are never authorization. See [the mobile approval contract](docs/mobile-approval-api.md).

## Local validation

Install [uv](https://docs.astral.sh/uv/), then run:

```bash
uv sync --extra dev --frozen
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

Running the HTTP server requires real Entra resource-server settings. Copy `.env.example` to `.env`, replace every placeholder with output from the identity bootstrap, and run:

```bash
uv run soffortbackend
```

There is intentionally no local authentication bypass. Unit tests inject a deterministic verifier, while manual HTTP testing uses a real Entra access token.

## Identity setup

1. Create or select a Microsoft Entra External ID tenant.
2. Run `scripts/bootstrap-identity.py` as an administrator. It creates the API, VS Code, and iOS public-client registrations, both delegated scopes, admin consent, and optional user-flow associations idempotently.
3. In Apple Developer, create the primary App ID, Services ID, Sign in with Apple key, and register the exact federation return URL displayed by Entra.
4. Configure Apple and Email One Time Passcode in the External ID user flow, enable open self-service registration, and associate both `soffortbackend-vscode` and `soffortbackend-ios` with that flow.
5. Upload or derive Apple material only through the Entra administration flow. Never copy the `.p8` file into this repository, AKS, GitHub Actions, or chat.
6. Grant the VS Code client `soffortbackend.access` and the iOS client `soffortbackend.mobile`. Perform both OAuth gates in `docs/identity-runbook.md`.

Upstream authentication is intentionally not hidden behind application code. Microsoft Entra owns
the Apple callback and email-code verification, then issues the audience-bound access token that
this service verifies.

## Azure deployment

The development topology uses West US 2, AKS Free management tier, two scheduled PAYG ARM64 nodes, ACR Basic, direct Traefik ingress, cert-manager, Flux, one serverless Cosmos DB account, and one Standard Key Vault. The app uses direct APNs, avoiding Redis, Service Bus, and Notification Hubs. GoDaddy remains authoritative for `soffort.com`; deployment outputs the static ingress IP for the apex `A` record. It deliberately excludes Azure Front Door, WAF, NAT Gateway, and paid monitoring.

Deployment sequence:

```bash
az login
az account set --subscription 86dfb8ca-2e38-4abb-9072-e8d077af295a
./scripts/preflight.sh
./scripts/bootstrap-azure.sh --budget-email you@example.com
```

The infrastructure workflow never reaches the private Kubernetes API. Flux reads this public Git
repository over HTTPS and reconciles `deploy/flux/dev`; GitHub Actions builds and scans an
immutable image, then opens a digest-only deployment pull request.

See `docs/operator-runbook.md` for start/stop, deployment, rollback, DNS, TLS, and incident procedures. Use `docs/e2e-test-runbook.md` for the complete authenticated VS Code acceptance test. Current development infrastructure has no control-plane SLA and is intentionally unavailable whenever the cluster is stopped.

## VS Code

The committed `.vscode/mcp.json` contains the generated non-secret public client ID. VS Code 1.123
or later opens the browser for managed External ID authentication on first use.

The real compatibility test is a release gate: if current VS Code cannot request an Entra token with the expected resource, audience, and scope, do not add an in-process OAuth proxy. Record the failing request/response metadata without tokens and revisit the managed identity-provider choice.

## Cost boundary

The target is approximately USD $95–130 per month when the cluster runs about twelve weekday hours. A GitHub workflow stops it after 19:00 America/Los_Angeles, but Azure budgets are alerts rather than a hard cap. Leaving two nodes running continuously is expected to exceed the $200 monthly limit.

Azure Front Door Premium and WAF are a documented future production migration, not development dependencies. See `docs/adr/0004-future-production-front-door.md`.
