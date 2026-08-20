# soffortbackend

`soffortbackend` is a small, production-shaped [Model Context Protocol](https://modelcontextprotocol.io/) resource server. It publishes one authenticated `hello_world` tool at `https://soffort.com/mcp` and is designed to run as a stateless, horizontally scalable workload in Azure Kubernetes Service (AKS).

Apple is the upstream sign-in method in Microsoft Entra External ID. The server accepts only short-lived Entra API access tokens; it never receives Apple ID tokens, Apple access tokens, or the Apple private key.

## API contract

| Path | Exposure | Purpose |
|---|---|---|
| `POST /mcp` | Public, bearer token required | Stateless Streamable HTTP MCP |
| `GET /.well-known/oauth-protected-resource/mcp` | Public | RFC 9728 discovery |
| `GET /livez` and `GET /readyz` | Cluster-only | Kubernetes probes |

The only tool is `hello_world(name: str = "World")`. It returns both MCP text content and this structured result:

```json
{"message":"Hello, World!","server":"soffortbackend"}
```

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
2. Run `scripts/bootstrap-identity.py` interactively as an administrator. It creates the API and public-client registrations idempotently and prints non-secret deployment outputs.
3. In Apple Developer, create the primary App ID, Services ID, Sign in with Apple key, and register the exact federation return URL displayed by Entra.
4. Configure Apple as the only identity provider in the External ID user flow and associate `soffortbackend-vscode` with that flow.
5. Upload or derive Apple material only through the Entra administration flow. Never copy the `.p8` file into this repository, AKS, GitHub Actions, or chat.
6. Grant the VS Code public client admin consent to `soffortbackend.access` and perform the VS Code OAuth compatibility gate described in `docs/identity-runbook.md`.

Apple federation configuration is intentionally not hidden behind application code. Microsoft Entra owns the Apple callback and issues the audience-bound access token that this service verifies.

## Azure deployment

The development topology uses West US 2, AKS Free management tier, two scheduled PAYG ARM64 nodes, ACR Basic, direct Traefik ingress, cert-manager, and Flux. GoDaddy remains authoritative for `soffort.com`; deployment outputs the static ingress IP for a manual apex `A` record. It deliberately excludes Azure Front Door, WAF, NAT Gateway, databases, and paid monitoring.

Deployment sequence:

```bash
az login
az account set --subscription 86dfb8ca-2e38-4abb-9072-e8d077af295a
./scripts/preflight.sh
./scripts/bootstrap-azure.sh --budget-email you@example.com
```

The infrastructure workflow never reaches the private Kubernetes API. Flux reads the private Git repository and reconciles `deploy/flux/dev`; GitHub Actions builds and scans an immutable image, then opens a digest-only deployment pull request.

See `docs/operator-runbook.md` for start/stop, deployment, rollback, DNS, TLS, and incident procedures. Current development infrastructure has no control-plane SLA and is intentionally unavailable whenever the cluster is stopped.

## VS Code

After identity bootstrap, replace `REPLACE_WITH_ENTRA_PUBLIC_CLIENT_ID` in `.vscode/mcp.json` with the generated non-secret public client ID. VS Code 1.123 or later opens the browser for Apple sign-in on first use.

The real compatibility test is a release gate: if current VS Code cannot request an Entra token with the expected resource, audience, and scope, do not add an in-process OAuth proxy. Record the failing request/response metadata without tokens and revisit the managed identity-provider choice.

## Cost boundary

The target is approximately USD $95–130 per month when the cluster runs about twelve weekday hours. A GitHub workflow stops it after 19:00 America/Los_Angeles, but Azure budgets are alerts rather than a hard cap. Leaving two nodes running continuously is expected to exceed the $200 monthly limit.

Azure Front Door Premium and WAF are a documented future production migration, not development dependencies. See `docs/adr/0004-future-production-front-door.md`.
