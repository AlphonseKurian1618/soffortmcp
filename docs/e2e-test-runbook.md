# End-to-end VS Code test runbook

This runbook proves the delivery outcome: VS Code authenticates a user, receives an audience- and
scope-bound access token, initializes `soffortbackend`, lists `hello_world`, and calls the tool
through `https://soffort.com/mcp`.

## Acceptance record

Record the date, tester, VS Code version, deployed image digest, and Git commit before starting.
Never record an access token, authorization code, email OTP, Apple subject, or private-relay email.

| Checkpoint | Expected result |
|---|---|
| Identity preflight | Apple validates PKCE, issuer, audience, tenant, client, resource, and scope; email status is recorded separately |
| DNS and TLS | `soffort.com` resolves to the reserved ingress IP and presents a trusted certificate |
| OAuth discovery | RFC 9728 metadata identifies the canonical resource and External ID authorization server |
| Authentication | VS Code opens a browser and completes the configured External ID flow |
| Authorization | Missing token returns 401; missing scope returns 403; correct token reaches MCP |
| MCP protocol | `initialize`, `tools/list`, and `tools/call` succeed |
| Tool contract | `hello_world` returns the exact text and structured result |

## Fixed development identifiers

- Azure subscription: `86dfb8ca-2e38-4abb-9072-e8d077af295a`
- Resource group: `rg-soffortbackend-dev-wus2`
- AKS cluster: `aks-soffortbackend-dev-wus2`
- MCP resource: `https://soffort.com/mcp`
- External tenant: `85685fcd-3fc0-4032-982c-92ddd6efc37b`
- VS Code client: `9cea70e5-8b4c-4f37-bf6f-2d789ae49492`
- API audience: `387b7862-7ab6-4139-af73-b54f535ded29`
- Required delegated scope: `soffortbackend.access`

These values are identifiers, not credentials. The Apple `.p8`, bearer tokens, and OTPs must never
be placed in the repository, shell history, screenshots, tickets, or test evidence.

## 1. Local and identity preflight

From the repository root:

```bash
make lint
make typecheck
make test
make bicep
```

Run the Apple authorization-code probe:

```bash
.venv/bin/python scripts/test-identity-pkce.py \
  --sign-in-method apple \
  --timeout-seconds 600
```

Apple mode adds Microsoft's supported `domain_hint=apple` issuer acceleration. Complete the Apple
prompt yourself. The script keeps codes and tokens in memory and prints only conformance facts.
Every boolean must be `true`, and `requested_sign_in_method` must be `apple`.

Run the email OTP probe in a fresh private browser session:

```bash
.venv/bin/python scripts/test-identity-pkce.py \
  --sign-in-method email \
  --timeout-seconds 600
```

Enter the email and OTP yourself. Email OTP is enabled in the same managed user flow, but the
current hosted provider page fails before it renders the selector. Record that result separately;
it does not weaken or block the proven Apple-authenticated development path. Do not claim email
E2E acceptance or promote the service to production until the managed-page issue is resolved. See
`docs/identity-runbook.md` for the reproduction record and safety boundary.

## 2. Infrastructure and cost gate

Confirm the correct subscription and that no unexpected development resources already exist:

```bash
az account set --subscription 86dfb8ca-2e38-4abb-9072-e8d077af295a
az account show --query '{subscription:id, tenant:tenantId, user:user.name}' --output table
./scripts/preflight.sh
az resource list \
  --resource-group rg-soffortbackend-dev-wus2 \
  --query '[].{name:name,type:type,location:location}' \
  --output table
```

Review the infrastructure workflow with `apply=false`. Confirm What-If contains no Azure Front
Door, WAF, NAT Gateway, AKS Automatic, more than two nodes, or an unapproved VM size. Then run it
with `apply=true`. Record its reserved ingress IP and ACR/identity outputs in the protected GitHub
`development` environment as described in `docs/operator-runbook.md`.

Do not start a cluster automatically in the morning. Stop it after testing through the
`cluster-lifecycle` workflow. Confirm the $150, $180, and $195 budget notifications exist before
leaving billable compute running.

## 3. GoDaddy DNS and TLS

In GoDaddy DNS for `soffort.com`, create or update this record after Azure returns the ingress IP:

| Type | Name | Value | TTL |
|---|---|---|---|
| A | `@` | `<reserved-ingress-ip>` | 600 seconds during validation |

Wait for public DNS, then verify:

```bash
dig +short A soffort.com
curl --fail --silent --show-error \
  https://soffort.com/.well-known/oauth-protected-resource/mcp
openssl s_client -connect soffort.com:443 -servername soffort.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

The A record must equal the reserved ingress IP. TLS must be trusted, unexpired, and valid for
`soffort.com`.

## 4. Deployment verification

Flux deploys immutable image digests; do not deploy `latest`. Verify reconciliation from an
approved network path to the private AKS API:

```bash
flux get all --all-namespaces
kubectl -n soffortbackend get deployment,pods,service
kubectl -n soffortbackend rollout status deployment/soffortbackend --timeout=5m
kubectl -n soffortbackend get pods -o wide
```

Expected state: two ready application replicas, no restarts, a ClusterIP application service, and
healthy Flux resources.

Verify the public security boundary without a token:

```bash
curl --include \
  https://soffort.com/.well-known/oauth-protected-resource/mcp
curl --include --request POST \
  --header 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"e2e-probe","version":"1"}}}' \
  https://soffort.com/mcp
curl --include https://soffort.com/livez
```

Expected results:

- protected-resource metadata: 200, canonical resource, authorization server, and required scope;
- unauthenticated MCP request: 401 and a `WWW-Authenticate` metadata challenge;
- public `/livez`: not routed (404), never an application health response.

## 5. VS Code desktop

1. Install or update stable VS Code to 1.123 or later.
2. Open this repository and inspect `.vscode/mcp.json`. It must contain the canonical URL and
   committed public client ID; it must contain no client secret or bearer token.
3. Run `Authentication: Remove Dynamic Authentication Providers` if an earlier failed MCP login is
   cached. Also remove the server account through **Accounts > Manage Trusted MCP Servers** when
   repeating a clean-login test.
4. Open `.vscode/mcp.json` and select **Start**, or run **MCP: List Servers**, choose
   `soffortbackend`, and start it.
5. Review and trust the MCP server when prompted. The browser must use the configured External ID
   tenant and return through `http://127.0.0.1:33418`.
6. Open **MCP: List Servers > soffortbackend > Show Output**. Confirm initialization succeeds and
   no token, code, email, or response body is logged.
7. In Agent mode, ask: `Use soffortbackend hello_world with the name VS Code.` Approve the tool
   call when prompted.

Expected tool result:

```json
{
  "message": "Hello, VS Code!",
  "server": "soffortbackend"
}
```

Repeat with no name and expect `Hello, World!`. Repeat with a 101-character name and expect a
validation error rather than truncation or a server failure.

## 6. Authorization checks

- Repeat the unauthenticated request and confirm 401, not a redirect or 200.
- Use a correctly signed token without `soffortbackend.access` in an isolated test and confirm 403
  plus `error="insufficient_scope"`. Never weaken the live API registration to create this test.
- Confirm a token for another audience, tenant, or client is rejected with 401.
- Confirm application logs contain only the request ID and non-identifying failure reason.

These negative tests prove authz is enforced by the resource server rather than merely presenting a
login page.

## 7. `vscode.dev` and stateless behavior

Open the repository through `vscode.dev`, start `soffortbackend`, and repeat the tool call. The OAuth
callback must use `https://vscode.dev/redirect`. Alternate at least ten calls while observing pod
logs; successful calls may land on either replica without a sticky session.

## 8. Completion and shutdown

Attach only sanitized evidence: versions, timestamps, status codes, non-secret claim checks, tool
output, pod readiness, image digest, and CI/deployment URLs. Then stop the cluster with the manual
`cluster-lifecycle` workflow and verify `powerState.code` is `Stopped`:

```bash
az aks show \
  --resource-group rg-soffortbackend-dev-wus2 \
  --name aks-soffortbackend-dev-wus2 \
  --query powerState.code \
  --output tsv
```

The test is complete only after both the functional result and cost-protection shutdown are
recorded.
