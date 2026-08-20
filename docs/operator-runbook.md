# Development operator runbook

## One-time bootstrap

1. Install Azure CLI, GitHub CLI, `uv`, Helm 4.2.4, Docker Buildx, and Python 3.14.
2. Authenticate `az` to subscription `86dfb8ca-2e38-4abb-9072-e8d077af295a` and authenticate `gh` as a repository administrator.
3. Run `./scripts/preflight.sh` and address every SKU, identity, or AKS-version failure.
4. Run `./scripts/bootstrap-azure.sh --budget-email <operator-email>`. This creates the development resource group, budget, and scoped GitHub OIDC identity. Flux reads the public repository over HTTPS and needs no deploy key.
5. Authenticate Azure CLI to the External ID tenant and run `python scripts/bootstrap-identity.py --tenant-id <external-tenant-guid> --tenant-subdomain <ciam-subdomain> --github-repository AlphonseKurian1618/soffortmcp`. This writes the non-secret identity outputs to protected GitHub environment variables; finish the Apple and Email OTP user-flow steps in `docs/identity-runbook.md`.
6. Confirm `OPERATOR_OBJECT_ID` in the GitHub development environment matches the value reported by `scripts/preflight.sh`.
7. Run the infrastructure workflow with `apply=false`, review What-If, then rerun with `apply=true` after environment approval.
8. Copy its ACR, release client ID, lifecycle client ID, and login-server outputs into `ACR_NAME`, `AZURE_RELEASE_CLIENT_ID`, `AZURE_LIFECYCLE_CLIENT_ID`, and `ACR_LOGIN_SERVER` development environment variables.
9. In GoDaddy DNS, create an apex `A` record whose host is `@` and value is the `ingressIpAddress` deployment output. Use a short TTL such as 600 seconds during setup. Inspect existing apex `A`, `AAAA`, forwarding, and parking records before replacing anything; DNS must resolve only to the AKS ingress before cert-manager can complete HTTP-01 validation.

No Apple secret, Azure service-principal secret, or Flux repository credential is used. Flux has public read-only HTTPS access; repository writes still require protected GitHub workflows and OIDC.
Release and scheduled lifecycle jobs intentionally remain skipped until their scoped identity variables exist.

## Start, stop, and inspect

Use the `cluster lifecycle` workflow to start or stop AKS. A schedule checks Los Angeles time hourly and stops it after 19:00 or before 07:00; there is no scheduled start. The Standard Load Balancer, public IPs, ACR, DNS, and disks continue to incur small charges while stopped.

The API server is private. For an exceptional read-only inspection, use Azure's control-plane command channel rather than opening it publicly:

```bash
az aks command invoke \
  --resource-group rg-soffortbackend-dev-wus2 \
  --name aks-soffortbackend-dev-wus2 \
  --command "kubectl get pods,helmreleases -A"
```

Do not place tokens or Apple/Entra responses in command output attached to an issue.

## Deploy and roll back

Merging application code runs CI and publishes a multi-architecture image only after tests and scans pass. The release workflow opens a second pull request changing the HelmRelease to an immutable digest. Merge that PR to deploy through Flux.

Rollback by reverting the digest commit. Flux applies the previous digest and Helm remediation rolls back a failed upgrade automatically. GitHub-hosted runners never run `kubectl` or `helm upgrade` against the private cluster.

## Smoke tests

After DNS, TLS, and Flux report healthy:

```bash
curl --fail --silent --show-error \
  https://soffort.com/.well-known/oauth-protected-resource/mcp
curl --include --request POST https://soffort.com/mcp \
  --header 'content-type: application/json' --data '{}'
```

The metadata request must return 200 and canonical resource `https://soffort.com/mcp`. The unauthenticated MCP request must return 401 with `WWW-Authenticate` pointing to that metadata. `/livez` and `/readyz` must not be publicly routed.

Complete the real VS Code Apple and Email OTP gates before unsuspending the first application
release. Run `scripts/load-test.py` only with a short-lived development token in a local shell;
shell history and logs must not retain it.

## Incidents and cost

- At the $150 alert, stop AKS and inspect Cost Analysis by resource.
- At $180 forecast, keep the cluster stopped except for a diagnosed test window.
- At $195 actual, stop AKS immediately and obtain owner approval before restarting.
- Azure budgets do not cap spend. Verify the cluster actually reaches `Stopped` after workflow execution.
- If the repository becomes private again, add a read-only Flux credential through protected settings before reconciliation; do not place it in Git.
- If Entra JWKS is unavailable, pods remain alive but unready and fail token verification closed.
- Renew the Apple federation credential at least 30 days before its six-month deadline.

Azure Front Door, WAF, private origin, paid AKS SLA, paid monitoring, and regional failover are production TODOs and must not be added to this development resource group.
