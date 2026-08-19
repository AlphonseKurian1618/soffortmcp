#!/usr/bin/env bash
set -euo pipefail

readonly SUBSCRIPTION_ID="86dfb8ca-2e38-4abb-9072-e8d077af295a"
readonly REPOSITORY="AlphonseKurian1618/soffortmcp"

usage() {
  echo "Usage: $0 --budget-email EMAIL [--dns-resource-group NAME]" >&2
}

budget_email=""
dns_resource_group=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --budget-email) budget_email="$2"; shift 2 ;;
    --dns-resource-group) dns_resource_group="$2"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "${budget_email}" ]] || { usage; exit 2; }

for command_name in az gh ssh-keygen; do
  command -v "${command_name}" >/dev/null || {
    echo "Missing required command: ${command_name}" >&2
    exit 1
  }
done

az account set --subscription "${SUBSCRIPTION_ID}"
if [[ -z "${dns_resource_group}" ]]; then
  dns_resource_group="$(az network dns zone list \
    --query "[?name=='soffort.com'].resourceGroup | [0]" -o tsv)"
fi
[[ -n "${dns_resource_group}" ]] || {
  echo "Azure DNS zone soffort.com was not found." >&2
  exit 1
}

deployment_name="soffortbackend-bootstrap-$(date -u +%Y%m%d%H%M%S)"
az deployment sub create \
  --name "${deployment_name}" \
  --location westus2 \
  --template-file infra/bootstrap.bicep \
  --parameters \
    dnsZoneResourceGroupName="${dns_resource_group}" \
    budgetContactEmails="[\"${budget_email}\"]"

infra_client_id="$(az deployment sub show --name "${deployment_name}" \
  --query properties.outputs.infrastructureClientId.value -o tsv)"
tenant_id="$(az account show --query tenantId -o tsv)"
operator_object_id="$(az ad signed-in-user show --query id -o tsv)"

temporary_directory="$(mktemp -d)"
trap 'rm -rf "${temporary_directory}"' EXIT
ssh-keygen -q -t ed25519 -N "" -C "soffortbackend-dev-flux" \
  -f "${temporary_directory}/flux"

# GitHub keeps the only durable copy of this read-only deploy key. The private
# half is stored as an environment secret and passed to ARM as a secure value.
gh api --method PUT "repos/${REPOSITORY}/environments/development" >/dev/null
gh repo deploy-key add "${temporary_directory}/flux.pub" \
  --repo "${REPOSITORY}" \
  --title "soffortbackend-dev-flux-$(date -u +%Y%m%d)"
gh api meta --jq '.ssh_keys[]' | sed 's/^/github.com /' > "${temporary_directory}/known_hosts"

private_key_b64="$(base64 < "${temporary_directory}/flux" | tr -d '\n')"
known_hosts_b64="$(base64 < "${temporary_directory}/known_hosts" | tr -d '\n')"
gh secret set FLUX_SSH_PRIVATE_KEY_B64 --repo "${REPOSITORY}" --env development \
  --body "${private_key_b64}"
gh variable set FLUX_SSH_KNOWN_HOSTS_B64 --repo "${REPOSITORY}" --env development \
  --body "${known_hosts_b64}"
gh variable set AZURE_INFRA_CLIENT_ID --repo "${REPOSITORY}" --env development \
  --body "${infra_client_id}"
gh variable set AZURE_TENANT_ID --repo "${REPOSITORY}" --env development \
  --body "${tenant_id}"
gh variable set AZURE_SUBSCRIPTION_ID --repo "${REPOSITORY}" --env development \
  --body "${SUBSCRIPTION_ID}"
gh variable set DNS_ZONE_RESOURCE_GROUP --repo "${REPOSITORY}" --env development \
  --body "${dns_resource_group}"
gh variable set OPERATOR_OBJECT_ID --repo "${REPOSITORY}" --env development \
  --body "${operator_object_id}"
gh variable set CERTIFICATE_EMAIL --repo "${REPOSITORY}" --env development \
  --body "${budget_email}"

echo "Azure/GitHub bootstrap completed. Configure External ID next, then run the infrastructure workflow."
