#!/usr/bin/env bash
set -euo pipefail

readonly SUBSCRIPTION_ID="86dfb8ca-2e38-4abb-9072-e8d077af295a"
readonly REPOSITORY="AlphonseKurian1618/soffortmcp"

usage() {
  echo "Usage: $0 --budget-email EMAIL" >&2
}

budget_email=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --budget-email) budget_email="$2"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "${budget_email}" ]] || { usage; exit 2; }

for command_name in az gh; do
  command -v "${command_name}" >/dev/null || {
    echo "Missing required command: ${command_name}" >&2
    exit 1
  }
done

az account set --subscription "${SUBSCRIPTION_ID}"

deployment_name="soffortbackend-bootstrap-$(date -u +%Y%m%d%H%M%S)"
az deployment sub create \
  --name "${deployment_name}" \
  --location westus2 \
  --template-file infra/bootstrap.bicep \
  --parameters \
    budgetContactEmails="[\"${budget_email}\"]"

infra_client_id="$(az deployment sub show --name "${deployment_name}" \
  --query properties.outputs.infrastructureClientId.value -o tsv)"
tenant_id="$(az account show --query tenantId -o tsv)"
operator_object_id="$(az ad signed-in-user show --query id -o tsv)"

gh api --method PUT "repos/${REPOSITORY}/environments/development" >/dev/null
gh variable set AZURE_INFRA_CLIENT_ID --repo "${REPOSITORY}" --env development \
  --body "${infra_client_id}"
gh variable set AZURE_TENANT_ID --repo "${REPOSITORY}" --env development \
  --body "${tenant_id}"
gh variable set AZURE_SUBSCRIPTION_ID --repo "${REPOSITORY}" --env development \
  --body "${SUBSCRIPTION_ID}"
gh variable set OPERATOR_OBJECT_ID --repo "${REPOSITORY}" --env development \
  --body "${operator_object_id}"
gh variable set CERTIFICATE_EMAIL --repo "${REPOSITORY}" --env development \
  --body "${budget_email}"

echo "Azure/GitHub bootstrap completed. Configure External ID next, then run the infrastructure workflow."
