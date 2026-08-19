#!/usr/bin/env bash
set -euo pipefail

# This script is read-only: it proves the selected subscription, region, DNS,
# Kubernetes version, VM SKU, and operator identity before any deployment.
readonly SUBSCRIPTION_ID="86dfb8ca-2e38-4abb-9072-e8d077af295a"
readonly LOCATION="westus2"

for command_name in az git python3; do
  command -v "${command_name}" >/dev/null || {
    echo "Missing required command: ${command_name}" >&2
    exit 1
  }
done

az account set --subscription "${SUBSCRIPTION_ID}"
active_subscription="$(az account show --query id -o tsv)"
[[ "${active_subscription}" == "${SUBSCRIPTION_ID}" ]] || {
  echo "Azure CLI selected the wrong subscription." >&2
  exit 1
}

dns_groups="$(az network dns zone list \
  --query "[?name=='soffort.com'].resourceGroup" \
  --output tsv)"
dns_group_count="$(printf '%s\n' "${dns_groups}" | awk 'NF { count += 1 } END { print count + 0 }')"
[[ "${dns_group_count}" -eq 1 ]] || {
  echo "Expected exactly one Azure DNS zone named soffort.com; found ${dns_group_count}." >&2
  exit 1
}

operator_object_id="$(az ad signed-in-user show --query id -o tsv)"

sku="Standard_D4pls_v6"
available="$(az vm list-skus --location "${LOCATION}" --size "${sku}" --all \
  --query "[?name=='${sku}' && length(restrictions)==\`0\`].name | [0]" -o tsv)"
if [[ -z "${available}" ]]; then
  sku="Standard_D4pls_v5"
  available="$(az vm list-skus --location "${LOCATION}" --size "${sku}" --all \
    --query "[?name=='${sku}' && length(restrictions)==\`0\`].name | [0]" -o tsv)"
fi
[[ -n "${available}" ]] || {
  echo "Neither approved ARM64 node SKU is currently available in ${LOCATION}." >&2
  exit 1
}

kubernetes_version="$(az aks get-versions --location "${LOCATION}" \
  --query "values[?isDefault].version | [0]" -o tsv)"
[[ -n "${kubernetes_version}" ]] || {
  echo "Could not resolve the current default GA AKS version." >&2
  exit 1
}

echo "Preflight passed. Supply these non-secret values to the deployment:"
printf 'DNS_ZONE_RESOURCE_GROUP=%s\n' "${dns_groups}"
printf 'OPERATOR_OBJECT_ID=%s\n' "${operator_object_id}"
printf 'NODE_VM_SIZE=%s\n' "${sku}"
printf 'KUBERNETES_VERSION=%s\n' "${kubernetes_version}"
