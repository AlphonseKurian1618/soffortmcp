#!/usr/bin/env python3
"""Reject Azure development templates that can unexpectedly exceed the budget."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

DISALLOWED_TYPES = {
    "microsoft.cdn/profiles",  # Azure Front Door is a production TODO.
    "microsoft.network/natgateways",
    "microsoft.insights/components",
    "microsoft.operationalinsights/workspaces",
}
ALLOWED_NODE_SIZES = {"Standard_D4pls_v6", "Standard_D4pls_v5"}


def walk_resources(template: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield ARM resources, including resources inside nested templates."""
    for resource in template.get("resources", []):
        yield resource
        nested = resource.get("properties", {}).get("template")
        if isinstance(nested, dict):
            yield from walk_resources(nested)


def validate(template: dict[str, Any]) -> list[str]:
    """Return human-readable cost-policy violations."""
    violations: list[str] = []
    resources = list(walk_resources(template))
    types = [str(resource.get("type", "")).lower() for resource in resources]
    for disallowed in DISALLOWED_TYPES:
        if disallowed in types:
            violations.append(f"development template contains disallowed resource {disallowed}")

    public_ips = [item for item in types if item == "microsoft.network/publicipaddresses"]
    if len(public_ips) != 2:
        violations.append(
            f"development must define exactly two public IPs, found {len(public_ips)}"
        )

    clusters = [
        item
        for item in resources
        if str(item.get("type", "")).lower() == "microsoft.containerservice/managedclusters"
    ]
    if len(clusters) != 1:
        violations.append(f"development must define exactly one AKS cluster, found {len(clusters)}")
        return violations

    cluster = clusters[0]
    sku = cluster.get("sku", {})
    if sku.get("name") != "Base" or sku.get("tier") != "Free":
        violations.append("AKS must use Base SKU with Free management tier")
    properties = cluster.get("properties", {})
    if properties.get("networkProfile", {}).get("outboundType") != "loadBalancer":
        violations.append("AKS development outbound must use Standard Load Balancer")
    pools = properties.get("agentPoolProfiles", [])
    if len(pools) != 1 or pools[0].get("count") != 2:
        violations.append("AKS must use one fixed two-node pool")
    if pools and pools[0].get("enableAutoScaling") is not False:
        violations.append("AKS cluster autoscaler must remain disabled")

    node_parameter = template.get("parameters", {}).get("nodeVmSize", {})
    allowed = set(node_parameter.get("allowedValues", []))
    if allowed != ALLOWED_NODE_SIZES:
        violations.append(f"nodeVmSize must allow only {sorted(ALLOWED_NODE_SIZES)}")
    return violations


def main() -> int:
    """Load a compiled ARM template and enforce the development guardrails."""
    parser = argparse.ArgumentParser()
    parser.add_argument("template", type=Path)
    args = parser.parse_args()
    template = json.loads(args.template.read_text(encoding="utf-8"))
    violations = validate(template)
    if violations:
        for violation in violations:
            print(f"ERROR: {violation}")
        return 1
    print("Development cost guardrails passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
