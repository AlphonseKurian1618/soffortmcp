#!/usr/bin/env python3
"""Enforce workload security and scaling policy on rendered Helm manifests."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


def validate(documents: list[dict[str, Any]]) -> list[str]:
    """Return violations found in the rendered application manifests."""
    violations: list[str] = []
    by_kind = {str(document.get("kind")): document for document in documents}
    deployment = by_kind.get("Deployment")
    if deployment is None:
        return ["Deployment is missing"]

    spec = deployment["spec"]
    if spec.get("replicas") != 2:
        violations.append("Deployment must start with two replicas")
    pod_spec = spec["template"]["spec"]
    pod_labels = spec["template"].get("metadata", {}).get("labels", {})
    if pod_labels.get("azure.workload.identity/use") != "true":
        violations.append("application pod must opt into Azure Workload Identity")
    if pod_spec.get("automountServiceAccountToken") is not False:
        violations.append("service-account tokens must not be mounted")
    security = pod_spec.get("securityContext", {})
    if security.get("runAsNonRoot") is not True:
        violations.append("pod must run as non-root")
    containers = pod_spec.get("containers", [])
    if len(containers) != 1:
        violations.append("exactly one application container is expected")
    else:
        container = containers[0]
        image = str(container.get("image", ""))
        if "@sha256:" not in image or image.endswith(":latest"):
            violations.append("container image must use an immutable sha256 digest")
        container_security = container.get("securityContext", {})
        if container_security.get("readOnlyRootFilesystem") is not True:
            violations.append("container root filesystem must be read-only")
        if container_security.get("allowPrivilegeEscalation") is not False:
            violations.append("privilege escalation must be disabled")
        if container_security.get("capabilities", {}).get("drop") != ["ALL"]:
            violations.append("all Linux capabilities must be dropped")
        resources = container.get("resources", {})
        if not resources.get("requests") or not resources.get("limits"):
            violations.append("container requests and limits are required")

    hpa = by_kind.get("HorizontalPodAutoscaler", {})
    if hpa.get("spec", {}).get("maxReplicas") != 4:
        violations.append("HPA maxReplicas must remain four")
    pdb = by_kind.get("PodDisruptionBudget", {})
    if pdb.get("spec", {}).get("minAvailable") != 1:
        violations.append("PDB must keep one replica available")
    if "NetworkPolicy" not in by_kind:
        violations.append("NetworkPolicy is missing")
    service_account = by_kind.get("ServiceAccount", {})
    annotations = service_account.get("metadata", {}).get("annotations", {})
    if not annotations.get("azure.workload.identity/client-id"):
        violations.append("service account must select the application workload identity")
    gateway = by_kind.get("Gateway", {})
    listener_ports = {
        listener.get("name"): listener.get("port")
        for listener in gateway.get("spec", {}).get("listeners", [])
    }
    # Traefik's Service maps public 80/443 to these internal entrypoints. A
    # Gateway using the public ports is rejected by Traefik as PortUnavailable.
    if listener_ports != {"http": 8000, "https": 8443}:
        violations.append("Gateway listeners must match Traefik entrypoints 8000/8443")
    return violations


def main() -> int:
    """Validate a Helm-rendered multi-document YAML file."""
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    loaded = yaml.safe_load_all(args.manifest.read_text(encoding="utf-8"))
    documents = [item for item in loaded if isinstance(item, dict)]
    violations = validate(documents)
    if violations:
        for violation in violations:
            print(f"ERROR: {violation}")
        return 1
    print("Rendered workload policy passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
