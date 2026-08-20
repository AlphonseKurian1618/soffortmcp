#!/usr/bin/env python3
"""Idempotently create the two Entra External ID application registrations.

Apple Developer configuration and the External ID Apple-only user flow remain
explicit portal operations because they require the one-time Apple private key
and tenant-specific federation callback. This script never accepts that key.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from uuid import uuid4

GRAPH = "https://graph.microsoft.com/v1.0"
API_NAME = "soffortbackend-api"
CLIENT_NAME = "soffortbackend-vscode"
SCOPE_VALUE = "soffortbackend.access"
RESOURCE_URI = "https://soffort.com/mcp"
REDIRECTS = ["http://127.0.0.1:33418", "https://vscode.dev/redirect"]


class GraphClient:
    """Small Microsoft Graph client that keeps bearer tokens out of logs."""

    def __init__(self, token: str) -> None:
        """Bind requests to one short-lived operator Graph access token."""
        self._token = token

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        """Send one JSON request and return the decoded Graph response."""
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310 - GRAPH is an HTTPS constant.
            f"{GRAPH}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                content = response.read()
        except urllib.error.HTTPError as error:
            # Graph error bodies contain correlation information but should not
            # contain the access token. They materially help an admin fix scopes.
            detail = error.read().decode(errors="replace")
            raise RuntimeError(f"Graph {method} {path} failed ({error.code}): {detail}") from error
        return json.loads(content) if content else None


def azure_access_token(tenant_id: str) -> str:
    """Obtain a Graph token from the operator's existing Azure CLI login."""
    command = [
        "az",
        "account",
        "get-access-token",
        "--tenant",
        tenant_id,
        "--resource-type",
        "ms-graph",
        "--query",
        "accessToken",
        "-o",
        "tsv",
    ]
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()  # noqa: S603


def find_application(graph: GraphClient, display_name: str) -> dict[str, Any] | None:
    """Find exactly one application registration by its stable display name."""
    escaped = display_name.replace("'", "''")
    query = urllib.parse.urlencode({"$filter": f"displayName eq '{escaped}'"})
    result = graph.request("GET", f"/applications?{query}")
    applications = result.get("value", [])
    if len(applications) > 1:
        raise RuntimeError(f"Multiple application registrations are named {display_name}")
    return applications[0] if applications else None


def ensure_service_principal(graph: GraphClient, app_id: str) -> dict[str, Any]:
    """Create the tenant-local service principal when it does not exist."""
    query = urllib.parse.urlencode({"$filter": f"appId eq '{app_id}'"})
    result = graph.request("GET", f"/servicePrincipals?{query}")
    principals = result.get("value", [])
    if len(principals) > 1:
        raise RuntimeError(f"Multiple service principals exist for appId {app_id}")
    if principals:
        return principals[0]
    return graph.request("POST", "/servicePrincipals", {"appId": app_id})


def ensure_api_application(graph: GraphClient) -> tuple[dict[str, Any], str]:
    """Create or normalize the MCP API registration and delegated scope."""
    application = find_application(graph, API_NAME)
    if application is None:
        scope_id = str(uuid4())
        application = graph.request(
            "POST",
            "/applications",
            {
                "displayName": API_NAME,
                "signInAudience": "AzureADMyOrg",
                "identifierUris": [RESOURCE_URI],
                "api": {
                    "requestedAccessTokenVersion": 2,
                    "oauth2PermissionScopes": [scope_definition(scope_id)],
                },
            },
        )
        return application, scope_id

    scopes = application.get("api", {}).get("oauth2PermissionScopes", [])
    matching = [scope for scope in scopes if scope.get("value") == SCOPE_VALUE]
    if len(matching) > 1:
        raise RuntimeError("Duplicate soffortbackend.access scopes exist")
    scope_id = matching[0]["id"] if matching else str(uuid4())
    if not matching:
        scopes.append(scope_definition(scope_id))
    graph.request(
        "PATCH",
        f"/applications/{application['id']}",
        {
            "identifierUris": [RESOURCE_URI],
            "api": {
                "requestedAccessTokenVersion": 2,
                "oauth2PermissionScopes": scopes,
            },
        },
    )
    return graph.request("GET", f"/applications/{application['id']}"), scope_id


def scope_definition(scope_id: str) -> dict[str, Any]:
    """Return the stable delegated permission contract."""
    return {
        "adminConsentDescription": "Access the authenticated soffortbackend MCP tools.",
        "adminConsentDisplayName": "Access soffortbackend",
        "id": scope_id,
        "isEnabled": True,
        "type": "Admin",
        "userConsentDescription": "Access the authenticated soffortbackend MCP tools.",
        "userConsentDisplayName": "Access soffortbackend",
        "value": SCOPE_VALUE,
    }


def ensure_client_application(
    graph: GraphClient,
    api_app_id: str,
    scope_id: str,
) -> dict[str, Any]:
    """Create or normalize the secretless VS Code public-client registration."""
    required_access = [
        {
            "resourceAppId": api_app_id,
            "resourceAccess": [{"id": scope_id, "type": "Scope"}],
        }
    ]
    body = {
        "displayName": CLIENT_NAME,
        "signInAudience": "AzureADMyOrg",
        "isFallbackPublicClient": True,
        "publicClient": {"redirectUris": REDIRECTS},
        "requiredResourceAccess": required_access,
    }
    application = find_application(graph, CLIENT_NAME)
    if application is None:
        return graph.request("POST", "/applications", body)
    graph.request("PATCH", f"/applications/{application['id']}", body)
    return graph.request("GET", f"/applications/{application['id']}")


def grant_admin_consent(
    graph: GraphClient,
    api_principal: dict[str, Any],
    client_principal: dict[str, Any],
) -> None:
    """Grant the public client the one delegated API scope tenant-wide."""
    query = urllib.parse.urlencode(
        {
            "$filter": (
                f"clientId eq '{client_principal['id']}' and resourceId eq '{api_principal['id']}'"
            )
        }
    )
    result = graph.request("GET", f"/oauth2PermissionGrants?{query}")
    grants = result.get("value", [])
    if grants:
        current = grants[0]
        scopes = set(str(current.get("scope", "")).split()) | {SCOPE_VALUE}
        graph.request(
            "PATCH",
            f"/oauth2PermissionGrants/{current['id']}",
            {"scope": " ".join(sorted(scopes))},
        )
        return
    graph.request(
        "POST",
        "/oauth2PermissionGrants",
        {
            "clientId": client_principal["id"],
            "consentType": "AllPrincipals",
            "resourceId": api_principal["id"],
            "scope": SCOPE_VALUE,
        },
    )


def update_vscode(client_id: str) -> None:
    """Commit-ready the non-secret VS Code client configuration."""
    path = Path(".vscode/mcp.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    document["servers"]["soffortbackend"]["oauth"]["clientId"] = client_id
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    """Bootstrap identity registrations and print non-secret deployment outputs."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--tenant-subdomain", required=True)
    parser.add_argument(
        "--github-repository",
        help="Optionally populate protected development environment variables with gh CLI",
    )
    args = parser.parse_args()
    token = azure_access_token(args.tenant_id)
    graph = GraphClient(token)

    api_app, scope_id = ensure_api_application(graph)
    client_app = ensure_client_application(graph, api_app["appId"], scope_id)
    api_principal = ensure_service_principal(graph, api_app["appId"])
    client_principal = ensure_service_principal(graph, client_app["appId"])
    grant_admin_consent(graph, api_principal, client_principal)
    update_vscode(client_app["appId"])

    # External ID accepts the friendly tenant subdomain for authorization, but
    # its OIDC metadata emits the tenant-ID hostname as the canonical ``iss``.
    # Token verification must use that byte-for-byte value or valid tokens fail.
    base = f"https://{args.tenant_id}.ciamlogin.com/{args.tenant_id}"
    output = {
        "ENTRA_ISSUER": f"{base}/v2.0",
        "ENTRA_JWKS_URL": f"{base}/discovery/v2.0/keys",
        "ENTRA_TENANT_ID": args.tenant_id,
        "ENTRA_API_AUDIENCE": api_app["appId"],
        "ENTRA_VSCODE_CLIENT_ID": client_app["appId"],
        "ENTRA_SCOPE_URI": f"{RESOURCE_URI}/{SCOPE_VALUE}",
    }
    print(json.dumps(output, indent=2))
    if args.github_repository:
        # Resolve the executable once rather than relying on a PATH search for every
        # subprocess. This also turns a missing GitHub CLI into an actionable error.
        github_cli = shutil.which("gh")
        if github_cli is None:
            raise SystemExit(
                "GitHub CLI is required when --github-repository is supplied. "
                "Install and authenticate gh, then rerun this command."
            )
        for name, value in output.items():
            subprocess.run(  # noqa: S603 - executable is resolved by shutil.which.
                [
                    github_cli,
                    "variable",
                    "set",
                    name,
                    "--repo",
                    args.github_repository,
                    "--env",
                    "development",
                    "--body",
                    value,
                ],
                check=True,
            )
    print("Complete the Apple-only user flow manually using docs/identity-runbook.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
