#!/usr/bin/env python3
"""Idempotently create the API, VS Code, and iOS External ID registrations.

Apple Developer configuration and the External ID Apple-plus-email user flow remain
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
from typing import Any, cast
from uuid import uuid4

GRAPH = "https://graph.microsoft.com/v1.0"
API_NAME = "Consentary API"
CLIENT_NAME = "Consentary for VS Code"
# This exact label is shown to customers during the native iOS login. Keep it
# product-only rather than exposing implementation suffixes such as "-ios".
IOS_CLIENT_NAME = "Consentary"
PREVIOUS_API_NAME = "consentary-api"
PREVIOUS_CLIENT_NAME = "consentary-vscode"
PREVIOUS_IOS_CLIENT_NAME = "consentary-ios"
LEGACY_API_NAME = "soffortbackend-api"
LEGACY_CLIENT_NAME = "soffortbackend-vscode"
LEGACY_IOS_CLIENT_NAME = "soffortbackend-ios"
SCOPE_VALUE = "soffortbackend.access"
MOBILE_SCOPE_VALUE = "soffortbackend.mobile"
RESOURCE_URI = "https://consentary.com/mcp"
REDIRECTS = ["http://127.0.0.1:33418", "https://vscode.dev/redirect"]
IOS_REDIRECTS = ["msauth.com.consentary.app://auth"]


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


def find_application(
    graph: GraphClient,
    display_name: str,
    *legacy_display_names: str,
) -> dict[str, Any] | None:
    """Find one registration by its current or pre-Consentary display name."""
    applications: list[dict[str, Any]] = []
    for candidate in (display_name, *legacy_display_names):
        escaped = candidate.replace("'", "''")
        query = urllib.parse.urlencode({"$filter": f"displayName eq '{escaped}'"})
        applications.extend(graph.request("GET", f"/applications?{query}").get("value", []))
    applications = list({application["id"]: application for application in applications}.values())
    if len(applications) > 1:
        raise RuntimeError(
            f"Multiple current or legacy application registrations match {display_name}"
        )
    return applications[0] if applications else None


def ensure_service_principal(
    graph: GraphClient,
    app_id: str,
    display_name: str,
) -> dict[str, Any]:
    """Create the tenant-local service principal and normalize its visible label."""
    query = urllib.parse.urlencode({"$filter": f"appId eq '{app_id}'"})
    result = graph.request("GET", f"/servicePrincipals?{query}")
    principals = result.get("value", [])
    if len(principals) > 1:
        raise RuntimeError(f"Multiple service principals exist for appId {app_id}")
    principal = (
        principals[0]
        if principals
        else graph.request("POST", "/servicePrincipals", {"appId": app_id})
    )
    if principal.get("displayName") != display_name:
        graph.request(
            "PATCH",
            f"/servicePrincipals/{principal['id']}",
            {"displayName": display_name},
        )
        principal = graph.request("GET", f"/servicePrincipals/{principal['id']}")
    return principal


def ensure_api_application(graph: GraphClient) -> tuple[dict[str, Any], dict[str, str]]:
    """Create or normalize the API registration and both delegated scopes."""
    application = find_application(graph, API_NAME, PREVIOUS_API_NAME, LEGACY_API_NAME)
    if application is None:
        scope_ids = {SCOPE_VALUE: str(uuid4()), MOBILE_SCOPE_VALUE: str(uuid4())}
        application = graph.request(
            "POST",
            "/applications",
            {
                "displayName": API_NAME,
                "signInAudience": "AzureADMyOrg",
                "identifierUris": [RESOURCE_URI],
                "api": {
                    "requestedAccessTokenVersion": 2,
                    "oauth2PermissionScopes": [
                        scope_definition(scope_ids[SCOPE_VALUE], SCOPE_VALUE),
                        scope_definition(scope_ids[MOBILE_SCOPE_VALUE], MOBILE_SCOPE_VALUE),
                    ],
                },
            },
        )
        return application, scope_ids

    scopes = application.get("api", {}).get("oauth2PermissionScopes", [])
    scope_ids: dict[str, str] = {}
    for value in (SCOPE_VALUE, MOBILE_SCOPE_VALUE):
        matching = [scope for scope in scopes if scope.get("value") == value]
        if len(matching) > 1:
            raise RuntimeError(f"Duplicate {value} scopes exist")
        scope_id = matching[0]["id"] if matching else str(uuid4())
        scope_ids[value] = scope_id
        if not matching:
            scopes.append(scope_definition(scope_id, value))
    graph.request(
        "PATCH",
        f"/applications/{application['id']}",
        {
            "displayName": API_NAME,
            "identifierUris": [RESOURCE_URI],
            "api": {
                "requestedAccessTokenVersion": 2,
                "oauth2PermissionScopes": scopes,
            },
        },
    )
    return graph.request("GET", f"/applications/{application['id']}"), scope_ids


def scope_definition(scope_id: str, value: str) -> dict[str, Any]:
    """Return the stable delegated permission contract."""
    mobile = value == MOBILE_SCOPE_VALUE
    description = (
        "Manage the signed-in user's profile, devices, and phone approvals."
        if mobile
        else "Access the authenticated Consentary MCP tools."
    )
    display_name = "Use Consentary mobile approval" if mobile else "Access Consentary"
    return {
        "adminConsentDescription": description,
        "adminConsentDisplayName": display_name,
        "id": scope_id,
        "isEnabled": True,
        "type": "Admin",
        "userConsentDescription": description,
        "userConsentDisplayName": display_name,
        "value": value,
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
    application = find_application(
        graph,
        CLIENT_NAME,
        PREVIOUS_CLIENT_NAME,
        LEGACY_CLIENT_NAME,
    )
    if application is None:
        return graph.request("POST", "/applications", body)
    graph.request("PATCH", f"/applications/{application['id']}", body)
    return graph.request("GET", f"/applications/{application['id']}")


def ensure_ios_application(
    graph: GraphClient,
    api_app_id: str,
    scope_id: str,
) -> dict[str, Any]:
    """Create or normalize the secretless Consentary iOS registration."""
    body = {
        "displayName": IOS_CLIENT_NAME,
        "signInAudience": "AzureADMyOrg",
        "isFallbackPublicClient": True,
        "publicClient": {"redirectUris": IOS_REDIRECTS},
        "requiredResourceAccess": [
            {
                "resourceAppId": api_app_id,
                "resourceAccess": [{"id": scope_id, "type": "Scope"}],
            }
        ],
    }
    application = find_application(
        graph,
        IOS_CLIENT_NAME,
        PREVIOUS_IOS_CLIENT_NAME,
        LEGACY_IOS_CLIENT_NAME,
    )
    if application is None:
        return graph.request("POST", "/applications", body)
    graph.request("PATCH", f"/applications/{application['id']}", body)
    return graph.request("GET", f"/applications/{application['id']}")


def grant_admin_consent(
    graph: GraphClient,
    api_principal: dict[str, Any],
    client_principal: dict[str, Any],
    scope_value: str,
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
        scopes = set(str(current.get("scope", "")).split()) | {scope_value}
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
            "scope": scope_value,
        },
    )


def ensure_user_flow_application(
    graph: GraphClient,
    flow_display_name: str,
    client_app_id: str,
) -> None:
    """Associate one public client with the named External ID user flow."""
    # This External ID collection currently rejects OData ``$select`` even
    # though most Graph collections accept it, so fetch the bounded flow list.
    result = graph.request("GET", "/identity/authenticationEventsFlows")
    matching = [
        flow for flow in result.get("value", []) if flow.get("displayName") == flow_display_name
    ]
    if len(matching) != 1:
        raise RuntimeError(
            f"Expected one External ID user flow named {flow_display_name}, found {len(matching)}"
        )
    flow_id = matching[0]["id"]
    path = (
        f"/identity/authenticationEventsFlows/{flow_id}/conditions/applications/includeApplications"
    )
    included = graph.request("GET", path).get("value", [])
    if any(item.get("appId") == client_app_id for item in included):
        return
    graph.request(
        "POST",
        path,
        {
            "@odata.type": "#microsoft.graph.authenticationConditionApplication",
            "appId": client_app_id,
        },
    )


def update_vscode(client_id: str) -> None:
    """Commit-ready the non-secret VS Code client configuration."""
    path = Path(".vscode/mcp.json")
    raw_document: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw_document, dict):
        raise RuntimeError(".vscode/mcp.json must contain a JSON object")
    document = cast(dict[str, Any], raw_document)
    raw_servers = document.setdefault("servers", {})
    if not isinstance(raw_servers, dict):
        raise RuntimeError(".vscode/mcp.json servers must be a JSON object")
    servers = cast(dict[str, Any], raw_servers)
    raw_server: Any = (
        servers.pop("soffortbackend", None) or servers.get("consentary") or dict[str, Any]()
    )
    if not isinstance(raw_server, dict):
        raise RuntimeError("The Consentary MCP server definition must be a JSON object")
    server = cast(dict[str, Any], raw_server)
    server["type"] = "http"
    server["url"] = RESOURCE_URI
    raw_oauth = server.setdefault("oauth", {})
    if not isinstance(raw_oauth, dict):
        raise RuntimeError("The Consentary OAuth definition must be a JSON object")
    raw_oauth["clientId"] = client_id
    servers["consentary"] = server
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    """Bootstrap identity registrations and print non-secret deployment outputs."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--tenant-subdomain", required=True)
    parser.add_argument(
        "--user-flow-display-name",
        help="Optionally associate both public clients with this existing user flow",
    )
    parser.add_argument(
        "--github-repository",
        help="Optionally populate protected development environment variables with gh CLI",
    )
    args = parser.parse_args()
    token = azure_access_token(args.tenant_id)
    graph = GraphClient(token)

    api_app, scope_ids = ensure_api_application(graph)
    client_app = ensure_client_application(graph, api_app["appId"], scope_ids[SCOPE_VALUE])
    ios_app = ensure_ios_application(graph, api_app["appId"], scope_ids[MOBILE_SCOPE_VALUE])
    api_principal = ensure_service_principal(graph, api_app["appId"], API_NAME)
    client_principal = ensure_service_principal(graph, client_app["appId"], CLIENT_NAME)
    ios_principal = ensure_service_principal(graph, ios_app["appId"], IOS_CLIENT_NAME)
    grant_admin_consent(graph, api_principal, client_principal, SCOPE_VALUE)
    grant_admin_consent(graph, api_principal, ios_principal, MOBILE_SCOPE_VALUE)
    if args.user_flow_display_name:
        ensure_user_flow_application(graph, args.user_flow_display_name, client_app["appId"])
        ensure_user_flow_application(graph, args.user_flow_display_name, ios_app["appId"])
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
        "ENTRA_IOS_CLIENT_ID": ios_app["appId"],
        "ENTRA_SCOPE_URI": f"{RESOURCE_URI}/{SCOPE_VALUE}",
        "ENTRA_MOBILE_SCOPE_URI": f"{RESOURCE_URI}/{MOBILE_SCOPE_VALUE}",
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
    print("Complete the Apple and Email OTP user flow using docs/identity-runbook.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
