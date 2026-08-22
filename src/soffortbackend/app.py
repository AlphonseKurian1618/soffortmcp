"""ASGI application composition for the authenticated MCP server."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Annotated, Protocol, cast

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.bearer_auth import RequireAuthMiddleware
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.routes import build_resource_metadata_url
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from soffortbackend.approval import ApprovalError, ApprovalService
from soffortbackend.auth import EntraTokenVerifier
from soffortbackend.catalog import parse_property_keys
from soffortbackend.device_security import normalize_purpose
from soffortbackend.disclosure import (
    DisclosureDecryptor,
    FakeDisclosureDecryptor,
    KeyVaultDisclosureDecryptor,
)
from soffortbackend.logging import RequestContextMiddleware
from soffortbackend.mobile_api import register_mobile_routes
from soffortbackend.models import Principal
from soffortbackend.notifications import (
    APNsApprovalNotifier,
    ApprovalNotifier,
    FakeApprovalNotifier,
)
from soffortbackend.settings import Settings
from soffortbackend.store import ApprovalStore, CosmosApprovalStore, InMemoryApprovalStore
from soffortbackend.tools import (
    ListAvailablePropertiesOutput,
    RequestPropertiesOutput,
    approval_error,
    list_result,
    request_result,
)

MCP_BODY_LIMIT_BYTES = 1024 * 1024


class ManagedTokenVerifier(TokenVerifier, Protocol):
    """Optional lifecycle surface implemented by the production verifier."""

    @property
    def ready(self) -> bool:
        """Return true once trusted signing keys are available."""
        ...

    async def start(self) -> None:
        """Initialize verifier resources."""
        ...

    async def close(self) -> None:
        """Close verifier resources."""
        ...

    async def verify_token(self, token: str) -> AccessToken | None:
        """Validate a bearer token."""
        ...


def create_app(
    settings: Settings,
    *,
    token_verifier: ManagedTokenVerifier | None = None,
    approval_store: ApprovalStore | None = None,
    notifier: ApprovalNotifier | None = None,
    disclosure_decryptor: DisclosureDecryptor | None = None,
) -> Starlette:
    """Create the authenticated, stateless MCP ASGI application."""
    verifier = token_verifier or cast(ManagedTokenVerifier, EntraTokenVerifier(settings))
    store = approval_store or (
        InMemoryApprovalStore() if settings.environment == "test" else CosmosApprovalStore(settings)
    )
    push = notifier or (
        FakeApprovalNotifier() if settings.environment == "test" else APNsApprovalNotifier(settings)
    )
    disclosure = disclosure_decryptor or (
        FakeDisclosureDecryptor()
        if settings.environment == "test"
        else KeyVaultDisclosureDecryptor(settings)
    )
    approvals = ApprovalService(settings, store, push, disclosure)

    @asynccontextmanager
    async def lifespan(_: MCPServer[None]) -> AsyncGenerator[None]:
        verifier_started = store_started = push_started = disclosure_started = False
        try:
            await verifier.start()
            verifier_started = True
            await store.start()
            store_started = True
            await push.start()
            push_started = True
            await disclosure.start()
            disclosure_started = True
            yield None
        finally:
            if disclosure_started:
                await disclosure.close()
            if push_started:
                await push.close()
            if store_started:
                await store.close()
            if verifier_started:
                await verifier.close()

    server: MCPServer[None] = MCPServer(
        name="soffortbackend",
        title="Soffort Backend",
        description="Phone-consented access to the user's local Permi vault.",
        instructions=(
            "Discover populated property metadata, then request exact properties "
            "for a stated purpose."
        ),
        website_url="https://soffort.com",
        version="0.1.0",
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(settings.canonical_issuer),
            resource_server_url=AnyHttpUrl(settings.canonical_public_url),
            required_scopes=[settings.required_scope_uri],
        ),
        token_verifier=verifier,
        lifespan=lifespan,
        log_level=settings.log_level,
    )

    def vscode_principal() -> Principal:
        token = get_access_token()
        principal = Principal.from_access_token(token) if token is not None else None
        if principal is None or principal.client_kind != "vscode":
            approval_error("approval_unavailable")
        return principal

    async def list_available_properties() -> Annotated[
        CallToolResult, ListAvailablePropertiesOutput
    ]:
        """Ask the iPhone before revealing which vault fields are populated."""
        try:
            approval = await approvals.request_available_properties(vscode_principal())
        except ApprovalError as error:
            approval_error(error.code.value)
        return list_result(approval)

    server.tool(
        name="list_available_properties",
        description=(
            "Ask the user's iPhone for permission to list populated Permi property metadata. "
            "This never returns property values."
        ),
        structured_output=True,
    )(list_available_properties)

    async def request_properties(
        properties: list[str],
        purpose: str,
    ) -> Annotated[CallToolResult, RequestPropertiesOutput]:
        """Request an explicitly selected subset of local vault values."""
        requested = parse_property_keys(properties)
        normalized_purpose = normalize_purpose(purpose)
        try:
            approval, values = await approvals.request_properties(
                vscode_principal(), requested, normalized_purpose
            )
        except ApprovalError as error:
            approval_error(error.code.value)
        return request_result(approval, values)

    server.tool(
        name="request_properties",
        description=(
            "Ask the user to selectively approve exact Permi property values "
            "for a short stated purpose."
        ),
        structured_output=True,
    )(request_properties)
    register_mobile_routes(server, settings, store, approvals)

    # SDK custom routes are intentionally unauthenticated. Kubernetes reaches
    # these through the ClusterIP, while the public Gateway routes only /mcp and
    # the RFC 9728 metadata path.
    async def livez(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        status = 200 if verifier.ready and store.ready and push.ready and disclosure.ready else 503
        payload = {"status": "ready" if status == 200 else "not_ready"}
        return JSONResponse(payload, status_code=status)

    server.custom_route("/livez", methods=["GET"], include_in_schema=False)(livez)
    server.custom_route("/readyz", methods=["GET"], include_in_schema=False)(readyz)

    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=settings.allowed_hosts,
        allowed_origins=settings.allowed_origins,
    )
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        max_request_body_size=MCP_BODY_LIMIT_BYTES,
        transport_security=transport_security,
        host=settings.bind_host,
    )

    # The SDK supports legacy SSE through GET and session termination through
    # DELETE. This service promises neither: stateless POST requests may land on
    # any replica. Keep the SDK's authorization wrapper on POST, then install an
    # equally protected method-rejection route for the two session verbs.
    mcp_route = next(
        route for route in app.routes if isinstance(route, Route) and route.path == "/mcp"
    )
    mcp_route.methods = {"POST"}

    async def reject_session_method(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response(status_code=405, headers={"Allow": "POST"})
        await response(scope, receive, send)

    protected_rejection = RequireAuthMiddleware(
        reject_session_method,
        required_scopes=[settings.required_scope_uri],
        resource_metadata_url=build_resource_metadata_url(
            AnyHttpUrl(settings.canonical_public_url)
        ),
    )
    app.router.routes.insert(
        1,
        Route("/mcp", endpoint=protected_rejection, methods=["GET", "DELETE"]),
    )
    # OAuth resource identity is path-sensitive. Silently redirecting `/mcp/`
    # risks a resource/audience mismatch, so only the canonical path is valid.
    app.router.redirect_slashes = False
    app.add_middleware(RequestContextMiddleware)
    app.state.mcp_server = server
    app.state.token_verifier = verifier
    app.state.approval_store = store
    app.state.approval_notifier = push
    return app
