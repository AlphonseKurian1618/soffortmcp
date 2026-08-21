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
from soffortbackend.tools import HelloWorldOutput, approval_error, approved_hello_world

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
) -> Starlette:
    """Create the authenticated, stateless MCP ASGI application."""
    verifier = token_verifier or cast(ManagedTokenVerifier, EntraTokenVerifier(settings))
    store = approval_store or (
        InMemoryApprovalStore() if settings.environment == "test" else CosmosApprovalStore(settings)
    )
    push = notifier or (
        FakeApprovalNotifier() if settings.environment == "test" else APNsApprovalNotifier(settings)
    )
    approvals = ApprovalService(settings, store, push)

    @asynccontextmanager
    async def lifespan(_: MCPServer[None]) -> AsyncGenerator[None]:
        verifier_started = store_started = push_started = False
        try:
            await verifier.start()
            verifier_started = True
            await store.start()
            store_started = True
            await push.start()
            push_started = True
            yield None
        finally:
            if push_started:
                await push.close()
            if store_started:
                await store.close()
            if verifier_started:
                await verifier.close()

    server: MCPServer[None] = MCPServer(
        name="soffortbackend",
        title="Soffort Backend",
        description="An authenticated hello-world MCP resource server.",
        instructions="Use hello_world to return a short greeting.",
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

    async def hello_world() -> Annotated[CallToolResult, HelloWorldOutput]:
        """Wait for one iPhone approval before disclosing the profile name."""
        token = get_access_token()
        principal = Principal.from_access_token(token) if token is not None else None
        if principal is None or principal.client_kind != "vscode":
            return approval_error("approval_unavailable")
        try:
            display_name = await approvals.request_hello_world(principal)
        except ApprovalError as error:
            return approval_error(error.code.value)
        return approved_hello_world(display_name)

    server.tool(
        name="hello_world",
        description="Request iPhone approval, then greet the approved app profile.",
        structured_output=True,
    )(hello_world)
    register_mobile_routes(server, settings, store, approvals)

    # SDK custom routes are intentionally unauthenticated. Kubernetes reaches
    # these through the ClusterIP, while the public Gateway routes only /mcp and
    # the RFC 9728 metadata path.
    async def livez(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        status = 200 if verifier.ready and store.ready and push.ready else 503
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
