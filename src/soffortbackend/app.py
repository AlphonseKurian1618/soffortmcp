"""ASGI application composition for the authenticated MCP server."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Protocol, cast

from mcp.server import MCPServer
from mcp.server.auth.middleware.bearer_auth import RequireAuthMiddleware
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.routes import build_resource_metadata_url
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from soffortbackend.auth import EntraTokenVerifier
from soffortbackend.logging import RequestContextMiddleware
from soffortbackend.settings import Settings
from soffortbackend.tools import hello_world

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
) -> Starlette:
    """Create the authenticated, stateless MCP ASGI application."""
    verifier = token_verifier or cast(ManagedTokenVerifier, EntraTokenVerifier(settings))

    @asynccontextmanager
    async def lifespan(_: MCPServer[None]) -> AsyncIterator[None]:
        await verifier.start()
        try:
            yield None
        finally:
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
    server.tool(
        name="hello_world",
        description="Return a friendly greeting from soffortbackend.",
        structured_output=True,
    )(hello_world)

    # SDK custom routes are intentionally unauthenticated. Kubernetes reaches
    # these through the ClusterIP, while the public Gateway routes only /mcp and
    # the RFC 9728 metadata path.
    async def livez(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        status = 200 if verifier.ready else 503
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
    return app
