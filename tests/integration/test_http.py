"""HTTP-level tests for discovery, authorization, and transport hardening."""

import httpx
import pytest
from mcp.server.auth.provider import AccessToken

from soffortbackend.app import create_app
from soffortbackend.settings import Settings


class WrongScopeVerifier:
    """Return a trusted token that lacks the MCP delegated permission."""

    ready = True

    async def start(self) -> None:
        """Match the production verifier lifecycle."""

    async def close(self) -> None:
        """Match the production verifier lifecycle."""

    async def verify_token(self, token: str) -> AccessToken | None:
        """Accept one fixture token while deliberately omitting the required scope."""
        if token != "valid-wrong-scope-token":
            return None
        return AccessToken(
            token=token,
            client_id="test-client",
            scopes=["other.scope"],
            expires_at=4_102_444_800,
            resource="http://testserver/mcp",
            subject="test-subject",
        )


@pytest.mark.asyncio
async def test_protected_resource_metadata_is_public(
    settings: Settings,
    fake_verifier,
) -> None:
    app = create_app(settings, token_verifier=fake_verifier)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            response = await client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    assert response.json()["resource"] == "http://testserver/mcp"
    assert response.json()["scopes_supported"] == [settings.required_scope_uri]
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_mcp_requires_bearer_token(settings: Settings, fake_verifier) -> None:
    app = create_app(settings, token_verifier=fake_verifier)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            response = await client.post("/mcp", json={})

    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert "invalid_token" in challenge
    assert "/.well-known/oauth-protected-resource/mcp" in challenge


@pytest.mark.asyncio
async def test_mcp_returns_insufficient_scope_for_trusted_token(settings: Settings) -> None:
    app = create_app(settings, token_verifier=WrongScopeVerifier())
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            response = await client.post(
                "/mcp",
                headers={"Authorization": "Bearer valid-wrong-scope-token"},
                json={},
            )

    assert response.status_code == 403
    challenge = response.headers["www-authenticate"]
    assert "insufficient_scope" in challenge
    assert settings.required_scope_uri in challenge


@pytest.mark.asyncio
async def test_unapproved_host_is_rejected(settings: Settings, fake_verifier) -> None:
    app = create_app(settings, token_verifier=fake_verifier)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://evil.example",
        ) as client:
            response = await client.post(
                "/mcp",
                headers={"Authorization": "Bearer valid-test-token"},
                json={},
            )

    assert response.status_code == 421


@pytest.mark.asyncio
async def test_unapproved_present_origin_is_rejected(settings: Settings, fake_verifier) -> None:
    app = create_app(settings, token_verifier=fake_verifier)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            response = await client.post(
                "/mcp",
                headers={
                    "Authorization": "Bearer valid-test-token",
                    "Origin": "https://evil.example",
                },
                json={},
            )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_health_routes_are_minimal(settings: Settings, fake_verifier) -> None:
    app = create_app(settings, token_verifier=fake_verifier)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            live = await client.get("/livez")
            ready = await client.get("/readyz")

    assert live.json() == {"status": "ok"}
    assert ready.json() == {"status": "ready"}


@pytest.mark.asyncio
async def test_modern_protocol_lists_and_calls_exact_tool(
    settings: Settings,
    fake_verifier,
) -> None:
    """Exercise the 2026 single-exchange profile through the real HTTP boundary."""
    app = create_app(settings, token_verifier=fake_verifier)
    headers = {
        "Authorization": "Bearer valid-test-token",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
    }
    modern_meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
            headers=headers,
        ) as client:
            listed = await client.post(
                "/mcp",
                headers={"Mcp-Method": "tools/list"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {"_meta": modern_meta},
                },
            )
            called = await client.post(
                "/mcp",
                headers={"Mcp-Method": "tools/call", "Mcp-Name": "hello_world"},
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "hello_world",
                        "arguments": {},
                        "_meta": modern_meta,
                    },
                },
            )

    assert listed.status_code == 200, listed.text
    assert [tool["name"] for tool in listed.json()["result"]["tools"]] == ["hello_world"]
    assert called.status_code == 200
    result = called.json()["result"]
    assert result["structuredContent"] == {
        "message": "Hello, World!",
        "server": "soffortbackend",
    }
    assert result["content"] == [{"type": "text", "text": "Hello, World!"}]


@pytest.mark.asyncio
async def test_handshake_protocol_initializes_and_lists_tool(
    settings: Settings,
    fake_verifier,
) -> None:
    """Exercise the supported 2025 handshake-era profile over stateless HTTP."""
    app = create_app(settings, token_verifier=fake_verifier)
    headers = {
        "Authorization": "Bearer valid-test-token",
        "Accept": "application/json, text/event-stream",
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
            headers=headers,
        ) as client:
            initialized = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "test-client", "version": "1"},
                    },
                },
            )
            listed = await client.post(
                "/mcp",
                headers={"MCP-Protocol-Version": "2025-11-25"},
                json={"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}},
            )

    assert initialized.status_code == 200, initialized.text
    assert initialized.json()["result"]["protocolVersion"] == "2025-11-25"
    assert listed.status_code == 200, listed.text
    assert [tool["name"] for tool in listed.json()["result"]["tools"]] == ["hello_world"]


@pytest.mark.asyncio
async def test_mcp_disallows_session_methods_and_trailing_slash(
    settings: Settings,
    fake_verifier,
) -> None:
    """Keep the public transport surface exact and free of persistent SSE sessions."""
    app = create_app(settings, token_verifier=fake_verifier)
    headers = {"Authorization": "Bearer valid-test-token"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
            follow_redirects=False,
        ) as client:
            get_response = await client.get("/mcp", headers=headers)
            delete_response = await client.delete("/mcp", headers=headers)
            trailing_response = await client.post("/mcp/", headers=headers, json={})

    assert get_response.status_code == 405
    assert delete_response.status_code == 405
    assert trailing_response.status_code == 404
    assert trailing_response.headers.get("location") is None


@pytest.mark.asyncio
async def test_mcp_rejects_body_over_one_mebibyte(settings: Settings, fake_verifier) -> None:
    """Reject oversized input before JSON parsing or tool dispatch."""
    app = create_app(settings, token_verifier=fake_verifier)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            response = await client.post(
                "/mcp",
                headers={
                    "Authorization": "Bearer valid-test-token",
                    "Content-Type": "application/json",
                },
                content=b" " * (1024 * 1024 + 1),
            )

    assert response.status_code == 413
