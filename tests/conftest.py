"""Shared fixtures for authenticated HTTP tests."""

from collections.abc import AsyncIterator
from uuid import UUID

import pytest
from mcp.server.auth.provider import AccessToken

from soffortbackend.models import PropertyMetadata
from soffortbackend.settings import Settings

TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
CLIENT_ID = UUID("22222222-2222-4222-8222-222222222222")
IOS_CLIENT_ID = UUID("33333333-3333-4333-8333-333333333333")
OBJECT_ID = "44444444-4444-4444-8444-444444444444"
EMAIL_KEY = "vault." + "a" * 43
NAME_KEY = "vault." + "b" * 43
EMAIL_METADATA = PropertyMetadata(EMAIL_KEY, "Personal · Email", "email", "moderate")
NAME_METADATA = PropertyMetadata(NAME_KEY, "Personal · Preferred name", "text", "moderate")


class FakeTokenVerifier:
    """Deterministic verifier used only through test dependency injection."""

    ready = True

    async def start(self) -> None:
        """Provide the production lifecycle shape."""

    async def close(self) -> None:
        """Provide the production lifecycle shape."""

    async def verify_token(self, token: str) -> AccessToken | None:
        """Accept one non-secret fixture token."""
        if token == "valid-test-token":
            client_id = CLIENT_ID
            scopes = ["http://testserver/mcp/soffortbackend.access"]
            client_kind = "vscode"
        elif token == "valid-mobile-token":
            client_id = IOS_CLIENT_ID
            scopes = ["http://testserver/mcp/soffortbackend.mobile"]
            client_kind = "ios"
        else:
            return None
        return AccessToken(
            token=token,
            client_id=str(client_id),
            scopes=scopes,
            expires_at=4_102_444_800,
            resource="http://testserver/mcp",
            subject=OBJECT_ID,
            claims={
                "tid": str(TENANT_ID),
                "oid": OBJECT_ID,
                "sub": "pairwise-test-subject",
                "client_kind": client_kind,
            },
        )


@pytest.fixture
def settings() -> Settings:
    """Return a secure test-only configuration using local HTTP URLs."""
    return Settings(
        _env_file=None,
        environment="test",
        public_url="http://testserver/mcp",
        entra_issuer="http://issuer.test/tenant/v2.0",
        entra_jwks_url="http://issuer.test/keys",
        entra_tenant_id=TENANT_ID,
        entra_api_audience="api-audience",
        entra_vscode_client_id=CLIENT_ID,
        entra_ios_client_id=IOS_CLIENT_ID,
        required_scope_uri="http://testserver/mcp/soffortbackend.access",
        mobile_scope_uri="http://testserver/mcp/soffortbackend.mobile",
        allowed_hosts_csv="testserver",
        allowed_origins_csv="https://vscode.dev",
    )


@pytest.fixture
async def fake_verifier() -> AsyncIterator[FakeTokenVerifier]:
    """Yield the deterministic test verifier."""
    yield FakeTokenVerifier()
