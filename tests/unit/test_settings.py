"""Tests for security-sensitive startup configuration."""

from uuid import UUID

import pytest
from pydantic import ValidationError

from soffortbackend.settings import Settings

TENANT = UUID("11111111-1111-4111-8111-111111111111")
CLIENT = UUID("22222222-2222-4222-8222-222222222222")


def test_missing_identity_configuration_fails_closed() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_apple_cannot_be_configured_as_access_token_issuer() -> None:
    with pytest.raises(ValidationError, match="Apple tokens cannot"):
        Settings(
            _env_file=None,
            environment="test",
            public_url="http://testserver/mcp",
            entra_issuer="https://appleid.apple.com",
            entra_jwks_url="https://appleid.apple.com/auth/keys",
            entra_tenant_id=TENANT,
            entra_api_audience="audience",
            entra_vscode_client_id=CLIENT,
            required_scope_uri="http://testserver/mcp/scope",
            allowed_hosts_csv="testserver",
            allowed_origins_csv="https://vscode.dev",
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"public_url": "https://other.example/mcp"},
        {"entra_issuer": "http://issuer.example/tenant/v2.0"},
        {"apple_private_key": "secret-value"},
        {"required_scope_uri": "https://other.example/scope"},
        {"allowed_hosts_csv": ""},
    ],
)
def test_production_security_boundaries_reject_unsafe_values(overrides: dict[str, object]) -> None:
    values: dict[str, object] = {
        "_env_file": None,
        "environment": "production",
        "entra_issuer": "https://tenant.ciamlogin.com/tenant/v2.0",
        "entra_jwks_url": "https://tenant.ciamlogin.com/tenant/discovery/v2.0/keys",
        "entra_tenant_id": TENANT,
        "entra_api_audience": "audience",
        "entra_vscode_client_id": CLIENT,
    }
    values.update(overrides)
    with pytest.raises(ValidationError):
        Settings(**values)  # type: ignore[arg-type]
