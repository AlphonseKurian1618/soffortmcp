"""Typed, fail-closed runtime configuration for soffortbackend."""

from functools import cached_property
from typing import Literal, Self
from urllib.parse import urlparse
from uuid import UUID

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

CANONICAL_MCP_URL = "https://soffort.com/mcp"
DEFAULT_SCOPE_URI = f"{CANONICAL_MCP_URL}/soffortbackend.access"


class Settings(BaseSettings):
    """Environment configuration validated before the server accepts traffic.

    There is deliberately no ``disable_auth`` option. Local and automated tests
    inject a verifier rather than creating a configuration switch that could be
    accidentally enabled in a deployed pod.
    """

    model_config = SettingsConfigDict(
        env_prefix="SOFFORT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    public_url: AnyHttpUrl = Field(default=AnyHttpUrl(CANONICAL_MCP_URL))
    entra_issuer: AnyHttpUrl
    entra_jwks_url: AnyHttpUrl
    entra_tenant_id: UUID
    entra_api_audience: str = Field(min_length=1, max_length=255)
    entra_vscode_client_id: UUID
    required_scope_value: str = Field(default="soffortbackend.access", min_length=1)
    required_scope_uri: str = Field(default=DEFAULT_SCOPE_URI, min_length=1)
    allowed_hosts_csv: str = "soffort.com"
    allowed_origins_csv: str = "https://vscode.dev"
    bind_host: str = "0.0.0.0"  # noqa: S104 - the container must accept Service traffic.
    port: int = Field(default=8000, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    jwks_default_ttl_seconds: int = Field(default=3600, ge=60, le=21600)
    jwks_refresh_cooldown_seconds: int = Field(default=30, ge=5, le=300)
    jwt_leeway_seconds: int = Field(default=30, ge=0, le=120)

    # This sentinel exists only to prove that accidentally supplied secrets are
    # rejected during config review. The application never reads Apple material.
    apple_private_key: SecretStr | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def validate_security_boundaries(self) -> Self:
        """Reject configuration that weakens the documented trust boundary."""
        public_url = str(self.public_url).rstrip("/")
        issuer = str(self.entra_issuer).rstrip("/")
        jwks_url = str(self.entra_jwks_url).rstrip("/")

        if self.environment != "test":
            if public_url != CANONICAL_MCP_URL:
                raise ValueError(f"public_url must be exactly {CANONICAL_MCP_URL}")
            if urlparse(issuer).scheme != "https" or urlparse(jwks_url).scheme != "https":
                raise ValueError("Entra issuer and JWKS URLs must use HTTPS")

        # Apple is an upstream identity provider for Entra, not an MCP token
        # issuer. Rejecting it here prevents a future operator from accepting an
        # Apple ID token whose audience is the Apple Services ID.
        if urlparse(issuer).hostname == "appleid.apple.com":
            raise ValueError("Apple tokens cannot be used as MCP access tokens")
        if self.apple_private_key is not None:
            raise ValueError("Apple private keys belong in Entra, never in this workload")
        if not self.required_scope_uri.startswith(f"{public_url}/"):
            raise ValueError("required_scope_uri must be beneath the canonical MCP resource")
        if not self.allowed_hosts or not self.allowed_origins:
            raise ValueError("Host and Origin allowlists cannot be empty")
        return self

    @cached_property
    def canonical_public_url(self) -> str:
        """Return the canonical MCP URL without an accidental trailing slash."""
        return str(self.public_url).rstrip("/")

    @cached_property
    def canonical_issuer(self) -> str:
        """Return the exact issuer string expected in Entra access tokens."""
        return str(self.entra_issuer).rstrip("/")

    @cached_property
    def canonical_jwks_url(self) -> str:
        """Return the configured Entra signing-key endpoint."""
        return str(self.entra_jwks_url).rstrip("/")

    @cached_property
    def allowed_hosts(self) -> list[str]:
        """Parse the comma-delimited Host allowlist."""
        return self._parse_csv(self.allowed_hosts_csv)

    @cached_property
    def allowed_origins(self) -> list[str]:
        """Parse the comma-delimited browser Origin allowlist."""
        return self._parse_csv(self.allowed_origins_csv)

    @staticmethod
    def _parse_csv(value: str) -> list[str]:
        values = [item.strip() for item in value.split(",") if item.strip()]
        return list(dict.fromkeys(values))
