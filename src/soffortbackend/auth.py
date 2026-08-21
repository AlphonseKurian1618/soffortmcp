"""Microsoft Entra JWT verification for the MCP resource server."""

import asyncio
import logging
import re
import time
from typing import cast

import httpx
import jwt
from jwt import PyJWK
from mcp.server.auth.provider import AccessToken

from soffortbackend.settings import Settings

LOGGER = logging.getLogger(__name__)
MAX_TOKEN_LENGTH = 16_384
MAX_AGE_PATTERN = re.compile(r"(?:^|,)\s*max-age=(\d+)\s*(?:,|$)", re.IGNORECASE)


class JwksCache:
    """Fetch and cache issuer signing keys with bounded rotation behavior."""

    def __init__(
        self,
        jwks_url: str,
        *,
        default_ttl_seconds: int = 3600,
        refresh_cooldown_seconds: int = 30,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Create a cache for one exact, trusted issuer JWKS endpoint."""
        self._jwks_url = jwks_url
        self._default_ttl = default_ttl_seconds
        self._refresh_cooldown = refresh_cooldown_seconds
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=3.0),
            follow_redirects=False,
        )
        self._owns_client = client is None
        self._keys: dict[str, PyJWK] = {}
        self._expires_at = 0.0
        self._last_refresh_attempt = 0.0
        self._lock = asyncio.Lock()

    @property
    def ready(self) -> bool:
        """Report whether at least one trusted signing key has been loaded."""
        return bool(self._keys)

    async def start(self) -> None:
        """Warm the cache without crash-looping during a temporary Entra outage."""
        try:
            await self._refresh(force=True)
        except httpx.HTTPError, ValueError:
            # Readiness remains false, so Kubernetes does not route traffic. A
            # later token verification will retry after the cooldown.
            LOGGER.exception("entra_jwks_initialization_failed")

    async def close(self) -> None:
        """Close the internally owned HTTP connection pool."""
        if self._owns_client:
            await self._client.aclose()

    async def get_key(self, key_id: str) -> PyJWK | None:
        """Return a key, refreshing once for expiry or an unfamiliar key ID."""
        now = time.monotonic()
        cached = self._keys.get(key_id)
        if cached is not None and now < self._expires_at:
            return cached

        # Unknown ``kid`` values commonly mean Entra rotated keys. The cooldown
        # prevents an attacker from turning random key IDs into an outbound HTTP
        # amplification loop.
        await self._refresh(force=cached is None)
        return self._keys.get(key_id)

    async def _refresh(self, *, force: bool) -> None:
        async with self._lock:
            now = time.monotonic()
            if not force and self._keys and now < self._expires_at:
                return
            if force and now - self._last_refresh_attempt < self._refresh_cooldown:
                return
            self._last_refresh_attempt = now

            response = await self._client.get(
                self._jwks_url,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            decoded = cast(object, response.json())
            if not isinstance(decoded, dict):
                raise ValueError("JWKS response is not an object")
            body = cast(dict[str, object], decoded)
            raw_keys_value = body.get("keys")
            if not isinstance(raw_keys_value, list) or not raw_keys_value:
                raise ValueError("JWKS response contains no keys")
            raw_keys = cast(list[object], raw_keys_value)

            parsed: dict[str, PyJWK] = {}
            for raw_key in raw_keys:
                if not isinstance(raw_key, dict):
                    continue
                key = cast(dict[str, object], raw_key)
                key_id = key.get("kid")
                if not isinstance(key_id, str) or not key_id:
                    continue
                if key.get("kty") != "RSA" or key.get("use", "sig") != "sig":
                    continue
                if key.get("alg", "RS256") != "RS256":
                    continue
                parsed[key_id] = PyJWK.from_dict(key, algorithm="RS256")
            if not parsed:
                raise ValueError("JWKS response contains no usable RS256 signing keys")

            ttl = self._cache_ttl(response.headers.get("cache-control", ""))
            self._keys = parsed
            self._expires_at = time.monotonic() + ttl
            LOGGER.info("entra_jwks_refreshed")

    def _cache_ttl(self, cache_control: str) -> int:
        match = MAX_AGE_PATTERN.search(cache_control)
        requested = int(match.group(1)) if match else self._default_ttl
        return max(60, min(requested, 21_600))


class EntraTokenVerifier:
    """Validate Entra access tokens and map their scope into MCP semantics."""

    def __init__(self, settings: Settings, jwks_cache: JwksCache | None = None) -> None:
        """Create a verifier bound to one tenant, audience, client, and scope."""
        self.settings = settings
        self.jwks = jwks_cache or JwksCache(
            settings.canonical_jwks_url,
            default_ttl_seconds=settings.jwks_default_ttl_seconds,
            refresh_cooldown_seconds=settings.jwks_refresh_cooldown_seconds,
        )

    @property
    def ready(self) -> bool:
        """Report whether JWT signature verification can currently proceed."""
        return self.jwks.ready

    async def start(self) -> None:
        """Warm signing keys during ASGI startup."""
        await self.jwks.start()

    async def close(self) -> None:
        """Release verifier network resources during graceful shutdown."""
        await self.jwks.close()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an SDK access token only after all security claims pass."""
        if not token or len(token) > MAX_TOKEN_LENGTH or token.count(".") != 2:
            return None
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256":
                return None
            key_id = header.get("kid")
            if not isinstance(key_id, str) or not key_id:
                return None
            signing_key = await self.jwks.get_key(key_id)
            if signing_key is None:
                return None

            claims = jwt.decode(
                token,
                key=signing_key.key,
                algorithms=["RS256"],
                audience=self.settings.entra_api_audience,
                issuer=self.settings.canonical_issuer,
                leeway=self.settings.jwt_leeway_seconds,
                options={"require": ["aud", "exp", "iat", "iss", "nbf", "sub", "oid"]},
            )
        except jwt.PyJWTError, httpx.HTTPError, ValueError, TypeError:
            # Do not include the token, claims, email, or subject in auth logs.
            LOGGER.warning("entra_token_rejected")
            return None

        tenant_id = claims.get("tid")
        if tenant_id != str(self.settings.entra_tenant_id):
            return None
        authorized_party = claims.get("azp") or claims.get("appid")
        authorized_clients = {
            str(self.settings.entra_vscode_client_id): "vscode",
            str(self.settings.entra_ios_client_id): "ios",
        }
        client_kind = authorized_clients.get(str(authorized_party))
        if client_kind is None:
            return None

        claim_scopes = set(str(claims.get("scp", "")).split())
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            return None
        object_id = claims.get("oid")
        if not isinstance(object_id, str) or not object_id:
            # ``sub`` is pairwise to the client registration. Phase 2 links the
            # VS Code and iOS sessions only through Entra's tenant-wide ``oid``;
            # accepting a token without it could route an approval to the wrong
            # account or tempt future code to fall back to mutable email.
            return None

        # Entra requests use the fully-qualified scope URI but emit the short
        # delegated permission name in ``scp``. Add the public URI only when its
        # short form is present. A signed token without that permission remains a
        # valid token so MCP can correctly answer 403 ``insufficient_scope``;
        # malformed, untrusted, or audience-invalid tokens still answer 401.
        mcp_scopes = set(claim_scopes)
        if self.settings.required_scope_value in claim_scopes:
            mcp_scopes.add(self.settings.required_scope_uri)
        if self.settings.mobile_scope_value in claim_scopes:
            mcp_scopes.add(self.settings.mobile_scope_uri)
        return AccessToken(
            token=token,
            client_id=str(authorized_party),
            scopes=sorted(mcp_scopes),
            expires_at=int(claims["exp"]),
            resource=self.settings.canonical_public_url,
            subject=object_id,
            claims={
                "tid": tenant_id,
                "oid": object_id,
                "sub": subject,
                "ver": claims.get("ver"),
                "client_kind": client_kind,
            },
        )
