"""Cryptographic and claim-validation tests for Entra access tokens."""

import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from soffortbackend.auth import EntraTokenVerifier, JwksCache
from soffortbackend.settings import Settings


def make_key(key_id: str = "test-key") -> tuple[Any, dict[str, Any]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk.update({"kid": key_id, "use": "sig", "alg": "RS256"})
    return private_key, public_jwk


def make_claims(settings: Settings, **overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": settings.canonical_issuer,
        "aud": settings.entra_api_audience,
        "sub": "entra-subject",
        "tid": str(settings.entra_tenant_id),
        "azp": str(settings.entra_vscode_client_id),
        "scp": settings.required_scope_value,
        "iat": now - 5,
        "nbf": now - 5,
        "exp": now + 300,
        "ver": "2.0",
    }
    claims.update(overrides)
    return claims


async def make_verifier(
    settings: Settings,
    jwk: dict[str, Any],
) -> tuple[EntraTokenVerifier, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"keys": [jwk]},
            headers={"Cache-Control": "public, max-age=600"},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cache = JwksCache(
        settings.canonical_jwks_url,
        refresh_cooldown_seconds=5,
        client=client,
    )
    await cache.start()
    return EntraTokenVerifier(settings, cache), requests


@pytest.mark.asyncio
async def test_valid_entra_token_is_mapped_to_mcp_scope(settings: Settings) -> None:
    private_key, jwk = make_key()
    verifier, requests = await make_verifier(settings, jwk)
    token = jwt.encode(
        make_claims(settings),
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    access_token = await verifier.verify_token(token)

    assert access_token is not None
    assert settings.required_scope_uri in access_token.scopes
    assert access_token.resource == settings.canonical_public_url
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", "https://wrong-issuer.example"),
        ("aud", "wrong-audience"),
        ("tid", "33333333-3333-4333-8333-333333333333"),
        ("azp", "44444444-4444-4444-8444-444444444444"),
        ("exp", 1),
        ("nbf", 4_102_444_800),
    ],
)
async def test_invalid_entra_claim_is_rejected(
    settings: Settings,
    claim: str,
    value: Any,
) -> None:
    private_key, jwk = make_key()
    verifier, _ = await make_verifier(settings, jwk)
    token = jwt.encode(
        make_claims(settings, **{claim: value}),
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    assert await verifier.verify_token(token) is None


@pytest.mark.asyncio
async def test_valid_token_without_required_scope_is_preserved(settings: Settings) -> None:
    """Leave scope authorization to MCP so it can distinguish 403 from 401."""
    private_key, jwk = make_key()
    verifier, _ = await make_verifier(settings, jwk)
    token = jwt.encode(
        make_claims(settings, scp="other.scope"),
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    access_token = await verifier.verify_token(token)

    assert access_token is not None
    assert settings.required_scope_uri not in access_token.scopes


@pytest.mark.asyncio
async def test_unknown_key_id_refresh_is_rate_limited(settings: Settings) -> None:
    private_key, jwk = make_key("known-key")
    verifier, requests = await make_verifier(settings, jwk)
    token = jwt.encode(
        make_claims(settings),
        private_key,
        algorithm="RS256",
        headers={"kid": "unknown-key"},
    )

    assert await verifier.verify_token(token) is None
    assert await verifier.verify_token(token) is None
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("token", ["", "not-a-jwt", "x" * 16_385])
async def test_malformed_token_is_rejected_without_network(settings: Settings, token: str) -> None:
    _, jwk = make_key()
    verifier, requests = await make_verifier(settings, jwk)
    assert await verifier.verify_token(token) is None
    assert len(requests) == 1  # Only the explicit startup warm-up occurred.


@pytest.mark.asyncio
async def test_jwks_start_failure_keeps_cache_unready() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cache = JwksCache("https://issuer.example/keys", client=client)
    await cache.start()
    assert cache.ready is False


@pytest.mark.asyncio
async def test_jwks_rejects_document_without_usable_keys() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"keys": [{"kid": "x", "kty": "EC"}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cache = JwksCache("https://issuer.example/keys", client=client)
    with pytest.raises(ValueError, match="no usable"):
        await cache.get_key("x")
