#!/usr/bin/env python3
"""Exercise Entra Apple or email-OTP authorization without exposing credentials.

This operator probe verifies the part of the MCP login flow that can be tested
before AKS exists: Entra must accept PKCE plus the MCP ``resource`` parameter,
authenticate through the selected user-flow method, and issue an audience-bound
delegated API token. Authorization codes, tokens, subjects, and email addresses
are kept in memory and are never printed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, cast

import jwt
from jwt import PyJWK

DEFAULT_TENANT_ID = "85685fcd-3fc0-4032-982c-92ddd6efc37b"
DEFAULT_TENANT_DOMAIN = "soffortcustomers.onmicrosoft.com"
DEFAULT_CLIENT_ID = "9cea70e5-8b4c-4f37-bf6f-2d789ae49492"
DEFAULT_AUDIENCE = "387b7862-7ab6-4139-af73-b54f535ded29"
DEFAULT_RESOURCE = "https://concentrey.com/mcp"
DEFAULT_SCOPE = "https://concentrey.com/mcp/soffortbackend.access"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:33418"


def base64url(value: bytes) -> str:
    """Return unpadded base64url text as required by OAuth PKCE."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def form_post(url: str, fields: dict[str, str]) -> dict[str, Any]:
    """POST a URL-encoded form and return a decoded JSON object."""
    request = urllib.request.Request(  # noqa: S310 - caller supplies a fixed HTTPS endpoint.
        url,
        method="POST",
        data=urllib.parse.urlencode(fields).encode("ascii"),
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            payload = cast(object, json.load(response))
    except urllib.error.HTTPError as error:
        # Entra's OAuth error has useful correlation identifiers. It does not
        # contain the submitted verifier, but only retain its documented fields.
        decoded = json.loads(error.read())
        safe_error = {
            key: decoded.get(key)
            for key in (
                "error",
                "error_description",
                "error_codes",
                "timestamp",
                "trace_id",
                "correlation_id",
            )
            if decoded.get(key) is not None
        }
        message = f"Token exchange failed ({error.code}): {json.dumps(safe_error)}"
        raise RuntimeError(message) from error
    if not isinstance(payload, dict):
        raise RuntimeError("Token endpoint returned a non-object JSON value")
    return cast(dict[str, Any], payload)


def load_oidc_metadata(tenant_domain: str, client_id: str) -> dict[str, str]:
    """Load and validate the public External ID OIDC endpoint metadata.

    External ID intentionally publishes a friendly tenant host for browser and
    token endpoints while tokens use a tenant-ID host in their ``iss`` claim.
    Consuming discovery preserves that supported distinction instead of
    assuming every endpoint can be derived from the issuer string.
    """
    discovery_url = (
        f"https://{tenant_domain.removesuffix('.onmicrosoft.com')}.ciamlogin.com/"
        f"{tenant_domain}/v2.0/.well-known/openid-configuration?"
        f"{urllib.parse.urlencode({'appid': client_id})}"
    )
    with urllib.request.urlopen(discovery_url, timeout=15) as response:  # noqa: S310
        raw_metadata = cast(object, json.load(response))
    if not isinstance(raw_metadata, dict):
        raise RuntimeError("OIDC discovery returned a non-object JSON value")
    metadata_object = cast(dict[str, object], raw_metadata)

    required = ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer")
    metadata: dict[str, str] = {}
    for key in required:
        value = metadata_object.get(key)
        if not isinstance(value, str) or not value.startswith("https://"):
            raise RuntimeError(f"OIDC discovery did not publish a valid {key}")
        metadata[key] = value
    return metadata


def receive_callback(redirect_uri: str, expected_state: str, timeout_seconds: int) -> str:
    """Receive exactly one loopback callback and return its code in memory."""
    parsed_redirect = urllib.parse.urlsplit(redirect_uri)
    if parsed_redirect.hostname != "127.0.0.1" or parsed_redirect.port is None:
        raise ValueError("The probe only accepts an explicit 127.0.0.1 loopback redirect")

    result: dict[str, str] = {}

    class CallbackHandler(BaseHTTPRequestHandler):
        """Capture the OAuth result while suppressing query-string access logs."""

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API name.
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            result["state"] = query.get("state", [""])[0]
            result["code"] = query.get("code", [""])[0]
            result["error"] = query.get("error", [""])[0]
            result["error_description"] = query.get("error_description", [""])[0]
            body = (
                b"<!doctype html><title>Concentrey identity test</title>"
                # Remove the already-consumed code from the visible address bar
                # before an operator takes a screenshot or copies the URL.
                b"<script>history.replaceState(null,'','/complete')</script>"
                b"<h1>Sign-in returned to Concentrey.</h1>"
                b"<p>You can return to Codex. This tab does not display any token or code.</p>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """Prevent the default server from logging the authorization code."""

    server = HTTPServer((parsed_redirect.hostname, parsed_redirect.port), CallbackHandler)
    server.timeout = timeout_seconds
    server.handle_request()
    server.server_close()

    if not result:
        raise TimeoutError(f"No OAuth callback arrived within {timeout_seconds} seconds")
    if not secrets.compare_digest(result.get("state", ""), expected_state):
        raise RuntimeError("OAuth callback state did not match")
    if result.get("error"):
        description = result.get("error_description", "")
        raise RuntimeError(f"Authorization failed: {result['error']}: {description}")
    code = result.get("code", "")
    if not code:
        raise RuntimeError("OAuth callback contained neither an authorization code nor an error")
    return code


def verify_access_token(
    token: str,
    *,
    issuer: str,
    jwks_url: str,
    audience: str,
    tenant_id: str,
    client_id: str,
    required_scope: str,
) -> dict[str, object]:
    """Verify the issued JWT and return only non-identifying conformance facts."""
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise RuntimeError("Access token is not an RS256 JWT with a key ID")

    with urllib.request.urlopen(jwks_url, timeout=15) as response:  # noqa: S310
        jwks = cast(object, json.load(response))
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise RuntimeError("Entra JWKS response has an unexpected shape")
    keys = cast(list[object], jwks["keys"])
    # Narrow the untyped JSON keys explicitly so Pyright can prove the value
    # passed into PyJWK is a JSON object rather than an arbitrary object.
    matching: list[dict[str, Any]] = []
    for raw_key in keys:
        if isinstance(raw_key, dict) and raw_key.get("kid") == header["kid"]:
            matching.append(cast(dict[str, Any], raw_key))
    if len(matching) != 1:
        raise RuntimeError("The token signing key was not uniquely present in Entra JWKS")
    signing_key = PyJWK.from_dict(matching[0], algorithm="RS256")

    claims = jwt.decode(
        token,
        key=signing_key.key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
        options={"require": ["aud", "exp", "iat", "iss", "nbf", "sub"]},
    )
    authorized_party = claims.get("azp") or claims.get("appid")
    scopes = set(str(claims.get("scp", "")).split())
    if claims.get("tid") != tenant_id:
        raise RuntimeError("Access token tenant claim did not match")
    if authorized_party != client_id:
        raise RuntimeError("Access token authorized-party claim did not match the VS Code client")
    if required_scope not in scopes:
        raise RuntimeError(f"Access token did not contain {required_scope}")

    # These booleans prove protocol compatibility without disclosing identity,
    # timestamps, JWT key identifiers, or any reusable bearer credential.
    return {
        "algorithm": "RS256",
        "issuer_matches": True,
        "audience_matches": True,
        "tenant_matches": True,
        "authorized_party_matches": True,
        "scope_present": True,
    }


def main() -> int:
    """Run one interactive Entra sign-in and print a sanitized result."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    parser.add_argument("--tenant-domain", default=DEFAULT_TENANT_DOMAIN)
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--audience", default=DEFAULT_AUDIENCE)
    parser.add_argument("--resource", default=DEFAULT_RESOURCE)
    parser.add_argument("--scope", default=DEFAULT_SCOPE)
    parser.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI)
    parser.add_argument(
        "--sign-in-method",
        choices=("apple", "email"),
        default="apple",
        help="The provider the operator must choose in the browser.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()

    metadata = load_oidc_metadata(args.tenant_domain, args.client_id)
    issuer = metadata["issuer"]
    authorization_endpoint = metadata["authorization_endpoint"]
    token_endpoint = metadata["token_endpoint"]
    jwks_url = metadata["jwks_uri"]
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64url(hashlib.sha256(verifier.encode("ascii")).digest())
    requested_scope = f"openid offline_access {args.scope}"
    authorization_fields = {
        "client_id": args.client_id,
        "response_type": "code",
        "redirect_uri": args.redirect_uri,
        "response_mode": "query",
        "scope": requested_scope,
        "resource": args.resource,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    if args.sign_in_method == "apple":
        # External ID's supported issuer acceleration bypasses the provider
        # picker. This is also deterministic: a cached local-account session
        # cannot accidentally turn an Apple compatibility test into email OTP.
        authorization_fields["domain_hint"] = "apple"
    authorization_url = f"{authorization_endpoint}?{urllib.parse.urlencode(authorization_fields)}"

    instruction = {
        "apple": "choose Sign in with Apple",
        "email": "enter an email address and complete its one-time passcode",
    }[args.sign_in_method]
    print(f"Open this authorization URL in Safari and {instruction}:")
    print(authorization_url)
    print("Waiting for the loopback callback; no code or token will be logged.", flush=True)
    code = receive_callback(args.redirect_uri, state, args.timeout_seconds)
    response = form_post(
        token_endpoint,
        {
            "client_id": args.client_id,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": args.redirect_uri,
            "code_verifier": verifier,
            "scope": requested_scope,
            "resource": args.resource,
        },
    )
    access_token = response.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise RuntimeError("Token endpoint returned no access token")
    report = verify_access_token(
        access_token,
        issuer=issuer,
        jwks_url=jwks_url,
        audience=args.audience,
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        required_scope="soffortbackend.access",
    )
    report["pkce_s256"] = True
    report["mcp_resource_parameter_accepted"] = True
    report["refresh_token_issued"] = isinstance(response.get("refresh_token"), str)
    # The requested method is an operator assertion, not a token claim. Run
    # each provider test in a fresh private-browser session so cached Entra
    # state cannot silently satisfy the authorization request through another
    # provider.
    report["requested_sign_in_method"] = args.sign_in_method
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        raise SystemExit(f"Identity compatibility test failed: {error}") from error
