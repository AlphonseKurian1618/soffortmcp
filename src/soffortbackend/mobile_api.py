"""Authenticated iPhone profile, device, and approval HTTP routes."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import uuid7

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from soffortbackend.approval import ApprovalService
from soffortbackend.device_security import (
    canonical_uuid7,
    enrollment_message,
    jwk_thumbprint,
    normalize_display_name,
    parse_public_jwk,
    require_fresh_issued_at,
    validate_apns_token,
    verify_signature,
)
from soffortbackend.models import Device, EnrollmentChallenge, Principal, StoreConflict
from soffortbackend.settings import Settings
from soffortbackend.store import ApprovalStore

MOBILE_BODY_LIMIT_BYTES = 64 * 1024


class MobileHttpError(Exception):
    """Internal control flow for a bounded RFC 9457-style response."""

    def __init__(
        self,
        status: int,
        code: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Create one bounded HTTP failure response."""
        self.status = status
        self.code = code
        self.headers = headers or {}
        super().__init__(code)


def register_mobile_routes(
    server: MCPServer[Any],
    settings: Settings,
    store: ApprovalStore,
    approvals: ApprovalService,
) -> None:
    """Register the narrow iPhone API before constructing the Starlette app."""

    async def resource_metadata(_: Request) -> Response:
        return JSONResponse(
            {
                "resource": settings.canonical_public_url,
                "authorization_servers": [settings.canonical_issuer],
                "scopes_supported": [settings.mobile_scope_uri],
                "bearer_methods_supported": ["header"],
            }
        )

    async def get_profile(request: Request) -> Response:
        async def operation(principal: Principal) -> Response:
            profile = await store.get_profile(principal.partition_key)
            if profile is None:
                raise MobileHttpError(404, "profile_required")
            return JSONResponse(
                {
                    "display_name": profile.display_name,
                    "version": profile.version,
                    "updated_at": _iso(profile.updated_at),
                }
            )

        return await _execute(request, settings, operation)

    async def put_profile(request: Request) -> Response:
        async def operation(principal: Principal) -> Response:
            body = await _read_object(request)
            _require_exact_members(body, {"display_name"})
            display_name = normalize_display_name(body["display_name"])
            profile = await store.put_profile(principal.partition_key, display_name)
            return JSONResponse(
                {
                    "display_name": profile.display_name,
                    "version": profile.version,
                    "updated_at": _iso(profile.updated_at),
                }
            )

        return await _execute(request, settings, operation)

    async def create_challenge(request: Request) -> Response:
        async def operation(principal: Principal) -> Response:
            if await store.get_profile(principal.partition_key) is None:
                raise MobileHttpError(409, "profile_required")
            challenge = EnrollmentChallenge(
                partition_key=principal.partition_key,
                challenge_id=str(uuid7()),
                nonce=secrets.token_urlsafe(32),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
            await store.create_challenge(challenge)
            return JSONResponse(
                {
                    "challenge_id": challenge.challenge_id,
                    "nonce": challenge.nonce,
                    "expires_at": _iso(challenge.expires_at),
                },
                status_code=201,
            )

        return await _execute(request, settings, operation)

    async def put_device(request: Request) -> Response:
        async def operation(principal: Principal) -> Response:
            device_id = canonical_uuid7(request.path_params["device_id"], "device_id")
            body = await _read_object(request)
            _require_exact_members(
                body,
                {
                    "challenge_id",
                    "public_jwk",
                    "apns_token",
                    "apns_environment",
                    "notifications_enabled",
                    "issued_at",
                    "signature",
                },
            )
            challenge_id = canonical_uuid7(body["challenge_id"], "challenge_id")
            challenge = await store.get_challenge(principal.partition_key, challenge_id)
            if challenge is None or challenge.consumed or challenge.expires_at <= datetime.now(UTC):
                raise MobileHttpError(409, "enrollment_challenge_unavailable")
            public_jwk, _ = parse_public_jwk(body["public_jwk"])
            issued_at = require_fresh_issued_at(body["issued_at"])
            message = enrollment_message(
                tenant_id=principal.tenant_id,
                object_id=principal.object_id,
                device_id=device_id,
                challenge_id=challenge_id,
                nonce=challenge.nonce,
                thumbprint=jwk_thumbprint(public_jwk),
                issued_at=issued_at,
            )
            verify_signature(public_jwk, message, body["signature"])
            environment = body["apns_environment"]
            if environment != settings.apns_environment:
                raise MobileHttpError(400, "unsupported_apns_environment")
            if body["notifications_enabled"] is not True:
                raise MobileHttpError(400, "notifications_must_be_enabled")
            device = Device(
                partition_key=principal.partition_key,
                device_id=device_id,
                public_jwk=public_jwk,
                apns_token=validate_apns_token(body["apns_token"]),
                apns_environment=environment,
                notifications_enabled=True,
                updated_at=datetime.now(UTC),
            )
            await store.register_device(challenge, device)
            return JSONResponse(
                {
                    "device_id": device.device_id,
                    "notifications_enabled": True,
                    "updated_at": _iso(device.updated_at),
                },
                status_code=201,
            )

        return await _execute(request, settings, operation)

    async def delete_device(request: Request) -> Response:
        async def operation(principal: Principal) -> Response:
            device_id = canonical_uuid7(request.path_params["device_id"], "device_id")
            await store.delete_device(principal.partition_key, device_id)
            return Response(status_code=204)

        return await _execute(request, settings, operation)

    async def get_approval(request: Request) -> Response:
        async def operation(principal: Principal) -> Response:
            approval_id = canonical_uuid7(request.path_params["approval_id"], "approval_id")
            approval = await store.get_approval(principal.partition_key, approval_id)
            if approval is None:
                raise MobileHttpError(404, "approval_not_found")
            return JSONResponse(
                {
                    "approval_id": approval.approval_id,
                    "tool_name": approval.tool_name,
                    "requester": approval.requester,
                    "arguments_hash": approval.arguments_hash,
                    "nonce": approval.nonce,
                    "status": approval.status.value,
                    "created_at": _iso(approval.created_at),
                    "expires_at": _iso(approval.expires_at),
                }
            )

        return await _execute(request, settings, operation)

    async def decide_approval(request: Request) -> Response:
        async def operation(principal: Principal) -> Response:
            approval_id = canonical_uuid7(request.path_params["approval_id"], "approval_id")
            body = await _read_object(request)
            _require_exact_members(
                body, {"device_id", "decision_id", "decision", "issued_at", "signature"}
            )
            device_id = canonical_uuid7(body["device_id"], "device_id")
            decision_id = canonical_uuid7(body["decision_id"], "decision_id")
            decision = body["decision"]
            if decision not in {"approved", "denied"}:
                raise MobileHttpError(400, "invalid_decision")
            issued_at = require_fresh_issued_at(body["issued_at"])
            approval = await approvals.decide(
                principal,
                approval_id=approval_id,
                device_id=device_id,
                decision_id=decision_id,
                decision=decision,
                issued_at=issued_at,
                signature=body["signature"],
            )
            return JSONResponse(
                {
                    "approval_id": approval.approval_id,
                    "status": approval.status.value,
                    "decided_at": _iso(approval.decided_at) if approval.decided_at else None,
                }
            )

        return await _execute(request, settings, operation)

    server.custom_route("/.well-known/oauth-protected-resource/v1", methods=["GET"])(
        resource_metadata
    )
    server.custom_route("/v1/me/profile", methods=["GET"])(get_profile)
    server.custom_route("/v1/me/profile", methods=["PUT"])(put_profile)
    server.custom_route("/v1/devices/enrollment-challenges", methods=["POST"])(create_challenge)
    server.custom_route("/v1/devices/{device_id}", methods=["PUT"])(put_device)
    server.custom_route("/v1/devices/{device_id}", methods=["DELETE"])(delete_device)
    server.custom_route("/v1/approvals/{approval_id}", methods=["GET"])(get_approval)
    server.custom_route("/v1/approvals/{approval_id}/decisions", methods=["POST"])(decide_approval)


async def _execute(request: Request, settings: Settings, operation: Any) -> Response:
    try:
        principal = _require_mobile_principal(settings)
        return await operation(principal)
    except MobileHttpError as error:
        return _problem(error.status, error.code, headers=error.headers)
    except ValueError, json.JSONDecodeError:
        return _problem(400, "invalid_request")
    except StoreConflict:
        return _problem(409, "decision_conflict")
    except Exception:
        return _problem(503, "service_unavailable")


def _require_mobile_principal(settings: Settings) -> Principal:
    token = get_access_token()
    parsed = urlsplit(settings.canonical_public_url)
    metadata = f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource/v1"
    if token is None:
        raise MobileHttpError(
            401,
            "invalid_token",
            headers={"WWW-Authenticate": f'Bearer resource_metadata="{metadata}"'},
        )
    if token.client_id != str(settings.entra_ios_client_id):
        raise MobileHttpError(403, "unauthorized_client")
    if settings.mobile_scope_uri not in token.scopes:
        raise MobileHttpError(
            403,
            "insufficient_scope",
            headers={
                "WWW-Authenticate": (
                    f'Bearer error="insufficient_scope", scope="{settings.mobile_scope_uri}"'
                )
            },
        )
    principal = Principal.from_access_token(token)
    if principal is None or principal.client_kind != "ios":
        raise MobileHttpError(401, "invalid_token")
    return principal


async def _read_object(request: Request) -> dict[str, Any]:
    length = request.headers.get("content-length")
    if length is not None and (not length.isdigit() or int(length) > MOBILE_BODY_LIMIT_BYTES):
        raise MobileHttpError(413, "request_too_large")
    collected = bytearray()
    async for chunk in request.stream():
        collected.extend(chunk)
        if len(collected) > MOBILE_BODY_LIMIT_BYTES:
            raise MobileHttpError(413, "request_too_large")
    decoded = cast(object, json.loads(collected or b"{}"))
    if not isinstance(decoded, dict):
        raise ValueError("request body must be an object")
    return cast(dict[str, Any], decoded)


def _require_exact_members(body: dict[str, Any], members: set[str]) -> None:
    if set(body) != members:
        raise ValueError("request body members do not match the contract")


def _problem(status: int, code: str, *, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(
        {
            "type": f"https://soffort.com/problems/{code}",
            "title": code.replace("_", " ").title(),
            "status": status,
            "code": code,
        },
        status_code=status,
        headers=headers,
        media_type="application/problem+json",
    )


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
