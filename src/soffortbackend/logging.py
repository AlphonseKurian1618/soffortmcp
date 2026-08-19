"""Minimal structured logging that intentionally excludes request content."""

import json
import logging
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from starlette.types import ASGIApp, Message, Receive, Scope, Send

request_id_context: ContextVar[str] = ContextVar("request_id", default="-")


class JsonFormatter(logging.Formatter):
    """Serialize standard log records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a record without copying arbitrary, potentially sensitive fields."""
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_context.get(),
        }
        for key in ("method", "path", "status_code", "duration_ms"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def configure_logging(level: str) -> None:
    """Configure the process root logger once for container-friendly JSON output."""
    root = logging.getLogger()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


class RequestContextMiddleware:
    """Add safe request correlation, response headers, and access logs.

    Authorization headers, query strings, and bodies are intentionally never
    inspected or emitted. This keeps tokens, OAuth codes, and user data out of
    logs even when a request fails.
    """

    def __init__(self, app: ASGIApp) -> None:
        """Wrap an ASGI application without retaining request data."""
        self.app = app
        self.logger = logging.getLogger("soffortbackend.access")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process one ASGI event stream."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        import time

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        candidate = headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        request_id = candidate if candidate.isalnum() and len(candidate) <= 64 else uuid4().hex
        token = request_id_context.set(request_id)
        started = time.perf_counter()
        status_code = 500

        async def send_with_headers(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                # Replace an inner cache policy instead of appending a second
                # Cache-Control field whose combined meaning may be ambiguous.
                response_headers = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if key.lower() != b"cache-control"
                ]
                response_headers.extend(
                    [
                        (b"x-request-id", request_id.encode("ascii")),
                        (b"cache-control", b"no-store"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                    ]
                )
                forwarded_proto = headers.get(b"x-forwarded-proto", b"")
                if scope.get("scheme") == "https" or forwarded_proto == b"https":
                    response_headers.append(
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
                    )
                message["headers"] = response_headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            self.logger.info(
                "request_completed",
                extra={
                    "method": scope.get("method", ""),
                    "path": scope.get("path", ""),
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                },
            )
            request_id_context.reset(token)
