"""Tests for safe structured access logging and response headers."""

import json
import logging
from typing import Any

import pytest

from soffortbackend.logging import JsonFormatter, RequestContextMiddleware, configure_logging


def test_json_formatter_emits_only_selected_context() -> None:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    record.authorization = "must-not-leak"
    payload = json.loads(JsonFormatter().format(record))

    assert payload["message"] == "hello world"
    assert "authorization" not in payload


def test_configure_logging_replaces_root_handlers() -> None:
    configure_logging("WARNING")
    root = logging.getLogger()
    assert root.level == logging.WARNING
    assert isinstance(root.handlers[0].formatter, JsonFormatter)


@pytest.mark.asyncio
async def test_request_middleware_replaces_cache_header_and_adds_hsts() -> None:
    sent: list[dict[str, Any]] = []

    async def inner(scope, receive, send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": [(b"cache-control", b"public")],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    middleware = RequestContextMiddleware(inner)
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/health",
        "scheme": "https",
        "headers": [(b"x-request-id", b"knownrequest123")],
    }
    await middleware(scope, receive, send)

    headers = dict(sent[0]["headers"])
    assert headers[b"cache-control"] == b"no-store"
    assert headers[b"x-request-id"] == b"knownrequest123"
    assert b"strict-transport-security" in headers


@pytest.mark.asyncio
async def test_request_middleware_passes_non_http_scope() -> None:
    called = False

    async def inner(scope, receive, send) -> None:
        nonlocal called
        called = True

    async def receive() -> dict[str, Any]:
        return {"type": "lifespan.startup"}

    async def send(message: dict[str, Any]) -> None:
        del message

    await RequestContextMiddleware(inner)({"type": "lifespan"}, receive, send)
    assert called
