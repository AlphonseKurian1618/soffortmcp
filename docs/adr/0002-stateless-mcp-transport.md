# ADR 0002: Stateless JSON Streamable HTTP

Status: accepted

## Decision

Serve MCP at exactly `/mcp` with JSON responses and `stateless_http=True`. Modern 2026-07-28 requests are sessionless by specification; the flag also removes in-memory sessions for 2025-11-25 clients.

## Rationale

Any authenticated request can reach either pod during scaling or a rolling update. This avoids sticky ingress, Redis, and session-loss failures while fitting a single request/response hello-world tool.

## Consequences

Server-to-client callbacks, resumability, and long-lived SSE are out of scope. `GET /mcp` is not an event stream. A future tool needing those capabilities requires a new architecture decision.

