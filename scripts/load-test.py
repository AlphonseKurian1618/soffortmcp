#!/usr/bin/env python3
"""Run the bounded authenticated development acceptance load test."""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time

import httpx


async def main_async() -> int:
    """Call the stateless MCP tool concurrently and enforce latency/error targets."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--token", required=True, help="Short-lived Entra access token; never logged"
    )
    parser.add_argument("--duration", type=int, default=600)
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()

    latencies: list[float] = []
    failures = 0
    deadline = time.monotonic() + args.duration
    headers = {
        "Authorization": f"Bearer {args.token}",
        "Accept": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
        "MCP-Method": "tools/call",
        "MCP-Name": "hello_world",
    }
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "hello_world", "arguments": {"name": "Load"}},
        "_meta": {
            "protocolVersion": "2026-07-28",
            "clientInfo": {"name": "soffort-load-test", "version": "0.1.0"},
            "capabilities": {},
        },
    }

    async with httpx.AsyncClient(timeout=10, http2=True) as client:

        async def worker() -> None:
            nonlocal failures
            while time.monotonic() < deadline:
                started = time.perf_counter()
                try:
                    response = await client.post(
                        "https://soffort.com/mcp",
                        headers=headers,
                        json=payload,
                    )
                    if response.status_code != 200:
                        failures += 1
                except httpx.HTTPError:
                    failures += 1
                finally:
                    latencies.append((time.perf_counter() - started) * 1000)

        await asyncio.gather(*(worker() for _ in range(args.concurrency)))

    if not latencies:
        print("No requests completed.")
        return 1
    p95 = statistics.quantiles(latencies, n=100)[94]
    failure_rate = failures / len(latencies)
    print(f"requests={len(latencies)} p95_ms={p95:.2f} failure_rate={failure_rate:.4%}")
    return 0 if p95 < 500 and failure_rate < 0.01 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async()))
