#!/usr/bin/env python3
"""Dry-run or delete only legacy Cosmos profile documents after vault E2E."""

from __future__ import annotations

import argparse
import asyncio
from typing import Any, cast

from azure.cosmos.aio import CosmosClient
from azure.identity.aio import DefaultAzureCredential


async def run() -> int:
    """Count profiles by default; require an exact count before deletion."""
    parser = argparse.ArgumentParser(
        description="Remove only kind=profile records; defaults to a count-only dry run."
    )
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--database", default="soffortbackend")
    parser.add_argument("--container", default="approval")
    parser.add_argument("--workload-client-id")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-count", type=int)
    args = parser.parse_args()
    if args.apply and args.expected_count is None:
        parser.error("--apply requires --expected-count from the immediately preceding dry run")

    credential = DefaultAzureCredential(managed_identity_client_id=args.workload_client_id)
    client = CosmosClient(args.endpoint, credential=credential)
    try:
        container = client.get_database_client(args.database).get_container_client(args.container)
        query = "SELECT c.id, c.partition_key FROM c WHERE c.kind = 'profile'"
        rows = [
            cast(dict[str, Any], row)
            async for row in container.query_items(query=query, enable_cross_partition_query=True)
        ]
        print(f"legacy_profile_count={len(rows)} mode={'apply' if args.apply else 'dry-run'}")
        if not args.apply:
            return 0
        if len(rows) != args.expected_count:
            print("Count changed since dry-run; nothing was deleted.")
            return 2

        # Point deletes bind both the fixed legacy id and its exact partition.
        # No owner identifiers are printed, keeping cleanup logs privacy-safe.
        for row in rows:
            if row.get("id") != "profile" or not isinstance(row.get("partition_key"), str):
                print("Unexpected query result; deletion stopped.")
                return 3
            await container.delete_item(item="profile", partition_key=row["partition_key"])
        print(f"legacy_profiles_deleted={len(rows)}")
        return 0
    finally:
        await client.close()
        await credential.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
