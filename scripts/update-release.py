#!/usr/bin/env python3
"""Update the GitOps release to one scanned, immutable container digest."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
RELEASE_PATH = Path("deploy/flux/dev/application/release.yaml")


def main() -> int:
    """Unsuspend the HelmRelease and replace exactly one image digest."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--digest", required=True)
    args = parser.parse_args()
    if not DIGEST_PATTERN.fullmatch(args.digest):
        parser.error("--digest must be a lowercase sha256 digest")

    content = RELEASE_PATH.read_text(encoding="utf-8")
    updated, suspend_count = re.subn(
        r"(?m)^  suspend: (?:true|false)$", "  suspend: false", content
    )
    updated, digest_count = re.subn(
        r"(?m)^      digest: sha256:[a-f0-9]{64}$",
        f"      digest: {args.digest}",
        updated,
    )
    if suspend_count != 1 or digest_count != 1:
        raise SystemExit("release file shape changed; refusing an ambiguous update")
    RELEASE_PATH.write_text(updated, encoding="utf-8")
    print(f"Updated {RELEASE_PATH} to {args.digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
