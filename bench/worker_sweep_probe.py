#!/usr/bin/env python3
"""Fine worker-count sweep to pick rayscan's automatic worker target."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

BINARY = Path("/mnt/e/VulnQuest_Pro/rayscan/target/release/rayscan")


def run(workers: int, runs: int = 3) -> tuple[float, float]:
    best_scan = None
    best_wall = None
    for _ in range(runs):
        start = time.perf_counter()
        done = subprocess.run(
            [
                str(BINARY),
                "scan",
                "--target",
                "127.0.0.1",
                "--ports",
                "1-65535",
                "--json",
                "--quiet",
                "--rate",
                "0",
                "--workers",
                str(workers),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        wall = time.perf_counter() - start
        if done.returncode != 0:
            print(done.stderr, file=sys.stderr)
            sys.exit(done.returncode)
        payload = json.loads(done.stdout)
        scan = payload["elapsed_ms"] / 1000.0
        if best_scan is None or scan < best_scan:
            best_scan = scan
        if best_wall is None or wall < best_wall:
            best_wall = wall
    assert best_scan is not None and best_wall is not None
    return best_scan, best_wall


def main() -> int:
    for workers in (64, 128, 256, 384, 512, 768, 1024):
        scan, wall = run(workers)
        print(
            f"workers={workers:<5} best_scan={scan:.3f}s best_wall={wall:.3f}s "
            f"({65535 / scan / 1000:.1f}k probes/s)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
