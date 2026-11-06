#!/usr/bin/env python3
"""Compare rayscan worker counts with and without service verification.

`--connect-only` skips banner reads on open ports, so the comparison separates
per-probe pipeline cost from tail latency caused by transient local listeners.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

BINARY = Path("/mnt/e/VulnQuest_Pro/rayscan/target/release/rayscan")


def run(workers: int, extra: list[str]) -> tuple[float, dict]:
    best = None
    payload = None
    for _ in range(3):
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
                *extra,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode != 0:
            print(done.stderr, file=sys.stderr)
            sys.exit(done.returncode)
        payload = json.loads(done.stdout)
        elapsed = payload["elapsed_ms"] / 1000.0
        if best is None or elapsed < best:
            best = elapsed
    assert best is not None and payload is not None
    return best, payload["summary"]


def main() -> int:
    for extra, label in (([], "verify"), (["--connect-only"], "connect-only")):
        for workers in (0, 64, 256, 1024, 4096):
            best, summary = run(workers, extra)
            rate = 65535 / best / 1000
            print(
                f"{label:<13} workers={workers:<5} best={best:.3f}s "
                f"({rate:.1f}k/s) open={summary['open']} closed={summary['closed']}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
