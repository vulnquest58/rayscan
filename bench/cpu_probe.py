#!/usr/bin/env python3
"""Measure CPU time vs wall time per worker count.

Distinguishes CPU saturation from scheduler/blocking stalls: if 4096 workers
burn ~1 core-second of CPU for a 2.1s wall scan while 256 workers burn far
more CPU in 0.6s, the high worker count is starving, not compute-bound.
"""

from __future__ import annotations

import json
import resource
import subprocess
import sys
import time
from pathlib import Path

BINARY = Path("/mnt/e/VulnQuest_Pro/rayscan/target/release/rayscan")


def run(workers: int) -> None:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
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
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    payload = json.loads(done.stdout)
    elapsed = payload["elapsed_ms"] / 1000.0
    print(
        f"workers={workers:<5} wall={wall:.3f}s scan={elapsed:.3f}s cpu={cpu:.3f}s "
        f"cpu/scan={cpu / max(elapsed, 1e-6):.1f} cores  "
        f"rate={65535 / elapsed / 1000:.1f}k/s"
    )


def main() -> int:
    for workers in (64, 256, 1024, 4096):
        run(workers)
    return 0


if __name__ == "__main__":
    sys.exit(main())
