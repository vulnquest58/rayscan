#!/usr/bin/env python3
"""Worker-count sweep for the Phase 8 speed track.

Finds how connect-scan throughput scales with worker count on loopback, which
is the first step in deciding whether the bottleneck is task overhead, socket
creation, or the result pipeline.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "target" / "release" / "rayscan"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--ports", default="1-65535")
    parser.add_argument("--workers", default="0,64,256,1024,4096")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args(argv)

    for workers in args.workers.split(","):
        times = []
        summary = None
        for _ in range(args.runs):
            start = time.perf_counter()
            completed = subprocess.run(
                [
                    str(args.binary),
                    "scan",
                    "--target",
                    "127.0.0.1",
                    "--ports",
                    args.ports,
                    "--json",
                    "--quiet",
                    "--rate",
                    "0",
                    "--workers",
                    workers,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            wall = time.perf_counter() - start
            if completed.returncode != 0:
                print(completed.stderr, file=sys.stderr)
                return completed.returncode
            payload = json.loads(completed.stdout)
            times.append(payload["elapsed_ms"] / 1000.0)
            summary = payload["summary"]
        best = min(times)
        jobs = payload["jobs"]
        print(
            f"workers={workers:>5} best={best:.3f}s "
            f"({jobs / best / 1000:.1f}k probes/s) "
            f"all={[round(t, 3) for t in times]} summary={summary}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
