#!/usr/bin/env python3
"""Repeatable local speed probe for the Phase 8 speed track.

Runs a fixed set of loopback scans several times and reports the elapsed time
of every run plus the median.  It never asserts on wall-clock time: machines
and load vary, so the gate evidence lives in docs/phase8-speed-gate.md.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "target" / "release" / "rayscan"

CASES = [
    ("top100", ["--top-ports", "100"]),
    ("top1000", ["--top-ports", "1000"]),
    ("full65535", ["--ports", "1-65535"]),
]


def run_scan(binary: Path, ports_args: list[str]) -> tuple[float, dict]:
    start = time.perf_counter()
    completed = subprocess.run(
        [
            str(binary),
            "scan",
            "--target",
            "127.0.0.1",
            *ports_args,
            "--json",
            "--quiet",
            "--rate",
            "0",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    wall = time.perf_counter() - start
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr)
        raise SystemExit(f"scanner exited with {completed.returncode}")
    payload = json.loads(completed.stdout)
    return wall, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)

    if not args.binary.is_file():
        parser.error(f"scanner binary not found: {args.binary}")

    report: dict[str, object] = {"binary": str(args.binary), "cases": []}
    for name, ports_args in CASES:
        elapsed: list[float] = []
        open_sets: list[set[int]] = []
        for _ in range(args.runs):
            wall, payload = run_scan(args.binary, ports_args)
            elapsed.append(payload["elapsed_ms"] / 1000.0)
            open_sets.append({int(item["port"]) for item in payload["open"]})
            expected = payload["jobs"]
            outcomes = sum(payload["summary"].values())
            if outcomes != expected:
                raise SystemExit(
                    f"{name}: outcome count mismatch {outcomes} != {expected}"
                )

        stable_open_set = all(s == open_sets[0] for s in open_sets[1:])
        entry = {
            "name": name,
            "runs": len(elapsed),
            "min_s": round(min(elapsed), 4),
            "median_s": round(statistics.median(elapsed), 4),
            "max_s": round(max(elapsed), 4),
            "jobs": expected,
            "open": len(open_sets[0]),
            "stable_open_set": stable_open_set,
        }
        report["cases"].append(entry)
        print(
            f"{name:12s} jobs={entry['jobs']:6d} "
            f"min={entry['min_s']:.3f}s median={entry['median_s']:.3f}s "
            f"max={entry['max_s']:.3f}s open={entry['open']}"
            + ("" if stable_open_set else " (open set varied: transient local ports)")
        )

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")
        print(f"wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
