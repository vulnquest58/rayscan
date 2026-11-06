#!/usr/bin/env python3
"""Verify the raw SYN accuracy gate against the running lab."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "target" / "release" / "rayscan"
DEFAULT_TRUTH = ROOT / "lab" / "ground_truth.json"


def run_scan(
    binary: Path, target: str, ports: str, timeout: float
) -> tuple[dict[str, object], float]:
    started = time.monotonic()
    completed = subprocess.run(
        [
            str(binary),
            "scan",
            "--syn",
            "--target",
            target,
            "--ports",
            ports,
            "--rate",
            "0",
            "--quiet",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    elapsed = time.monotonic() - started
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr)
        raise RuntimeError(f"scanner exited with {completed.returncode}")
    return json.loads(completed.stdout), elapsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--truth", type=Path, default=DEFAULT_TRUTH)
    parser.add_argument("--target", default="10.77.0.2")
    parser.add_argument("--ports", default="1-65535")
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=300.0)
    args = parser.parse_args(argv)

    if not args.binary.is_file():
        parser.error(f"scanner binary not found: {args.binary}")
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    truth = json.loads(args.truth.read_text(encoding="utf-8"))
    expected = {int(port) for port in truth["open"]}
    forbidden = {int(port) for port in truth.get("tarpit", [])}
    forbidden.update(int(port) for port in truth.get("synproxy", []))

    for index in range(1, args.runs + 1):
        payload, elapsed = run_scan(
            args.binary, args.target, args.ports, args.timeout
        )
        actual = {int(item["port"]) for item in payload["open"]}
        summary = payload["summary"]
        total = sum(int(value) for value in summary.values())
        jobs = int(payload["jobs"])

        if actual != expected:
            print(
                f"run {index}: FAIL expected={sorted(expected)} actual={sorted(actual)}",
                file=sys.stderr,
            )
            return 1
        if actual & forbidden:
            print(
                f"run {index}: FAIL false positives={sorted(actual & forbidden)}",
                file=sys.stderr,
            )
            return 1
        if total != jobs:
            print(
                f"run {index}: FAIL summary total={total} jobs={jobs}",
                file=sys.stderr,
            )
            return 1

        print(
            f"run {index:2d} PASS open={len(actual)} "
            f"filtered={summary['filtered']} silent={summary['silent']} "
            f"elapsed_ms={payload['elapsed_ms']} wall={elapsed:.3f}s"
        )

    print(f"PASS raw SYN accuracy gate: {args.runs}/{args.runs} exact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
