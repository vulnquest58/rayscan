#!/usr/bin/env python3
"""Compare rayscan against nmap on loopback for the Phase 8 speed track.

Records wall-clock time for the same port range.  nmap's TCP connect scan
(-sT) is the fair comparison for the unprivileged engine; the raw SYN engine is
compared separately against `nmap -sS` when run as root.
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


def timed(cmd: list[str]) -> tuple[float, int, str]:
    start = time.perf_counter()
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return time.perf_counter() - start, completed.returncode, completed.stderr


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--ports", default="1-65535")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--nmap-mode", default="-sT", choices=["-sT", "-sS"])
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)

    rayscan_cmd = [
        str(args.binary),
        "scan",
        "--target",
        args.target,
        "--ports",
        args.ports,
        "--json",
        "--quiet",
        "--rate",
        "0",
    ]
    nmap_cmd = [
        "nmap",
        args.nmap_mode,
        "-T4",
        "--max-retries",
        "1",
        "-p",
        args.ports,
        args.target,
        "-oN",
        "-",
    ]

    results: dict[str, object] = {"target": args.target, "ports": args.ports}
    for name, cmd in (("rayscan", rayscan_cmd), ("nmap", nmap_cmd)):
        times = []
        code = 0
        err = ""
        for _ in range(args.runs):
            elapsed, code, err = timed(cmd)
            times.append(elapsed)
        results[name] = {
            "seconds": [round(t, 3) for t in times],
            "best_s": round(min(times), 3),
            "exit": code,
        }
        print(f"{name:9s} best={min(times):.3f}s all={[round(t, 3) for t in times]} exit={code}")
        if code != 0:
            print(f"  stderr: {err.strip()[:400]}", file=sys.stderr)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(results, indent=2) + "\n")
        print(f"wrote {args.json_out}")
    return 0 if results["rayscan"]["exit"] == 0 else 1  # type: ignore[index]


if __name__ == "__main__":
    sys.exit(main())
