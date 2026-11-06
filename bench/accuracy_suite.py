#!/usr/bin/env python3
"""Multi-profile accuracy suite for the raw SYN engine.

Cycles through 0 %, 5 %, and 20 % packet-loss netem profiles and runs
rayscan --syn against the lab target.  At each profile asserts:
  - recall >= 0.99  (at least 99 % of true-open ports found)
  - false_positives == 0  (no tarpit / SYN-proxy ports in open list)
  - summary total == jobs  (no accounting bug)

Requires:
  - Root privileges (lab setup and teardown use ip netns / tc).
  - lab/lab.sh in the project root.
  - A compiled release binary at target/release/rayscan.

Usage:
  sudo python3 bench/accuracy_suite.py [--runs N] [--binary PATH]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "target" / "release" / "rayscan"
DEFAULT_TRUTH = ROOT / "lab" / "ground_truth.json"
LAB_SH = ROOT / "lab" / "lab.sh"

LOSS_PROFILES = ["0%", "5%", "20%"]
RECALL_THRESHOLD = 0.99


def run_lab(action: str, loss: str = "0%") -> None:
    env = os.environ.copy()
    env["LAB_LOSS"] = loss
    result = subprocess.run(
        ["bash", str(LAB_SH), action],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        raise RuntimeError(f"lab.sh {action} failed with exit {result.returncode}")


def run_scan(binary: Path, target: str, ports: str, timeout: float) -> dict:
    result = subprocess.run(
        [
            str(binary), "scan",
            "--syn",
            "--target", target,
            "--ports", ports,
            "--rate", "0",
            "--quiet",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        raise RuntimeError(f"scanner exited with {result.returncode}")
    return json.loads(result.stdout)


def evaluate(
    payload: dict,
    expected: set[int],
    forbidden: set[int],
) -> tuple[float, int, bool]:
    """Return (recall, false_positive_count, summary_ok)."""
    actual: set[int] = {int(item["port"]) for item in payload["open"]}
    true_positives = len(actual & expected)
    recall = true_positives / len(expected) if expected else 1.0
    false_positives = len(actual & forbidden)
    summary = payload["summary"]
    total = sum(int(v) for v in summary.values())
    summary_ok = total == int(payload["jobs"])
    return recall, false_positives, summary_ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--truth", type=Path, default=DEFAULT_TRUTH)
    parser.add_argument("--target", default="10.77.0.2")
    parser.add_argument("--ports", default="1-65535")
    parser.add_argument("--runs", type=int, default=3,
                        help="Scan repetitions per loss profile (default: 3)")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--profiles", nargs="+", default=LOSS_PROFILES,
                        help="Loss profiles to test (default: 0%% 5%% 20%%)")
    args = parser.parse_args(argv)

    if not args.binary.is_file():
        parser.error(f"scanner binary not found: {args.binary}")
    if os.geteuid() != 0:
        parser.error("accuracy_suite.py must run as root (lab control requires root)")

    truth = json.loads(args.truth.read_text(encoding="utf-8"))
    expected = {int(p) for p in truth["open"]}
    forbidden = {int(p) for p in truth.get("tarpit", [])}
    forbidden |= {int(p) for p in truth.get("synproxy", [])}

    print(f"rayscan Phase 3 accuracy suite")
    print(f"binary : {args.binary}")
    print(f"target : {args.target}  ports: {args.ports}")
    print(f"expected open: {sorted(expected)}")
    print(f"forbidden (FP): {sorted(forbidden)}")
    print(f"profiles: {args.profiles}  runs/profile: {args.runs}")
    print()

    # Header
    hdr = f"{'loss':>6}  {'run':>3}  {'recall':>7}  {'FP':>4}  {'summary':>7}  {'elapsed_ms':>12}  result"
    print(hdr)
    print("-" * len(hdr))

    overall_pass = True

    for loss in args.profiles:
        # Bring lab up with this loss profile
        run_lab("down")
        time.sleep(0.5)
        run_lab("up", loss=loss)
        time.sleep(0.5)

        profile_pass = True
        for run_idx in range(1, args.runs + 1):
            t0 = time.monotonic()
            try:
                payload = run_scan(args.binary, args.target, args.ports, args.timeout)
            except Exception as exc:
                print(f"{loss:>6}  {run_idx:>3}  {'ERROR':>7}  {'?':>4}  {'?':>7}  {'?':>12}  {exc}")
                profile_pass = False
                overall_pass = False
                continue

            wall = time.monotonic() - t0
            recall, fp, summary_ok = evaluate(payload, expected, forbidden)
            elapsed_ms = payload.get("elapsed_ms", wall * 1000)

            pass_run = recall >= RECALL_THRESHOLD and fp == 0 and summary_ok
            tag = "PASS" if pass_run else "FAIL"
            if not pass_run:
                profile_pass = False
                overall_pass = False

            print(
                f"{loss:>6}  {run_idx:>3}  {recall:>7.4f}  {fp:>4}  "
                f"{'OK' if summary_ok else 'BROKEN':>7}  {elapsed_ms:>12.1f}  {tag}"
            )

        # Take lab down after each profile
        run_lab("down")
        time.sleep(0.5)

        profile_tag = "PASS" if profile_pass else "FAIL"
        print(f"  → profile {loss}: {profile_tag}")
        print()

    if overall_pass:
        print(f"ALL PROFILES PASS — recall >= {RECALL_THRESHOLD:.0%}, FP == 0")
        return 0
    else:
        print("SOME PROFILES FAILED — see rows marked FAIL above")
        return 1


if __name__ == "__main__":
    sys.exit(main())

