#!/usr/bin/env python3
"""Verify banner-based service detection against the running lab."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "target" / "release" / "rayscan"
DEFAULT_TRUTH = ROOT / "lab" / "ground_truth.json"
DEFAULT_PORTS = "80,443,3306,8080,8081,9000,9003"


def run_scan(
    binary: Path,
    target: str,
    ports: str,
    timeout: float,
    syn: bool,
    detection: bool,
) -> dict[str, object]:
    command = [
        str(binary),
        "scan",
        "--target",
        target,
        "--ports",
        ports,
        "--timeout",
        "2",
        "--quiet",
        "--json",
    ]
    if syn:
        command.extend(["--syn", "--rate", "0", "--retries", "2"])
    if not detection:
        command.append("--no-service-detection")

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr)
        raise RuntimeError(f"scanner exited with {completed.returncode}")
    return json.loads(completed.stdout)


def check_payload(
    payload: dict[str, object],
    expected: set[int],
    forbidden: set[int],
    details: dict[str, dict[str, str]],
    require_metadata: bool,
) -> list[str]:
    failures: list[str] = []
    opens = payload["open"]
    actual = {int(item["port"]) for item in opens}
    if actual != expected:
        failures.append(f"expected={sorted(expected)} actual={sorted(actual)}")
    if actual & forbidden:
        failures.append(f"false positives={sorted(actual & forbidden)}")

    summary = payload["summary"]
    total = sum(int(value) for value in summary.values())
    jobs = int(payload["jobs"])
    if total != jobs:
        failures.append(f"summary total={total} jobs={jobs}")

    for item in opens:
        port = int(item["port"])
        service = item.get("service")
        banner = item.get("banner")
        if not require_metadata:
            if service is not None or banner is not None:
                failures.append(f"port {port} retained service metadata")
            continue

        expected_detail = details.get(str(port))
        if expected_detail is None:
            continue
        if not isinstance(service, dict):
            failures.append(f"port {port} missing service")
            continue
        if service.get("name") != expected_detail["name"]:
            failures.append(
                f"port {port} name={service.get('name')} "
                f"expected={expected_detail['name']}"
            )
        for field in ("product", "version"):
            expected_value = expected_detail.get(field)
            if expected_value is not None and service.get(field) != expected_value:
                failures.append(
                    f"port {port} {field}={service.get(field)} "
                    f"expected={expected_value}"
                )
        if not banner:
            failures.append(f"port {port} missing banner")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--truth", type=Path, default=DEFAULT_TRUTH)
    parser.add_argument("--target", default="10.77.0.2")
    parser.add_argument("--ports", default=DEFAULT_PORTS)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--syn", action="store_true")
    args = parser.parse_args(argv)

    if not args.binary.is_file():
        parser.error(f"scanner binary not found: {args.binary}")
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    truth = json.loads(args.truth.read_text(encoding="utf-8"))
    expected = {int(port) for port in truth["open"]}
    forbidden = {int(port) for port in truth.get("tarpit", [])}
    forbidden.update(int(port) for port in truth.get("synproxy", []))
    details = {
        str(port): value
        for port, value in truth["service_details"].items()
    }

    mode = "SYN" if args.syn else "connect"
    for index in range(1, args.runs + 1):
        payload = run_scan(
            args.binary,
            args.target,
            args.ports,
            args.timeout,
            args.syn,
            detection=True,
        )
        failures = check_payload(payload, expected, forbidden, details, True)
        if failures:
            print(f"run {index}: FAIL {'; '.join(failures)}", file=sys.stderr)
            return 1
        print(
            f"run {index:2d} PASS open={len(payload['open'])} "
            f"services={len(payload['open'])} "
            f"elapsed_ms={payload['elapsed_ms']}"
        )

    control = run_scan(
        args.binary,
        args.target,
        args.ports,
        args.timeout,
        args.syn,
        detection=False,
    )
    failures = check_payload(control, expected, forbidden, details, False)
    if failures:
        print(f"control: FAIL {'; '.join(failures)}", file=sys.stderr)
        return 1
    print(
        f"control PASS open={len(control['open'])} metadata=0 "
        f"elapsed_ms={control['elapsed_ms']}"
    )

    print(f"PASS {mode} service detection gate: {args.runs}/{args.runs} exact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
