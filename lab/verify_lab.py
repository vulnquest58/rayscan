#!/usr/bin/env python3
"""Verify that the lab still matches its ground truth."""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRUTH = json.loads((HERE / "ground_truth.json").read_text(encoding="utf-8"))


def connect(host: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def check_open(host: str, port: int) -> tuple[bool, str]:
    try:
        with connect(host, port, 2.0):
            return True, "connected"
    except OSError as exc:
        return False, f"expected open, got {type(exc).__name__}: {exc}"


def check_closed(host: str, port: int) -> tuple[bool, str]:
    try:
        with connect(host, port, 1.0):
            return False, "expected refused, got a connection"
    except ConnectionRefusedError:
        return True, "refused"
    except OSError as exc:
        return False, f"expected refused, got {type(exc).__name__}: {exc}"


def check_filtered(host: str, port: int) -> tuple[bool, str]:
    try:
        with connect(host, port, 0.8):
            return False, "expected timeout, got a connection"
    except (TimeoutError, socket.timeout):
        return True, "timed out"
    except OSError as exc:
        return False, f"expected timeout, got {type(exc).__name__}: {exc}"


def check_tarpit(host: str, port: int) -> tuple[bool, str]:
    try:
        with connect(host, port, 1.0) as connection:
            connection.settimeout(0.5)
            try:
                data = connection.recv(64)
            except (TimeoutError, socket.timeout):
                return True, "connected, silent"
            if not data:
                return False, "connected, then closed without data"
            return False, f"expected silence, got {len(data)} bytes"
    except OSError as exc:
        return False, f"expected tarpit, got {type(exc).__name__}: {exc}"


def check_synproxy(host: str, port: int) -> tuple[bool, str]:
    try:
        with connect(host, port, 1.0) as connection:
            connection.settimeout(0.5)
            try:
                data = connection.recv(64)
            except (TimeoutError, socket.timeout, ConnectionResetError):
                return True, "connected, proxied"
            if not data:
                return True, "connected, proxied"
            return False, f"expected proxy, got {len(data)} bytes"
    except OSError as exc:
        return False, f"expected syn proxy, got {type(exc).__name__}: {exc}"


def main() -> int:
    host = str(TRUTH["target"])
    checks: list[tuple[str, bool, str]] = []

    for port in TRUTH["open"]:
        ok, detail = check_open(host, port)
        checks.append((f"open {port}", ok, detail))
    for port in TRUTH["closed"]:
        ok, detail = check_closed(host, port)
        checks.append((f"closed {port}", ok, detail))
    for port in TRUTH["filtered"]:
        ok, detail = check_filtered(host, port)
        checks.append((f"filtered {port}", ok, detail))
    for port in TRUTH["tarpit"]:
        ok, detail = check_tarpit(host, port)
        checks.append((f"tarpit {port}", ok, detail))
    for port in TRUTH.get("rate_limited", []):
        ok, detail = check_open(host, port)
        checks.append((f"rate-limited {port}", ok, detail))
    for port in TRUTH.get("synproxy", []):
        ok, detail = check_synproxy(host, port)
        checks.append((f"synproxy {port}", ok, detail))

    failed = [name for name, ok, _ in checks if not ok]
    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<14} {detail}")
    if failed:
        print(f"lab check failed: {len(failed)} mismatch(es)", file=sys.stderr)
        return 1
    print(f"lab check passed: {len(checks)} states match ground truth")
    return 0


if __name__ == "__main__":
    sys.exit(main())
