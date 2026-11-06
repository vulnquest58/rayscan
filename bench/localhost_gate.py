#!/usr/bin/env python3
"""Prove the Phase 1 localhost gate: an exact 1-65535 open-port set.

The script first records the machine's baseline open ports, then starts two
banner listeners on free loopback ports and requires the second full scan to
return exactly the baseline plus those two listeners.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "target" / "release" / "rayscan"


def full_scan(binary: Path, timeout: float) -> tuple[set[int], dict[str, object]]:
    completed = subprocess.run(
        [
            str(binary),
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "1-65535",
            "--json",
            "--quiet",
            "--rate",
            "0",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr)
        raise RuntimeError(f"scanner exited with {completed.returncode}")
    payload = json.loads(completed.stdout)
    open_ports = {int(item["port"]) for item in payload["open"]}
    return open_ports, payload


class BannerListener:
    """Serve one banner per connection until closed.

    The scanner opens more than one connection per port (the probe plus the
    post-scan local recheck), so a listener that stops after the first accept
    would be reported closed by the recheck.
    """

    def __init__(self, port: int) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", port))
        self.socket.listen(8)
        self.socket.settimeout(0.05)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                connection.sendall(b"rayscan localhost gate\n")
            except OSError:
                pass
            finally:
                connection.close()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=5)
        self.socket.close()


def new_listener(baseline: set[int], attempts: int = 50) -> tuple[int, BannerListener]:
    for _ in range(attempts):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        if port in baseline:
            continue
        return port, BannerListener(port)
    raise RuntimeError("could not allocate a loopback listener outside the baseline")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--timeout", type=float, default=300.0)
    args = parser.parse_args(argv)

    if not args.binary.is_file():
        parser.error(f"scanner binary not found: {args.binary}")

    print("scanning the baseline open set on 127.0.0.1:1-65535")
    baseline, baseline_payload = full_scan(args.binary, args.timeout)

    ports = []
    listeners = []
    for _ in range(2):
        port, listener = new_listener(baseline)
        ports.append(port)
        listeners.append(listener)

    expected = baseline | set(ports)
    print(f"baseline open: {sorted(baseline)}")
    print(f"listeners:     {sorted(ports)}")

    actual, payload = full_scan(args.binary, args.timeout)
    for listener in listeners:
        listener.close()

    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        print(f"FAIL missing={missing} extra={extra}", file=sys.stderr)
        return 1

    summary = payload["summary"]
    print(
        "PASS exact open set; "
        f"open={len(actual)} closed={summary['closed']} "
        f"silent={summary['silent']} elapsed_ms={payload['elapsed_ms']}"
    )
    print(f"baseline scan elapsed_ms={baseline_payload['elapsed_ms']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
