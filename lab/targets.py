#!/usr/bin/env python3
"""Ground-truth TCP services for the rayscan lab.

This process runs inside the ``rayscan-srv`` network namespace. It binds one
listener per port so every result can be checked against a known state.
"""

from __future__ import annotations

import argparse
import signal
import socket
import sys
import threading
import time
from pathlib import Path

BANNERS = {
    80: (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: rayscan-lab\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: close\r\n\r\nOK"
    ),
    443: (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Server: rayscan-lab\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n\r\n"
    ),
    8080: (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: rayscan-lab\r\n"
        b"Content-Length: 5\r\n"
        b"Connection: close\r\n\r\nhello"
    ),
    8081: (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: rayscan-lab-rate-limited\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: close\r\n\r\nOK"
    ),
    3306: (
        b"\x4a\x00\x00\x00\x0a8.0.36-rayscan-lab\x00"
        b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ),
}

STOP = threading.Event()


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        port = int(item, 10)
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
        ports.append(port)
    if not ports:
        raise ValueError("at least one port is required")
    return ports


def serve(listener: socket.socket, port: int, tarpit: bool) -> None:
    listener.settimeout(0.5)

    while not STOP.is_set():
        try:
            connection, peer = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        thread = threading.Thread(
            target=handle,
            args=(connection, peer, port, tarpit),
            daemon=True,
        )
        thread.start()

    listener.close()


def handle(
    connection: socket.socket,
    peer: tuple[str, int],
    port: int,
    tarpit: bool,
) -> None:
    try:
        if tarpit:
            # Complete the handshake, then never answer. This is the
            # "open but silent" case that a scanner must not mistake for a
            # responsive service.
            while not STOP.is_set():
                time.sleep(0.5)
            return

        banner = BANNERS.get(port, f"rayscan-lab service on port {port}\n".encode())
        connection.sendall(banner)
        connection.shutdown(socket.SHUT_WR)
        time.sleep(0.02)
    except OSError:
        pass
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--open", default="80,443,8080,8081,3306")
    parser.add_argument("--tarpit", default="9000")
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args()

    try:
        open_ports = parse_ports(args.open)
        tarpit_ports = parse_ports(args.tarpit)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    listeners: list[tuple[socket.socket, int, bool]] = []
    try:
        for port, tarpit in [(port, False) for port in open_ports] + [
            (port, True) for port in tarpit_ports
        ]:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", port))
            listener.listen(128)
            listeners.append((listener, port, tarpit))
            print(f"listening port={port} tarpit={str(tarpit).lower()}", flush=True)
    except OSError as exc:
        for listener, _, _ in listeners:
            listener.close()
        print(f"cannot bind lab listener: {exc}", file=sys.stderr)
        return 1

    threads: list[threading.Thread] = []
    for listener, port, tarpit in listeners:
        thread = threading.Thread(
            target=serve, args=(listener, port, tarpit), daemon=True
        )
        thread.start()
        threads.append(thread)

    if args.ready_file:
        args.ready_file.parent.mkdir(parents=True, exist_ok=True)
        args.ready_file.write_text("ready\n", encoding="utf-8")

    def stop(_signum: int, _frame: object) -> None:
        STOP.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    try:
        while not STOP.wait(0.5):
            pass
    finally:
        STOP.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
