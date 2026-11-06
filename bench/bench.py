#!/usr/bin/env python3
"""Run and score port scanners against the rayscan lab.

The harness is intentionally dependency-free. It knows the output formats of
rayscan, nmap, masscan, and rustscan, and it treats the lab's ground truth as
the only source of truth.

Rayscan's Phase 1 contract is documented in docs/benchmark-contract.md.
"""

from __future__ import annotations

import argparse
import json
import re
import resource
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TRUTH = ROOT / "lab" / "ground_truth.json"
DEFAULT_OUTPUT = ROOT / "bench" / "results" / "latest.json"
DEFAULT_TOOLS = ("rayscan", "nmap", "masscan", "rustscan")
OPEN = "open"


@dataclass(frozen=True)
class Target:
    host: str
    port: int


@dataclass
class Metrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    recall: float
    precision: float
    f1: float

    def to_dict(self) -> dict[str, float | int]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "recall": self.recall,
            "precision": self.precision,
            "f1": self.f1,
        }


@dataclass
class Run:
    tool: str
    command: list[str]
    elapsed_seconds: float = 0.0
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    open_ports: set[Target] = field(default_factory=set)
    metrics: Metrics | None = None
    cpu_seconds: float | None = None
    max_rss_kb: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.exit_code == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": self.tool,
            "command": self.command,
            "ok": self.ok,
            "elapsed_seconds": self.elapsed_seconds,
            "exit_code": self.exit_code,
            "open_ports": [
                {"host": target.host, "port": target.port}
                for target in sorted(self.open_ports, key=lambda item: (item.host, item.port))
            ],
            "metrics": self.metrics.to_dict() if self.metrics else None,
            "cpu_seconds": self.cpu_seconds,
            "max_rss_kb": self.max_rss_kb,
            "error": self.error,
            "stdout_tail": self.stdout[-2000:],
            "stderr_tail": self.stderr[-2000:],
        }


def parse_nmap(output: str, default_host: str) -> set[Target]:
    root = ET.fromstring(output)
    found: set[Target] = set()
    for host in root.findall("host"):
        address = host.find("address")
        host_value = address.get("addr") if address is not None else default_host
        host_value = host_value or default_host
        for port in host.findall("./ports/port"):
            state = port.find("state")
            port_number = port.get("portid")
            if state is None or state.get("state") != OPEN or port_number is None:
                continue
            found.add(Target(host_value, int(port_number)))
    return found


def parse_masscan(output: str, default_host: str) -> set[Target]:
    found: set[Target] = set()
    text = output.strip()
    if not text:
        return found
    try:
        records = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if isinstance(records, dict):
        records = [records]
    for record in records:
        if not isinstance(record, dict):
            continue
        host_value = record.get("ip") or record.get("host") or default_host
        for item in record.get("ports", []):
            if isinstance(item, dict) and item.get("status", OPEN) == OPEN:
                found.add(Target(str(host_value), int(item["port"])))
    return found


def parse_rustscan(output: str, default_host: str) -> set[Target]:
    found: set[Target] = set()
    pattern = re.compile(r"\bOpen\s+([^\s:]+):(\d+)\b", re.IGNORECASE)
    for match in pattern.finditer(output):
        host_value = match.group(1) or default_host
        found.add(Target(host_value, int(match.group(2))))
    return found


def parse_rayscan(output: str, default_host: str) -> set[Target]:
    found: set[Target] = set()
    text = output.strip()
    if not text:
        return found

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None

    if payload is None:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                _add_rayscan_item(found, item, default_host)
        return found

    if isinstance(payload, dict):
        items = payload.get("open") or payload.get("results") or []
    else:
        items = payload
    for item in items:
        _add_rayscan_item(found, item, default_host)
    return found


def _add_rayscan_item(found: set[Target], item: object, default_host: str) -> None:
    if isinstance(item, int):
        found.add(Target(default_host, item))
        return
    if not isinstance(item, dict):
        return
    if item.get("state", OPEN) != OPEN:
        return
    port = item.get("port")
    if port is None:
        return
    host_value = item.get("host") or default_host
    found.add(Target(str(host_value), int(port)))


PARSERS: dict[str, Callable[[str, str], set[Target]]] = {
    "nmap": parse_nmap,
    "masscan": parse_masscan,
    "rustscan": parse_rustscan,
    "rayscan": parse_rayscan,
}


def score(predicted: set[Target], truth: set[Target]) -> Metrics:
    true_positives = len(predicted & truth)
    false_positives = len(predicted - truth)
    false_negatives = len(truth - predicted)
    predicted_count = true_positives + false_positives
    recall = true_positives / len(truth) if truth else 0.0
    precision = true_positives / predicted_count if predicted_count else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return Metrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        recall=recall,
        precision=precision,
        f1=f1,
    )


def build_command(
    tool: str,
    target: str,
    ports: str,
    rate: int,
    timeout: float,
    binary: Path,
) -> list[str]:
    if tool == "rayscan":
        return [
            str(binary),
            "scan",
            "--target",
            target,
            "--ports",
            ports,
            "--json",
        ]
    if tool == "nmap":
        command = [
            "nmap",
            "-n",
            "-Pn",
            "-p",
            ports,
            "--open",
            "--host-timeout",
            f"{max(1, int(timeout))}s",
            "-oX",
            "-",
            target,
        ]
        return command
    if tool == "masscan":
        return [
            "masscan",
            "-p",
            ports,
            "--rate",
            str(rate),
            "-oJ",
            "-",
            target,
        ]
    if tool == "rustscan":
        return [
            "rustscan",
            "-a",
            target,
            "-p",
            ports,
            "--greppable",
        ]
    raise ValueError(f"unknown tool: {tool}")


def run_tool(
    tool: str,
    command: list[str],
    parser: Callable[[str, str], set[Target]],
    target: str,
    truth: set[Target] | None,
    timeout: float,
) -> Run:
    result = Run(tool=tool, command=command)
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        result.error = "executable not found"
        result.elapsed_seconds = time.perf_counter() - started
        return result
    except subprocess.TimeoutExpired as exc:
        result.error = f"timed out after {timeout:.0f}s"
        result.elapsed_seconds = time.perf_counter() - started
        result.stdout = exc.stdout or ""
        result.stderr = exc.stderr or ""
        return result
    finally:
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        result.cpu_seconds = round(
            (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime),
            4,
        )
        result.max_rss_kb = after.ru_maxrss

    result.elapsed_seconds = round(time.perf_counter() - started, 4)
    result.exit_code = completed.returncode
    result.stdout = completed.stdout or ""
    result.stderr = completed.stderr or ""
    if completed.returncode != 0:
        result.error = f"exit code {completed.returncode}"
        return result

    try:
        result.open_ports = parser(result.stdout, target)
    except (ET.ParseError, ValueError, KeyError, TypeError) as exc:
        result.error = f"cannot parse output: {exc}"
        return result

    if truth is not None:
        result.metrics = score(result.open_ports, truth)
    return result


def load_lab(path: Path) -> tuple[str, str, set[Target]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    target = str(payload["target"])
    ports = sorted(
        {
            int(port)
            for key in (
                "open",
                "closed",
                "filtered",
                "tarpit",
                "rate_limited",
                "synproxy",
            )
            for port in payload.get(key, [])
        }
    )
    truth = {Target(target, int(port)) for port in payload["open"]}
    return target, ",".join(str(port) for port in ports), truth


def format_table(runs: list[Run]) -> str:
    header = f"{'tool':<10} {'status':<10} {'seconds':>9} {'recall':>8} {'precision':>10} {'f1':>7} {'open':>5}"
    lines = [header, "-" * len(header)]
    for run in runs:
        status = "ok" if run.ok else (run.error or "failed")
        metrics = run.metrics
        recall = f"{metrics.recall:.3f}" if metrics else "-"
        precision = f"{metrics.precision:.3f}" if metrics else "-"
        f1 = f"{metrics.f1:.3f}" if metrics else "-"
        lines.append(
            f"{run.tool:<10} {status:<10} {run.elapsed_seconds:>9.3f} "
            f"{recall:>8} {precision:>10} {f1:>7} {len(run.open_ports):>5}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", action="store_true", help="use lab/ground_truth.json and all lab ports")
    parser.add_argument("--target", help="target host or CIDR")
    parser.add_argument("--ports", help="comma-separated ports")
    parser.add_argument("--truth", type=Path, help="ground-truth JSON")
    parser.add_argument("--tools", default=",".join(DEFAULT_TOOLS))
    parser.add_argument("--binary", type=Path, default=ROOT / "target" / "release" / "rayscan")
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--require-all", action="store_true")
    args = parser.parse_args(argv)

    truth: set[Target] | None = None
    target = args.target
    ports = args.ports

    if args.lab:
        target, lab_ports, truth = load_lab(args.truth or DEFAULT_TRUTH)
        ports = ports or lab_ports
    elif args.truth:
        _, _, truth = load_lab(args.truth)

    if not target or not ports:
        parser.error("provide --target and --ports, or use --lab")

    tools = [item.strip() for item in args.tools.split(",") if item.strip()]
    unknown = [tool for tool in tools if tool not in PARSERS]
    if unknown:
        parser.error(f"unknown tool(s): {', '.join(unknown)}")

    runs: list[Run] = []
    for tool in tools:
        command = build_command(tool, target, ports, args.rate, args.timeout, args.binary)
        if args.dry_run:
            run = Run(tool=tool, command=command)
            print(" ".join(command))
            runs.append(run)
            continue
        if shutil.which(command[0]) is None:
            run = Run(tool=tool, command=command, error="executable not found")
            runs.append(run)
            if args.require_all:
                print(f"{tool}: executable not found", file=sys.stderr)
            continue
        run = run_tool(tool, command, PARSERS[tool], target, truth, args.timeout)
        runs.append(run)

    if not args.dry_run:
        print(format_table(runs))
        for run in runs:
            if run.error:
                print(f"{run.tool}: {run.error}", file=sys.stderr)

    if not args.no_save:
        payload = {
            "target": target,
            "ports": ports,
            "tools": tools,
            "results": [run.to_dict() for run in runs],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if not args.dry_run:
            print(f"saved {args.output}")

    if args.require_all and not args.dry_run and any(not run.ok for run in runs):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
