# Rayscan benchmark contract

The benchmark harness consumes the scanner through this contract. Keep it stable
unless the harness and its tests are changed in the same commit.

## Command

```text
rayscan scan --target <host-or-cidr> --ports <list> --json
```

- `--target` is one IPv4 address, CIDR, or range.
- `--ports` is a comma-separated list (`80,443,8000-8100`).
- `--json` writes one JSON object to stdout and nothing else to stdout.
- Progress and diagnostics go to stderr.
- Exit code `0` means the scan completed, even if no ports were open.
- Exit code `1` means a runtime failure.
- Exit code `2` means invalid arguments.

## JSON

```json
{
  "target": "10.77.0.2",
  "open": [
    {"host": "10.77.0.2", "port": 80, "state": "open"},
    {"host": "10.77.0.2", "port": 443, "state": "open"}
  ]
}
```

The harness accepts:

- `open` or `results` as the list key;
- objects with `host`, `port`, and optional `state` (`open` by default);
- a bare integer port when the target is singular.

`open` is always present in the object output. `results` is added when a
non-open state is selected with `--show` or `--all-states`; its entries carry
`state`, so non-open entries are ignored by the harness. A JSON-lines stream is
also accepted for streaming experiments (`--format jsonl`).

The scanner's default verified mode waits briefly for a banner after a
successful handshake. A tarpit or SYN proxy that never supplies a banner is
`silent` or `closed`, not `open`. `--connect-only` disables that verification
and restores handshake-only behaviour.

## SYN mode

`--syn` uses the same command and JSON contract. It requires Linux
root/`CAP_NET_RAW` and is Linux-only. Raw SYN-ACKs are candidates: by default
each candidate is connect-verified before it appears in `open`. For raw
diagnostics, `--syn --connect-only` reports the layer-3/4 result directly.
`--retries N` controls both raw retransmission and connect-verification retries.

The exact SYN lab gate is `bench/syn_gate.py` (`make syn-gate`). It scores the
same `open` list against `lab/ground_truth.json` and requires an exact set, so a
tarpit or SYN proxy in `open` is a failure.

## False positives

The harness compares predicted open ports with `lab/ground_truth.json`. A
predicted open port on a closed, filtered, or tarpit port is a false positive.
This is deliberate: a scanner that calls a tarpit open has failed the accuracy
test even though the TCP handshake succeeded.

## Resource reporting

The harness records:

- wall time from `time.perf_counter()`;
- child CPU time from `getrusage(RUSAGE_CHILDREN)` deltas;
- max RSS from `ru_maxrss` (diagnostic only).

It does not pin CPUs or control background load. Those belong in the
performance phase, where the benchmark hardware must be fixed and documented.
