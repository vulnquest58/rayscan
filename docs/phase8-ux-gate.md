# Phase 8 — UX Foundation Checkpoint

**Date:** 2026-11-06
**Status:** UX foundation complete and approved; speed-track evidence lives in
`docs/phase8-speed-gate.md`.
**Toolchain:** Rust 1.99.1, edition 2024.

This checkpoint covers discoverability and presentation only. It does not claim
the speed or accuracy improvements planned for the rest of Phase 8.

## Delivered

| Area | Result |
| :--- | :--- |
| Guided setup | `rayscan interactive` prompts for target, ports, profile, mode, UDP, format, and output path. It refuses non-TTY stdin/stdout and only offers raw SYN/OS after a privilege check. |
| Diagnostics | `rayscan doctor` reports platform, terminal, color, worker limits, config, UDP engines, raw-SYN privilege, and route. `--json` emits the same data for automation. |
| Themes | Global `--theme {dark,light,hacker,minimal}` and `theme` in `rayscan.toml`. Minimal, `NO_COLOR`, and non-TTY stdout suppress ANSI. |
| Tables | `comfy-table` rendering with stable minimum column widths, themed headers/state cells, optional OS column, and no ANSI when color is disabled. |
| Progress | `ProgressEvent` carries the port state; progress shows live open/silent counts and updates every 64 probes. |
| Documentation | README, CLI help, CHANGELOG, and the generated `man/rayscan.1` describe the new commands and theme flag. |

## Verification

```text
$ CARGO_TARGET_DIR=/tmp/rayscan-target make ci
EXIT:0

test result: ok. 111 passed; 0 failed
test result: ok. 11 passed; 0 failed
Ran 13 tests in 0.133s
cargo build --release --locked
    Finished `release` profile [optimized] target(s) in 0.16s
```

`make ci` includes `cargo fmt --check`, clippy with `-D warnings`, all Rust
tests, the Python harness tests, and a release build.

```text
$ cargo audit
EXIT:0
warning: 1 allowed warning found
Crate: fxhash 0.2.1 — unmaintained (RUSTSEC-2025-0057)
```

The warning is an unmaintained transitive dependency of `inquire`; it is not a
known vulnerability. It is tracked for replacement rather than silently ignored.

Cross-builds also pass with the new dependencies:

```text
musl   exit 0 — static-pie ELF, `rayscan 0.1.0`
Windows exit 0 — PE32+ x86-64 console executable
```

### Tables and themes

`table_renders_rows_without_ansi_when_color_is_off` verifies that the plain
table contains the expected host/port/state/service values and no `ESC[` bytes.
`dynamic_table_keeps_header_labels_intact` verifies that narrow terminals keep
`HOST`, `SERVICE`, and `LATENCY_MS` readable instead of collapsing to one
character per column.

### Interactive TTY smoke test

The wizard was driven through a real PTY with default answers:

```text
target     127.0.0.1
ports      Top 100
profile    Balanced
mode       TCP connect (raw SYN unavailable without root)
UDP        No
format     table
output     stdout
start      Yes
```

Result: `100/100` probes, `closed 100`, a correctly aligned empty table, and the
normal summary. A piped invocation exits with usage status 2 and the message
`interactive mode requires a terminal`.

### Doctor output

Rootless Linux run:

| Check | Status | Evidence |
| :--- | :--- | :--- |
| platform | PASS | `linux x86_64` |
| terminal | WARN | piped stdin/stdout in automation; PASS in a PTY |
| color | WARN | plain output when not a TTY; PASS in a PTY |
| workers | PASS | 384 automatic workers for 65,535 probes (cores × 32, capped at 512) |
| udp | PASS | DNS, rpcbind, SNMP, NTP, NetBIOS, SIP |
| config | PASS | built-in defaults; invalid `rayscan.toml` becomes FAIL |
| raw-syn | WARN | requires root or `CAP_NET_RAW`; PASS under sudo |
| route | PASS | `eth0 via 172.22.64.1` |

## Checkpoint limits

- Release archives and platform binaries still predate Phase 8 and will be
  rebuilt after the speed and accuracy tracks.
- Windows raw SYN remains out of scope until an Npcap/WinDivert backend exists;
  the Windows binary keeps the connect + UDP engines.
- Docker image construction remains unverified until a Docker host is available.
- Speed and accuracy work has not started; this checkpoint is presentation,
  diagnostics, and guidance only.
