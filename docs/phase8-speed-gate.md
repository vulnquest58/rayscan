# Phase 8 — Speed Track Checkpoint

**Date:** 2026-11-06
**Status:** Speed track complete; awaiting review before the accuracy track.
**Toolchain:** Rust 1.99.1, edition 2024. Evidence host: 12-core WSL VM,
`ip_local_port_range` 32768-60999, release binary from `make ci`.

This checkpoint covers wall-clock speed only. Accuracy claims belong to the
accuracy track and to the Phase 1/2 gate documents.

## What changed

| Area | Change |
| :--- | :--- |
| Result delivery (`src/scanner.rs`) | Workers batch probes into `Vec<PortResult>` messages (64 results or a 50 ms flush) over a bounded channel sized from the worker count; the receiver unwinds batches with identical per-result semantics (counts, `probed_ports`, retain filter, progress ticks). |
| Hot-path allocations (`src/scanner.rs`, `src/classify.rs`) | Closed probes — the scan majority — skip their `detail` string unless `--show`/`--save-state` will display it; `classify_kind()` classifies an error without formatting. |
| Worker auto-sizing (`src/limits.rs`) | Automatic workers = `min(cores × 32, nofile × 3/4)` clamped to 64–512 (`MAX_AUTO_WORKERS`); `--workers` still accepts up to 4,096. |
| Local-open recheck (`src/verify.rs`) | After a connect scan, open ports on local targets are re-verified with one sequential connection at a time; refusals are reclassified. Removes TCP simultaneous-open phantom listeners (see below). Remote targets are skipped — no extra packets. |

## Diagnosis (measured, not guessed)

- The loopback ceiling for a raw `tokio` connect loop is ≈130k probes/s.
  An isolated micro-bench (modes `timeout | chanempty | full | batch`) showed
  the per-result `async_channel` send/recv was the bottleneck: 36k probes/s
  with per-result messages vs 135k for a bare connect loop; batching results
  recovered ≈108k probes/s in isolation.
- CPU cost is ≈90–110 µs per probe, dominated by kernel system time
  (≈6 syscalls per probe plus ~1.5 futex). `nmap -sT` spends only ≈1.6 s of
  CPU total (single-threaded) vs ≈6.4 s for rayscan, but loses wall-clock
  anyway once the worker count is right.
- Worker sweep on a full-range loopback scan (`bench/worker_sweep_probe.py`):

  | workers | full 1-65535 elapsed |
  | ---: | ---: |
  | 64 | 0.56–0.74 s |
  | 384 | 0.62 s (best) |
  | 512 | 0.66 s |
  | 1024 | 0.76 s |
  | 2048 | 1.31 s |
  | 4096 | 2.13 s (only 3.1 cores busy — scheduler/futex starvation) |

  Above ~512 workers the engine collapses, which is why auto-sizing is capped
  at 512 while explicit `--workers` up to 4,096 remains available.

## Evidence

### Before/after (loopback, `--rate 0`, 5 runs per case)

| case | before min/median | after min/median | speedup (median) |
| :--- | ---: | ---: | ---: |
| top100 | 0.018 / 0.027 s | 0.018 / 0.020 s | ≈1.0× (process startup dominates) |
| top1000 | 0.110 / 0.122 s | 0.072 / 0.093 s | 1.3× |
| full65535 | 2.319 / 2.376 s | 0.696 / 0.729 s | **3.3×** |

Full-range throughput: ≈28k probes/s before → ≈90k probes/s after (median).
Raw data: `bench/results/speed_before.json`, `bench/results/speed_after.json`.

The before-run reported `stable_open_set: false` on the full range (phantom
ports, see below); every after-run is stable with `open=0`.

### rayscan vs nmap (loopback, 1-65535, 3 runs each)

| tool | seconds | best |
| :--- | :--- | ---: |
| rayscan (after) | 0.808, 0.648, 0.723 | **0.648 s** |
| nmap `-sT -T4 --max-retries 1` | 2.415, 1.327, 1.325 | 1.325 s |

Best-vs-best: **2.0× faster than nmap** (median-vs-median 1.8×; nmap's first
run is a cold start at 2.415 s). Before the speed track the same comparison
was 2.178 s vs 2.327 s — barely ahead. Raw data:
`bench/results/speed_compare_before.json`, `bench/results/speed_compare_after.json`.

### Open-set integrity: the local simultaneous-open recheck

Loopback scans pair two of the scanner's own in-flight connections about half
the time (TCP simultaneous open), reporting phantom "open" ports that always
land in the ephemeral range as pairs — `ss -ltn` shows no listener. This
pre-dated the speed work but polluted every local measurement and made
`bench/localhost_gate.py` fail with phantom extras/missing ports.

The recheck in `src/verify.rs` re-verifies local opens one connection at a
time (a lone connection cannot pair with anything) and reclassifies refusals.
It runs only for targets that are this machine, so remote scans send no extra
packets.

```text
$ python3 bench/localhost_gate.py
scanning the baseline open set on 127.0.0.1:1-65535
baseline open: []
listeners:     [34211, 59479]
PASS exact open set; open=2 closed=65533 silent=0 elapsed_ms=739.798
baseline scan elapsed_ms=699.554
```

Both scans (baseline and listener scan) now return exact sets. Known residue
deferred to the accuracy track: with `--save-state`/`--show silent`,
phantom *silent* states (rare, one side of a pair timing out during banner
inspection) are not rechecked — only `open` results are.

## Verification

```text
$ make ci
EXIT: 0   # fmt, clippy -D warnings,119 unit + 11 CLI + 13 python tests,
          # release build — log: bench/results/ci_speed.log

$ cargo audit
EXIT: 0   # warning: 1 allowed warning found (fxhash 0.2.1, RUSTSEC-2025-0057)

$ python3 bench/localhost_gate.py
PASS exact open set; open=2 closed=65533 silent=0
```

The unit suite includes `reports_every_probe_across_batch_boundaries`
(1 worker × 200 probes: counts, `probed_ports`, results, and progress ticks
must all equal 200) and six `verify::recheck_local_opens` tests (refusal
reclassification, live listener kept with banner intact, remote untouched,
retain-all replacement, shutdown short-circuit, local-address detection).

## Limits

- Numbers come from a shared WSL VM with background load; run-to-run variance
  is ≈±20%. `speed_probe.py` never asserts on wall-clock — the tables above
  are recorded evidence, not a CI gate.
- Windows/macOS performance is unmeasured; the Docker image remains unverified.
- The recheck adds a sequential pass over local opens (≈0.1 ms for typical
  open counts; included in `elapsed_ms`).
- Phantom-open removal is a benchmark/gate integrity fix; deeper accuracy
  work (SYN-path verification, tarpit behavior, Metasploitable suite) stays
  in the accuracy track.
