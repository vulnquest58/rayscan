# Phase 1 gate evidence

Environment: WSL2 Ubuntu 22.04, Linux 6.18.33.2, Rust 1.99.1, Python 3.10.12,
nmap 7.80. The lab is a network namespace plus veth pair; no external target is
contacted.

## CI-equivalent checks

```console
$ make ci
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
    Running unittests src/lib.rs
    running 30 tests ... 30 passed
    Running tests/cli.rs
    running 6 tests ... 6 passed
python3 -m unittest discover -s bench/tests -t . -v
    Ran 13 tests
    OK
cargo build --release --locked
    Finished release profile
```

The unprivileged CI job runs the same commands plus the release build. The lab
workflow is manual because it needs root.

## Dependency audit

```console
$ cargo audit
    Loaded 1403 security advisories
    Scanning Cargo.lock for vulnerabilities (79 crate dependencies)
```

No vulnerabilities or warnings were reported.

## Exact localhost gate

`bench/localhost_gate.py` records the baseline open set, binds two banner
listeners on free loopback ports, and scans `127.0.0.1:1-65535` again. The second
scan must match the baseline plus exactly those listeners.

```console
$ make localhost-gate
scanning the baseline open set on 127.0.0.1:1-65535
baseline open: []
listeners:     [41737, 46707]
PASS exact open set; open=2 closed=65532 silent=1 elapsed_ms=2409.83
baseline scan elapsed_ms=2407.869
```

The listener ports are ephemeral and vary per run. Both full scans completed in
about 2.4 seconds with no throttle (`--rate 0`). The two silent results are
existing loopback handshakes that did not emit a banner; they are not counted as
open.

## Lab ground truth at 0% loss

```console
$ make lab-check
PASS  open 80        connected
PASS  open 443       connected
PASS  open 3306      connected
PASS  open 8080      connected
PASS  open 8081      connected
PASS  closed 81      refused
PASS  closed 9999    refused
PASS  filtered 9001  timed out
PASS  tarpit 9000    connected, silent
PASS  rate-limited 8081 connected
PASS  synproxy 9003  connected, proxied
lab check passed: 11 states match ground truth
```

## Benchmark against the lab

With the lab running and nmap installed:

```console
$ python3 bench/bench.py --lab --tools rayscan,nmap
tool       status       seconds   recall  precision      f1  open
-----------------------------------------------------------------
rayscan    ok             1.530    1.000      1.000   1.000     5
nmap       ok             1.364    1.000      0.714   0.833     7
```

Rayscan finds all five ground-truth open ports and no false positives. Nmap is
slightly faster in this environment but reports the tarpit (`9000`) and the SYN
proxy (`9003`) as open; the harness counts both as false positives.

Observed scanner states for the non-open lab targets:

- tarpit `9000`: `silent`
- SYN proxy `9003`: `closed` after a reset during verification
- filtered `9001`: `filtered`
- closed `81`, `9999`: `closed`

None of them appears in the JSON `open` list.

## 5% loss

The lab was restarted with `LAB_LOSS=5%`. `make lab-check` again passed all 11
ground-truth checks. Ten consecutive benchmark scans produced:

```console
rayscan    ok             1.531    1.000      1.000   1.000     5
rayscan    ok             1.529    1.000      1.000   1.000     5
rayscan    ok             1.530    1.000      1.000   1.000     5
rayscan    ok             1.527    1.000      1.000   1.000     5
rayscan    ok             1.526    1.000      1.000   1.000     5
rayscan    ok             1.528    1.000      1.000   1.000     5
rayscan    ok             1.526    1.000      1.000   1.000     5
rayscan    ok             1.527    1.000      1.000   1.000     5
rayscan    ok             1.528    1.000      1.000   1.000     5
rayscan    ok             1.530    1.000      1.000   1.000     5
```

The 1.5-second minimum connect timeout leaves room for the kernel's normal SYN
retransmission under loss. This was the reason the minimum timeout was raised
from 250ms during Phase 1 verification.

## Gate criteria

- [x] `make ci` passes: format, clippy with `-D warnings`, 30 unit tests, 6 CLI
      tests, 13 benchmark-harness tests, and release build.
- [x] `cargo audit` is clean.
- [x] `127.0.0.1:1-65535` returns exactly the known open set.
- [x] Default verified mode finds all lab open ports with no false positives.
- [x] The lab passes all 11 ground-truth checks at 0% and 5% loss.
- [x] Tarpit and SYN-proxy handshakes are not reported as open.
- [x] Rate limiting, worker bounds, target caps, and local-resource retry
      behavior are covered by tests or exercised by the lab.

## Known limitations

- Verification mode intentionally classifies a silent real service as `silent`.
  Use `--connect-only` when handshake-only semantics are required.
- Raw SYN discovery and verification were added in Phases 2 and 3. UDP scanning
  and service fingerprinting remain later phases.
- The minimum 1.5-second timeout trades some speed for loss tolerance.
- No external/public target has been scanned; only localhost and the isolated
  lab are authorized.
