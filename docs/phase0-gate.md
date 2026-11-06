# Phase 0 gate evidence

Environment: WSL2 Ubuntu 22.04, Linux 6.18.33.2, Rust 1.99.1, Python 3.10.12,
nmap 7.80. The lab is a network namespace plus veth pair; no external target is
contacted.

## CI-equivalent checks

```console
$ make ci
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
    Running tests/cli.rs
    running 3 tests
    test version_is_reported ... ok
    test no_arguments_shows_help ... ok
    test help_describes_the_phase_zero_shell ... ok
python3 -m unittest discover -s bench/tests -t . -v
    Ran 13 tests
    OK
$ cargo build --release --locked
```

The release build is also run by the CI `check` job.

## Dependency audit

```console
$ make audit
    Loaded 1403 security advisories
    Scanning Cargo.lock for vulnerabilities (22 crate dependencies)
```

No vulnerabilities were reported.

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

The lab also passed the same eleven checks with `LAB_LOSS=5%`.

## Benchmark-harness proof

With the lab running and only nmap installed:

```console
$ python3 bench/bench.py --lab --tools nmap
tool       status       seconds   recall  precision      f1  open
-----------------------------------------------------------------
nmap       ok             1.242    1.000      0.714   0.833     7
```

Nmap finds all five ground-truth open ports, but also reports the tarpit
(`9000`) and the SYN proxy (`9003`) as open. Those two results are false
positives by the harness's definition, which is exactly why those targets
exist: a completed TCP handshake is not proof of a useful service or a real
backend.

The benchmark harness itself was also exercised offline by its 13 parser,
metric, command-contract, and dry-run tests; it does not require nmap, masscan,
or rustscan to be installed.
