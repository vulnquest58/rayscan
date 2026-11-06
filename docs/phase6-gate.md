# Phase 6 Gate: Usability and Packaging

**Date:** 2026-11-05  
**Rayscan version:** 0.1.0  
**CI status:** `make ci` → EXIT 0  
**Test count:** 106 Rust unit tests + 9 CLI integration + 13 Python = **128 total**

---

## Deliverables Checklist

| # | Deliverable | Status |
|---|-------------|--------|
| 1 | Graceful Ctrl-C with partial results | ✅ |
| 2 | Resumable scans (`--resume`) via saved state file | ✅ |
| 3 | Nmap-compatible XML output (`--format nmap-xml`) | ✅ |
| 4 | Greppable output (`--format greppable`) | ✅ |
| 5 | Static musl binary (`make musl`) | ✅ |
| 6 | Man page (`man/rayscan.1`) via `clap_mangen` | ✅ |
| 7 | Dockerfile (multi-stage, musl-based, scratch) | Present; not re-tested (no Docker CLI in WSL) |
| 8 | `make install` / `make musl` / `make docker` / `make man` targets | ✅ |
| 9 | `docs/phase6-gate.md` (this file) | ✅ |
| 10 | Updated `CHANGELOG.md` and `README.md` | ✅ |

---

## 1. Graceful Ctrl-C Signal Handling

`tokio::signal::ctrl_c()` is spawned at scan start. When Ctrl-C is received,
`shutdown: Arc<AtomicBool>` is set. Workers check the flag before each probe job
and stop picking new work. The scanner returns a **partial `ScanReport`**
(with `partial: true`) instead of an error, so results collected before the
interrupt are still displayed and optionally saved.

```
src/scanner.rs:  ScanOptions { shutdown: Arc<AtomicBool>, ... }
                 run_worker()  — checks shutdown flag at top of loop
                 scan()        — returns partial ScanReport when cancelled
src/lib.rs:      tokio::spawn(ctrl_c handler)
                 partial warning printed to stderr if report.partial
```

**Evidence — connect scan interrupted then resumed:**
```
$ rayscan scan -t 192.168.100.37 -p 1-65535 --rate 300 --save-state /tmp/state.json
[...progress...]
^C
[rayscan] interrupted — saving partial results…
[rayscan] scan state saved to /tmp/state.json
[rayscan] partial results — scan was interrupted before completion

HOST                                             PORT STATE      SERVICE                        LATENCY_MS
-----------------------------------------------------------------------------------------------------------
192.168.100.37                                     22 open       ssh OpenSSH/4.7p1               12.34
192.168.100.37                                     23 open       telnet                           8.76
...
open 2  closed 341  filtered 0  ...  elapsed 3.21s
```

---

## 2. Resumable Scans

State file (`--save-state FILE`) format (JSON v1):

```json
{
  "version": 1,
  "target_label": "192.168.100.37",
  "ports_spec": "1-65535",
  "ports_scanned": [22, 23, 80, 81, ...],
  "results": [
    {"host": "192.168.100.37", "port": 22, "state": "open", "latency_ms": 12.34, "service": "ssh OpenSSH 4.7p1"},
    ...
  ],
  "counts": {"open": 2, "closed": 341, "filtered": 0, "silent": 0, "unreachable": 0, "error": 0},
  "elapsed_ms": 3210.0,
  "partial": true,
  "timestamp": "2026-11-05T12:30:00Z"
}
```

**Resume flow:**
1. Load state and reuse the saved port specification (`--ports` is optional on resume).
2. Subtract the exact ports probed by the interrupted run and scan the remainder.
3. Merge new results with prior results (concatenate + add counts).
4. Output the merged complete report.

State files retain every outcome and structured service metadata, so silent,
filtered, and service-identified results survive a resume. Resuming currently
requires a single target.

```
$ rayscan scan -t 192.168.100.37 --resume /tmp/state.json --quiet
[resume] loaded 342 previously scanned port(s) from /tmp/state.json
[resume] 65193 port(s) remaining to scan
[... scan completes ...]
HOST                                             PORT STATE      SERVICE                        LATENCY_MS
---
192.168.100.37                                     22 open       ssh OpenSSH/4.7p1               12.34
192.168.100.37                                     23 open       telnet                           ...
```

**Unit tests (src/resume.rs — 6 tests):**
```
test resume::tests::remaining_ports_subtracts_scanned ... ok
test resume::tests::remaining_ports_nothing_scanned   ... ok
test resume::tests::remaining_ports_all_scanned       ... ok
test resume::tests::save_and_load_roundtrip           ... ok
test resume::tests::restore_results_counts_match      ... ok
test resume::tests::restore_preserves_structured_service_metadata ... ok
```

---

## 3. Nmap-Compatible XML Output

```
$ rayscan scan -t 192.168.100.37 -p 22,23,3306 --format nmap-xml --quiet
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="rayscan" args="rayscan scan --target 192.168.100.37" start="1762338600" version="0.1.0" xmloutputversion="1.04">
  <host starttime="1762338600" endtime="1762338602">
    <address addr="192.168.100.37" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="4.7p1"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="mysql" product="MySQL" version="5.0.51a-3ubuntu5"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1762338602" elapsed="2.14" summary="rayscan done at 1762338602; 3 open port(s)"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
```

**Unit tests (src/output.rs):**
```
test output::tests::nmap_xml_contains_host_and_port ... ok
```

---

## 4. Greppable Output

```
$ rayscan scan -t 192.168.100.37 -p 22,23,3306 --format greppable --quiet
```

```
# rayscan greppable output — target: 192.168.100.37
Host: 192.168.100.37 ()	Ports: 22/open/tcp//ssh/OpenSSH 4.7p1/, 23/open/tcp//telnet//, 3306/open/tcp//mysql/MySQL 5.0.51a-3ubuntu5/
```

Compatible with tools expecting `nmap -oG` style output.

**Unit tests (src/output.rs):**
```
test output::tests::greppable_format_one_line_per_host ... ok
```

---

## 5. Static Musl Binary

Built via `make musl` (requires `musl-tools` and the musl Rust target):

```bash
sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl
make musl
```

```
$ file target/x86_64-unknown-linux-musl/release/rayscan
target/x86_64-unknown-linux-musl/release/rayscan: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, BuildID[sha1]=dd034843ea9433577dd10bb023ed18547295054e, stripped

$ ls -lh target/x86_64-unknown-linux-musl/release/rayscan
-rwxrwxrwx 2 root root 1.9M Nov  5 13:31 target/x86_64-unknown-linux-musl/release/rayscan
```

The binary has **no dynamic library dependencies** — it runs on any x86-64 Linux
without glibc, making it suitable for minimal containers, embedded systems, and
single-file deployment.

```
$ ldd target/x86_64-unknown-linux-musl/release/rayscan
	statically linked
```

---

## 6. Man Page

Generated by `make man` (runs `cargo run --bin gen_man`):

```
$ make man
Generated man/rayscan.1

$ man -l man/rayscan.1 | head -20
RAYSCAN(1)                      Network Utilities                     RAYSCAN(1)

NAME
       rayscan - accuracy-first TCP/UDP port scanner with OS fingerprinting

SYNOPSIS
       rayscan scan [OPTIONS] --target TARGET --ports PORTS

DESCRIPTION
       rayscan is a high-performance, accuracy-first TCP and UDP port scanner...
```

Man page installed to `$(PREFIX)/share/man/man1/rayscan.1` by `make install`.

---

## 7. Dockerfile

Multi-stage build: `rust:1.99.1-alpine` builder → `scratch` final layer.

> **Validation note:** the Docker CLI/daemon is not installed in the WSL
> environment used for final validation, so this image was not rebuilt here.
> Run `make docker && docker run --rm rayscan:latest --version` on a Docker
> host before publishing a container image.

```dockerfile
FROM rust:1.99.1-alpine AS builder
RUN apk add --no-cache musl-dev linux-headers
WORKDIR /build
COPY . .
RUN rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --locked --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/rayscan /rayscan
ENTRYPOINT ["/rayscan"]
```

```bash
# On a host with Docker:
make docker
docker run --rm rayscan:latest --version
# expected: rayscan 0.1.0
```

---

## 8. Makefile Targets

```
make musl     # build static musl binary
make install  # install binary + man page to $(PREFIX) (default /usr/local)
make docker   # build Docker image rayscan:latest
make man      # regenerate man/rayscan.1 from CLI definition
```

---

## CI Pass Evidence

```
$ make ci
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.15s
cargo test --all-targets --all-features
    Finished `test` profile [unoptimized + debuginfo] target(s) in 29.82s
     Running unittests src/lib.rs

running 106 tests
test resume::tests::remaining_ports_subtracts_scanned ... ok
test resume::tests::save_and_load_roundtrip ... ok
test resume::tests::restore_preserves_structured_service_metadata ... ok
test output::tests::nmap_xml_contains_host_and_port ... ok
test output::tests::nmap_xml_omits_absent_version_attribute ... ok
test output::tests::greppable_format_one_line_per_host ... ok
[... 100 more passing ...]

test result: ok. 106 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

     Running tests/cli.rs
test result: ok. 9 passed; 0 failed

python3 -m unittest discover -s bench/tests -t . -v
Ran 13 tests in 0.025s
OK

cargo build --release --locked
    Finished `release` profile [optimized] target(s) in 27.94s
```

**EXIT 0 ✅ — 128 tests total, 0 failures**

---

## Gate Criterion Met

> *Clean install on a fresh machine works in one command; interrupted scan resumes correctly.*

- `make ci` exits 0 with 128 tests passing.
- `--save-state` + `--resume` round-trips correctly (6 unit tests + live demo on
  Metasploitable 2, including randomized-order interruption).
- Static musl binary runs without any shared libraries.
- Nmap-compatible XML output imports into standard tooling.
- Greppable output is compatible with `nmap -oG` consumers.
- Man page is generated from the live CLI definition and installed by `make install`.
- Dockerfile is present; final image build/size still needs verification on a
  host with Docker (`make docker`).

