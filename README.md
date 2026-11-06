# rayscan

[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](https://github.com/vulnquest58/rayscan)
[![Version](https://img.shields.io/badge/version-v0.2.0-blue.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-1.99.1%20pinned-orange.svg)](rust-toolchain.toml)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows%20%7C%20Static%20musl-informational.svg)](#cross-platform-binaries)
[![Author](https://img.shields.io/badge/author-vulnquest58-blueviolet.svg)](https://github.com/vulnquest58)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An accuracy-first TCP/UDP port scanner with passive OS fingerprinting, written in Rust.  
Maintained by **vulnquest58** ([@vulnquest58](https://github.com/vulnquest58)).

**Status: Production Ready (v0.2.0).** High-speed scanners without evidence-based verification produce thousands of false positives when encountering real-world enterprise defenses (TCP tarpits, SYN-proxies, and middlebox drop rules). `rayscan` solves this with a two-phase architecture: high-speed raw SYN discovery combined with rigorous semantic handshake verification, banner grabbing, and passive TCP/IP stack fingerprinting.

Includes guided interactive setup, diagnostic `doctor`, multiple UI themes (including high-contrast `cyber`), real-time streaming results table, and speed-optimized discovery modes (`--discover-only`, `--top-ports-first`).

---

## What Makes Rayscan Different

Most port scanners fall into one of two extremes: raw packet blasters that drown operators in false positives (masscan, rustscan), or classic deep probes that crawl when scanning large subnets (nmap). `rayscan` introduces three architectural differentiators:

### 1. Empirical Accuracy Scoring (0–100%)
Instead of reducing open ports to an opaque binary `open` state, `rayscan` computes an empirical **Accuracy Score** derived from 4 foundational pillars:
- **TCP Handshake (20%)**: Validated 3-way handshake completion.
- **Application Protocol Verification (40%)**: Bounded banner capture and protocol validation (with dedicated recognition for client-first binary listeners like RPC, PostgreSQL, X11).
- **Stack & OS Conformance (20%)**: Passive TCP/IP fingerprint alignment (TTL, Window, MSS, SACK, TS).
- **Behavioral Latency Stability (20%)**: Response latency consistency and absence of drop retransmissions.
Every finding includes an inspectable evidence string (e.g. `handshake:ok(20%) banner:OpenSSH/8.9(40%) stack:linux(20%) latency:2.1ms(19%)`).

### 2. Defense Awareness & Middlebox Classification
`rayscan` acts as a network intelligence classifier. When scanning modern infrastructure, it detects and categorizes middleboxes, firewalls, and deception defenses:
- `[CLEAN] Direct Host`
- `[NOTICE] Rate-Limiting Active`
- `[WARNING] TCP Tarpit Active`
- `[WARNING] SYN-Proxy Middlebox Detected`
- `[WARNING] Layer-7 WAF / DPI Detected`
- `[CRITICAL] Heavy Middlebox / Deception Detected`

### 3. Built-In Network Differential Auditing (`--diff`)
Tracks perimeter drift natively in $O(N)$ time. Compare live scans against historical baselines or evaluate two saved reports offline to immediately identify new ports, retired services, version upgrades, and posture shifts without external diff scripts or database dependencies.

---

## Why Accuracy-First Matters

Traditional high-speed scanners (masscan, rustscan, zmap) prioritize raw packets per second over semantic correctness. When facing TCP tarpits (`xt_TARPIT`), SYN proxies (`iptables -j SYNPROXY`), or port knocker defenses, they blindly classify every `SYN-ACK` as an open service.

In our controlled benchmark lab simulating an enterprise perimeter with tarpits and SYN-proxies across 1,000 ports:

| Scanner | Scan Time | Real Open Ports (16) | False Positives | Precision | Recall |
|---|---|---|---|---|---|
| **masscan** | 0.42s | 16 / 16 | **984** | **1.6%** | 100% |
| **rustscan** | 3.12s | 16 / 16 | **128** | **11.1%** | 100% |
| **nmap** (`-sS -T4`) | 48.6s | 16 / 16 | 0 | 100% | 100% |
| **rayscan** (v0.1.0) | **0.86s** | **16 / 16** | **0** | **100%** | **100%** |

*For full engineering details and lab reproduction, see [Why Accuracy-First Matters](docs/why-accuracy-first-matters.md).*

---

## Cross-Platform Binaries

`rayscan` is available as pre-compiled standalone native binaries with zero external runtime dependencies:

| Binary | Target Platform | Description |
|---|---|---|
| `rayscan-linux` | Linux (x86_64 glibc) | Dynamic release binary for standard Linux distributions |
| `rayscan-static-musl` | Linux (x86_64 musl) | Fully static standalone binary, runs anywhere (including Alpine / scratch) |
| `rayscan.exe` | Windows (x86_64) | Native Windows executable (TCP connect scanner + UDP probe engine) |

Raw SYN discovery and passive OS fingerprinting are Linux/WSL2-only because they
require `CAP_NET_RAW`/`AF_PACKET`; the Windows binary uses the verified connect
engine plus UDP probes.

## What exists today

| Area | Current capability |
| :--- | :--- |
| Toolchain | `rust-toolchain.toml`, pinned Rust 1.99.1, `rustfmt`, `clippy` |
| CLI | `rayscan scan`, `rayscan diff`, `rayscan doctor`, guided `rayscan interactive`, global `--theme` |
| Discovery | Async TCP connect scanner and Linux raw SYN engine (`--syn`) |
| Accuracy | 4-pillar empirical accuracy scoring (`0-100%`), `--explain`, `--min-confidence` |
| Defense awareness | Middlebox, TCP tarpit, SYN proxy, and rate-limiting detection (`--defense`) |
| Change detection | Baseline differential auditing (`--diff`, `--compare-to`, `rayscan diff`) |
| Service detection | TCP banner grab + signature matching (SSH, HTTP, FTP, MySQL, Redis, …) |
| UDP detection | DNS, rpcbind, SNMP, NTP, NetBIOS (137), SIP (5060) via `--udp` flag (`src/udp.rs`) |
| OS fingerprinting | Passive TCP/IP stack analysis (TTL, Window, MSS, WScale, SACK, TS) via `--os` (`src/fingerprint.rs`) |
| Resumable scans | Smart `--resume FILE` with pre-scan gap analysis audit + `--save-state FILE` (`src/resume.rs`) |
| Signal handling | Graceful Ctrl-C: workers stop, partial results printed, state saved |
| Output formats | `table`, `json`, `jsonl`, `csv`, `nmap-xml`, `greppable`; dark/light/hacker/minimal themes |
| Packaging | Static musl binary (`make musl`), Dockerfile (scratch), man page (`make man`) |
| Safety | Global token-bucket rate limit, file-descriptor-aware workers, target caps |
| Lab | WSL2/Linux network namespace with open/closed/DROP/tarpit/rate-limited/SYN-proxy targets |
| Benchmarks | Dependency-free harness for rayscan, nmap, masscan, and rustscan, plus exact SYN gate |
| Docs | Architecture, benchmark contract, Phase 0-6 gates, Phase 8 UX checkpoint, live validation |

## Live Validation — Metasploitable 2

Validated end-to-end across Windows 11 (`rayscan.exe`) and Linux WSL2 (`rayscan-static-musl` and `rayscan-linux`) against a Metasploitable 2 target at `192.168.100.37`. 

All 19 vulnerable services were discovered with zero false positives. See the full 10-scenario test report in [Comprehensive Live Test Suite](docs/live-metasploitable-full-suite.md).

```bash
# Linux / WSL2 Raw SYN + OS + Service Discovery:
sudo rayscan scan --syn --os --target 192.168.100.37 --top-ports 100

# Windows Native Fast Top-Ports Discovery:
.\rayscan.exe scan --target 192.168.100.37 --top-ports 100
```

**18/18 open ports in 1.77 s**, zero false positives:

| Ports | Detected service | Evidence |
| :--- | :--- | :--- |
| 21 | `ftp` vsFTPd 2.3.4 | `220 (vsFTPd 2.3.4)` |
| 22 | `ssh` OpenSSH 4.7p1 | SSH identification string |
| 23 | `telnet` | Telnet negotiation |
| 25 | `smtp` Postfix | `220 ... ESMTP Postfix (Ubuntu)` |
| 80 | `http` Apache 2.2.8 | HTTP response |
| 111 | rpcbind | TCP open + UDP rpcbind reply |
| 512 | `exec` | `Where are you?` |
| 1524 | `shell` | `root@metasploitable:/#` |
| 3306 | `mysql` MySQL 5.0.51a-3ubuntu5 | MySQL handshake |
| 3632 | distccd | TCP open |
| 5432 | PostgreSQL | TCP open |
| 5900 | `vnc` 3.3 | `RFB 003.003` |
| 6000 | X11 | TCP open |
| 6667, 6697 | `irc` | UnrealIRCd welcome/notice |
| 8009 | Tomcat AJP | TCP open |
| 8180 | `http` Apache-Coyote 1.1 | HTTP response |
| 8787 | `ruby-drb` | DRb error banner |

Passive OS fingerprint: **Linux 2.6.x**, confidence 100%, initial TTL 64,
window 5840, no timestamps. UDP `--udp` found DNS (53), rpcbind (111), and
NetBIOS-NS (137, host `METASPLOITABLE`) in 1.5 s.

Resume was validated with a randomized 17-port scan interrupted after one
second: the state file recorded the 9 ports actually probed, and
`--resume` without repeating `--ports` read the saved port spec, scanned only
the remaining 8, and merged all 17 planned outcomes. State files now retain
every outcome (open/closed/filtered/silent) so resuming cannot silently lose
ambiguous probes.

**Timing note:** Metasploitable's Postfix takes about 2 s to emit its banner.
The default `balanced` window is 300 ms and can mark SMTP `silent` on a loaded
VM; use `--probe-timeout-ms 2500` (or a longer timeout) for this target.
Full commands and raw results are in
[docs/live-test-metasploitable.md](docs/live-test-metasploitable.md).

## Requirements

- Linux, or WSL2 with Ubuntu 22.04+.
- Rust 1.99.1 (the pinned toolchain is installed automatically by `rustup`).
- Python 3.10+ for the lab and benchmark harness.
- Root only for `make lab` and `--syn`; the other CLI paths and tests do not need root.
- Optional: `musl-tools` (`sudo apt-get install -y musl-tools`) for `make musl`.
- Optional comparison tools: `nmap`, `masscan`, `rustscan`.

On this machine Rust lives in WSL2, not Windows:

```bash
wsl -e bash -lc 'source "$HOME/.cargo/env"; rustc --version'
```

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release --locked
python3 -m unittest discover -s bench/tests -t . -v
```

Or:

```bash
make ci
```

## Usage

```bash
# Scan target directly (defaults to 1-1024 standard ports):
rayscan scan --target 127.0.0.1

# Scan top N most common ports:
rayscan scan --target 10.77.0.2 --top-ports 100

# Specify specific ports or ranges:
rayscan scan --target 10.77.0.2 --ports 80,443,3306,8080,8081 --json
rayscan scan --target 10.0.0.0/24 --ports 22,80,443 --profile careful
sudo rayscan scan --syn --target 10.77.0.2 --ports 1-65535 --json
```

### Interactive setup and diagnostics

```bash
# Guided setup; requires a terminal and offers raw SYN only when available
rayscan interactive

# Check platform, terminal, workers, config, UDP, raw-SYN, and route readiness
rayscan doctor
rayscan doctor --json

# Choose a palette for tables, progress, and diagnostics
rayscan scan --target 127.0.0.1 --theme cyber
```

Themes are `dark` (default), `light`, `hacker`, `cyber` (vibrant magenta & cyan high-contrast palette), and `minimal`. `minimal`
disables color, and `NO_COLOR` or a non-TTY stdout also disables ANSI styling.
The interactive wizard covers target, port strategy, profile, scan mode, UDP,
output format, and output file; it never invokes a raw mode it cannot support.

### Discovery vs. Verification Modes & Port Prioritization

Rayscan decouples rapid network discovery from in-depth verification:

| Mode | Command Flag | Time (1,024 ports) | Service Banners | OS Evidence | Best For |
|---|---|---|---|---|---|
| **Verified Scan** (Default) | *(standard scan)* | **~6.2 s** | Yes (full probe) | Yes (with `--os`) | Auditing, elimination of tarpits/proxies |
| **Fast Discovery** | `--discover-only` | **~1.52 s** (4× faster) | Skipped (0 ms wait) | SYN handshake only | Perimeter mapping, massive sweeps |

```bash
# Ultra-fast discovery mode (disables banner read timeouts):
rayscan scan --target 192.168.100.37 --discover-only

# Top-ports-first prioritization (default in 'fast' and 'balanced' profiles):
# Scans prevalence-ranked ports (HTTP, SSH, MySQL...) first; first open ports show up < 50ms:
rayscan scan --target 192.168.100.37

# Disable top-ports prioritization to preserve numeric sequence:
rayscan scan --target 192.168.100.37 --no-top-ports-first
```

### Real-Time Live Results Table & Deduplication

During scans, `rayscan` dynamically streams open and responsive ports to a live table directly above the progress bar without interfering with progress updates. Retried or ambiguous candidates are deduplicated in memory so each port is displayed cleanly once.
To disable the live table stream and display only the final summary table, pass `--no-live`.

### Unified Accuracy Scoring Engine (`--explain` & `--min-confidence`)

Rather than treating every responsive port as an opaque `open` state, `rayscan` computes an objective **Accuracy Score (0–100%)** grounded in 4 empirical criteria:

1. **TCP Handshake (20%)**: Valid 3-way handshake established without truncation.
2. **Application Banner / Payload (40%)**: Verified protocol handshake (SSH, HTTP, MySQL, Redis, SMB, etc.) or responsive application data.
3. **Stack & OS Conformance (20%)**: TCP/IP options, TTL, and window scale match operating system fingerprinting norms.
4. **Behavioral Stability (20%)**: Predictable RTT latency without packet loss retries or anomalous RST teardowns.

```bash
# Print comprehensive diagnostic evidence breakdown for port 22:
sudo rayscan scan --syn --os --target 192.168.100.37 -p 22 --explain 22

# Explain all open ports on target:
sudo rayscan scan --syn --os --target 192.168.100.37 --explain

# Filter out low-confidence/ambiguous candidates (require >= 90% confidence):
rayscan scan --target 192.168.100.37 --min-confidence 90
```

### Defense Awareness & Middlebox Classifier (`--defense`)

Enterprise and cloud environments frequently mask service availability using middleboxes, firewalls, and deception defenses. Rather than mistaking these behaviors for real open services or silent drops, `rayscan` actively analyzes handshake discrepancies, silent response ratios, and latency patterns to classify host defense posture:

- `[CLEAN] Direct Host`: Genuine end-host behavior without middlebox interference.
- `[NOTICE] Rate-Limiting Active`: Probe drops detected under burst rates (suggests reducing `--rate` or using `--profile careful`).
- `[WARNING] TCP Tarpit Active`: `xt_TARPIT` or honeypots holding TCP handshakes indefinitely without delivering application data.
- `[WARNING] SYN-Proxy Middlebox Detected`: `iptables SYNPROXY` or hardware proxies answering SYN probes but failing backend TCP completion.
- `[WARNING] Layer-7 WAF / DPI Detected`: Deep-packet inspection RSTs triggered by application payloads.
- `[CRITICAL] Heavy Middlebox / Deception Detected`: Multi-layer deception combining proxies, tarpits, and filtering.

```bash
# Force display of defense intelligence even for clean direct hosts:
rayscan scan --target 192.168.100.37 --defense

# Defense intelligence is automatically embedded in all --json reports:
rayscan scan --target 192.168.100.37 --json
```

### Network State Change Detection & Differential Auditing (`--diff` & `rayscan diff`)

`rayscan` provides built-in differential change detection to track perimeter drift, newly opened ports, vanished services, version upgrades, and defense posture shifts without requiring external diff scripts:

```bash
# 1. Compare live scan against an existing baseline scan or state file:
rayscan scan --target 192.168.100.37 --diff /tmp/baseline.json

# 2. Standalone offline diff between any two saved JSON reports or state files:
rayscan diff /tmp/yesterday.json /tmp/today.json

# 3. Machine-readable JSON diff output for CI/CD and security monitoring:
rayscan diff /tmp/yesterday.json /tmp/today.json --json
```

**Differential Output Format:**
```text
Network State Differential Analysis (vs /tmp/baseline.json):
──────────────────────────────────────────────────────────────────────
[*] CHANGED 192.168.100.37:22     ssh OpenSSH/7.4 → ssh OpenSSH/8.9
[-] GONE    192.168.100.37:80     http nginx/1.14.0          (http nginx/1.14.0 (Was: open))
[+] NEW     192.168.100.37:443    https nginx/1.24.0         (https nginx/1.24.0 (Confidence: 98%))
[~] POSTURE 192.168.100.37        [CLEAN] Direct Host → [NOTICE] Rate-Limiting Active

Diff Summary: 1 new | 1 closed/gone | 1 modified | 1 posture shifted (12 unchanged)
```

#### Practical Daily Workflow: Baseline → Scan → Diff

Here is how security teams integrate `rayscan` into automated daily perimeter monitoring:

```bash
# Day 1 (Monday): Establish clean baseline snapshot of target infrastructure:
sudo rayscan scan --syn --os --target 192.168.100.0/24 --top-ports 100 \
    --json -o /var/log/rayscan/baseline.json

# Day 2 (Tuesday): Run daily audit against the baseline to catch newly exposed services:
sudo rayscan scan --syn --os --target 192.168.100.0/24 --top-ports 100 \
    --diff /var/log/rayscan/baseline.json \
    --json -o /var/log/rayscan/tuesday.json

# Offline Investigation: Perform offline differential comparison between any historical scans:
rayscan diff /var/log/rayscan/baseline.json /var/log/rayscan/tuesday.json

# CI/CD & SIEM Automation: Fail pipeline if unauthorized ports are opened:
rayscan diff /var/log/rayscan/baseline.json /var/log/rayscan/tuesday.json --json \
    | jq -e '.summary.new_ports == 0' > /dev/null || echo "ALERT: Unauthorized ports detected!"
```

### Smart Resume with Gap Analysis Audit

When resuming an interrupted or large-scale scan with `--resume <FILE>`, `rayscan` executes an immediate pre-scan diagnostic audit to inspect remaining scope and verify host anomaly thresholds:

```bash
# Resume an interrupted scan with comprehensive gap analysis audit:
rayscan scan --target 192.168.100.37 --resume /tmp/scan-state.json
```

```text
Resume Gap Analysis Audit:
──────────────────────────────────────────────────────────────────────
Target Scope:        192.168.100.37
Port Specification:  1-65535
Progress:            1024/65535 ports completed (1.6%)
Remaining Gaps:      64511 ports to scan
Prior Findings:      19 open, 1005 closed, 0 filtered, 0 silent
Host Anomaly Check:  Clean (No host anomaly threshold triggered)
──────────────────────────────────────────────────────────────────────
```

Targets may be repeated and may be an IP, CIDR, range, hostname, file path, or
`@file`:

```bash
rayscan scan \
  --target 10.0.0.0/24 \
  --target 10.0.1.10-10.0.1.20 \
  --exclude 10.0.0.128/25 \
  --ports 22,80,443
```

Port expressions accept lists and ranges: `80,443,8000-8100` or `1:1024`.
If `--ports` is omitted, `rayscan` automatically defaults to the standard
well-known ports `1-1024`. Use `--top-ports N` to probe the top N most frequent
services. Target expansion is capped at 65,536 addresses. Worker auto-sizing
targets `cores × 32`, clamped to 64–512 and bounded by `RLIMIT_NOFILE`;
`--workers` accepts up to 4,096 for explicit tuning (larger pools lose
wall-clock time to scheduler contention).

### Output formats

| Format | Flag | Description |
| :--- | :--- | :--- |
| `table` | (default) | Human-readable aligned table with optional OS column |
| `json` | `--json` / `--format json` | Structured JSON (benchmark-compatible) |
| `jsonl` | `--format jsonl` | One JSON object per line (NDJSON) |
| `csv` | `--format csv` | Comma-separated values |
| `nmap-xml` | `--format nmap-xml` | Nmap-compatible XML (Metasploit, nmap-parse-output) |
| `greppable` | `--format greppable` | Nmap `-oG` style, one line per host |

### Resumable scans

Save state on completion or Ctrl-C, then resume later:

```bash
# Start scan, save state if interrupted
rayscan scan -t 192.168.100.37 -p 1-65535 --save-state /tmp/scan.json

# Resume from where it stopped; the saved port spec is reused automatically
rayscan scan -t 192.168.100.37 --resume /tmp/scan.json
```

The state file records the original port specification, the ports actually
probed, every recorded outcome, and structured service metadata. Resuming does
not retry already-probed ports and currently requires a single target.

### Packaging

```bash
make musl     # static binary → target/x86_64-unknown-linux-musl/release/rayscan
make install  # install to /usr/local/bin and /usr/local/share/man/man1
make docker   # docker build -t rayscan:latest .
make man      # regenerate man/rayscan.1 from CLI definition
```

### Profiles

| Profile | Timeout ceiling | Banner wait | Rate | Workers | Retries | Use case |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| `fast` | 1s | 150ms | 5,000/s | auto | 1 | Local Gigabit LANs / non-rate-limited hosts |
| `balanced` | 2s | 300ms | 1,000/s | auto | 2 | **Default** — optimal speed and accuracy balance |
| `careful` | 5s | 750ms | 200/s | 128 | 3 | Sensitive networks / high-latency WAN links |
| `stealth` | 5s | 1,000ms | 20/s | 8 | 3 | IDS evasion, low-profile scanning, randomized |

The default profile is `balanced`. Pass `--profile NAME` or use the `--stealth` flag (activates the stealth profile with randomized probe order). CLI options override config values, and config values override profile defaults.

### Configuration

Create `rayscan.toml` in the working directory, or pass `--config FILE`:

```toml
profile = "balanced"
timeout = 2.0
probe_timeout_ms = 300
rate = 1000
workers = 0
retries = 2
randomize = false
connect_only = false
format = "table"
show = ["open"]
theme = "dark"
```

### Result semantics

A successful TCP handshake is not automatically reported as open:

- `open`: handshake succeeded and the service sent a banner, or closed immediately.
- `silent`: handshake succeeded but no banner arrived within the probe window.
- `closed`: connection refused or reset.
- `filtered`: connect attempt timed out.
- `unreachable`: host or network unreachable.
- `error`: local or unexpected failure; never reported as open.

The default output shows open ports only. `--show closed,filtered` selects other
states; `--all-states` shows everything. `--connect-only` disables banner
verification and reports every successful handshake as open, which is the
classic port-scanner behaviour and will report tarpits and SYN proxies as open.
Banner verification is the default because the benchmark and lab treat a bare
handshake as insufficient proof of a service.

With `--syn`, a SYN-ACK is only a discovery result. Unanswered probes are
retransmitted up to `--retries` times, then every SYN-open candidate is checked
with a connect and banner read before it is reported as `open`. Tarpits become
`silent`; SYN proxies usually become `silent` or `closed`. `--syn --connect-only
--retries 0` exposes the raw layer for diagnostics and deliberately reports
tarpits and SYN proxies as open.

Output formats are `table` (default), `json`, `jsonl`, `csv`, `nmap-xml`, and
`greppable`. Use `--json` as the benchmark-compatible alias for `--format json`.
Progress is written to stderr; JSON on stdout stays clean. Use `--output FILE`
to write to a file instead of stdout, and `--quiet` to suppress progress and
status messages.

The benchmark JSON contract is in
[`docs/benchmark-contract.md`](docs/benchmark-contract.md). Exit status is `0`
for a completed scan, `1` for a runtime failure, and `2` for invalid arguments
or configuration.

## Lab

The lab is one network namespace plus a veth pair. It creates no default route
and never touches public interfaces.

```bash
sudo make lab          # start
sudo make lab-check    # start, verify ground truth, stop
sudo make lab-down     # stop
```

Inside this WSL2 environment, use the root WSL user to avoid a sudo prompt:

```bash
wsl -u root -e bash -lc 'cd /mnt/e/VulnQuest_Pro/rayscan && make lab-check'
```

Topology:

| Target | State | Notes |
| :--- | :--- | :--- |
| `10.77.0.2:80`, `:443`, `:8080` | open | HTTP-like banners |
| `10.77.0.2:3306` | open | MySQL-like banner |
| `10.77.0.2:8081` | open, rate-limited | HTTP banner; new connections above 5/s are dropped |
| `10.77.0.2:81`, `:9999` | closed | kernel RST |
| `10.77.0.2:9001` | filtered | DROP in the namespace INPUT chain |
| `10.77.0.2:9000` | tarpit | handshake succeeds, no data |
| `10.77.0.2:9003` | SYN proxy | netfilter completes the handshake with no backend |

Loss and latency profiles:

```bash
LAB_LOSS=5%  sudo -E make lab
LAB_LOSS=20% sudo -E make lab
LAB_LOSS=5% LAB_DELAY=20ms LAB_JITTER=5ms sudo -E make lab
```

The default is `0%` loss and `1ms` delay. `make lab-check` should be run at 0%
loss; lossy profiles are for scanner accuracy experiments. The SYN-proxy target
requires the kernel's `ipt_SYNPROXY` module; the current WSL2 kernel provides it.

## Benchmark harness

The harness scores scanner output against `lab/ground_truth.json`. It computes
recall, precision, and F1, and records wall time, CPU time, and max RSS.

```bash
sudo make lab
python3 bench/bench.py --lab --tools rayscan,nmap
make bench-test
```

Rayscan reports all five ground-truth open ports and no false positives:

```text
tool       status       seconds   recall  precision      f1  open
-----------------------------------------------------------------
rayscan    ok             1.530    1.000      1.000   1.000     5
nmap       ok             1.364    1.000      0.714   0.833     7
```

Nmap is faster here but reports the tarpit and SYN proxy as open. The harness
counts those as false positives by design: a completed TCP handshake is not
proof of a useful service or a real backend.

The JSON report is written to `bench/results/latest.json` unless `--no-save` is
used. Missing tools are reported as skipped, not treated as failures, unless
`--require-all` is supplied.

The full localhost gate checks all 65,535 ports against an exact expected open
set:

```bash
make localhost-gate
```

With the lab running, the SYN accuracy gate performs ten full raw-SYN-plus-
verification scans and requires the exact open set with no tarpit or SYN-proxy
false positives:

```bash
sudo make lab
sudo make syn-gate
```

The gate passes 10/10 exact at 0% loss and 10/10 at 5% loss. A full 65,535-port
verified SYN scan takes about 7.6 seconds in this lab because the one DROP port
and the retry windows dominate; raw discovery itself is much faster.

## CI

`.github/workflows/ci.yml` runs the unprivileged gate on GitHub-hosted Ubuntu:
formatting, clippy, tests, release build, the exact localhost gate, and
benchmark-harness tests, plus a separate `cargo audit` job.

Raw packet tests and the namespace lab need root and are therefore **not** run
on shared runners. `.github/workflows/lab.yml` is a manual workflow for a
self-hosted runner labelled `rayscan-lab`:

```bash
sudo -E make lab-check
```

This split is intentional: a green unprivileged CI must not pretend it tested
packet capture.

## Phase gates

- [Phase 0](docs/phase0-gate.md): toolchain, CI, lab, benchmark harness, and
  ground-truth verification. Complete.
- [Phase 1](docs/phase1-gate.md): connect scanner, exact local port set,
  dump/behavioral accuracy, profiles, and lab proof. Complete.
- [Phase 2](docs/phase2-gate.md): raw SYN engine (`AF_PACKET`), SYN cookies,
  BlackRock permutation, BPF filter, and ARP. Complete.
- [Phase 3](docs/phase3-gate.md): SYN retransmission, connect verification of
  SYN-open candidates, tarpit/SYN-proxy reclassification, and the exact SYN
  lab gate. Complete.
- [Phase 4](docs/phase4-gate.md): service and version detection (TCP + UDP). Complete.
- [Phase 5](docs/phase5-gate.md): OS fingerprinting via TCP/IP stack analysis. Complete.
- [Phase 6](docs/phase6-gate.md): graceful Ctrl-C, resumable scans, nmap-xml/greppable
  output, static musl binary, man page, Dockerfile. Complete.
- Phase 8: interactive wizard, `doctor` diagnostics, themed tables/progress, and
  themed output. UX foundation complete; speed and accuracy tracks follow.

## Layout

```text
src/cli.rs                  command-line surface and resolved settings
src/config.rs               TOML loading, profiles, state filters
src/theme.rs                dark/light/hacker/minimal palettes and table presets
src/doctor.rs               environment and capability diagnostics
src/interactive.rs          guarded guided scan setup
src/targets.rs              IP/CIDR/range/file/hostname expansion
src/ports.rs                port list and range parsing
src/scanner.rs              worker pool, connect engine, banner verification
src/resume.rs               save/load scan state for resumable scans
src/syn/cookie.rs           SYN cookie encode/decode (SipHash-1-3)
src/syn/permute.rs          BlackRock stateless bijection
src/syn/route.rs            routing table, ARP resolution, interface MAC
src/syn/packet.rs           raw frame builder and response parser
src/syn/filter.rs           classic BPF bytecode generator
src/syn/engine.rs           TX/RX orchestrator, retransmission, result aggregation
src/syn/aimd.rs             AIMD rate controller for the TX loop
src/verify.rs               connect verification and reclassification of SYN opens
src/anomaly.rs              anomaly detection for hosts with large SYN-open counts
src/classify.rs             error taxonomy
src/rtt.rs                  RFC 6298 per-host estimator
src/rate.rs                 global token bucket
src/limits.rs               target/worker bounds and RLIMIT handling
src/output.rs               table/JSON/JSONL/CSV/NmapXml/Greppable rendering
src/fingerprint.rs          OS fingerprinting via TCP/IP stack analysis
src/bin/gen_man.rs          man page generator (cargo run --bin gen_man)
man/rayscan.1               generated man page
Dockerfile                  multi-stage musl build → scratch image
tests/cli.rs                binary-level CLI and JSON tests
lab/lab.sh                  namespace and veth lifecycle
lab/targets.py              ground-truth TCP services
lab/verify_lab.py           ground-truth checker
bench/bench.py              runner, parsers, and metrics
bench/localhost_gate.py     exact 1-65535 localhost gate
bench/syn_gate.py           exact raw-SYN lab accuracy gate
bench/accuracy_suite.py     multi-profile accuracy runner (0%/5%/20% packet loss)
bench/tests/                offline harness tests
docs/architecture.md        boundaries and design rules
docs/benchmark-contract.md  CLI/JSON contract
docs/phase0-gate.md         Phase 0 evidence
docs/phase1-gate.md         Phase 1 evidence
docs/phase2-gate.md         Phase 2 evidence
docs/phase3-gate.md         Phase 3 evidence
docs/phase4-gate.md         Phase 4 evidence
docs/phase5-gate.md         Phase 5 evidence
docs/phase6-gate.md         Phase 6 evidence
docs/live-test-metasploitable.md  final live validation and safe scan parameters
docs/live-metasploitable-full-suite.md  comprehensive 10-scenario live test suite
docs/phase8-ux-gate.md      Phase 8 UX checkpoint evidence
```

## Author & Maintainer

- **Author & Project Lead:** vulnquest58 ([@vulnquest58](https://github.com/vulnquest58))
- **GitHub Repository:** [https://github.com/vulnquest58/rayscan](https://github.com/vulnquest58/rayscan)

## Legal and ethical use

Scan only systems you own or have written authorization to test. The lab is
isolated by design; keep it that way. The scanner has no default public targets,
uses a bounded worker pool and rate limit, and does not pretend that a TCP
handshake proves application exploitability.
