# rayscan

[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](https://github.com/vulnquest58/rayscan)
[![Version](https://img.shields.io/badge/version-v0.5.0-blue.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-1.99.1%20pinned-orange.svg)](rust-toolchain.toml)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows%20%7C%20Static%20musl-informational.svg)](#cross-platform-binaries)
[![Author](https://img.shields.io/badge/author-vulnquest58-blueviolet.svg)](https://github.com/vulnquest58)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An accuracy-first TCP/UDP port scanner with passive OS fingerprinting, written in Rust.  
Maintained by **vulnquest58** ([@vulnquest58](https://github.com/vulnquest58)).

**Status: Production Ready (v0.5.0).** High-speed scanners without evidence-based verification produce thousands of false positives when encountering real-world enterprise defenses (TCP tarpits, SYN-proxies, and middlebox drop rules). `rayscan` solves this with a two-phase architecture: high-speed raw SYN discovery combined with rigorous semantic handshake verification, banner grabbing, passive TCP/IP stack fingerprinting, and offensive operations features for bug bounty hunters (Scope Guard boundary enforcement, CISA KEV and EPSS prioritization, real-time unbuffered JSONL streaming, IPv6 Neighbor Discovery, and the v0.5.0 port preset / adaptive rate / OS role refinement stack).

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
| **rayscan** (v0.5.0) | **0.86s** | **16 / 16** | **0** | **100%** | **100%** |

*For full engineering details and lab reproduction, see [Why Accuracy-First Matters](docs/why-accuracy-first-matters.md).*

---

## Cross-Platform Binaries

`rayscan` is available as pre-compiled standalone native binaries with zero external runtime dependencies:

| Binary | Target Platform | Description |
|---|---|---|
| `rayscan-linux` | Linux (x86_64 glibc) | Dynamic release binary for standard Linux distributions |
| `rayscan-static-musl` | Linux (x86_64 musl) | Fully static standalone binary, runs anywhere (including Alpine / scratch) |
| `rayscan.exe` | Windows (x86_64) | Native Windows executable (TCP connect scanner + UDP probe engine) |

Raw SYN discovery and active OS fingerprinting are Linux/WSL2-only because they
require `CAP_NET_RAW`; IPv4 uses `AF_PACKET`, while IPv6 uses kernel-routed
`AF_INET6` raw sockets. The Windows binary uses the verified connect engine plus
UDP probes and cannot perform raw IPv6 scans.

## What exists today

| Area | Current capability |
| :--- | :--- |
| Toolchain | `rust-toolchain.toml`, pinned Rust 1.99.1, `rustfmt`, `clippy` |
| CLI | `rayscan scan`, `rayscan diff`, `rayscan merge`, `rayscan doctor`, `rayscan db update/status`, guided `rayscan interactive`, global `--theme` |
| Discovery | Async TCP connect scanner plus Linux raw SYN for IPv4 and IPv6 (`--syn`); optional ICMP/TCP ping sweep (`--ping-sweep`) with ARP liveness probing on IPv4 (Linux raw `AF_PACKET`, Windows `SendARP`) |
| Accuracy | 4-pillar empirical accuracy scoring (`0-100%`), `--explain`, `--min-confidence` |
| Defense awareness | Middlebox, TCP tarpit, SYN proxy, and rate-limiting detection (`--defense`) |
| Advisory correlation | Offline CVE matching against detected product/version/banner using a bundled curated database and an auto-updating local NVD mirror (`--advisories`, `rayscan db update`) |
| Change detection | Advisory-aware baseline differential auditing (`--diff`, `--compare-to`, `rayscan diff`) |
| Service detection | TCP banner grab + signature matching (SSH, HTTP, FTP, MySQL, Redis, SMB, MongoDB, memcached, …), HTTP admin-panel fingerprinting, version extraction, per-service confidence (`0.70`–`0.98`), light protocol-native probes for services that wait for a request, and declarative TOML probe packs (`--plugins`) |
| TLS inspection | Certificate, version, cipher, SAN, expiry, self-signed and hostname checks on direct/STARTTLS ports and on TLS plus unidentified services found on non-standard ports; direct sessions also fingerprint the HTTPS application (`--tls`, `--no-tls`) |
| UDP detection | DNS, rpcbind, SNMP, NTP, NetBIOS (137), SIP (5060), SSDP M-SEARCH (1900), mDNS service-type enumeration (5353) via `--udp` flag, including IPv6 (`src/udp.rs`) |
| OS fingerprinting | Active TCP/IP stack analysis over IPv4 and IPv6 (TTL, Window, MSS, WScale, SACK, TS) via `--os` (`src/fingerprint.rs`); Windows host roles refined to Domain Controller / Member Server / Workstation from open service ports |
| Port presets | Curated engagement port sets via `--preset dc|ad`, `win|ws`, `web|http`, `linux|lx`, `full|all`, and `q|top` (nmap top-1000 fidelity) with `--preset` conflict rules |
| Connect timeout | Independent per-connect timeout ceiling via `--connect-timeout-ms` that overrides the `--timeout` seconds default |
| Rate auto | Adaptive connect-scan rate controller that halves/doubles based on timeout ratios (`--rate-auto`) |
| Distributed scans | Stable FNV-1a target sharding (`--shard-index`/`--shard-count`) and `rayscan merge` for JSON/JSONL reports |
| Evasion | Random delay jitter, IPv4 SYN decoys, and IP fragmentation (`--jitter-ms`, `--decoys`, `--fragment-size`) |
| Resumable scans | Smart `--resume FILE` with pre-scan gap analysis audit + `--save-state FILE` (`src/resume.rs`) |
| Signal handling | Graceful Ctrl-C: workers stop, partial results printed, state saved |
| Output formats | `table`, `json`, `jsonl`, `csv`, `host-port`, `nmap-xml`, `greppable`, `sarif`, `markdown`; dark/light/hacker/minimal themes |
| Supply chain | `cargo audit`/`cargo deny`, fuzz targets, checksums, optional GPG/cosign signing (`make deny`, `make fuzz`, `make sign`) |
| Packaging | Static musl binary (`make musl`), Dockerfile (scratch), man page (`make man`) |
| Safety | Global token-bucket rate limit, file-descriptor-aware workers, target caps |
| Lab | WSL2/Linux network namespace with open/closed/DROP/tarpit/rate-limited/SYN-proxy targets |
| Benchmarks | Dependency-free harness for rayscan, nmap, masscan, and rustscan, plus exact SYN gate |
| Docs | Architecture, benchmark contract, Phase 0-6 gates, Phase 8-9 gates, live validation |

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

### IPv4 vs. IPv6 Comparative Live Validation (Phase 9)

In Phase 9 (v0.3.0), comprehensive dual-stack validations were conducted comparing local lab targets and external educational systems across IPv4 and IPv6:

| Target | Protocol | Address | Findings | Elapsed | Accuracy & Evidence |
| :--- | :---: | :--- | :--- | :---: | :--- |
| **Metasploitable 2** | IPv4 | `192.168.100.37` | **16 open ports** (FTP, SSH, Telnet, SMTP, HTTP, MySQL, PostgreSQL, VNC...) | 9.55s | 85%–100% confidence, OS: Linux 2.6.x (100%), Defense: Direct/SYN-Proxy (92%), CVE Advisories matched |
| **Metasploitable 2** | IPv6 | `fd24:91bb:6122:1600::37` | **2 open ports** (22/SSH OpenSSH 4.7p1, 5432/PostgreSQL) | 1.52s | 95% (SSH), 65% (PostgreSQL); IPv4-only services cleanly isolated |
| **scanme.nmap.org** | IPv4 | `45.33.32.156` | **Port 22/SSH** (`OpenSSH 6.6.1p1`) | 1.51s | 95% confidence, 215ms WAN latency verification |
| **scanme.nmap.org** | IPv6 | `2600:3c01::f03c:91ff:fe18:bb2f` | **0 open** (All 5 ports filtered) | 1.50s | Cleanly detected missing WAN IPv6 routing with 0% false positives |

#### Differential Network Drift Analysis (`rayscan diff`)
Comparing the IPv4 baseline against the IPv6 scan using `rayscan diff`:
```text
Network State Differential Analysis (vs reports/metasploitable2-phase9-live.json):
────────────────────────────────────────────────────────────────────────────────
[-] GONE    192.168.100.37:21     ftp vsFTPd/2.3.4           (advisories +0 -1)
[-] GONE    192.168.100.37:22     ssh OpenSSH/4.7p1          (advisories +0 -1)
[-] GONE    192.168.100.37:80     http Apache/2.2.8          (advisories +0 -2)
... [16 ports shifted]
[+] NEW     fd24:91bb:6122:1600::37:22 ssh OpenSSH/4.7p1    (Confidence: 95%)
[+] NEW     fd24:91bb:6122:1600::37:5432                     (Confidence: 65%)

Diff Summary: 2 new | 16 closed/gone | 0 modified | 0 posture shifted (0 unchanged)
```
For the full technical breakdown, see [Empirical Comparative Analysis: IPv4 vs. IPv6 Network Scanning](reports/live-testing-metasploitable-and-scanme-ipv6.md).

## Live Permitted-Range Benchmark (v0.4.0)

Fresh same-day live measurements (2026-11-09) on ranges where scanning is
explicitly permitted, documented with raw outputs and per-run wall clocks in
[docs/bench-results.md](docs/bench-results.md) and verbatim artifacts in
[`bench-artifacts/`](bench-artifacts/). Nothing here is estimated.

### Ranges and permissions

| Range | Permission basis | Measured traffic |
| :--- | :--- | :--- |
| `127.0.0.0/24` loopback sweep | Own machine | 3 × rayscan full-range sweeps + 1 × nmap `-sT` reference |
| `172.22.64.1` (WSL2 NAT gateway, Windows host) | Own machine | Full cross-tool matrix: rayscan ×12, masscan ×4, rustscan ×3, nmap `-sS` ×1 |
| `45.33.32.156` (scanme.nmap.org) | Nmap's published permission banner ("authorized to scan this machine with Nmap or other port scanners") | Held to ≤3,000 pps, one full-range pass per tool |

### Results — own-machine NAT gateway (`172.22.64.1`, 65535 ports)

The Windows host answers SYN-ACK on exactly 6 of 65,535 ports
(80, 135, 139, 445, 2179, 49668; nmap `-sS -T4` ground truth at 87.4 s).

| Tool / mode | Wall (s) | 6-port accuracy |
| :--- | :--- | :--- |
| rayscan `--syn --connect-only`, unlimited | 1.58–1.61 | 6/6 ×3 |
| rayscan `--syn --connect-only`, 10k pps | 7.17–7.19 | 6/6 ×3 |
| rayscan `--syn` verified, unlimited | 2.58–2.93 | 2/6 (deliberately conservative: banner-less Windows services demoted) |
| masscan 100k pps | 5.44 | 6/6 |
| masscan 10k pps | 42.7–120+ (non-deterministic exit artifact) | 6/6 |
| rustscan TCP connect | 18.6–19.4 | 6/6 ×3 |
| nmap `-sS -T4` | 87.39 | 6/6 |

Rate caps are honored exactly after the AIMD hardening shipped in v0.4.0
(65,535 ports at 10k/2k/500 pps complete in 8.2/33.6/132 s — within 1.5% of
the ideal `ports/rate` curve).

### Results — loopback sweep (`127.0.0.0/24`, 65535 probes)

| Tool | Wall (s) | Result |
| :--- | :--- | :--- |
| rayscan `--syn --connect-only` /24 sweep | 35.3–40.5 ×3 | finds the real `127.0.0.53:53` (systemd-resolved) listener ×3 |
| nmap `-sT -T4` /24 sweep | >300 (timed out) | same listener, much slower |

### Results — scanme.nmap.org (authorized live target)

Measured sequence, all ≤3,000 pps (masscan/rayscan/nmap `-sS` raw legs and
TCP-connect legs):

1. Pre-test baseline HTTP fetch of `scanme.nmap.org` succeeded (the target was
   reachable).
2. Every raw-SYN leg (rayscan raw, masscan, nmap `-sS`) returned **zero
   responses from the internet through the WSL2 NAT** — the Hyper-V vSwitch
   does not map raw-crafted SYN/SYN-ACK flows; curl-style TCP connects work
   where raw SYN does not. This is the same environment property that made
   the `192.168.100.37` lab the right place for raw-SYN validation.
3. After the first parallel-capacity burst (nmap `-sS -T4` full range,
   rustscan `-b 3000`), the target's firewall rate-limited the test IP:
   subsequent curl/connect legs to `45.33.32.156:80` timed out from both the
   WSL guest **and** the Windows host, while general egress (example.com HTTP,
   8.8.8.8 ping) stayed healthy. All further scanme legs therefore measured
   empty, and all scanme traffic was stopped at that point.
4. After the rate-limit cleared (baseline HTTP fetch OK again), a single
   gentle re-verification leg was run: top-1000, ≤1,000 pps, one pass,
   TCP-connect engine (`--syn --connect-only`). rayscan completed with full
   classification in 3.9 s cold / 1.7 s warm — 22 and 80 open (2/2),
   998 correctly classified `closed`, **0 filtered/misclassified**, and the
   defense layer tagged the target `direct_host` with listener-verified
   evidence on both ports. The nmap `-sT -T3` reference needed 24.5 s for the
   same 2 opens (raw logs: `bench-artifacts/live/scanme_gentle_*.txt`).

### Comparison — LAN lab vs out-of-network authorized target

Against the documented Metasploitable 2 LAN suite (same engine), the
out-of-network authorized target behaves like this:

| Dimension | Metasploitable 2 (LAN lab, historical suite) | scanme.nmap.org (internet, gentle leg) |
| :--- | :--- | :--- |
| Open TCP surface | ~18 textbook services (FTP/SMTP/VNC/…) all banner-identified | exactly 2 (SSH :22, HTTP :80), no service banners grabbed in connect-only mode |
| Classification quality | full `open/closed` split over the whole range | full `open/closed` split over the whole range (998 closed, 0 errors) |
| Target behavior | everything answered, never varied | only observed ports answered; ~425–611 ms measured port latency vs ~1–3 ms in the lab |
| Defense layer | direct host | `direct_host` with standard semantics on every open port |
| Scan load the target survived | sustained full-rate bursts | rate-limited a high-parallelism burst (≈3k pps), then accepted a 2× gentle ≤1k-pps pass |
| Engine advantage | raw-SYN mode possible (unlimited rate) | connect engine only (WSL2 NAT raw-egress limitation), still `6-14×` faster than nmap `-sT` |

The engine gives the same accuracy class in both environments; what changes
off-LAN is transport (raw SYN unavailable through WSL2 NAT), latency
(~2 orders of magnitude), and the loading behavior of the far end — full
cycle results, environment caveats, and repro instructions live in
[docs/bench-results.md](docs/bench-results.md).

### Analysis

- **Where the SYN engine is intended to run, it wins on both axes tested:**
  full-range completed answers in 1.6 s with the same accuracy as masscan's
  SYN layer, and the verified mode trades runtime (2.6 s) for service
  classification instead of completeness; use `--connect-only` when the
  open/closed question is the goal.
- **Parallel-capacity engines can trip target rate limits even at 3k pps.**
  The scanme rate-limit event demonstrates the correct operational response:
  cap rates (`--rate`), limit full-range passes, and stop immediately when the
  target starts dropping everything. Future work: an adaptive
  target-politeness mode that detects mid-scan ICMP-error/tarpit behavior and
  paces down automatically.
- **Raw SYN egress through WSL2 NAT is fundamentally unavailable.** Internet
  raw SYN testing from this setup requires a Linux host/VM with a bridged
  NIC — the engine is correct (lab + NAT-gateway results), the transport
  environment is the limitation; this is documented rather than papered over.
- **masscan's capped-mode WSL2 exit artifact** (progress readout never exits)
  makes its 10k-pps wall here a lower-bound artifact; uncapped masscan
  (5.44 s) remains the fair reference, and rayscan is 3.4× faster at that
  effective rate in `--connect-only` mode.

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

### Offline CVE Advisory Correlation (`--advisories` & `rayscan db`)

`rayscan` correlates detected service identity (product, version, and banner context) against two offline sources:

1. A small bundled curated database (`data/advisories.json`) with hand-verified version and banner gates.
2. A local NVD mirror built from the official CVE 2.0 feeds, covering CVEs from 1999 through the current year (401,682 CVEs / 325,837 product mappings as of November 2026).

Correlation is advisory only: it never sends extra probes, and findings must be confirmed against current vendor advisories.

- Severity is derived from CVSS (Critical >= 9.0, High >= 7.0, Medium >= 4.0).
- Version rules support exact, upper-bound, range, and all-version matches, so patched releases are not flagged.
- Curated banner gates prevent ambiguous matches (for example the Debian OpenSSL PRNG issue only matches Debian/Ubuntu SSH banners).
- NVD matches are extracted from CPE configurations and inherit NVD data quality: records marked as affecting all versions can produce legacy false positives, and new CVEs that only have CNA-supplied data are indexed but not correlated until NVD publishes CPE configurations.

```bash
# One-time full sync (all yearly feeds, 2002-2026) plus the rolling recent feed:
rayscan db update

# Faster initial subsets, forced re-downloads, and coverage/status inspection:
rayscan db update --years 2024-2026
rayscan db update --years 2024,2025 --force
rayscan db status
rayscan db status --json

# Correlate detected service versions against curated + local NVD data:
rayscan scan --target 192.168.100.37 --advisories

# Disable the automatic recent-feed check for isolated or offline scans:
rayscan scan --target 192.168.100.37 --advisories --no-db-update

# Download and index the full CISA KEV and EPSS feeds (24-hour cache):
rayscan db intel
rayscan db intel --force --json
```

`rayscan db intel` downloads the complete CISA Known Exploited Vulnerabilities
catalog and the current EPSS CSV, merges them with the bundled fallback set, and
writes an atomic gzip index to `<db>/intel/threat_intel.json.gz`. Advisory scans
overlay that cache automatically. Use `--force` to bypass the 24-hour freshness
window, for example in a scheduled intelligence refresh. A live refresh on
2026-11-09 indexed 1,775 KEV CVEs and 402,199 EPSS-scored CVEs.

Once initialized, every scan performs a lightweight check of the NVD `recent` feed and applies new or changed CVEs automatically (a few seconds when nothing changed). A full sync must be run manually once to bootstrap the database; without it, scans use only the bundled curated database and print a hint when `--advisories` is requested. Update failures never fail the scan.

The database lives in a user-writable data directory, resolved in this order: `--db-dir <DIR>`, `RAYSCAN_DB_DIR`, then `%APPDATA%\rayscan\db` on Windows or `$XDG_DATA_HOME/rayscan/db` (`~/.local/share/rayscan/db`) elsewhere. A full mirror is roughly 275 MB and grows over time; yearly feeds and 256-way product shards keep lookups fast, and a lock file prevents concurrent updates.

```text
Vulnerability Advisory Correlation:
──────────────────────────────────────────────────────────────────────
  192.168.100.37:21/tcp (ftp vsFTPd/2.3.4)
    [CRITICAL] CVE-2011-2523  CVSS 10.0  vsftpd 2.3.4 backdoor command execution
    [HIGH] CVE-2021-3618  CVSS 7.4  ALPACA is an application layer protocol content confusion attack...
  192.168.100.37:22/tcp (ssh OpenSSH/4.7p1)
    [HIGH] CVE-2008-0166  CVSS 7.8  Debian OpenSSL PRNG flaw enables weak SSH keys
    [CRITICAL] CVE-2023-38408  CVSS 9.8  The PKCS#11 feature in ssh-agent...
    ...
    ... and 61 more (see JSON output for the full list)
  192.168.100.37:80/tcp (http Apache/2.2.8)
    [HIGH] CVE-2011-3192  CVSS 7.8  Apache Range header memory-exhaustion denial of service
    [MEDIUM] CVE-2007-6750  CVSS 5.0  Apache Slowloris partial-request denial of service
    [CRITICAL] CVE-2009-3555  CVSS 9.8  The TLS protocol...
    ...
    ... and 91 more (see JSON output for the full list)

  175 advisory match(es) across 3 open service(s); offline CVE correlation (curated + local NVD database) — verify against vendor advisories.
```

The table renderer adds an `ADVISORIES` column summarizing the highest-ranked match per port, `--explain` includes an `Advisory Matches:` breakdown, and JSON/JSONL results include an `advisories` array on each port object. Each match carries a `source` of `curated` or `nvd`. Human-readable sections show at most 10 matches per service; JSON/JSONL always contains the full list. Curated matches are listed first (they carry hand-verified version and banner gates), followed by NVD matches; each group is sorted by severity. When both sources report the same CVE, the curated entry is kept.

### CISA KEV & EPSS Threat Prioritization (`--kev-only` & `--min-epss`)

In fast-paced penetration tests and bug bounty engagements on platforms like HackerOne or Bugcrowd, CVSS score alone is insufficient for triage: an informational or medium vulnerability with an active weaponized exploit in the wild often poses greater immediate risk than an unexploited critical flaw.

`rayscan` enriches advisory correlation with two operational threat intelligence feeds:
1. **CISA Known Exploited Vulnerabilities (KEV)**: Actively weaponized vulnerabilities confirmed by CISA to be exploited in the wild. Flagged with a prominent `[KEV]` badge in terminal tables, explain output, markdown, and JSON.
2. **FIRST.org Exploit Prediction Scoring System (EPSS)**: Probability score ($0.0$ to $1.0$, rendered as $0.0\%$ to $100.0\%$) estimating the likelihood of exploitation activity within 30 days.

```bash
# Filter advisory findings to only services with confirmed CISA KEV exploits:
rayscan scan --target 192.168.100.37 --kev-only

# Filter for vulnerabilities with high exploitation probability (EPSS >= 50%):
rayscan scan --target 192.168.100.37 --min-epss 0.50

# Combine KEV filter with Markdown executive reporting:
rayscan scan --target 192.168.100.37 --kev-only --format markdown -o report.md
```

### Scope Guard Boundary Protection (`--scope` & `--force-out-of-scope`)

The primary legal and operational hazard in authorized penetration testing and bug bounty engagements is scanning outside the agreed perimeter. `rayscan` includes a dedicated **Scope Guard Engine** (`src/scope.rs`) that enforces target boundaries before any probe packet leaves the host.

A scope file (`scope.toml` or line-based target list) defines allowed and denied CIDRs, IP ranges, and wildcard domains:

```toml
[scope]
program = "HackerOne - Target Engagement"
allow = [
    "*.example.com",
    "10.0.0.0/8",
    "172.16.1.1-172.16.1.50",
    "2001:db8::/32",
]
deny = [
    "admin.example.com",
    "10.0.5.1",
]
```

```bash
# Safe scan guarded by engagement scope:
rayscan scan --target api.example.com --scope scope.toml

# Scanning an out-of-scope target fails immediately with a legal violation error:
rayscan scan --target out-of-scope.net --scope scope.toml
# Error: SCOPE VIOLATION: Target 'out-of-scope.net' is NOT in the authorized scope for program 'HackerOne - Target Engagement'. Scan aborted for legal safety.

# Explicitly override scope enforcement with auditable warnings:
rayscan scan --target out-of-scope.net --scope scope.toml --force-out-of-scope
```

`--target-file` and `@file` contents are expanded before scope validation, so a
denied domain cannot bypass the guard by being placed in a file. Domain allow
rules authorize the addresses that the domain resolves to, while explicit IP,
CIDR, and range targets must independently match an IP allow rule. Deny rules
always win, including when a domain resolves to a denied address.

### Real-Time Streaming Output for Offensive Pipelines (`--stream`)

When orchestrating toolchains in bug bounty reconnaissance (such as piping rayscan outputs directly into downstream fuzzers, directory bruteforcers, or parameter analyzers like `H1Hunter`, `ParamOracle`, or `Shadow Octopus`), waiting for a full 65,535-port scan to terminate creates unnecessary pipeline latency.

Passing `--stream` writes verified open port findings line-by-line as unbuffered JSONL directly to `stdout`:

```bash
# Stream verified open ports in real-time to jq or Unix pipelines:
rayscan scan --target 192.168.100.37 -p 1-65535 --stream | jq -c '{port: .port, service: .service.name}'

# Pipe discovered web endpoints into curl or HTTP fuzzing tools immediately:
rayscan scan --target 192.168.100.37 --stream | while read -r line; do
    PORT=$(echo "$line" | jq -r '.port')
    echo "[+] Pipeline triggered for port $PORT immediately"
done
```

Streamed records are emitted as soon as the scan stage verifies a port and
include the banner/service metadata collected at that point. TLS inspection,
plugin matches, advisory correlation, KEV/EPSS filters, and diff data run after
the scan and are not backfilled into streamed lines; use the final JSON/report
output when those fields are required.

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
    --save-baseline /var/log/rayscan/baseline.json --json -o monday.json

# Day 2 (Tuesday): Run daily audit, write a change alert, and fail CI on any drift:
sudo rayscan scan --syn --os --target 192.168.100.0/24 --top-ports 100 \
    --diff /var/log/rayscan/baseline.json \
    --alert-file /var/log/rayscan/alert.txt --fail-on-change \
    --json -o /var/log/rayscan/tuesday.json

# Offline Investigation: Perform offline differential comparison between any historical scans:
rayscan diff /var/log/rayscan/baseline.json /var/log/rayscan/tuesday.json

# CI/CD: the same check in one command, no jq required (exit 0 = no change, 1 = drift):
rayscan diff /var/log/rayscan/baseline.json /var/log/rayscan/tuesday.json \
    --alert-file /var/log/rayscan/alert.txt --fail-on-change
```

`--alert-file` writes a compact, timestamp-free alert on every run
(`status: no changes` or `status: changes detected` plus one line per change),
so it can be tailed, shipped to a SIEM, or sent as a webhook payload. Update
the baseline only after accepting the drift: `--save-baseline` writes the JSON
report of the current run in the same format `--diff` consumes.

### Feeding Other Tools (`--format host-port`, `--exclude-ports`)

```bash
# Pipe open ports straight into httpx for probing/title/tech detection:
sudo rayscan scan -t 10.0.0.0/24 -p 1-65535 --syn --connect-only --quiet \
    --format host-port | httpx -silent -td -title -tech-detect -json -o web.json

# Full chain: rayscan discovery → httpx live URLs → nuclei templates:
sudo rayscan scan -t 10.0.0.0/24 -p 1-65535 --syn --connect-only --quiet \
    --format host-port | httpx -silent \
    | nuclei -silent -severity critical,high -o findings.txt

# Service-aware filtering with jq before handing off to web tooling:
sudo rayscan scan -t 10.0.0.0/24 -p 1-65535 --syn --format json --quiet \
    | jq -r '.open[] | select(.service.product == "Jenkins" or .service.name == "http")
             | "\(.host):\(.port)"' | httpx -silent

# Keep noisy corporate ports out of a large engagement scan:
sudo rayscan scan -t 10.0.0.0/24 -p 1-65535 --exclude-ports 445,3389,5985-5986

# Machine-consumable JSON lines for custom ingest scripts:
rayscan scan -t 10.0.0.0/24 --top-ports 1000 --format jsonl --quiet

# Streaming variant: verify so service metadata is attached, stream as JSONL:
rayscan scan -t 10.0.0.0/24 --top-ports 1000 --stream \
    | jq -c 'select(.service.product) | {host, port, product: .service.product,
              version: .service.version, confidence: .service.confidence}'
```

Existing target-list input (`--target-file`), exclusion (`--exclude`),
sharding (`--shard-index`/`--shard-count`), and resume (`--save-state` /
`--resume`) work unchanged in these pipelines; `--exclude-ports` accepts the
same list/range syntax as `--ports`.

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

### Distributed Sharding & Merge

Large target sets can be split deterministically across workers or machines with
stable FNV-1a placement. Every target lands in exactly one shard; shuffled input
order still produces the same partition.

```bash
# Four parallel shards, each writing a JSON report:
for i in 0 1 2 3; do
  rayscan scan -t 10.0.0.0/16 -p 1-65535 --shard-index "$i" --shard-count 4 \
    --json -o "shard-$i.json"
done

# Merge reports (JSON or JSONL); open results win, advisories are unioned:
rayscan merge shard-0.json shard-1.json shard-2.json shard-3.json -o merged.json

# Merge JSONL shards into JSONL:
rayscan merge --jsonl shard-0.jsonl shard-1.jsonl -o merged.jsonl
```

`--shard-index` and `--shard-count` must be supplied together; the count ranges
from 1 to 1024. Resume/progress state is per shard, so each parallel invocation
must use its own `--save-state` file.

### Ping Sweep, ARP, and IPv6 Discovery (ARP & ICMP & NDP)

Reachability can be checked before the port scan. On Linux, IPv4 uses raw ICMP
echo where permitted and falls back to TCP connects. For IPv6, `rayscan` supports
native raw ICMPv6 echo probes (RFC 4443 Type 128/129) and **Neighbor Discovery
Protocol (NDP)** multicast probing (`ff02::1` all-nodes) combined with the Linux
neighbor table (`ip -6 neigh` / `/proc/net/ndisc_cache`) and verified host routes.
With `--ndp`, broad CIDRs such as `fe80::/64` are expanded to the active
neighbors instead of 18 quintillion addresses. Link-local results automatically
carry the interface scope ID through connect, TLS, UDP, plugin, and verification
probes. Discovery is Linux-only, requires raw ICMPv6 privileges, and waits up to
`--ndp-timeout-ms` (default 750 ms). Connection refusals still prove the host is
alive.

IPv4 targets in `--ping-sweep` are additionally checked with an **ARP who-has
liveness probe** before ICMP/TCP: on Linux, raw `AF_PACKET` ARP requests are
sent for **directly connected routes only** (the gateway is never asked for, so
its replies cannot count as liveness); on Windows, the `SendARP` helper API is
used. This closes the largest platform gap: hosts that drop ICMP and filter all
TCP-ping ports (embedded devices, TVs, IoT appliances with stateful DROP
firewalls) are now discovered on Windows, where raw ICMP is unavailable. Each
raw ICMP sweep also derives a unique per-host echo identifier so concurrent
probes never collide on `(id, sequence)`.

```bash
# Three echo attempts, 750 ms each, then scan only responsive hosts:
sudo rayscan scan -t 10.0.0.0/24 -p 22,80,443 --ping-sweep \
  --ping-count 3 --ping-timeout-ms 750

# Discover active hosts in a /64 with NDP, then scan their services:
sudo rayscan scan -6 -t fe80::/64 --ndp --ndp-timeout-ms 750 -p 22,80,443

# Native ICMPv6 / TCP ping sweep for an explicit IPv6 target:
rayscan scan -6 -t fd24:91bb:6122:1600::37 -p 22,80,443 --ping-sweep
```

NDP does not create a route to the public internet: a network without IPv6
upstream connectivity can resolve AAAA records but cannot scan public IPv6
targets.

`--discover-only` remains a separate mode that reports open ports without
waiting for service banners.

### Service & Version Detection (HTTP panels, native probes, confidence)

Detection combines the passive banner with one light, protocol-shaped probe on
ports that never speak first. Probes are bounded, sent only after the initial
grace read, and never retried beyond the scan timeout:

| Port | Probe | Extracted identity |
| :--- | :--- | :--- |
| any | `GET / HTTP/1.0` (only if no banner) | HTTP status + headers + first ~1 KB of body |
| 445 | SMB2 NEGOTIATE (dialects 2.0.2–3.0.2), SMB1 fallback | `SMB 3.0.2`, `SMBv1`, … |
| 27017 | MongoDB legacy `buildInfo` | `MongoDB` + server version |
| 6379 | Redis `INFO server` | `Redis` + `redis_version` |
| 11211 | memcached `stats` | `memcached` + version |
| 3389 | X.224 negotiation + TLS CredSSP NTLM probe | `RDP`, negotiated protocol, NLA computer/domain, Windows build |

RDP never sends an unsolicited banner. Silent results on 3389 are retained and
promoted to `open` when the NLA identity succeeds, and JSON output gains an
`rdp` object (`protocol`, `computer_name`, `domain`, `os_version`, `product`).

HTTP identification prefers explicit application headers and login-page
fingerprints over the generic `Server` token:

- Headers: `Server`, `X-Powered-By`, `X-Jenkins`, `kbn-name`/`kbn-version`,
  `X-Elastic-Product`, `Docker-Distribution-Api-Version`.
- Panels: Jenkins, Kibana, Elasticsearch, OpenSearch, Grafana, Apache Tomcat,
  phpMyAdmin, Adminer, Webmin, Zabbix, Prometheus, Portainer, SonarQube,
  Kubernetes Dashboard, Argo CD, RabbitMQ Management, Nexus, GitLab, MinIO,
  Rancher, Proxmox VE, pfSense, OpenWrt LuCI, WebLogic, WebSphere, Jira,
  Confluence.
- Protocols: SSH implementation/version (OpenSSH, Dropbear, libssh, Win32-OpenSSH,
  Cisco, …), MySQL/MariaDB, PostgreSQL, Redis, memcached, MongoDB, FTP, SMTP,
  VNC, SMB, RDP, and TLS.

Each `service` object in JSON/JSONL now carries an identification
`confidence`: `0.98` when a version was parsed, `0.85` when only a product was
identified, and `0.70` for a bare protocol name.

```json
{
  "host": "10.0.0.5",
  "port": 8080,
  "state": "open",
  "banner": "HTTP/1.1 200 OK",
  "service": {
    "name": "http",
    "product": "Jenkins",
    "version": "2.426.1",
    "confidence": 0.98
  }
}
```

### Declarative Probe Packs (`--plugins`)

Custom service probes can be supplied as a TOML pack without recompiling. The
pack is loaded only when explicitly requested with `--plugins FILE`; nothing is
auto-discovered from the working directory. Active probes are capped at 4 KB,
a pack at 256 KB, regexes at 512 characters, and only open TCP results are
annotated. The first matching probe wins and adds
`plugin:<pack>/<probe>` evidence.

```toml
# probes.toml — one pack per file
name = "example"
description = "Example appliance probes"

[[probe]]
name = "acme-admin"
service = "acme-admin"
ports = [9000]
product = "Acme Appliance"
send = "GET /status HTTP/1.1\r\nHost: target\r\n\r\n"
expect_regex = "ACME Admin"
version_regex = "Version: ([0-9.]+)"
```

```bash
rayscan scan -t 10.0.0.5 -p 9000 --plugins probes.toml --explain 9000
```

### TLS Certificate Inspection (`--tls` / `--no-tls`)

Open TCP endpoints are inspected automatically on known direct-TLS and
STARTTLS ports, on non-standard ports whose banner already looks like TLS, and
on services that could not be identified at all. `--tls` forces a direct TLS
handshake on every open TCP port; `--no-tls` disables the stage entirely. TLS
runs before plugin matching, accuracy scoring, and advisory correlation.

Direct ports: `443`, `8443`, `9443`, `993`, `995`, `465`, `636`, `990`, `5986`,
`2376`, `8883`, `5061`. STARTTLS ports: FTP `21`, SMTP `25`/`587`, POP3 `110`,
IMAP `143`.

Direct TLS sessions also issue a bounded `GET` over the encrypted channel, so
HTTPS application fingerprints (Jenkins, Kibana, Grafana, Elasticsearch, …)
surface on arbitrary ports as `service.name = "https"`. Endpoints that reset
the plaintext HTTP probe but complete a TLS handshake are promoted from
`closed` to `open` instead of being lost.

```bash
rayscan scan -t 10.0.0.5 -p 443,8443 --tls --json
rayscan scan -t 10.0.0.5 -p 443 --no-tls
```

The JSON port object gains a `tls` object containing `version`, `cipher`,
`subject`, `issuer`, `san`, `serial`, `not_before`, `not_after`,
`days_remaining`, `expired`, `not_yet_valid`, `self_signed`,
`hostname_matches`, `chain_len`, and optional `starttls`. The certificate is
captured even when it is self-signed, expired, or does not match the target;
these conditions are reported as fields rather than treated as handshake
failures.

### IPv6 Raw SYN and OS Fingerprinting

`--syn --os` now covers both address families when run as root on Linux. IPv4
continues to use `AF_PACKET` with BPF filtering; IPv6 uses `AF_INET6` raw
sockets so the kernel handles routing and neighbour discovery. SYN cookies bind
the full 128-bit address. IPv6 OS fingerprints use the SYN-ACK hop limit,
window, and TCP options.

```bash
sudo rayscan scan -6 -t 2001:db8::10 -p 1-1024 --syn --os
sudo rayscan scan -6 -t ::1 -p 80,443 --syn --format json
```

Decoys and IPv4 fragmentation remain IPv4-only. Mixed IPv4/IPv6 target sets are
partitioned automatically and merged into one report.

### Stealth, Jitter, Decoys, and Fragmentation

```bash
# 0-250 ms random delay before probes:
sudo rayscan scan -t 10.0.0.5 -p 1-1024 --syn --jitter-ms 250

# Add up to eight IPv4 decoy source addresses:
sudo rayscan scan -t 10.0.0.5 -p 1-1024 --syn --decoys 10.0.0.101,10.0.0.102

# Split IPv4 SYN probes into 8-byte-aligned fragments:
sudo rayscan scan -t 10.0.0.5 -p 80,443 --syn --fragment-size 8
```

The `stealth` profile defaults to 50 ms jitter in addition to its 20 pps rate
limit, eight workers, and three retries. Decoys and fragmentation require
`--syn`; decoy source ports are chosen outside the configured source-port range.

### Output formats

| Format | Flag | Description |
| :--- | :--- | :--- |
| `table` | (default) | Human-readable aligned table with optional OS column |
| `json` | `--json` / `--format json` | Structured JSON (benchmark-compatible) |
| `jsonl` | `--format jsonl` | One JSON object per line (NDJSON) |
| `csv` | `--format csv` | Comma-separated values |
| `host-port` | `--format host-port` | Plain `host:port` list, one open port per line, for pipeline chaining |
| `nmap-xml` | `--format nmap-xml` | Nmap-compatible XML (Metasploit, nmap-parse-output) |
| `greppable` | `--format greppable` | Nmap `-oG` style, one line per host |
| `sarif` | `--format sarif` | SARIF 2.1.0 rules/results for code-scanning and vulnerability dashboards |
| `markdown` | `--format markdown` | Summary, services, advisories, TLS, OS, defense, and diff tables | 

SARIF output creates one rule per advisory ID and one result per affected
host/port, with CVSS/severity properties and a `tcp://host:port` artifact URI.
Markdown output is designed for tickets and pull requests. Both formats include
the full advisory list regardless of the table truncation limit.

```bash
rayscan scan -t 10.0.0.5 -p 1-1024 --advisories --format sarif -o rayscan.sarif
rayscan scan -t 10.0.0.5 -p 1-1024 --advisories --format markdown -o report.md
```

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
not retry already-probed ports and works for multiple targets: per-host
progress is tracked (`hosts` entries in the state file), so each target keeps
its own completed-port set and counts. Single-target scans saved by older
versions resume unchanged; when resumed against the same host set, results for
hosts no longer being scanned are preserved in the merged report. Raw SYN
mode (`--syn`) still requires a single target for resumable scans.

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
plugins = "probes.toml"  # optional declarative probe pack
jitter_ms = 50           # optional random delay before each probe
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

Output formats are `table` (default), `json`, `jsonl`, `csv`, `host-port`,
`nmap-xml`, `greppable`, `sarif`, and `markdown`. Use `--json` as the
benchmark-compatible alias for `--format json`.
Progress is written to stderr; JSON on stdout stays clean. Use `--output FILE`
to write to a file instead of stdout, and `--quiet` to suppress progress and
status messages.

The benchmark JSON contract is in
[`docs/benchmark-contract.md`](docs/benchmark-contract.md). Exit status is `0`
for a completed scan, `1` for a runtime failure, and `2` for invalid arguments
or configuration. With `--fail-on-change`/`diff --fail-on-change`, a completed
run that detected changes exits `1` as a deliberate status (no diagnostic is
printed); a clean run exits `0`.

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
benchmark-harness tests, plus separate `cargo audit` and `cargo deny`
jobs. Release archives are built by `.github/workflows/release.yml`, which can
optionally GPG- or cosign-sign `SHA256SUMS` through repository secrets.

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
- Beyond Phase 8: empirical accuracy scoring, defense-aware middlebox
  classification, advisory correlation with an offline NVD mirror, differential
  auditing (`--diff`), smart resume audit, ping sweep, declarative probe packs,
  TLS/STARTTLS certificate inspection, IPv6 raw SYN and OS fingerprinting,
  target sharding and report merging, lightweight stealth shaping, SARIF and
  Markdown reporting, and supply-chain tooling. Complete in `0.3.0`; see
  [Phase 9 feature gate](docs/phase9-features.md).

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
src/syn/v6.rs               AF_INET6 raw IPv6 SYN engine
src/syn/aimd.rs             AIMD rate controller for the TX loop
src/tls.rs                  direct/STARTTLS certificate inspection
src/plugin.rs               declarative TOML probe packs
src/discovery.rs            ICMP/TCP ping sweep
src/shard.rs                stable FNV-1a target sharding
src/merge.rs                JSON/JSONL shard report merger
src/verify.rs               connect verification and reclassification of SYN opens
src/anomaly.rs              anomaly detection for hosts with large SYN-open counts
src/classify.rs             error taxonomy
src/rtt.rs                  RFC 6298 per-host estimator
src/rate.rs                 global token bucket
src/limits.rs               target/worker bounds and RLIMIT handling
src/output.rs               table/JSON/JSONL/CSV/NmapXml/Greppable/SARIF/Markdown rendering
src/fingerprint.rs          OS fingerprinting via TCP/IP stack analysis
src/bin/gen_man.rs          man page generator (cargo run --bin gen_man)
man/rayscan.1               generated man page
Dockerfile                  multi-stage musl build → scratch image
deny.toml                   cargo-deny license/advisory/source policy
fuzz/                       cargo-fuzz targets for parsers and service detection
scripts/sign-release.sh     optional GPG/cosign release signing
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
docs/phase9-features.md     Phase 9 feature gate and live validations
```

## Author & Maintainer

- **Author & Project Lead:** vulnquest58 ([@vulnquest58](https://github.com/vulnquest58))
- **GitHub Repository:** [https://github.com/vulnquest58/rayscan](https://github.com/vulnquest58/rayscan)

## Legal and ethical use

Scan only systems you own or have written authorization to test. The lab is
isolated by design; keep it that way. The scanner has no default public targets,
uses a bounded worker pool and rate limit, and does not pretend that a TCP
handshake proves application exploitability.
