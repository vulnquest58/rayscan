# Changelog

All notable changes to rayscan are documented here.

## [Unreleased]

## [0.5.0] - 2026-11-13

### Added

- **Port presets** (`--preset <PRESET>`): curated engagement port sets with
  `dc|ad`, `win|ws`, `web|http`, `linux|lx`, `full|all`, and `q|top` (nmap
  top-1000 frequency table) presets. `--preset` conflicts with `--ports` and
  `--top-ports`. Presets expand to explicit port lists for save/resume state
  compatibility.
- **Independent connect timeout** (`--connect-timeout-ms`): per-connect
  timeout ceiling in milliseconds that overrides `--timeout` seconds.
- **Adaptive rate control** (`--rate-auto`): connect-scan rate controller
  halves the rate when >25% of probes time out in a 500-probe window and
  increases by 25% when <5% time out, clamped by a floor and ceiling.
- **Windows OS role refinement**: inferred `OsRole` from open service ports
  (Domain Controller / Member Server / Workstation) and emitted in table/JSON
  outputs and `OsGuess`.
- **`--compare` alias** for `--diff` (visible alias `compare-to` retained).
- **ARP host-discovery sweep** (`src/discovery.rs`): IPv4 targets in
  `--ping-sweep` are now probed with an ARP who-has liveness check before
  ICMP/TCP. Linux sends raw `AF_PACKET` ARP requests for **directly connected
  routes only** (reusing the SYN engine's route/ARP machinery; the gateway is
  never probed, so its replies cannot count as liveness). Windows uses the
  `SendARP` helper API from iphlpapi. This closes the largest platform gap in
  host discovery: hosts that drop ICMP and filter every TCP-ping port
  (embedded devices, TVs, IoT appliances) were previously undiscoverable on
  Windows, where raw ICMP is unavailable. Live-verified: a webOS smart TV that
  answers no ping port is now found via `--ping-sweep` on Windows.
- **UDP probes for SSDP (1900) and mDNS (5353)** (`src/udp.rs`): an M-SEARCH
  `ssdp:all` request and a `_services._dns-sd._udp.local` PTR enumeration
  query, with response classifiers (SSDP `ST:`/`Server:`/`Location:` header
  extraction; mDNS responses are classified as `mdns` instead of `dns`).
  These surface UPnP routers and IoT/Bonjour devices on LAN sweeps.
- **ICMP echo id hardening** (`src/discovery.rs`): each raw ICMP/ICMPv6 sweep
  now derives a per-target echo identifier from `(pid ^ target)`, so
  concurrent probes can never collide on `(id, sequence)` if the kernel
  multiplexes replies across raw sockets.
- **`--format port-list`** (aliases `ports`/`portlist`): comma-separated open
  port numbers only, ready to paste into `-p` of any tool. Entries are sorted
  and de-duplicated (audit RSC-BUG-003). When no `--ports`/`--top-ports` is
  given, this discovery format sweeps the full TCP range (1-65535) and includes
  handshake-completed silent listeners by default, so a fresh target can be
  enumerated in one command and the resulting list used for a deeper
  second-stage scan; other formats keep the 1-1024 / open-only defaults.

### Fixed

- **Post-handshake resets no longer classify open ports as closed** (audit
  RSC-BUG-001): verification only runs after a successful TCP connect, so a
  reset/abort/broken-pipe reported there proves the port accepted the
  connection. SYN-proxy-protected hosts previously produced ~32% false
  negatives on live HTB targets.
- **Machine-readable formats auto-quiet** (audit RSC-BUG-002 / PROPOSAL-001):
  `[tls]`, `[rdp]`, `[os]` and plugin progress lines are suppressed
  automatically for every non-human format (`port-list`, `json`, `jsonl`,
  `csv`, `nmap-xml`, `greppable`, `sarif`, `host-port`) — `--quiet` is no
  longer required for clean pipeline output. All progress writes remain on
  stderr.
- **Defense intelligence never contaminates machine formats** (audit
  RSC-BUG-004): defense blocks render only for table output; `port-list` and
  other machine formats emit results only, even with `--defense` set.

### Tests

- Regression coverage for the v0.4.0 audit: reset-after-handshake and
  accept-then-close classified `Open` (RSC-BUG-001), port-list dedup
  (RSC-BUG-003), pure `--format port-list` stdout with `--tls --os --defense`
  and no progress on stderr (RSC-BUG-002/004, PROPOSAL-001), and
  machine-format classification.

### Deferred (roadmap)

- ACK scan (`--ack`) with an `unfiltered` port state in the SYN engine to
  distinguish stateful-DROP filtering from reachable-but-unfiltered hosts.
- Raw SYN scanning on Windows via an Npcap packet path.

## [0.4.0] - 2026-11-11

### Added

- **Pipeline-ready output and exit codes**: `--format host-port` (alias
  `hostport`/`plain`) emits one `host:port` per open port for direct chaining
  into httpx/nuclei-style tools (IPv6 bracketed). `--exclude-ports` accepts the
  same list/range syntax as `--ports` and applies to resumed scans too.
  `--fail-on-change` on `scan --diff` and on the standalone `diff` subcommand
  exits `1` when new/gone/modified ports or posture shifts are detected, while
  a clean run exits `0` (no diagnostic printed on the status path). Exit codes
  remain `0`/`1`/`2` for success/runtime failure/usage otherwise.
- **Baseline and alert workflow**: `--save-baseline FILE` writes the current
  run as a JSON baseline in the exact format `--diff` consumes.
  `--alert-file FILE` (scan and `diff`) writes a compact, timestamp-free alert
  on every run — `status: no changes` or `status: changes detected` with one
  line per change — suitable for log shipping or a future webhook bridge.
- **Expanded service and version detection**:
  - HTTP now sends `GET` instead of `HEAD`, identifies products from
    `Server`, `X-Powered-By`, `X-Jenkins`, `kbn-name`/`kbn-version`,
    `X-Elastic-Product`, and `Docker-Distribution-Api-Version`, and fingerprints
    common Bug Bounty web surfaces from login/dashboard pages (Jenkins, Kibana,
    Elasticsearch/OpenSearch, Grafana, Apache Tomcat, phpMyAdmin, Adminer,
    Webmin, Zabbix, Prometheus, Portainer, SonarQube, Kubernetes Dashboard,
    Argo CD, RabbitMQ Management, Nexus, GitLab, MinIO, Rancher, Proxmox VE,
    pfSense, OpenWrt LuCI, WebLogic, WebSphere, Jira, Confluence).
  - Native probes now run before the HTTP probe on their ports: SMB2 NEGOTIATE
    with SMB1 fallback (dialect reported, e.g. `SMB 3.0.2`), MongoDB legacy
    `buildInfo` (server version), Redis `INFO server` (`redis_version`), and
    memcached `stats` (version). The previous MongoDB probe used an invalid
    opcode and is replaced by a correctly framed OP_QUERY.
  - SSH parsing recognizes OpenSSH, Dropbear, libssh, Win32-OpenSSH, Cisco,
    Paramiko, AsyncSSH, PuTTY, and SunSSH.
  - RDP identity: X.224 connection negotiation followed by a TLS CredSSP NTLM
    probe recovers the negotiated security protocol (`HYBRID_EX`, `HYBRID`,
    `SSL`, …), NLA computer/domain names, and the Windows build, mapped to a
    product such as `Windows 10 / Server 2019`. Silent RDP ports are retained
    and promoted to `open`, and JSON results gain an `rdp` object.
  - `service` objects now include an identification `confidence` (`0.98` with
    version, `0.85` with product, `0.70` with protocol name only) for JSON/JSONL
    pipelines and `jq` filtering.
- **TLS auto-inspection on non-standard ports**: in the default `Auto` mode,
  an open port whose banner already looks like TLS — or whose service could not
  be identified at all — is now inspected for certificate/version/cipher
  metadata instead of being limited to the well-known TLS port list. HTTP and
  other identified services are skipped as before.
- **HTTPS application fingerprints**: after a direct TLS handshake, a bounded
  decrypted `GET` reuses the HTTP fingerprint database, so Jenkins, Kibana,
  Grafana, Elasticsearch, and other products are reported as
  `service.name = "https"` with product/version on arbitrary ports. Ports that
  complete a TCP handshake but reset the plaintext probe are retained for TLS
  inspection and promoted from `closed` to `open` when the handshake succeeds.

- **Multi-target resume**: `--resume`/`--save-state` no longer require a single
  target. Per-host progress is tracked in the state file (`hosts` entries with
  each target's probed ports and state counts), so an interrupted multi-target
  scan resumes by scanning only each host's remaining ports. Merged reports add
  prior results/counts without duplication, and resuming a complete state
  finishes instantly with no probes. Single-target states saved by earlier
  versions resume unchanged; resuming them against a different host set keeps
  prior results only for hosts outside the new scan. Raw SYN mode
  (`--syn`) remains single-target for resumable scans.

- **Scope Guard Engine** (`--scope FILE`, `--force-out-of-scope`, `src/scope.rs`):
  Enforces legal and operational engagement boundaries for bug bounty hunters
  (e.g., HackerOne, Bugcrowd) and offensive security teams. Supports structured
  `scope.toml` or line-based target lists with CIDRs, IPv4 ranges, and wildcard
  domains (`*.example.com`). Explicit deny rules override allowlists, and
  unauthorized targets are rejected before packets are sent unless overridden
  with `--force-out-of-scope`. Target-file contents are expanded before
  validation, domain allow rules authorize the addresses they resolve to, and
  explicit IP/CIDR targets are checked against IP allowlists independently.
- **CISA KEV & EPSS Threat Prioritization** (`--kev-only`, `--min-epss SCORE`,
  `rayscan db intel`, `src/advisory.rs`, `src/intel.rs`, `data/cisa_kev.json`):
  Correlates open services against the CISA Known Exploited Vulnerabilities
  catalog and FIRST.org Exploit Prediction Scoring System (EPSS). Services with
  active weaponized exploitation in the wild are highlighted with bold `[KEV]`
  badges and probability metrics in table, markdown, JSON, and SARIF outputs.
  Hunters can filter directly for exploitable targets via `--kev-only` and `--min-epss`.
  `rayscan db intel [--force] [--json]` downloads the complete CISA KEV catalog
  and current EPSS CSV, merges them with the bundled fallback set, and atomically
  caches a gzip index under `<db>/intel/threat_intel.json.gz` with a 24-hour
  freshness window. Cached indicators are overlaid automatically for advisory
  scans.
- **Real-Time Streaming Output** (`--stream`, `src/lib.rs`, `src/output.rs`):
  Streams verified port findings line-by-line as unbuffered JSONL directly to
  `stdout`. Allows downstream pipeline tools (H1Hunter, ParamOracle, Shadow Octopus)
  to consume findings asynchronously without waiting for the full scan to finish.
  Post-scan TLS, plugin, and advisory enrichment is not backfilled into streamed
  records; use the final report when those fields are required.
- **IPv6 Neighbor Discovery Protocol (NDP) & ICMPv6 Sweep** (`--ndp`,
  `--ndp-timeout-ms`, `src/discovery.rs`, `src/targets.rs`):
  Expands broad IPv6 CIDRs such as `/64` through link-local all-nodes multicast
  probing (`ff02::1`), the Linux neighbor table (`ip -6 neigh` /
  `/proc/net/ndisc_cache`), and verified host routes instead of enumerating
  every address. Replies are merged and deduplicated, and link-local results are
  automatically attached to the correct interface scope ID for connect, TLS,
  UDP, plugin, and verification probes. Discovery is Linux-only, requires raw
  ICMPv6 privileges, and honors `--ndp-timeout-ms` (default 750 ms). Native raw
  ICMPv6 Echo (Type 128/129) remains available to `--ping-sweep`.

### Changed

- Version bumped to `0.4.0` across `Cargo.toml`, README, and man pages.
- `--advisories` is automatically activated when passing `--kev-only` or `--min-epss`.
- Table and markdown advisory summaries now prominently display `[KEV]` and EPSS percentages.
- JSON results now include `cisa_kev: bool` and `epss: Option<f32>` fields for every advisory.
- **Raw SYN engine throughput rework** (`src/syn/engine.rs`, `src/syn/v6.rs`,
  `src/syn/packet.rs`): IPv4 SYN frames are now written directly into
  preallocated batch slots reused across every probe and retransmission pass,
  eliminating the per-frame heap allocation and `to_vec()` copy on the hot
  transmit path. IPv6 probes switched from one `sendto(2)` syscall per packet to
  batched `sendmmsg(2)` over the same reused-buffer pool. The default batch size
  rose from 64 to 4096 frames per syscall, response draining/progress/AIMD
  updates now run once per batch flush instead of once per probe, and pacing is
  enforced exactly once per flush.
- **Parallel SYN transmit sharding** (`src/syn/engine.rs`): target list is split
  into contiguous shards, one dedicated AF_PACKET TX thread per shard (up to
  half the CPU cores, capped at 8), each with its own rate budget, AIMD
  controller, pacer, tx-time map, and retransmission pass. The single RX thread
  fan-outs decoded responses to the owning shard via a target map, and shard
  reports are merged into the final `ScanReport` (`workers` reports TX shards
  plus the RX thread). Retransmission passes remain per-shard and skip probes
  already answered within their own shard.
- **Batched SYN receive** (`src/syn/engine.rs`, `src/syn/v6.rs`): both RX loops
  replaced per-packet `recvfrom(2)` with `recvmmsg(2)` over prebuilt iovec/
  `mmsghdr` arrays of 64 reusable 2 KiB slots, cutting one syscall per response
  frame on the hot receive path.
- **AIMD rate control hardened for silent paths** (`src/syn/aimd.rs`,
  `src/syn/engine.rs`, `src/syn/v6.rs`): discovered through live benchmarking
  against a NAT'd reachability-real target. Three defects fixed:
  (1) the AIMD update ran once per batch flush with cumulative counters read
  before the just-flushed batch's responses could arrive, so every update read
  the ratio low and multiplicative decrease collapsed the rate toward `min_pps`
  (a 65535-port capped scan would run roughly 50x slower than the requested
  rate); updates now happen on a fixed 1-second window with per-window
  counters; (2) sub-1-percent response ratios carry no congestion signal when
  the path or target silently drops RST responses (common behind firewalls and
  NATs), so the controller now freezes the configured rate instead of
  collapsing it; partial response ratios still feed the regular AIMD logic;
  (3) the additive-increase step doubled from `rate/20` to `rate/4` so the
  controller can recover the configured rate within a few seconds after a
  real decrease. Additionally, when the first pass observes responses on under
  1 percent of probes, retransmission passes are skipped: a path that answers
  nothing does not begin answering after a resend, and the retry passes would
  only re-pay the full wall clock. Rate caps are now honored exactly
  (65535 ports at 10000/2000/500 pps complete in 8.2/33.6/132 s respectively
  in the benchmark environment).
- **Live permitted-range benchmark documentation** (`README.md`,
  `docs/bench-results.md`, `bench-artifacts/`): same-day live measurements on
  explicitly permitted ranges - the loopback sweep, the WSL2 NAT gateway
  (`172.22.64.1`, full cross-tool matrix against masscan/rustscan/nmap), and
  scanme.nmap.org (held to ≤3,000 pps, one full-range pass per tool, traffic
  stopped when the target rate-limited the test IP). Raw per-run logs, runner
  scripts, and parsed JSON results are archived verbatim under
  `bench-artifacts/` (including `bench-artifacts/live/`).

### Fixed

- An empty JSON baseline (target with no open ports) is now accepted by
  `--diff`/`rayscan diff` instead of being rejected as an invalid file.

## [0.3.0] - 2026-11-08

### Added

- **TLS inspection** (`--tls`, `--no-tls`, `src/tls.rs`): Direct and STARTTLS
  handshakes on known ports capture protocol version, cipher, certificate
  subject/issuer/SANs/serial/validity, days remaining, self-signed and hostname
  status, chain length, and STARTTLS protocol. Certificates are captured even
  when untrusted; metadata appears in JSON, CSV, and Markdown output.
- **SARIF 2.1.0 and Markdown output** (`--format sarif`, `--format markdown`):
  Advisory rules and findings with CVSS/severity properties and host:port
  locations, plus human-readable summary, services, vulnerabilities, TLS, OS,
  defense, and differential sections.
- **Advisory-aware diffs** (`src/diff.rs`): Baselines retain
  `{id, severity, cvss}` advisories. Diffs report added/resolved/re-scored
  findings, advisory counts in change summaries, and new critical advisories.
- **Declarative probe packs** (`--plugins FILE`, `src/plugin.rs`): TOML packs
  with passive or active payloads, literal/regex expectations, version capture,
  bounded resource limits, and first-match-wins semantics.
- **ICMP/TCP ping sweep** (`--ping-sweep`, `--ping-count`, `--ping-timeout-ms`,
  `src/discovery.rs`): Linux IPv4 raw ICMP with TCP fallback; IPv6 TCP fallback.
  Connection refusals count as alive, target order is preserved, and work is
  chunked across hosts.
- **Raw IPv6 SYN scanning and IPv6 OS fingerprinting** (`src/syn/v6.rs`): Linux
  `AF_INET6` raw sockets, full 128-bit SYN cookies, retries, rate limiting, and
  SYN-ACK option classification. Mixed IPv4/IPv6 target sets are scanned and
  merged transparently.
- **Distributed target sharding** (`--shard-index`, `--shard-count`,
  `src/shard.rs`): Stable FNV-1a placement with family-aware hashing and
  validation up to 1,024 shards.
- **Report merge command** (`rayscan merge`, `src/merge.rs`): Merge JSON or JSONL
  reports, deduplicate host:port results with open-wins precedence, union
  advisories, merge OS/defense maps, and adjust summaries.
- **Stealth traffic shaping** (`--jitter-ms`, `--decoys`, `--fragment-size`):
  Random delay before scanner probes and SYN batches, up to eight IPv4 decoy
  source addresses, and 8-byte-aligned IPv4 SYN fragmentation. The stealth
  profile now defaults to 50 ms jitter.
- **Supply-chain tooling**: `deny.toml`, `cargo-fuzz` targets for service, UDP,
  and packet parsers, `make deny`/`make fuzz`/`make sign`, optional GPG/cosign
  signing in `make dist`, a CI deny job, and a tag-triggered release workflow for
  musl Linux and Windows GNU archives.

### Changed

- Version bumped to `0.3.0` across `Cargo.toml`, archives, README, and man page.
- Phase 9 feature gate documented in `docs/phase9-features.md`, including live
  STARTTLS and Metasploitable 2 validations.
- JSON port objects now include an optional `tls` object; CSV gains
  `tls_version`, `tls_subject`, and `tls_days_remaining` columns.
- Raw SYN target handling now accepts IPv4 and IPv6 in the same invocation.
- UDP probing binds `[::]:0` for IPv6 targets instead of an IPv4 wildcard.
- `--ping-count` and `--ping-timeout-ms` require `--ping-sweep`; `--decoys` and
  `--fragment-size` require `--syn`.
- Output format enum now includes `sarif` and `markdown`.

### Fixed

- `rayscan merge` no longer duplicates open-only JSON entries into a redundant
  `results` array; `results` is emitted only when an input supplied one or the
  inputs are JSONL.
- UDP service probing against IPv6 targets no longer fails on an IPv4-only bind.
- SMTP STARTTLS negotiation now handles a bare `250` response terminator.
- Clippy warnings in checksum, plugin hex parsing, and packet tests.

## [0.2.0] - 2026-11-07

### Added

- **Unified Accuracy Scoring Engine (0–100%)** (`src/accuracy.rs`): Every responsive port is scored across 4 empirical pillars:
  - TCP Handshake (20%): verified 3-way handshake completion.
  - Application Protocol (40%): bounded protocol parsing and banner validation, with dedicated recognition for silent/binary client-first listeners (rpcbind 111, PostgreSQL 5432, X11 6000, AJP 8009, NFS 2049).
  - Stack / OS Conformance (20%): TCP/IP options and TTL fingerprint alignment.
  - Behavioral Latency Stability (20%): RTT consistency and absence of drop retries.
- **Explain Mode & Confidence Filter** (`--explain [PORT]`, `--min-confidence <N>`): Detailed diagnostic breakdown of scoring criteria and evidence strings; ability to filter out low-confidence or ambiguous candidates.
- **Defense Awareness & Middlebox Classifier** (`src/defense.rs`): Evaluates target defensive perimeters into a 6-tier posture hierarchy:
  - `[CLEAN] Direct Host`
  - `[NOTICE] Rate-Limiting Active`
  - `[WARNING] TCP Tarpit Active`
  - `[WARNING] SYN-Proxy Middlebox Detected`
  - `[WARNING] Layer-7 WAF / DPI Detected`
  - `[CRITICAL] Heavy Middlebox / Deception Detected`
- **Defense Observations Tracking** (`src/model.rs`, `src/verify.rs`): `ScanReport` retains reclassified verification drops so middlebox discrepancies are detected even when `--show closed` is omitted.
- **Network State Change Detection & Differential Auditing** (`src/diff.rs`):
  - Live scan comparison via `--diff <FILE>` / `--compare-to <FILE>`.
  - Standalone offline CLI subcommand `rayscan diff <BASELINE> <CURRENT> [--json]`.
  - Colorful visual indicators: `[+] NEW`, `[-] GONE`, `[*] CHANGED`, `[~] POSTURE`.
- **Smart Resume with Pre-Scan Gap Analysis Audit** (`src/resume.rs`): Visual audit table displaying completed vs remaining ports, completion percentage, prior findings, and host anomaly flags before resumed probing begins.
- **Speed & Discovery Optimizations** (`--discover-only`, `--top-ports-first`):
  - `--discover-only` mode disables banner waits for ultra-fast perimeter mapping (~1.52 s / 1k ports).
  - `--top-ports-first` prioritized ordering enabled by default in `fast` and `balanced` profiles (first results < 50 ms).
- **Live Results Table & In-Memory Deduplication** (`src/lib.rs`): Streams responsive ports cleanly above the progress bar with `HashSet<(IpAddr, u16)>` deduplication during retries.
- **Cyber High-Contrast Theme** (`--theme cyber`): Enhanced terminal visibility palette for modern terminals.
- **Standalone Native Windows Subcommand Execution**: `rayscan.exe diff` supported natively alongside connect scanning.
- **Offline CVE Advisory Correlation** (`--advisories`, `src/advisory.rs`, `data/advisories.json`): Detected service product/version/banner tuples are matched against a bundled curated CVE database (vsftpd 2.3.4 backdoor, Samba 3.0.x, UnrealIRCd 3.2.8.1, Debian OpenSSH PRNG, Apache 2.2.x DoS and 2.4.49/2.4.50 path traversal, Exim 4.87-4.91, distccd). Findings attach to port results and render as an `ADVISORIES` table column, a severity-sorted correlation section, `--explain` breakdowns, and `advisories` arrays in JSON/JSONL output. Correlation is fully offline and advisory only; no additional target traffic is generated.
- **Local NVD CVE Advisory Database** (`rayscan db update`, `rayscan db status`, `src/db/`): A user-maintained mirror built from the official NVD CVE 2.0 feeds covering 1999 through 2026 (over 400k CVEs and 325k product mappings at release). Feed processing is streamed and digest-verified, and the mirror is stored as compact yearly records plus 256-way product shards with atomic manifest updates and a concurrency lock. Manual refreshes support `--years SPEC` subsets and `--force`; `db status [--json]` reports coverage, age, and staleness. Every scan checks the rolling `recent` feed and applies changes automatically unless `--no-db-update` is passed, and update failures never fail a scan. NVD matches merge with curated findings and are tagged with `source: "nvd"`; curated findings rank first and each source is severity-sorted, while human-readable advisory sections cap at 10 rows per service and JSON keeps the full list. Database location follows `--db-dir`, `RAYSCAN_DB_DIR`, or the platform data directory.

### Changed

- Scans now perform an automatic lightweight NVD `recent`-feed check by default; use `--no-db-update` to disable it.
- Updated version to `v0.2.0` across `Cargo.toml`, `Makefile`, `README.md`, man pages, and distribution archives.
- Streamlined `render_table` with `TableOptions` parameter struct.
- Hardened test assertions against package version macros.

### Fixed

- **Defense Awareness false positives on client-first services** (`src/defense.rs`): known binary-protocol ports (rpcbind 111, distccd 3632, PostgreSQL 5432, X11 6000, AJP 8009, ...) that hold connections mute are no longer counted as TCP-tarpit evidence, verification failures on those ports no longer imply a SYN proxy, and their low accuracy scores no longer suggest rate-limiting. Expected client-first listeners are reported as a neutral indicator instead.
- Anomaly annotations (`anomaly:`) are now detected on any result for a host instead of only the first result, so tarpit/honeypot farms cannot be missed by result ordering.

## [0.1.0] - 2026-11-03

### Added

- **`Profile::Stealth` and `--stealth` flag** (`src/config.rs`, `src/cli.rs`):
  new stealth profile (rate 20 pps, probe timeout 1000ms, workers 8, retries 3) with
  automatic probe randomization to evade basic network IDS thresholds and rate-limiting middleboxes.
- **Expanded UDP detection** (`src/udp.rs`): added active probes and response decoders
  for NetBIOS Name Service (NBNS port 137, extracting computer/workgroup names) and
  SIP VoIP/PBX (port 5060, parsing SIP status line and Server product/version).
- **Expanded OS fingerprinting database** (`src/fingerprint.rs`): added signatures for
  pfSense / OPNsense firewalls (FreeBSD kernel), MikroTik RouterOS (Linux router kernel
  with timestamps disabled), and Windows Server 2019/2022.
- **Technical whitepaper** (`docs/why-accuracy-first-matters.md`): deep-dive analysis on
  why high-speed scanners fail against TCP tarpits and SYN proxies, and how rayscan't two-phase
  verification solves it with 100% precision.
- **Public release README overhaul** (`README.md`): added status badges (CI, Version, Rust, Platforms, License),
  tarpit comparison benchmark matrix, and profile selection guide.
- **Graceful Ctrl-C signal handling** (`src/lib.rs`): `tokio::signal::ctrl_c()`
  spawned at scan start sets a `shutdown: Arc<AtomicBool>` on `ScanOptions`.
  Workers check the flag before each job; when set they stop picking new work and
  the scan returns a **partial report** instead of an error.
- **`partial: bool` field on `ScanReport`** (`src/model.rs`): `true` when the
  scan was interrupted before all probes completed.  Callers can distinguish a
  complete result from an interrupted one.
- **Resumable scans** (`src/resume.rs`): new `--save-state FILE` and `--resume FILE`
  CLI flags.  `save_state()` serialises the current scan results, counts, elapsed
  time, and list of probed ports to a versioned JSON file.  `--resume` loads the
  saved state, computes remaining ports, runs only those ports, and merges results.
- **Optional ports specification & `--top-ports` flag** (`src/cli.rs`, `src/ports.rs`):
  `--ports` is now optional; when omitted, `rayscan` automatically defaults to the
  standard well-known ports `1-1024`. Added `--top-ports N` to probe the top N most
  frequently used services (e.g. `--top-ports 100`).
- **Native Windows release binary** (`rayscan.exe`): cross-compiled for
  `x86_64-pc-windows-gnu` via MinGW toolchain; runs natively on Windows CMD and PowerShell.
- **Nmap-compatible XML output** (`src/output.rs`, `--format nmap-xml`): full
  `<nmaprun>` / `<host>` / `<ports>` / `<runstats>` tree compatible with
  Metasploit, nmap-parse-output, and other nmap-XML consumers.  OS fingerprints
  appear as `<os><osmatch>` elements.
- **Greppable output** (`src/output.rs`, `--format greppable`): Nmap `-oG`-style
  one-line-per-host format: `Host: <ip>  Ports: <port>/<state>/<proto>//<svc>/…`
- **Static musl binary** (`make musl`): cross-compiles rayscan for
  `x86_64-unknown-linux-musl` producing a fully-static binary with no libc
  dependency; install `musl-tools` and run `make musl` once.
- **Man page** (`man/rayscan.1`, `make man`): full `roff` manual page generated
  from the clap command definition via `clap_mangen`; covers all flags, formats,
  output modes, and exit codes.
- **`src/bin/gen_man.rs`**: build-time helper binary that regenerates `man/rayscan.1`.
- **Dockerfile** (multi-stage): `rust:1.99.1-alpine` builder compiles the musl
  binary; `scratch` final layer holds only the binary.  Build with `make docker`.
- **Makefile targets**: `make musl`, `make install`, `make docker`, `make man`.
  `make install` copies the release binary to `$(PREFIX)/bin/rayscan` and the man
  page to `$(PREFIX)/share/man/man1/rayscan.1`.
- **`shutdown: Arc<AtomicBool>`** field on `ScanOptions`: workers consult the flag
  at the top of each job loop iteration.
- **6 unit tests** in `src/resume.rs`: port subtraction, empty / full / partial
  scanned sets, save/load round-trip, restored-counts verification, and
  structured service-metadata restoration.
- **1 unit test** in `src/ports.rs` for saved `top-N` and list specifications.
- **4 unit tests** in `src/output.rs`: NmapXml host/port/service elements,
  empty-version omission, greppable one-line-per-host, and XML closure.
- `docs/phase6-gate.md`: gate report with musl binary evidence, nmap XML sample,
  greppable sample, resume demo, man page, and Dockerfile notes (image build
  still requires a Docker host).

### Changed

- `src/model.rs`: `ScanReport` gains `partial: bool` and `probed_ports: Vec<u16>`.
  All existing constructors (scanner, syn/engine, anomaly, verify, output tests)
  updated.
- `src/scanner.rs`: `ScanOptions` gains `shutdown: Arc<AtomicBool>`.  `scan()`
  returns a partial `ScanReport` (instead of `Err`) when interrupted and records
  every port that was actually probed.  `run_worker()` checks the shutdown flag
  before each probe.
- `src/lib.rs`: when `--save-state` is used, all outcomes are retained for the
  state file while display filtering remains unchanged; a resumed run reuses the
  saved port specification and rejects multiple targets.
- `src/cli.rs`: `ScanArgs` gains `--resume` and `--save-state` flags;
  `ResolvedConfig` gains `resume_file: Option<PathBuf>` and
  `save_state_file: Option<PathBuf>`.
- `src/output.rs`: `OutputFormat` gains `NmapXml` and `Greppable` variants;
  `emit()` dispatches to the new renderers.
- `src/lib.rs`: `pub mod resume` registered; `run_scan()` wires signal handling,
  resume loading, state saving, and partial-report warning.
- `Cargo.toml`: `[[bin]] gen_man` section added; `clap_mangen = "0.2"` and tokio
  `signal` feature were already added in Phase 6 prep.
- `make ci` test count: **106 Rust unit tests + 9 CLI integration + 13 Python = 128 total**.
- **Live Metasploitable 2 validation** (`docs/live-test-metasploitable.md`):
  18/18 open ports with service/version metadata and Linux 2.6.x OS fingerprint
  in 1.77 s; UDP DNS/rpcbind/NetBIOS detection in 1.5 s.

### Fixed

- **OS classifier false positive** (`src/fingerprint.rs`): Ubuntu/Metasploitable
  fingerprints without TCP timestamps were classified as MikroTik RouterOS.
  The Linux 2.6.x signature now accepts absent timestamps and the MikroTik
  window range was narrowed; regression test added.
- **Service/version parsing** (`src/service.rs`): extract FTP product/version
  from `220 (vsFTPd 2.3.4)`, identify Postfix SMTP, IRC 6667/6697, shell
  prompts, Ruby DRb, and rexec (`Where are you?`).
- **UDP detection** (`src/udp.rs`, `src/lib.rs`): added NTP, SNMP, and RPC
  portmapper probes; port-aware response inspection; independent probing of
  requested UDP ports even when TCP is closed; UDP service metadata is now
  attached to the structured result.
- **Resume correctness** (`src/lib.rs`, `src/resume.rs`, `src/model.rs`):
  resume reuses the saved port specification when `--ports` is omitted, records
  the exact ports probed by an interrupted randomized scan, preserves all
  outcomes and structured service metadata, and rejects multi-target resume
  rather than producing incomplete state.
- **Nmap XML** (`src/output.rs`): omit `product`/`version` attributes when the
  value is unknown instead of emitting empty strings.

---

## [Unreleased - Phase 5]

### Added

- **OS fingerprinting** (`src/fingerprint.rs`): opt-in via `--os` flag.
  Sends one raw SYN probe (AF_PACKET) per discovered host, extracts features
  from the SYN-ACK (TTL, window, MSS, WScale, SACK, timestamps, DF bit,
  options order), and classifies the host's OS family using weighted additive
  scoring against an 11-entry signature database.
- **`OsFamily`** enum: `Linux`, `Windows`, `MacOS`, `Bsd`, `Cisco`, `Unknown`.
- **`TcpFingerprint`** struct: raw TCP/IP features parsed from a SYN-ACK frame.
- **`OsGuess`** struct (serde-serialisable): family, detail string, confidence
  score, and inferred initial TTL.
- **`WinMatch`** matcher: `Any`, `Exact`, `Range`, `Set` — used in signatures.
- **`infer_initial_ttl()`**: snaps observed TTL + hops to nearest of 64/128/255.
- **`classify()`**: weighted additive scoring returning the best-matching `OsGuess`.
- **`parse_tcp_options()`**: extracts MSS, WScale, SACK-OK, timestamps from raw
  option bytes; records option order.
- **`fingerprint_from_frame()`**: parse Ethernet/IPv4/TCP frame → `TcpFingerprint`.
- **`probe_fingerprint()`** / **`probe_fingerprint_async()`**: Linux-only raw SYN
  probe; runs in `spawn_blocking`; returns `None` gracefully without root.
- **`build_fingerprint_syn()`**: 74-byte SYN frame with full TCP options section
  (MSS, NOP, WScale, NOP, NOP, SACK-OK, Timestamps) to elicit a rich SYN-ACK.
- **9 unit tests** in `src/fingerprint.rs`: TTL inference, Linux/Windows/Cisco/
  BSD/macOS classification, options parsing, frame rejection, hop estimation.
- **`report.os_fingerprints`**: `HashMap<IpAddr, OsGuess>` added to `ScanReport`.
- **JSON `os_fingerprints` field**: emitted in `--json` output when `--os` is used.
- **OS column in table output**: visible when `--os` returns at least one result.
- `docs/phase5-gate.md`: lab gate report with signature DB, scoring rationale,
  unit test evidence, and live Metasploitable 2 results.

### Changed

- `src/model.rs`: `ScanReport` gains `os_fingerprints: HashMap<IpAddr, OsGuess>`.
  All existing `ScanReport` constructors (scanner, syn/engine, anomaly, verify,
  output tests) updated with `os_fingerprints: HashMap::new()`.
- `src/cli.rs`: `ScanArgs` gains `--os` flag; `ResolvedConfig` gains
  `os_detection: bool`.
- `src/lib.rs`: Phase 5 OS probing stage wired after Phase 4 UDP detection;
  progress messages printed to stderr when `--os` is active.
- `src/output.rs`: `JsonReport` gains `os_fingerprints` (skipped when empty);
  `render_table` shows an OS column when fingerprints are present.

---

## [Unreleased - Phase 4]

### Added

- **UDP detection** (`src/udp.rs`): opt-in UDP fingerprinting via `--udp` flag.
  Sends a DNS probe to each open TCP port; identifies DNS, SNMP, and NTP from
  the response bytes; falls back to preserving printable ASCII banners.
- **UDP wired into `run_scan()`** (`src/lib.rs`): when `--udp` is set, every
  open TCP port is probed with `probe_udp()` after TCP scan completes; detected
  UDP service info is attached to the port's banner field.
- **`UdpServiceInfo` / `UdpDetection`** structs in `src/udp.rs`: serde-serialisable
  UDP result types with optional product and version fields.
- **5 unit tests** in `src/udp.rs` covering DNS, SNMP, NTP, text banner, and
  empty-data edge cases.
- `docs/phase4-gate.md`: lab gate report with live Metasploitable 2 evidence.

### Changed

- `src/lib.rs`: `report` binding made `mut` so UDP probing can mutate results
  in-place after the TCP scan completes.
- `src/cli.rs` `ResolvedConfig` now includes `udp_detection: bool` (wired from
  the `--udp` CLI flag).

---

## [Unreleased - Phase 3]

### Added

- **AIMD rate control** (`src/syn/aimd.rs`): additive-increase/multiplicative-decrease
  congestion avoidance for the SYN TX loop; enabled by default, disable with `--no-aimd`.
- **Retry rate reduction** (`--retry-rate N`): retransmission passes run at a reduced
  packet rate (default: rate/4) to avoid flooding the network.
- **Anomaly detection** (`src/anomaly.rs`, `--anomaly-threshold N`): flags hosts that
  respond with an anomalously large number of SYN-ACKs for extra scrutiny before they
  are added to the verified open set.
- **Confidence field** on `PortResult` (`confidence: Option<f32>`): carried through the
  verification pipeline and emitted in JSON and CSV output when present.
- `verify_syn_open_candidates()` in `src/verify.rs`: accepts a pre-filtered candidate
  list from the anomaly detection stage, keeping the verification path composable.
- New CLI flags: `--no-aimd`, `--aimd-min-rate N`, `--retry-rate N`, `--anomaly-threshold N`.
- `bench/accuracy_suite.py`: multi-profile accuracy runner that cycles through
  `LAB_LOSS=0%/5%/20%`, asserts recall ≥ 0.99 and FP = 0, and prints a results table.
- 31 new unit tests (77 Rust + 13 Python total):
  - 6 in `src/syn/aimd.rs` covering AIMD additive/multiplicative steps and clamps.
  - 3 in `src/anomaly.rs` covering threshold logic and partition results.
  - 2 more in `src/verify.rs` covering candidate-list reclassification and count merging.

### Changed

- Default `--syn` now performs discovery plus verification. Use `--syn --connect-only`
  for raw layer-3/4 semantics (deliberately reports tarpits and SYN proxies as open).
- `--connect-only` consistently disables both banner verification and SYN candidate
  verification.
- `SynScanOptions` gains `retry_rate_pps`, `aimd`, and `aimd_min_pps` fields.

### Fixed

- Low `--rate` values could stall forever when a transmit batch exceeded the
  token-bucket burst; batches now acquire tokens in burst-sized steps.
- SYN latency no longer includes time spent waiting in the transmit pacer.

## [Unreleased - Phase 2]

### Added

- Raw SYN engine (`--syn` flag) using `AF_PACKET + SOCK_RAW` on Linux.
- SipHash-1-3 SYN cookies encoded in the TCP ISN — stateless, zero per-probe heap allocation.
- BlackRock stateless bijection (masscan-style Feistel cipher) for full port-range coverage
  with no repeats and O(1) memory regardless of target count.
- Dedicated RX thread with kernel-side BPF filter accepting only SYN-ACK, RST, and
  ICMP port-unreachable replies to our source-port range (61000–61999).
- ARP resolution over `AF_PACKET` to discover the gateway MAC address.
- `/proc/net/route` parser to select the correct outgoing interface and source IP per target.
- Clear error and exit code 1 when `CAP_NET_RAW` or root is absent; the caller
  can re-run without `--syn` to use the Phase 1 connect scan.
- `siphasher`, `crossbeam-channel`, and `core_affinity` dependencies (87 crates total,
  `cargo audit` clean).
- 10 new unit tests: cookie encode/decode, BPF filter shape, raw-frame build/parse
  (SYN-ACK, RST, ICMP unreachable), BlackRock bijectivity, and route/MAC parsing.
- `docs/phase2-gate.md` with terminal evidence for all gate criteria.

### Changed

- `src/lib.rs` now exposes `pub mod syn` gated on `#[cfg(target_os = "linux")]`.
- `ScanArgs` gains `--syn` flag; `run_scan` dispatches to `syn::engine::syn_scan`
  when the flag is set.

## [Unreleased]

### Added

- Async TCP connect scanner with a fixed worker pool and lazy target/port job
  production.
- Target parsing for IPs, CIDRs, ranges, files, `@file`, hostnames, exclusions,
  and IPv4/IPv6 family selection, with a 65,536-address cap.
- Port list/range parsing and validation.
- Built-in `fast`, `balanced`, and `careful` profiles plus optional
  `rayscan.toml` configuration.
- Table, JSON, JSONL, and CSV output; `--json` benchmark alias; file output.
- Banner verification so tarpits and SYN proxies are not reported as open;
  `--connect-only` restores handshake-only behavior.
- RFC 6298 per-host RTT estimator, 1.5s minimum timeout, global token bucket,
  `RLIMIT_NOFILE`-aware workers, and local-resource retries.
- JSON error taxonomy for open, closed, filtered, silent, unreachable, and
  error states.
- 30 unit tests, 6 binary-level CLI tests, and an exact `1-65535` localhost gate.
- Phase 1 architecture and gate documentation.

### Changed

- The CLI now exposes `rayscan scan`; the Phase 0 shell is gone.
- Default scans verify a service after the handshake instead of treating every
  successful handshake as open.
- `make ci` now includes the release build.

## [0.1.0 - Phase 0] - 2026-11-03

### Added

- Phase 0 Rust CLI shell with `--version` and `--help`.
- Pinned Rust 1.99.1 toolchain with `rustfmt` and `clippy`.
- GitHub Actions CI for formatting, clippy, tests, release build, benchmark
  tests, and `cargo audit`.
- WSL2/Linux network-namespace lab with open, closed, DROP-filtered, tarpit,
  rate-limited, and SYN-proxy targets, plus `netem` delay/jitter/loss profiles.
- Ground-truth checker and benchmark harness for rayscan, nmap, masscan, and
  rustscan.
- Offline parser and metric tests for the benchmark harness.

### Notes

- The connect scanner is Phase 1 and is not implemented in this release.
- Raw-packet lab tests require root and are isolated from shared CI.
