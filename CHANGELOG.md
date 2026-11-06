# Changelog

All notable changes to rayscan are documented here.

## [Unreleased - Phase 8]

### Added

- **Guided interactive setup** (`src/interactive.rs`): `rayscan interactive`
  walks through target, port strategy, profile, scan mode, UDP, output format,
  and output file. It requires a TTY, refuses to run in pipelines, and offers
  raw SYN/OS modes only when `CAP_NET_RAW` is available.
- **Capability diagnostics** (`src/doctor.rs`): `rayscan doctor [--json]`
  reports platform, terminal, color, worker limits, config, UDP support,
  raw-SYN privilege, and route readiness.
- **Themes** (`src/theme.rs`): `dark`, `light`, `hacker`, and `minimal` palettes
  for tables, progress, and diagnostics, with a global `--theme` flag and
  `theme` config key. `minimal`, `NO_COLOR`, and non-TTY stdout disable ANSI.
- **Themed table rendering** (`src/output.rs`): `comfy-table` layout with
  dynamic terminal width, themed headers/state cells, optional OS column, and
  no ANSI bytes when color is off.
- **Live progress states** (`src/scanner.rs`): the progress callback now
  receives `ProgressEvent { state }`; `run_scan` shows open/silent counts and
  updates every 64 probes.
- `comfy-table 7.2.2` and `inquire 0.7.5` dependencies for tables and prompts.
- Unit coverage for themes, plain/dynamic table rendering, doctor JSON, config
  theme, and CLI doctor/interactive behavior; suite is now 119 unit + 11 CLI +
  13 harness tests.
- **Batched result delivery** (`src/scanner.rs`): workers accumulate probes
  into batches (64 results or a 50 ms flush) instead of one channel message per
  probe; the receiver unwinds batches with identical per-result semantics. A
  per-result channel was the scan bottleneck (≈36k probes/s vs ≈135k for a bare
  connect loop), and batching restored ≈108k probes/s in isolation.
- **Local-open recheck** (`src/verify.rs`): after a connect scan, open ports on
  local targets are re-verified with one sequential connection at a time. Two
  of the scanner's own in-flight connections can complete a TCP simultaneous
  open and be reported as phantom listeners in the ephemeral port range; a lone
  recheck connection cannot pair with anything, so refusals are reclassified.
  Remote targets are skipped, so external scans send no extra packets.
- **Speed benchmark harness** (`bench/speed_probe.py`, `bench/speed_compare.py`):
  repeatable loopback timing with medians and open-set stability checks, plus a
  rayscan-vs-nmap wall-clock comparison. Results land in `bench/results/` and
  are summarized in `docs/phase8-speed-gate.md`.

### Changed

- `Cli` gains a global `--theme` option and `doctor`/`interactive` subcommands;
  `ResolvedConfig` carries the selected theme and the global flag overrides it.
- `ProgressCallback` changed from `Fn()` to `Fn(ProgressEvent) + Send + Sync`;
  scanner, verification, and raw-SYN paths updated.
- `emit()` and `render_table()` are theme-aware; the hand-written table renderer
  was replaced by `comfy-table`.
- `FileConfig` accepts `theme`; CLI/config precedence resolves it like profiles.
- **Worker auto-sizing capped at 512** (`src/limits.rs`): automatic workers are
  `min(cores × 32, nofile × 3/4)` clamped to 64–512 (`MAX_AUTO_WORKERS`).
  Measurements show the connect engine collapsing above ~512 workers (4,096
  workers take 2.13 s vs 0.62 s at 384 on a full-range loopback scan), while
  `--workers` still accepts up to 4,096 for explicit tuning.
- **Detail strings skipped for non-retained states** (`src/scanner.rs`,
  `src/classify.rs`): closed probes — the scan majority — no longer allocate a
  `String` unless `--show`/`--save-state` will display them; `classify_kind()`
  classifies an error without formatting a detail string.
- README, CLI help, and the man page document the new UX surface.

## [0.1.0 - Phase 6]

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
