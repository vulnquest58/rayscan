# Phase 9 feature gate

This checkpoint records the `0.3.0` feature set and the evidence gathered to
validate it. It follows `docs/phase8-speed-gate.md` and
`docs/next-phase-enhancements.md`.

## Scope completed

- IPv6 raw SYN discovery and IPv6 OS fingerprinting (`src/syn/v6.rs`,
  `src/fingerprint.rs`)
- ICMP/TCP ping sweep (`src/discovery.rs`), with a live local-host ping sweep
  validated through the `localhost` gate
- Declarative TOML probe packs (`src/plugin.rs`)
- TLS/STARTTLS certificate inspection (`src/tls.rs`)
- SARIF 2.1.0 and Markdown reporting (`src/output.rs`)
- Advisory-aware differential auditing (`src/diff.rs`)
- Stable FNV-1a target sharding and report merging (`src/shard.rs`,
  `src/merge.rs`)
- Random jitter, IPv4 SYN decoys, and IPv4 SYN fragmentation
  (`src/scanner.rs`, `src/syn/engine.rs`, `src/syn/packet.rs`)
- Supply-chain tooling: `deny.toml`, fuzz targets, signing helper, CI/release
  workflows

## Local automated gates

| Check | Command | Result |
| :--- | :--- | :--- |
| Formatting and lint | `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| Unit and CLI tests | `cargo test --all-targets --all-features` | 200 library + 11 CLI tests pass |
| Benchmark harness tests | `python3 -m unittest discover -s bench/tests` | 13 pass |
| Exact localhost gate | `python3 bench/localhost_gate.py` | exact 65,535-port open set |
| Lab ground truth | `make lab-check` | 11/11 states match |
| Raw SYN accuracy | `make syn-gate` | 10/10 exact runs |
| Service detection | `make service-gate` | 3/3 exact with metadata |
| SYN service detection | `make syn-service-gate` | 3/3 exact with metadata |
| Supply-chain policy | `make deny` | advisories/bans/licenses/sources pass |
| Fuzz parsers | `make fuzz FUZZ_TARGET=service_inspect|udp_inspect|packet_parse` | 3,116 / 155,283 / 940,888 runs, no crashes |

## Live validations

### STARTTLS handshakes on `127.0.0.1:587`

A local Python TLS server exposes a minimal SMTP greeting and upgrades to TLS
1.3 after `STARTTLS`. A `0.3.0` binary scanned it with automatic STARTTLS
inspection and captured:

```json
{
  "version": "TLSv1.3",
  "cipher": "TLS13_AES_256_GCM_SHA384",
  "subject": "CN=localhost",
  "self_signed": true,
  "hostname_matches": false,
  "chain_len": 1,
  "starttls": "smtp"
}
```

### Ping sweep on `127.0.0.1`

`rayscan scan -t 127.0.0.1 -p 22 --ping-sweep --ping-count 1
--ping-timeout-ms 500 --json` reported:

```text
[discover] probing 1 host(s) with 1 ping probe(s), 500 ms timeout …
[discover] 1 of 1 host(s) responded
```

Remote ICMP replies from WSL2 NAT are not guaranteed to reach raw sockets, so
the scanner falls back to connect pings and may mark remote hosts unreachable
when ICMP is filtered. That behavior is expected rather than a defect.

### IPv6 UDP DNS on `::1:53`

A local IPv6 UDP DNS server answered a synthetic A query. `rayscan scan -6 -t
::1 -p 53 --udp --json` reported:

```json
{
  "host": "::1",
  "port": 53,
  "state": "open",
  "banner": "udp:dns",
  "service": {"name": "udp:dns"},
  "confidence": 0.9
}
```

### Metasploitable 2 at `192.168.100.37`

Live connect and raw-SYN scans, plus OS fingerprinting, were repeated against
the local Metasploitable 2 VM:

- `22`, `80`, `111`, and `5900` reported open with no false positives.
- Passive and raw-SYN OS classification returned `Linux 2.6.x`, confidence
  100%, initial TTL 64.
- Advisory correlation matched:
  - `21/ftp` → `CVE-2011-2523` critical, CVSS 10.0 (vsftpd 2.3.4 backdoor).
  - `22/ssh` → `CVE-2008-0166` high, CVSS 7.8 (Debian OpenSSL PRNG).
  - `80/http` → `CVE-2011-3192` high and `CVE-2007-6750` medium (Apache 2.2.8).
- The Windows binary reached the same target over `SSH-2.0-OpenSSH_4.7p1
  Debian-8ubuntu1` with 95% confidence.

## Release artifacts

`make dist` produces:

- `dist/rayscan-0.3.0-linux-x86_64.tar.gz`
- `dist/rayscan-0.3.0-windows-x86_64.zip`
- `dist/SHA256SUMS`

Signing is optional and activated by `RAYSCAN_GPG_KEY` or
`RAYSCAN_COSIGN_KEY` through `scripts/sign-release.sh`.
