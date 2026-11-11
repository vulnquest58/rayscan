# Phase 9 feature gate

This checkpoint records the `0.3.0` and `0.4.0` feature sets and the evidence
gathered to validate them. It follows `docs/phase8-speed-gate.md` and
`docs/next-phase-enhancements.md`.

## v0.4.0 scope completed

- Scope Guard enforcement with structured TOML or line-based allow/deny rules,
  target-file expansion, wildcard domains, resolved-address semantics, and
  `--force-out-of-scope` audit warnings (`src/scope.rs`, `src/lib.rs`)
- Full CISA KEV and EPSS ingestion via `rayscan db intel`, atomic gzip cache,
  24-hour freshness, bundled fallback, and automatic advisory overlay
  (`src/intel.rs`, `src/advisory.rs`, `src/db/mod.rs`)
- Real-time `--stream` JSONL findings with immediate flush and deduplication
  (`src/lib.rs`, `src/output.rs`)
- IPv6 NDP multicast discovery via `--ndp`: `ff02::1` probing, Linux neighbor
  table + host-route merge, broad `/64` target expansion, and scoped link-local
  socket addresses (`src/discovery.rs`, `src/targets.rs`)

## 0.3.0 scope completed

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
| Unit and CLI tests | `cargo test --all-targets --all-features` | 219 library + 15 CLI tests pass |
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

### Full CISA KEV and EPSS refresh on 2026-11-09

A live `rayscan db intel --db-dir /tmp/rayscan-intel --force --json` refresh
downloaded the complete feeds and wrote the gzip cache:

```json
{
  "path": "/tmp/rayscan-intel/intel/threat_intel.json.gz",
  "kev_count": 1775,
  "epss_count": 402199,
  "total": 402199,
  "refreshed": true
}
```

A second invocation without `--force` returned `"refreshed": false` from the
fresh cache. A local vsftpd 2.3.4 banner scan with `--kev-only` correlated
`CVE-2011-2523` with `cisa_kev: true` and `epss: 0.96184`; adding
`--min-epss 0.99` removed that advisory as expected.

### IPv6 NDP discovery in a Linux network namespace

A veth pair connected the root namespace (`fe80::1/64`) to `ndpns`
(`fe80::2/64`). An HTTP listener bound `[::]:8080` inside the namespace.
`ff02::1%veth-ray` ping confirmed both kernels answer multicast echo. NDP then
discovered both namespace link-local addresses, and the scanner successfully
connected using the registered interface scope:

```text
rayscan scan -t fe80::/64 --ndp -6 -p 8080 --connect-only \
  --no-service-detection --no-tls --no-live --no-db-update --format json
```

Result: `targets: 2`, `open: 2` (`fe80::2:8080` and the namespace's autoconfigured
link-local address), `elapsed_ms: 4.133`.

A second run after flushing the neighbor cache isolated the raw multicast probe.
`tcpdump` observed `fe80::1 > ff02::1: ICMP6 echo request` and `fe80::2 >
fe80::1: ICMP6 echo reply`; the scanner resolved only `fe80::2` from `fe80::/64`
and correctly reported port 8080 closed when no listener was present:

```json
{
  "targets": 1,
  "open": [],
  "summary": {"open": 0, "closed": 1}
}
```

This validates multicast probing, neighbor-table merge, broad `/64` expansion,
and link-local scope-ID handling.

### Public IPv6 `nmap.org` — environment blocked

`nmap.org` resolves to `2600:3c01:e000:3e6::6d4e:7061`. Both the WSL2 guest and
the native Windows host lack working IPv6 upstream connectivity (`ping -6`
returns `Network is unreachable` in WSL2; native IPv6 TCP to `nmap.org:443`
times out). Public IPv6 scanning could not be validated from this network. NDP
and IPv6 service scanning were instead validated against the local namespace
above.

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

- `dist/rayscan-0.4.0-linux-x86_64.tar.gz`
- `dist/rayscan-0.4.0-windows-x86_64.zip`
- `dist/SHA256SUMS`

Signing is optional and activated by `RAYSCAN_GPG_KEY` or
`RAYSCAN_COSIGN_KEY` through `scripts/sign-release.sh`.
