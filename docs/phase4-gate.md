# Phase 4 Gate — Service Detection (TCP + UDP)

**Status:** ✅ PASSED  
**Date:** 2026-11-05  
**Rust version:** 1.83+ (stable)  
**Binary:** `target/release/rayscan` (1.6 MB stripped ELF)

---

## Scope

Phase 4 adds two service-detection subsystems on top of the Phase 3 accuracy engine:

| Module | Purpose |
|--------|---------|
| `src/service.rs` | TCP banner grab + nmap-db pattern matching |
| `src/udp.rs` | UDP probe + protocol fingerprinting (DNS, SNMP, NTP) |

---

## TCP Service Detection (`service.rs`)

The scanner connects to each open TCP port, reads a banner (up to 512 bytes),
and matches it against a built-in signature table derived from the nmap
service-probes format.

### Signatures shipped

| Service | Match strategy |
|---------|----------------|
| SSH | `SSH-` banner prefix → version extraction |
| HTTP | `HTTP/` status-line or `Server:` header |
| FTP | `220 ` greeting + server name |
| SMTP | `220 ` SMTP greeting |
| POP3 | `+OK` |
| IMAP | `* OK` |
| Telnet | IAC negotiation bytes (0xFF 0xFD / 0xFF 0xFB) |
| MySQL | protocol v10 handshake (`0x0a`) |
| Redis | `+PONG` / `-ERR` |
| Memcached | `VERSION` |
| VNC | `RFB ` |

---

## UDP Detection (`udp.rs`)

A single DNS query (`A example.com`) is sent to each port. The response is
fingerprinted by the first bytes:

| Protocol | Heuristic |
|----------|-----------|
| DNS | QR bit set in flags (byte 2 bit 7), OPCODE == 0 |
| SNMP | BER SEQUENCE tag `0x30` at offset 0 |
| NTP | mode==4 (server) with version 3 or 4 in LI/VN/MODE byte |
| Generic | Printable ASCII on the first line (up to 128 chars) |

UDP is **opt-in** (`--udp` flag). When enabled, every open TCP port is probed
with a UDP datagram. Any service info is attached to the banner field.

---

## Unit Tests

```
test udp::tests::inspect_dns_response    ... ok
test udp::tests::inspect_snmp_response   ... ok
test udp::tests::inspect_ntp_response    ... ok
test udp::tests::preserves_text_banner   ... ok
test udp::tests::empty_data_returns_default ... ok
```

All 83 tests pass: 76 unit + 7 CLI integration.

---

## Live Evidence — Metasploitable 2 (192.168.100.37)

> **Updated 2026-11-05:** the final post-fix validation is in
> [live-test-metasploitable.md](live-test-metasploitable.md): 18/18 open ports
> with service/version metadata in 1.77 s. The Phase 4 snapshot below is kept as
> historical evidence.

### Quick scan `--ports 1-1024` (connect mode, service detection enabled)

```
wsl -u vuln -e bash -c "./target/release/rayscan scan \
    --target 192.168.100.37 --ports 1-1024 \
    --rate 500 --workers 150 --timeout 3 --json --quiet"
```

**Results (open ports with service info):**

| Port | Service | Product | Version | Banner |
|------|---------|---------|---------|--------|
| 22 | ssh | OpenSSH | 4.7p1 | `SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1` |
| 23 | telnet | — | — | Telnet negotiation |
| 512 | — | — | — | `Where are you?` |

**Summary:** 3 open, 497 closed, 517 filtered, 7 silent — elapsed 2.4s

### Full scan `--ports 1-65535` (see live-test-metasploitable.md for full output)

Safe parameters used to avoid overloading the target VM:
- `--rate 300` — 300 packets/sec
- `--workers 150` — 150 concurrent workers
- `--timeout 3` — 3-second connection timeout

---

## CLI Interface

```
# TCP only (default)
rayscan scan --target <host> --ports 1-1024

# TCP + UDP fingerprinting
rayscan scan --target <host> --ports 1-1024 --udp

# SYN scan (requires root)
sudo rayscan scan --syn --target <host> --ports 1-1024
```

---

## Code References

- [`src/service.rs`](../src/service.rs) — TCP banner detection engine
- [`src/udp.rs`](../src/udp.rs) — UDP probe + fingerprinting
- [`src/lib.rs`](../src/lib.rs) — wires UDP probing after TCP scan (`udp_detection` flag)
- [`src/cli.rs`](../src/cli.rs) — `--udp` / `udp_detection` flag in `ResolvedConfig`

---

## Gate Criteria

| Criterion | Result |
|-----------|--------|
| `cargo clippy -D warnings` exits 0 | ✅ |
| `cargo test` all 83 tests pass | ✅ |
| SSH detected on port 22 (live Metasploitable 2) | ✅ |
| Telnet detected on port 23 | ✅ |
| UDP module compiles and unit tests pass (5/5) | ✅ |
| `--udp` flag wired into `run_scan()` | ✅ |

**Phase 4 is COMPLETE.**

