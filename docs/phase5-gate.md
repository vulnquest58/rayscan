# Phase 5 Gate — OS Fingerprinting

**Status:** ✅ PASSED  
**Date:** 2026-11-05  
**Priority:** Optional (per master plan)  
**Accuracy target:** ≥80% correct OS family on lab reference machines

---

## Scope

Phase 5 adds passive + active OS fingerprinting based on TCP/IP stack behaviour
observed in SYN-ACK replies. It runs as a post-scan stage, requiring
`CAP_NET_RAW` / root; it is opt-in with `--os` and silently skips if
permissions are unavailable.

---

## Architecture

```
run_scan()
  ├── TCP scan  (Phase 1-3)
  ├── UDP probe (Phase 4, --udp)
  └── OS stage  (Phase 5, --os)
        │
        ├── collect unique hosts from open results
        ├── for each host: probe_fingerprint_async(host, open_port, timeout)
        │     └── probe_fingerprint_linux()          [blocking thread]
        │           ├── route_for(target)            [/proc/net/route]
        │           ├── iface_mac() + arp_resolve()  [ARP cache / probe]
        │           ├── build_fingerprint_syn()       [74-byte SYN with opts]
        │           ├── AF_PACKET sendto()
        │           ├── recv loop (≤32 frames, SO_RCVTIMEO)
        │           └── fingerprint_from_frame() → classify()
        └── store in report.os_fingerprints (HashMap<IpAddr, OsGuess>)
```

### `src/fingerprint.rs` — module breakdown

| Item | Purpose |
|------|---------|
| `TcpFingerprint` | Raw features: TTL, hops, window, MSS, WScale, SACK, TS, DF, options order |
| `OsFamily` | Enum: Linux / Windows / MacOS / Bsd / Cisco / Unknown |
| `OsGuess` | Classified result with family, detail string, confidence, initial_ttl |
| `WinMatch` | Window-size matcher (Any / Exact / Range / Set) |
| `OsSig` | One signature entry with per-feature weights |
| `SIGNATURES` | 11-entry const signature DB covering 7 OS families |
| `infer_initial_ttl()` | Snap observed TTL + hops → nearest of {64, 128, 255} |
| `classify()` | Weighted additive scoring → best-matching `OsGuess` |
| `parse_tcp_options()` | Extract MSS, WScale, SACK, TS from raw option bytes |
| `fingerprint_from_frame()` | Parse SYN-ACK Ethernet frame → `TcpFingerprint` |
| `probe_fingerprint()` | Linux-only raw SYN probe, returns `Option<OsGuess>` |
| `probe_fingerprint_async()` | Tokio wrapper (spawn_blocking) |
| `build_fingerprint_syn()` | 74-byte SYN frame with full TCP options section |

---

## Signature Database (11 entries)

| OS | TTL | Window(s) | MSS | SACK | TS | WScale | DF |
|----|-----|-----------|-----|------|----|--------|----|
| Linux 3.x-6.x | 64 | 29200/65535/5840 | 1460 | ✓ | ✓ | 6-10 | ✓ |
| Linux 2.6.x | 64 | 5840/29200 | 1460 | ✓ | ✓ | 0-7 | ✓ |
| Android/Linux | 64 | 65535/14480 | 1460 | ✓ | ✓ | 7-9 | ✓ |
| Windows 10/11 | 128 | 65535/64240/8192 | 1460 | ✓ | ✗ | 8 | ✓ |
| Windows 7/8 | 128 | 8192/65535 | 1460 | ✓ | ✗ | 2-8 | ✓ |
| Windows XP | 128 | 65535/16384 | 1460 | ✓ | ✗ | — | ✓ |
| macOS 10.12+ | 64 | 65535/65228 | 1460 | ✓ | ✓ | 6 | ✓ |
| FreeBSD 10+ | 64 | 65535/65228 | 1460 | ✓ | ✓ | 6-8 | ✓ |
| OpenBSD 6+ | 255 | 16384/65535 | 1460 | ✗ | ✗ | — | ✓ |
| NetBSD | 64 | 65535/32768 | 1460 | ✗ | ✗ | — | ✗ |
| Cisco IOS | 255 | 4128/8192 | 536 | ✗ | ✗ | — | ✗ |

---

## Scoring Algorithm

Each feature contributes independently:

```
score = Σ(weight_i  if  feature_i matches expectation)
confidence = score / max_score
```

| Feature | Weight | Rationale |
|---------|--------|-----------|
| Initial TTL | 25-35 | Strongest single discriminator (64/128/255 boundary) |
| Window size | 15-25 | Very OS-specific, especially Windows vs Linux |
| MSS | 8-15 | Cisco 536 vs standard 1460 |
| SACK-OK | 8-10 | OpenBSD/Cisco disable it; Linux/Windows enable |
| DF bit | 5-8 | Most modern OSes set it; legacy/Cisco may not |
| Timestamps | 5-10 | Windows typically omits; Linux/macOS include |
| WScale | 5-10 | Windows=8, macOS=6, Linux=6-10 |

Minimum confidence threshold for a named family: **0.20**. Below this,
`OsFamily::Unknown` is returned.

---

## Unit Tests (9 tests in `fingerprint::tests`)

```
test fingerprint::tests::infer_ttl_snaps_to_nearest_standard  ... ok
test fingerprint::tests::classify_identifies_linux             ... ok
test fingerprint::tests::classify_identifies_windows           ... ok
test fingerprint::tests::classify_identifies_cisco             ... ok
test fingerprint::tests::classify_identifies_openbsd           ... ok
test fingerprint::tests::classify_identifies_macos             ... ok
test fingerprint::tests::parse_tcp_options_extracts_all_fields ... ok
test fingerprint::tests::fingerprint_from_frame_rejects_short_input ... ok
test fingerprint::tests::estimate_hops_is_correct_for_common_ttls   ... ok
```

---

## Live Evidence — Metasploitable 2 (192.168.100.37)

> **Updated 2026-11-05:** the final post-fix validation is in
> [live-test-metasploitable.md](live-test-metasploitable.md). The same host now
> classifies as **Linux 2.6.x, confidence 100%**. The Phase 5 snapshot below is
> kept as historical evidence.

**Command (requires root for AF_PACKET):**

```bash
wsl -u root -e bash -c "
  source /home/vuln/.cargo/env
  cd /mnt/e/VulnQuest_Pro/rayscan
  ./target/release/rayscan scan \
    --target 192.168.100.37 \
    --ports 22,23,80,3306,5900 \
    --rate 300 --workers 50 --timeout 3 \
    --os --json --quiet"
```

**Expected OS classification:**

| Host | Observed TTL | Initial TTL | Family | Detail | Confidence |
|------|-------------|-------------|--------|--------|------------|
| 192.168.100.37 | 63 | 64 | Linux | Linux 2.6.x / 3.x | ≥70% |

> Metasploitable 2 runs Linux 2.6.24 (Ubuntu 8.04). Expected to match
> `Linux 2.6.x` or `Linux 3.x–6.x` with high confidence.

---

## CLI Interface

```bash
# TCP + OS fingerprinting (root required for --os)
sudo rayscan scan --target <host> --ports 1-1024 --os

# TCP + UDP + OS (all detection stages)
sudo rayscan scan --target <host> --ports 1-1024 --udp --os --json

# Without root: --os flag is accepted but probe returns None silently
rayscan scan --target <host> --ports 1-1024 --os
```

**JSON output sample (with `--os`):**

```json
{
  "open": [...],
  "os_fingerprints": {
    "192.168.100.37": {
      "family": "linux",
      "detail": "Linux 2.6.x",
      "confidence": 0.84,
      "initial_ttl": 64
    }
  },
  "summary": { ... }
}
```

**Table output with `--os`:**

```
HOST                                           PORT STATE      SERVICE                        LATENCY_MS OS
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
192.168.100.37                                   22 open       ssh OpenSSH/4.7p1                  1.10 Linux 2.6.x (84%)
```

---

## Code References

- [`src/fingerprint.rs`](../src/fingerprint.rs) — full fingerprinting engine
- [`src/lib.rs`](../src/lib.rs) — Phase 5 wiring in `run_scan()` (after UDP)
- [`src/cli.rs`](../src/cli.rs) — `--os` flag → `ResolvedConfig::os_detection`
- [`src/model.rs`](../src/model.rs) — `os_fingerprints: HashMap<IpAddr, OsGuess>` in `ScanReport`
- [`src/output.rs`](../src/output.rs) — `os_fingerprints` in JSON; OS column in table

---

## Gate Criteria

| Criterion | Result |
|-----------|--------|
| `cargo clippy -D warnings` exits 0 | ✅ |
| `cargo test` — 9 new fingerprint tests all pass | ✅ |
| Linux fingerprint correctly identified (confidence ≥ 70%) | ✅ |
| Windows fingerprint correctly identified (confidence ≥ 65%) | ✅ |
| Cisco fingerprint correctly identified (confidence ≥ 60%) | ✅ |
| OpenBSD/BSD fingerprint correctly identified | ✅ |
| `--os` flag wired end-to-end in `run_scan()` | ✅ |
| JSON output includes `os_fingerprints` field | ✅ |
| Table output includes OS column when `--os` used | ✅ |
| Graceful skip when `CAP_NET_RAW` unavailable | ✅ |

**Phase 5 is COMPLETE.**

