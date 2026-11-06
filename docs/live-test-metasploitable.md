# Live Test — Metasploitable 2 (192.168.100.37)

**Date:** 2026-11-05  
**Scanner:** rayscan v0.1.0 release binary  
**Target:** Metasploitable 2 VM at `192.168.100.37` (VMware, same LAN as WSL2 host)  
**Host:** WSL2, Wi-Fi `192.168.100.8`  
**Latency:** ~1 ms RTT, TTL 63, one LAN hop

All commands below were run from WSL2. Raw-SYN and OS-fingerprint runs need
root; connect and UDP runs do not.

---

## 1. Final SYN + Service + OS Scan

This is the canonical validation run. The 2.5 s banner window is required for
Metasploitable's Postfix, which takes about 2 s to emit its greeting.

```bash
sudo rayscan scan --syn --target 192.168.100.37 \
  --ports 21,22,23,25,80,111,512,1524,3306,3632,5432,5900,6000,6667,6697,8009,8180,8787 \
  --os --rate 20 --retries 2 --timeout 6 --probe-timeout-ms 2500 \
  --json --quiet -o bench/results/live_meta_final3.json
```

**Result:** 18/18 open ports in **1.77 s** (`elapsed_ms=1765.829`), zero
unexpected open ports.

| Port | Service | Product / version | Banner or evidence |
| ---: | :--- | :--- | :--- |
| 21 | `ftp` | vsFTPd 2.3.4 | `220 (vsFTPd 2.3.4)` |
| 22 | `ssh` | OpenSSH 4.7p1 | `SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1` |
| 23 | `telnet` | — | Telnet negotiation |
| 25 | `smtp` | Postfix | `220 metasploitable.localdomain ESMTP Postfix (Ubuntu)` |
| 80 | `http` | Apache 2.2.8 | `HTTP/1.1 200 OK` |
| 111 | rpcbind | — | TCP open; UDP rpcbind reply with `--udp` |
| 512 | `exec` | — | `Where are you?` |
| 1524 | `shell` | — | `root@metasploitable:/#` |
| 3306 | `mysql` | MySQL 5.0.51a-3ubuntu5 | MySQL handshake |
| 3632 | distccd | — | TCP open |
| 5432 | PostgreSQL | — | TCP open |
| 5900 | `vnc` | 3.3 | `RFB 003.003` |
| 6000 | X11 | — | TCP open |
| 6667 | `irc` | — | UnrealIRCd welcome/notice |
| 6697 | `irc` | — | UnrealIRCd welcome/notice |
| 8009 | Tomcat AJP | — | TCP open |
| 8180 | `http` | Apache-Coyote 1.1 | `HTTP/1.1 200 OK` |
| 8787 | `ruby-drb` | — | Ruby DRb error banner |

### OS fingerprint

```json
{
  "family": "linux",
  "detail": "Linux 2.6.x",
  "confidence": 1.0,
  "initial_ttl": 64
}
```

The same host reports window 5840, MSS 1460, window scale 5, SACK enabled,
timestamps disabled, and DF set. That signature is now classified as Linux
2.6.x. An earlier build incorrectly classified the same fingerprint as
MikroTik RouterOS; the MikroTik signature was tightened and a regression test
was added.

---

## 2. UDP Detection

```bash
rayscan scan --target 192.168.100.37 \
  --ports 53,69,111,123,137,161,500,5060,1900,5353 \
  --udp --rate 10 --workers 2 --timeout 4 --probe-timeout-ms 1500 \
  --json --quiet -o bench/results/live_meta_udp_final.json
```

**Result:** 3 UDP services in **1.50 s**:

| Port | Service | Detail |
| ---: | :--- | :--- |
| 53 | `udp:dns` | DNS response |
| 111 | `udp:rpcbind` | RPC portmapper reply |
| 137 | `udp:netbios-ns` | NetBIOS name `METASPLOITABLE` |

UDP results use the `udp:` service prefix and `detail: "udp"` so they cannot be
confused with a TCP service on the same port.

---

## 3. Resume Validation

A randomized 17-port connect scan was interrupted after one second, then
resumed without repeating `--ports`:

```bash
timeout -s INT 1 ./target/release/rayscan scan -t 192.168.100.37 \
  -p 21,22,23,80,111,512,1524,3306,3632,5432,5900,6000,6667,6697,8009,8180,8787 \
  --rate 8 --workers 2 --timeout 5 --probe-timeout-ms 2500 --randomize \
  --save-state bench/results/resume_state_v5.json \
  --json --quiet -o bench/results/resume_partial_v5.json

./target/release/rayscan scan -t 192.168.100.37 \
  --resume bench/results/resume_state_v5.json \
  --json --quiet -o bench/results/resume_final_v6.json
```

**State:** 9 ports actually probed out of the 17-port saved specification.
**Resume:** scanned only the remaining 8 ports and merged all 17 planned
outcomes. That run finished with 14 open and 3 silent; the three silent results
are retained in the merged report instead of disappearing. Port 25 was excluded
from this particular run to avoid its known intermittent 2 s banner timing.

The state format now preserves:

- the original port specification (including `top-N`),
- the exact ports probed by the interrupted run,
- all outcomes (open/closed/filtered/silent/unreachable/error),
- structured service name/product/version metadata.

Resuming currently requires a single target.

---

## 4. Output Formats

The same open set was rendered and checked in all supported formats:

```bash
rayscan scan -t 192.168.100.37 --ports 21,22,23,25,80 --quiet
rayscan scan -t 192.168.100.37 --ports 21,22,23,25,80 --json
rayscan scan -t 192.168.100.37 --ports 21,22,23,25,80 --format nmap-xml
rayscan scan -t 192.168.100.37 --ports 21,22,23,25,80 --format greppable
rayscan scan -t 192.168.100.37 --ports 21,22,23,25,80 --stealth
```

The nmap XML contains `<host>`, `<ports>`, `<state>`, `<service>`, and
`<osmatch>` elements. Service attributes are omitted when the value is unknown
instead of being emitted as empty strings. The greppable format emits one
`Host: ... Ports: ...` line per host.

---

## 5. Target Behavior and Safe Parameters

Metasploitable 2 is resource-constrained and occasionally drops or delays
probes under load. Observed behavior during this validation:

- Postfix on port 25 sometimes needs the full 2.5 s banner window.
- Broad scans at high rate and worker counts can saturate the VM; it may then
  stop answering until reset.
- Targeted SYN scans are the most reproducible: 18/18 open in 1.77 s.
- Earlier broad connect scan (`1-65535`, 300 pps, 150 workers) completed in
  about 219 s and found 17 open ports, including two ephemeral RPC ports.
- The VM was reset between overloaded runs with:

```powershell
& "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" -T ws reset `
  "E:\VulnQuest_Pro\nexlab\vm\Metasploitable2-Linux\Metasploitable.vmx"
```

Recommended commands:

```bash
# Fast, reproducible targeted SYN scan with services and OS
sudo rayscan scan --syn --target 192.168.100.37 \
  --ports 21,22,23,25,80,111,512,1524,3306,3632,5432,5900,6000,6667,6697,8009,8180,8787 \
  --os --rate 20 --retries 2 --timeout 6 --probe-timeout-ms 2500 --json

# Safe connect scan, no root
rayscan scan --target 192.168.100.37 --ports 1-1024 \
  --rate 100 --workers 16 --timeout 3 --json --quiet

# UDP services
rayscan scan --target 192.168.100.37 \
  --ports 53,69,111,123,137,161,500,5060,1900,5353 --udp --json
```

Do not use `--workers 4096` or rates above roughly 500 pps against this VM.
