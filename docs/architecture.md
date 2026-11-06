# Architecture

## Phase boundaries

**Phase 0** built the measurement apparatus: pinned toolchain, CI, lab namespace,
and benchmark harness.

**Phase 1** added the async TCP connect engine. It is the accuracy baseline, the
fallback on systems without raw-socket capability, and the benchmark reference.

**Phase 2** added a raw SYN engine (`--syn`) that runs on Linux with
`CAP_NET_RAW`. It shares the same CLI, output schema, and lab ground truth as
Phase 1. Without raw-socket capability it fails with a clear error and exit code
1; the caller can re-run without `--syn` to use the connect engine.

**Phase 3** made raw SYN results trustworthy and introduced congestion control.
Unanswered probes are retransmitted up to the configured retry count at a reduced
rate controlled by an AIMD controller (`syn::aimd`). Every SYN-open candidate is
rechecked with a connect plus banner verification. Hosts with anomalously large
open-port counts are flagged by `anomaly::partition_candidates()` before
verification. Tarpits and SYN proxies are therefore reclassified instead of being
reported as open.

```text
CLI / config
     |
     v
targets + ports
     |
     +--[default]--> bounded worker pool --> result collector --> output
     |                    |        |
     |                    |        +-- classify
     |                    |        +-- RTT estimator
     |                    |        +-- token bucket
     |                    +----------- service verification (banner)
     |
     +--[--syn / Linux + CAP_NET_RAW]-->  syn::engine
                                              |
                                    +---------+---------+
                                    |                   |
                                 TX thread           RX thread
                             (BlackRock permute)  (BPF filter)
                             (SYN cookies)        (SYN-ACK / RST / ICMP)
                             (raw AF_PACKET)      (validate cookie)
     ^
     |
bench/bench.py  --->  lab/ground_truth.json
     ^                         |
     |                         v
nmap / masscan / rustscan   lab/lab.sh (network namespace)
```

The default `--syn` path feeds SYN-open candidates through `verify` before
output. `--connect-only` bypasses that recheck and exposes raw SYN semantics.

## Modules

| Module | Responsibility |
| :--- | :--- |
| `cli` | Clap surface, resolved settings, profile precedence, exit codes |
| `config` | TOML schema, built-in profiles, state filters |
| `targets` | IP, CIDR, range, file, `@file`, hostname, family filtering, exclusions |
| `ports` | Port lists, ranges, validation, deduplication |
| `scanner` | Worker pool, per-probe logic, service verification, result collection |
| `classify` | Mapping OS errors to closed/filtered/unreachable/resource failures |
| `rtt` | RFC 6298 SRTT/RTTVAR estimator with Karn backoff |
| `rate` | Shared token bucket |
| `limits` | Target cap, worker cap, `RLIMIT_NOFILE` sizing |
| `output` | Table, JSON, JSONL, and CSV rendering |
| `syn::cookie` | SipHash-1-3 SYN cookie encode / decode / validate |
| `syn::permute` | BlackRock stateless bijection (Feistel cipher), no repeats |
| `syn::route` | `/proc/net/route` LPM parser, ARP resolution, `iface_ip/mac/index` |
| `syn::packet` | Raw Ethernet/IP/TCP frame builder; SYN-ACK / RST / ICMP parser |
| `syn::filter` | Classic BPF bytecode generator and `attach_filter()` |
| `syn::engine` | TX/RX thread orchestrator, retransmission passes, and result aggregation |
| `syn::aimd` | AIMD rate controller for the TX loop — additive increase on success, multiplicative decrease on loss |
| `verify` | Connect-plus-banner verification of SYN-open candidates and state/count merging |
| `anomaly` | Flags hosts with anomalously large open-port counts for pre-verification scrutiny |

## Job model

Targets and ports are materialized as two small vectors. The cross product is
never materialized: a shared atomic index hands out `(target_index, port_index)`
jobs to a fixed worker pool. Memory is O(targets + ports), not O(jobs).

Each worker accumulates completed results and ships them in batches (64
results or a 50 ms flush) through a bounded channel sized from the worker
count. The collector unwinds each batch, updates full state counts, and
retains only states selected for output. This keeps a default open-only
scan from storing every closed port and removes a channel round-trip per
probe.

Targets are capped at 65,536 addresses (a `/16`). Automatic worker sizing
targets `cores × 32`, clamped to 64–512 and bounded at roughly 75% of
`RLIMIT_NOFILE`; beyond about 512 workers the connect engine loses
wall-clock time to scheduler contention (4,096 workers run roughly 2×
slower than 384 on a 12-core host). `--workers` still accepts up to 4,096
for explicit tuning. The soft limit is raised to a safe working value when
the hard limit allows it.

## Connect engine

For each job:

1. Acquire a token from the global rate limiter, if a rate is configured.
2. Read the per-host timeout from the RTT estimator.
3. Run `TcpStream::connect` under that timeout.
4. Classify a failure using the raw OS error first, then `ErrorKind`.
5. On handshake success, wait briefly for a banner unless `--connect-only` is set.
6. Emit `open`, `closed`, `filtered`, `silent`, `unreachable`, or `error`.

Timeouts do not provide RTT samples (Karn's rule); they increase a bounded
per-host backoff. Successful connects and RTT-bearing refusals update SRTT and
RTTVAR. The minimum connect timeout is 1.5 seconds so a dropped SYN has room for
the kernel's normal retransmission even under lab loss. Only local resource
failures (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`) are retried; they are never
reported as a port state.

## SYN engine (`--syn`, Linux + CAP_NET_RAW)

The SYN engine uses two OS threads — one TX, one RX — each dedicated to a core:

**TX thread:**
1. Permute logical probe indices with the BlackRock bijection (Feistel cipher on
   `Z_n`), so every `(target, port)` probe is visited exactly once without
   materializing the full job list.
2. Derive a source port from the permuted index in `[61000, 61999]` and encode
   the target `(dst_ip, dst_port, src_port)` into a SipHash-1-3 SYN cookie
   placed in the TCP ISN. Source ports are reused across different probes; the
   cookie binds the full tuple.
3. Build raw Ethernet/IPv4/TCP frames (source MAC from `iface_mac`, destination
   MAC from ARP, headers by hand) and send them in batches with `sendmmsg(2)`.
4. After the timeout window, retransmit only probes that received no response,
   up to the configured retry count, using fresh source ports.

**RX thread:**
1. Receives frames on the `AF_PACKET` socket filtered by a classic BPF program
   that accepts SYN-ACK, RST, and ICMP unreachable packets for the scanner's
   source-port range.
2. Validates the SYN cookie in each SYN-ACK (`ack_no - 1 == stored ISN`).
3. Records `open` (SYN-ACK), `closed` (RST), or `filtered` (ICMP unreachable
   or no response after the retry window).

Per-probe transmit timestamps and terminal states are kept in bounded hash maps
for the duration of the scan. The source-port and destination-port vectors are
small; the full target/port Cartesian product is never materialized.

**Fallback:** when `CAP_NET_RAW` is absent, the engine prints one line to stderr
and exits with code 1. The caller can then re-invoke without `--syn` to use the
connect scanner. IPv6 raw SYN is not implemented; IPv6 targets return a usage
error when `--syn` is requested.

## Result semantics

The JSON schema (`host`, `port`, `state`) is identical for both engines.

| State | Connect engine meaning | Verified `--syn` meaning | Raw `--syn --connect-only` meaning |
| :--- | :--- | :--- | :--- |
| `open` | Handshake + banner, or immediate peer close | SYN-ACK candidate passes connect + banner verification | SYN-ACK received and cookie validates |
| `silent` | Handshake succeeded; no banner in window | Candidate handshake succeeded; no banner in window | *(not emitted)* |
| `closed` | ECONNREFUSED / RST | Candidate connect refused or reset | RST received |
| `filtered` | Connect timed out | Candidate connect timed out | ICMP unreachable or no response after retries |
| `unreachable` | EHOSTUNREACH / ENETUNREACH | Candidate connect unreachable | *(not emitted)* |
| `error` | Local or unexpected failure | Local verification failure | *(not emitted)* |

> **Note:** At the raw SYN layer, tarpits and SYN proxies respond with a
> SYN-ACK and look open. The default `--syn` path therefore rechecks every
> SYN-open candidate through the connect engine and reclassifies it. Raw-layer
> behavior is available with `--syn --connect-only` for diagnostics.

## Configuration

TOML values are loaded from `--config FILE`, or from `rayscan.toml` in the
working directory when present. Precedence is:

```text
CLI argument > TOML value > selected profile default > built-in fallback
```

The `fast`, `balanced`, and `careful` profiles adjust the timeout ceiling, banner
wait, rate, worker count, and retry count. Input validation rejects
non-positive timeouts, probe windows outside 10-60,000ms, rates above 1,000,000/s,
and worker counts above 4,096.

## Lab and benchmark

`lab/lab.sh` creates one network namespace, a veth pair, host/target addresses,
a DROP rule, a 5/s conntrack limit, a netfilter SYN proxy, and a `netem` qdisc.
It has no default route and never touches public interfaces.

The benchmark harness compares predicted open ports with
`lab/ground_truth.json`. Any predicted open port outside the ground-truth open
set is a false positive, including tarpits and SYN proxies. The harness does not
pin CPUs or control background load; that belongs in the dedicated performance
phase.

## Rules for later phases

1. Every new module must be reachable from the CLI and covered by a test.
2. The lab and benchmark must remain runnable without external scanners.
3. A speed change that lowers recall or precision is a regression, not a win.
4. Raw-packet code stays Linux-first; unsupported platforms fail visibly.
5. Never report a local resource error (`EMFILE`, `ENOBUFS`) as a port state.
6. Preserve the benchmark JSON contract unless the harness and tests change in
   the same commit.
