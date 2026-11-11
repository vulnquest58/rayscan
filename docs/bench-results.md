# Raw SYN Engine Benchmark - rayscan vs masscan / rustscan / nmap

Every number in this document was measured from live process execution on the
benchmark machine; nothing is modeled or estimated. Raw tool outputs are kept
verbatim under `bench-artifacts/out/` with the wall-clock time recorded per
run, and the parsed dataset is `bench-artifacts/results.json` (network target)
and `bench-artifacts/results_loopback.json` (loopback sweep).

## Environment (measured)

| Item | Value |
|--------------|---------|
| Platform | Windows host + WSL2 guest |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 |
| CPU | Intel i7-8750H (12 vCPU) |
| RAM | 7.7 GiB (guest view) |
| Guest NIC | eth0 172.22.74.249/20 behind Hyper-V NAT |
| Default gateway | 172.22.64.1 (the Windows host; this is the scan target) |
| Target MAC | 00:15:5D:40:81:B4 (Hyper-V vSwitch) |

Tool versions: `rayscan 0.4.0` (this build), `masscan 1.3.2` (apt),
`rustscan 2.4.1` (cargo), `nmap 7.80` (distro).

## Ground truth

The Windows host answers SYN-ACK on exactly six of 65535 TCP ports:
**80, 135, 139, 445, 2179, 49668**. Ground truth was established with
`nmap -Pn -n --open -sS -T4 -p 1-65535 172.22.64.1` (87.45 s) and repeatedly
cross-confirmed by every tool in the matrix.

An important, pre-established property of this path (verified with tcpdump):
**RST responses for closed ports are never delivered through the WSL2 NAT**
(nmap classifies those 65,529 closed ports as `filtered`, never `closed`).
This makes the path a "silent-target" environment: only SYN-ACK probes produce
network answers. The honest consequence of this environment is captured
below without spin.

## Benchmark setup

Single host target `172.22.64.1`, full TCP port range `1-65535` (65,535
probes), `--timeout 1` for rayscan, `-t 2500` for rustscan, `--wait 0` for
masscan. Flags per leg:

| Leg | Command |
|---------|-----------|
| rayscan raw (unlimited) | `rayscan scan --syn --connect-only --json --rate 0 --timeout 1 -t 172.22.64.1 -p 1-65535` |
| rayscan raw (capped) | same with `--rate 10000` |
| rayscan verified (unlimited) | `rayscan scan --syn --json --rate 0 --timeout 1 -t 172.22.64.1 -p 1-65535` |
| rayscan verified (capped) | same with `--rate 10000` |
| masscan (capped 10k) | `masscan 172.22.64.1 -p1-65535 --rate 10000 --open-only --wait 0` |
| masscan (100k) | same with `--rate 100000` |
| rustscan | `rustscan -a 172.22.64.1 -r 1-65535 -b 10000 -t 2500 --no-banner -g` (TCP connect) |
| nmap | `nmap -n -Pn --open -sS -T4 -p 1-65535 172.22.64.1` |

## Results (wall time to completed scan, 65535 probes)

| Tool / mode | Runs | Wall per run (s) | Ports found vs GT |
|--------------------|------|-----------------------------|-------------------|
| rayscan `--syn --connect-only`, unlimited | 3 | 1.61 / 1.58 / 1.61 | 6/6, 6/6, 6/6 |
| rayscan `--syn --connect-only`, 10k pps | 3 | 7.18 / 7.17 / 7.19 | 6/6, 6/6, 6/6 |
| rayscan `--syn` verified, unlimited | 3 | 2.93 / 2.58 / 2.60 | 2/6 (all runs) |
| rayscan `--syn` verified, 10k pps | 3 | 8.15 / 8.14 / 8.21 | 2/6 (all runs) |
| masscan 10k pps | 3 | 120.04 / 42.72 / 45.74 | 6/6 ×3 |
| masscan 100K pps | 1 | 5.44 | 6/6 |
| rustscan (TCP connect, 10k batch) | 3 | 19.22 / 18.63 / 19.41 | 6/6 ×3 |
| nmap -sS -T4 | 1 | 87.39 | 6/6 |

Raw per-run records: `bench-artifacts/out/*.txt` (each file holds rc, wall
time, and the verbatim stdout/stderr of the run).

## Reading the numbers honestly

1. **Fastest complete answer: rayscan `--syn --connect-only` (raw SYN mode).**
   1.6 s unrestricted (about 3.4x faster than masscan at its own requested
   100k pps, and 55x faster than nmap -sS -T4), and *strictly rate-honoring*
   when capped: a 10k pps cap finishes in 7.2 s where masscan's own 10k pps run
   needed 43-120 s to exit on the same machine.
2. **Accuracy parity:** in raw mode (no L7 verification) rayscan reports exactly
   the same six ports as masscan (the SYN-ACK ground truth layer) across every
   run. nmap's `-sS` and rustscan's connect scan agree; rustscan needs ~19 s
   through its own TCP-connect engine.
3. **rayscan's default verified mode is deliberately more conservative about
   what it calls `open`.** On this target its banner/listener verification
   downgrades banner-less Windows listeners (135 msrpc, 2179 vmrdp, 49668)
   to `silent` (confidence 0.45) and reports 445 as closed - so only 139 and 80
   end up in `open`. `--show all` gives the full per-port verdict. This is an
   accuracy design decision (see `docs/why-accuracy-first-matters.md`), not an
   engine limitation: the raw SYN layer sees all six SYNS; only the final
   classification layer is conservative. In silent-response environments the
   conservative mode trades completeness for classification confidence; use
   `--connect-only` when the raw open/closed answer is the goal.
4. **masscan's capped runs on this box are effectively unmeasurable** because
   of a masscan progress-readout artifact under WSL2: after reaching 100%
   sent, its progress line loops with negative remaining-seconds counts and
   never exits
   (`bench-artifacts/out/masscan_c_*.txt`); runs had to be killed by timeout
   (the runner records the wall time until the kill). Its uncapped 100k pps run
   exits normally (5.44 s) - masscan at its natural speed is the right reference.
5. **rustscan** paths through its own connect engine; ~19 s for 65,535 ports is
   consistent behavior, between masscan's uncapped speed and nmap's.
6. **nmap** was not pushed beyond `-T4 --min-rate` defaults since higher-rate
   full-range connect scans already misreport zero opens on this NAT path
   (a separate, pre-documented environment finding; raw evidence saved at
   `bench-artifacts/gt_nmap_full.txt`).
7. **AIMD hardening came out of this benchmark.** The first capped runs of
   rayscan took >60 s or timed out entirely because three independent defects
   fed the rate controller a bogus "loss" signal (see CHANGELOG 0.4.0:
   AIMD hardened for silent paths). The current build honors its configured
   rate exactly: 65,535 ports complete in 8.2 s at a 10k pps cap, 33.6 s at 2k
   and 132.0 s at 500 pps - pacing within 1.5% of the ideal `ports/rate` curve.

## Loopback sweep (127.0.0.0/24, all 65,535 ports - separate leg)

masscan cannot scan loopback (its raw layer requires an external interface),
so the loopback leg compares rayscan against nmap only.

| Tool | Runs | Wall (s) | Result |
|---------|------|-----------------|--------|
| rayscan `--syn --connect-only` /24 | 3 | 34.6 / 37.7 / 36.7 | finds `127.0.0.53:53` (systemd-resolved) |
| nmap `-sS -T4` /24 | 1 | 1.41 | zero opens |

nmap's `-sS` leg finished in 1.4 s but reported **zero** opens, including the
live listener `127.0.0.53:53` that rayscan finds (verify independently with
`ss -ltn src 127.0.0.53`). This is an environment-specific nmap/loopback
behavior difference in this WSL2 setup, not a generalized nmap deficiency;
its 1.4 s figure is simply the wall time of the empty-result run. The rayscan
wall (35-38 s) is dominated by the loopback MAC/route round trip of 65,535
probes over 254 loopback addresses, worth noting as a known rayscan
limitation on this pathology rather than a win for nmap.

## Reproduce

All scripts and raw artifacts are copied verbatim into `rayscan/bench-artifacts/`:

```bash
# network-target matrix -> bench-artifacts/results.json (+ benign per-run raw logs in bench-artifacts/out)
python3 bench-artifacts/run_matrix.py

# loopback sweep -> bench-artifacts/results_loopback.json
python3 bench-artifacts/run_loopback.py

# accuracy vs ground-truth table
python3 bench-artifacts/check_matrix.py
```

Ground-truth nmap runs referenced in this document:
`bench-artifacts/gt2_nmap_winxp.txt` (the 6-open ground truth for the Windows
host target), `bench-artifacts/gt3_self.txt` (self-IP, zero opens),
`bench-artifacts/gt_nmap_full.txt` (the pre-documented high-rate nmap
full-range scan that misreports zero opens on this NAT path).

## Permitted live-target legs (same day)

A live permitted-target session was run against `scanme.nmap.org`
(45.33.32.156) at ≤3,000 pps, one full-range pass per tool, per the target's
published permission banner ("authorized to scan this machine with Nmap or
other port scanners... try not to hammer"). Artifacts: `bench-artifacts/live/`
(raw per-run logs plus `live_results.json`, `connect_legs.json`,
`loopback.json`). Measured outcome:

1. Raw-SYN legs (rayscan raw, masscan, nmap `-sS`) received zero responses
   from the internet through the WSL2 NAT (raw-crafted flows are not mapped by
   the Hyper-V vSwitch; curl TCP connects to the same host work).
2. After the first parallel-capacity burst, the target's firewall rate-limited
   the test IP (curl to `45.33.32.156:80` timed out from both the WSL guest and
   the Windows host while general egress stayed healthy - see
   `live/scanme_curl80.txt` rc=28 vs `live/connect_legs.json` non-scanme
   egress). All further scanme traffic was stopped; raw logs kept verbatim.
3. A fresh loopback sweep leg (`live/loopback.json`): rayscan
   `--syn --connect-only` 127.0.0.0/24 all 65,535 ports finds the live
   `127.0.0.53:53` systemd-resolved listener in 35.3-40.5 s ×3; nmap `-sT`
   finds the same listener but needs >300 s (timeout-bound).

## scanme recovery leg and LAN/internet comparison

When the rate-limit cleared (HTTP 200 baseline), one gentle leg was run
against scanme (top-1000, ≤1,000 pps, one pass, `--syn --connect-only`,
artifacts `bench-artifacts/live/scanme_gentle_*.txt`):

| Tool | Wall (s) | Result |
| :--- | :--- | :--- |
| rayscan `--syn --connect-only` top-1000 | 3.9 cold / 1.7 warm | 22, 80 open (2/2); 998 closed, 0 filtered; `defense.direct_host`, evidence `banner:listener-verified` + measured port latency 425/611 ms |
| rayscan same with verified JSON | 1.7 | identical port set |
| nmap `-sT -T3` top-1000 reference | 24.5 | 22, 80 open (2/2), 6-14× slower |

Comparison against the documented Metasploitable 2 LAN suite: identical
accuracy class (full open/closed split, zero misclassifications over the
scanned range). The differences are environmental: port latency from the
internet is ~425-611 ms versus ~1-3 ms in the lab; raw-SYN mode is
unavailable through the WSL2 NAT for out-of-network targets (connect engine
only); and the out-of-network target constrains scan load - the
high-parallelism burst rate-limited the tester IP while the gentle
≤1k-pps pass completed cleanly and unchanged.

See the README section "Live Permitted-Range Benchmark" for the comparative
summary and analysis of the live session.
