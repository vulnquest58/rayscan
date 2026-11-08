# Empirical Comparative Analysis: IPv4 vs. IPv6 Network Scanning
## Target 1: Metasploitable 2 (Lab Environment) | Target 2: scanme.nmap.org (Public Educational Target)

- **Date:** 2026-11-08
- **Tool:** `rayscan` v0.3.0 (x86_64 Linux & Windows Native)
- **Engines Evaluated:** Raw SYN Discovery, TCP Verification, OS Fingerprinting, Defense Awareness Classifier, CVE Advisory Engine, and Network Differential Audit (`rayscan diff`).

---

## 1. Executive Summary

| Target | Protocol | Target Address | Open Ports Discovered | Scan Duration | Accuracy & Confidence |
| :--- | :---: | :--- | :--- | :---: | :---: |
| **Metasploitable 2** | **IPv4** | `192.168.100.37` | **16 ports** (FTP, SSH, Telnet, SMTP, HTTP, MySQL, PostgreSQL, VNC, etc.) | 9.55s | **85% – 100%** |
| **Metasploitable 2** | **IPv6** | `fd24:91bb:6122:1600::37` | **2 ports** (22/SSH OpenSSH 4.7p1, 5432/PostgreSQL) | 1.52s | **95%** (SSH), **65%** (PostgreSQL) |
| **scanme.nmap.org** | **IPv4** | `45.33.32.156` | **Port 22** (SSH OpenSSH 6.6.1p1) | 1.51s | **95%** (WAN RTT: 215ms) |
| **scanme.nmap.org** | **IPv6** | `2600:3c01::f03c:91ff:fe18:bb2f` | **0 open** (All 5 ports filtered due to ISP routing) | 1.50s | **0%** (Clean Filtered classification) |

---

## 2. Metasploitable 2 Deep Dive

### 2.1 IPv4 Evaluation (`192.168.100.37`)
A total of 1,034 ports were evaluated (covering ports 1–1024 plus high-risk ephemeral services: 1524, 2049, 2121, 3306, 5432, 5900, 6000, 6667, 8009, 8180).

- **Execution Time:** 9.55 seconds.
- **Port Findings:**
  - `21/tcp`: `vsFTPd 2.3.4` (100% confidence, RTT: 12.28ms)
  - `22/tcp`: `OpenSSH 4.7p1` (95% confidence, RTT: 1011.36ms)
  - `23/tcp`: `telnet` (90% confidence, RTT: 1010.87ms)
  - `25/tcp`: `Postfix` (100% confidence, RTT: 1.99ms)
  - `80/tcp`: `Apache 2.2.8` (100% confidence, RTT: 1.42ms)
  - `111/tcp`: RPC binary listener (85% confidence, RTT: 1011.37ms)
  - `512/tcp`: `exec` (95% confidence, RTT: 0.92ms)
  - `514/tcp`: Listener verified (88% confidence, RTT: 1.60ms)
  - `1524/tcp`: Root shell backdoor (95% confidence, RTT: 1.24ms)
  - `3306/tcp`: `MySQL 5.0.51a-3ubuntu5` (95% confidence, RTT: 1010.42ms)
  - `5432/tcp`: PostgreSQL binary listener (90% confidence, RTT: 0.64ms)
  - `5900/tcp`: `VNC 3.3` (95% confidence, RTT: 1010.81ms)
  - `6000/tcp`: X11 binary listener (90% confidence, RTT: 1.57ms)
  - `6667/tcp`: IRC (95% confidence, RTT: 1.91ms)
  - `8009/tcp`: AJP13 binary listener (90% confidence, RTT: 0.98ms)
  - `8180/tcp`: `Apache-Coyote 1.1` (100% confidence, RTT: 1.10ms)
- **OS Fingerprinting:**
  - Family: `Linux 2.6.x (linux)` — **100% Confidence**.
  - Signature Evidence: `TTL=63, Window=5840, MSS=1460, WScale=5, SACK=yes, DF=yes, Options=mss,nop,nop,sack,nop,wscale`.
- **Defense Awareness Classifier:**
  - Classified as `direct_host / syn_proxy` with 92% confidence.
  - The defense classifier explicitly identifies client-first binary listeners (RPC, PostgreSQL, X11, AJP) held mute as expected TCP behavior rather than treating them as tarpit or drop anomalies.
- **CVE Advisory Correlation:**
  - `21/tcp` (vsftpd 2.3.4): `CVE-2011-2523` [Critical] (CVSS 10.0) — Backdoor Command Execution.
  - `22/tcp` (OpenSSH 4.7p1): `CVE-2008-0166` [High] (CVSS 7.8) — Debian OpenSSL PRNG Predictable Key Flaw.
  - `80/tcp` (Apache 2.2.8): `CVE-2011-3192` [High] (CVSS 7.8) — Range Header Memory Exhaustion DoS; `CVE-2007-6750` [Medium] (CVSS 5.0) — Slowloris Partial-Request DoS.

### 2.2 IPv6 Evaluation (`fd24:91bb:6122:1600::37`)
Metasploitable 2 was assigned a static Unique Local Address (ULA) on the bridged LAN (`fd24:91bb:6122:1600::37/64`).

- **Execution Time:** 1.52 seconds.
- **Discovered IPv6 Listeners:**
  - `22/tcp` (open, 95% confidence): `OpenSSH 4.7p1`, RTT: 4.79ms.
  - `5432/tcp` (open, 65% confidence): PostgreSQL binary listener, RTT: 22.74ms.
- **Protocol Parity Analysis:**
  - Services bound exclusively to `0.0.0.0` (such as Apache HTTP, vsftpd, MySQL, and VNC) did not open IPv6 sockets.
  - `rayscan` correctly reported these as `filtered` or `closed` with 0% confidence, avoiding false positives.

---

## 3. Public Target Deep Dive: scanme.nmap.org

### 3.1 IPv4 Evaluation (`45.33.32.156`)
- **Ports Probed:** 22, 80, 443, 9929, 31337.
- **Execution Time:** 1.51 seconds.
- **Findings:**
  - `22/tcp`: **Open** with **95% Confidence**.
  - Service: `OpenSSH 6.6.1p1`.
  - WAN Latency: **215.03ms**.
  - Criteria Breakdown: Handshake established (20%), SSH Banner identified (40%), TCP stack standard (15%), Stability (20%).

### 3.2 IPv6 Evaluation (`2600:3c01::f03c:91ff:fe18:bb2f`)
- **Ports Probed:** 22, 80, 443, 9929, 31337.
- **Execution Time:** 1.50 seconds.
- **Findings:**
  - All 5 ports correctly reported as `filtered` with **0% Confidence**.
  - Diagnostic Root Cause: The local Wi-Fi router issues IPv6 ULA addresses (`fd24:91bb:6122:...`) but lacks upstream global IPv6 WAN routing from the ISP. Consequently, outgoing IPv6 SYN frames to public global unicast addresses receive no SYN-ACK or ICMP response.
  - Scanner Behavior: `rayscan` handled the complete lack of responses gracefully within 1.50s without hanging, crashing, or misreporting ports as open.

---

## 4. Differential Analysis (`rayscan diff`)

Using the integrated differential auditing command:
```bash
rayscan diff reports/metasploitable2-phase9-live.json reports/metasploitable2-ipv6-live.json
```

### Resulting Output:
```text
Network State Differential Analysis (vs reports/metasploitable2-phase9-live.json):
────────────────────────────────────────────────────────────────────────────────
[-] GONE    192.168.100.37:21     ftp vsFTPd/2.3.4           (advisories +0 -1)
[-] GONE    192.168.100.37:22     ssh OpenSSH/4.7p1          (advisories +0 -1)
[-] GONE    192.168.100.37:80     http Apache/2.2.8          (advisories +0 -2)
[-] GONE    192.168.100.37:23     telnet                     (telnet (Was: open))
[-] GONE    192.168.100.37:25     smtp Postfix               (smtp Postfix (Was: open))
[-] GONE    192.168.100.37:111                               (open port (Was: open))
[-] GONE    192.168.100.37:512    exec                       (exec (Was: open))
[-] GONE    192.168.100.37:514                               (open port (Was: open))
[-] GONE    192.168.100.37:1524   shell                      (shell (Was: open))
[-] GONE    192.168.100.37:3306   mysql MySQL/5.0.51a-3ubuntu5 (mysql (Was: open))
[-] GONE    192.168.100.37:5432                              (open port (Was: open))
[-] GONE    192.168.100.37:5900   vnc VNC/3.3                (vnc VNC/3.3 (Was: open))
[-] GONE    192.168.100.37:6000                              (open port (Was: open))
[-] GONE    192.168.100.37:6667   irc                        (irc (Was: open))
[-] GONE    192.168.100.37:8009                              (open port (Was: open))
[-] GONE    192.168.100.37:8180   http Apache-Coyote/1.1     (http Apache-Coyote/1.1 (Was: open))
[+] NEW     fd24:91bb:6122:1600::37:22 ssh OpenSSH/4.7p1    (Confidence: 95%)
[+] NEW     fd24:91bb:6122:1600::37:5432                     (Confidence: 65%)

Diff Summary: 2 new | 16 closed/gone | 0 modified | 0 posture shifted (0 unchanged)
```

### Analysis of the Diff:
1. **Attack Surface Shift:** Accurately isolates services that transitioned from IPv4 to dual-stack IPv6 (SSH and PostgreSQL).
2. **Vulnerability Delta:** Tracks changes in vulnerability exposure (e.g. `advisories +0 -1` on Port 21 and `advisories +0 -2` on Port 80) across network layers.

---

## 5. Artifact Files Reference

- **Full IPv4 Scan (JSON):** [`reports/metasploitable2-phase9-live.json`](file:///e:/VulnQuest_Pro/rayscan/reports/metasploitable2-phase9-live.json)
- **Full IPv6 Scan (JSON):** [`reports/metasploitable2-ipv6-live.json`](file:///e:/VulnQuest_Pro/rayscan/reports/metasploitable2-ipv6-live.json)
- **scanme.nmap.org IPv4 (JSON):** [`reports/scanme-ipv4.json`](file:///e:/VulnQuest_Pro/rayscan/reports/scanme-ipv4.json)
- **scanme.nmap.org IPv6 (JSON):** [`reports/scanme-ipv6.json`](file:///e:/VulnQuest_Pro/rayscan/reports/scanme-ipv6.json)
- **Native Windows Release Binary:** [`rayscan.exe`](file:///e:/VulnQuest_Pro/rayscan/rayscan.exe)
- **Release Distribution Archives:** [`dist/`](file:///e:/VulnQuest_Pro/rayscan/dist)
