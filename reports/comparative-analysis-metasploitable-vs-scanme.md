# Comparative Analysis: Local Lab Target vs. Public Educational WAN Target

**Tool:** `rayscan v0.2.0`  
**Date:** `2026-11-07`  
**Targets Evaluated:**
1. **Local Lab (LAN):** Metasploitable 2 (`192.168.100.37`)
2. **Public Educational (WAN):** `scanme.nmap.org` (`45.33.32.156`)

---

## 1. Comparative Matrix

| Evaluation Dimension | Metasploitable 2 (LAN Lab) | scanme.nmap.org (Internet WAN) | Analytical Meaning |
| :--- | :--- | :--- | :--- |
| **Network Proximity** | Local L2 Wi-Fi Bridge (`192.168.100.0/24`) | Public WAN (Fremont, CA, USA) | Tests scanner adaptability from <1ms LAN to >200ms trans-continental latency. |
| **Typical Latency (RTT)** | `0.54ms – 7.55ms` | `210.3ms – 222.2ms` | Stability scoring automatically adjusts to RTT scale without false penalization. |
| **Discovered Open Ports** | **17 open ports** (Range 1–10,000) | **1 open port** (22/tcp SSH) + silent HTTP 80 | Validates high-density service environments vs. minimal hardened public hosts. |
| **Application Identification** | vsFTPd 2.3.4, OpenSSH 4.7p1, Apache 2.2.8, MySQL 5.0.51a, VNC 3.3, UnrealIRCd, Tomcat 5.5, Ruby DRb | OpenSSH 6.6.1p1 (Ubuntu Linux) | Accurate extraction of product names and version strings across both environments. |
| **Accuracy Score (v0.2.0)** | **90% – 100%** on genuine services | **95%** (22/tcp SSH) | Binary listeners (111, 5432, 6000, 8009) now achieve solid 90% confidence. |
| **OS Fingerprinting** | `Linux 2.6.x` (**100%**) | Stack metrics evaluated over WAN hops | SYN-ACK TCP option parsing functions across raw sockets and routed paths. |
| **Defense Awareness** | Multi-Layer / Rate-Limiting Active | Clean Direct Endpoint / Tarpit Classifier | Accurately distinguishes between local buffer pressure and remote firewall filtering. |
| **Scan Speed & Ergonomics** | 10,000 ports in **55.28s** (`--rate 170`) | Top 100 ports in **1.62s** (native) / **1.93s** (SYN) | High-speed throughput without dropping packets or exhausting host resources. |

---

## 2. Key Findings & Engine Validations

### 1. Empirical Accuracy Engine Robustness
- **Clear Banner Services:** Services sending clear ASCII protocol banners (FTP, SSH, HTTP, MySQL, VNC) consistently score **95% – 100%** regardless of whether they are local or across the Internet.
- **Silent Binary Protocol Listeners:** In v0.1.0, services such as `rpcbind (111)`, `PostgreSQL (5432)`, and `X11 (6000)` scored ~70%. In v0.2.0, the newly integrated protocol awareness recognizes standard binary daemon ports, elevating their score to **90%** (`banner:binary-protocol(30%)`).

### 2. Defense Awareness & Middlebox Classification
- On `scanme.nmap.org`, rayscan evaluated the public firewall behavior: port 22 completed standard 3-way handshake with prompt banner (`[CLEAN] Direct Host`), while mute ports that accept TCP handshakes without application responses were cleanly identified and tagged with actionable guidance.

### 3. Cross-Platform Parity
- Tested both Windows native `rayscan.exe` and Linux `rayscan` (raw SYN via WSL2). Both produce identical JSON output structure, consistent accuracy classifications, and sub-second parsing times for change detection (`--diff`).
