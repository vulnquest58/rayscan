#!/usr/bin/env python3
"""Real benchmark matrix runner: rayscan / masscan / rustscan / nmap.

Everything is measured from live process execution. No expected numbers are
used anywhere; results are written to /root/bench/results.json.
"""
import json
import os
import re
import subprocess
import time

TARGET = "172.22.64.1"
GT_OPEN = {80, 135, 139, 445, 2179, 49668}
RAYS = "/mnt/e/VulnQuest_Pro/rayscan/target/release/rayscan"
PORTS = "1-65535"
CAP_RATE = 10000

os.makedirs("/root/bench/out", exist_ok=True)


def timed(name, cmd, timeout_s):
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        rc = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as e:
        rc = f"TIMEOUT({timeout_s})"
        stdout = e.stdout.decode(errors="replace") if e.stdout else ""
        stderr = e.stderr.decode(errors="replace") if e.stderr else ""
    wall = time.perf_counter() - start
    out_path = f"/root/bench/out/{name}.txt"
    with open(out_path, "w") as f:
        f.write(f"# rc={rc} wall={wall:.3f}\n--- STDOUT ---\n{stdout}\n--- STDERR ---\n{stderr}\n")
    print(f"{name}: rc={rc} wall={wall:.2f}s -> {out_path}", flush=True)
    return {"rc": rc, "wall": round(wall, 3), "stdout": stdout, "stderr": stderr}


def ports_from_rayscan(stdout):
    try:
        report = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return set()
    return {(f"{r['host']}:{r['port']}") for r in report.get("open", [])}


def masscan_open(txt_log_path):
    found = set()
    for line in open(txt_log_path, errors="replace"):
        for m in re.finditer(r"Discovered open port (\d+)/tcp on ([\d.]+)", line):
            found.add(f"{m.group(2)}:{m.group(1)}")
    return found


def parse_generic_open(stdout):
    found = set()
    # nmap style "80/tcp open  http"
    for m in re.finditer(r"(\d+)/tcp\s+open", stdout):
        found.add(f"{TARGET}:{m.group(1)}")
    # rustscan style "172.22.64.1 -> [80,135,139]"
    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+) -> \[([\d,]+)\]", stdout):
        for port in m.group(2).split(","):
            if port:
                found.add(f"{m.group(1)}:{port}")
    # rustscan style "Open 172.22.64.1:80"
    for m in re.finditer(r"Open\s+(\d+\.\d+\.\d+\.\d+):(\d+)", stdout):
        found.add(f"{m.group(1)}:{m.group(2)}")
    return found


results = {}

masscan_json = "/root/bench/out/masscan_out.json"

# --- rayscan (unlimited rate), 3 runs
results["rayscan_unlimited"] = []
for i in range(3):
    r = timed(f"rayscan_u_{i}", [RAYS, "scan", "--syn", "--json", "--rate", "0",
                                 "--timeout", "1", "-t", TARGET, "-p", PORTS], 180)
    results["rayscan_unlimited"].append({
        "wall": r["wall"], "rc": r["rc"],
        "opens": sorted(ports_from_rayscan(r["stdout"])),
    })

# --- rayscan (capped 10k pps), 3 runs
results["rayscan_capped_10k"] = []
for i in range(3):
    r = timed(f"rayscan_c_{i}", [RAYS, "scan", "--syn", "--json", "--rate", str(CAP_RATE),
                                 "--timeout", "1", "-t", TARGET, "-p", PORTS], 180)
    results["rayscan_capped_10k"].append({
        "wall": r["wall"], "rc": r["rc"],
        "opens": sorted(ports_from_rayscan(r["stdout"])),
    })

# --- rayscan raw SYN (connect-only: no banner verification), 3+3 runs
results["rayscan_conn_unlimited"] = []
for i in range(3):
    r = timed(f"rayscan_cu_{i}", [RAYS, "scan", "--syn", "--connect-only", "--json",
                                  "--rate", "0", "--timeout", "1", "-t", TARGET,
                                  "-p", PORTS], 180)
    results["rayscan_conn_unlimited"].append({
        "wall": r["wall"], "rc": r["rc"],
        "opens": sorted(ports_from_rayscan(r["stdout"])),
    })
results["rayscan_conn_capped_10k"] = []
for i in range(3):
    r = timed(f"rayscan_cc_{i}", [RAYS, "scan", "--syn", "--connect-only", "--json",
                                  "--rate", str(CAP_RATE), "--timeout", "1", "-t", TARGET,
                                  "-p", PORTS], 180)
    results["rayscan_conn_capped_10k"].append({
        "wall": r["wall"], "rc": r["rc"],
        "opens": sorted(ports_from_rayscan(r["stdout"])),
    })

# --- masscan (capped 10k pps), 3 runs (needs timeout kill due to WSL2 UI bug)
results["masscan_capped_10k"] = []
for i in range(3):
    r = timed(f"masscan_c_{i}", ["masscan", TARGET, "-p" + PORTS,
                                 "--rate", str(CAP_RATE), "--open-only",
                                 "--wait", "0"], 120)
    opens = masscan_open(f"/root/bench/out/masscan_c_{i}.txt")
    results["masscan_capped_10k"].append({"wall": r["wall"], "rc": r["rc"],
                                          "opens": sorted(opens)})
    if r["rc"] == f"TIMEOUT(120)":
        results["masscan_capped_10k"][-1]["note"] = "killed by timeout (WSL2 progress readout never exits)"

# --- masscan (100k pps attempt; needs timeout kill due to WSL2 UI bug)
results["masscan_100k"] = []
r = timed("masscan_u_0", ["masscan", TARGET, "-p" + PORTS, "--rate", "100000",
                          "--open-only", "--wait", "0"], 120)
results["masscan_100k"] = [{
    "wall": r["wall"], "rc": r["rc"],
    "opens": sorted(masscan_open("/root/bench/out/masscan_u_0.txt")),
    "note": "rate=100000; killed at timeout due to WSL2 progress readout bug",
}]

# --- rustscan, 3 runs
RUSTSCAN = "/home/vuln/.cargo/bin/rustscan"
results["rustscan_10k_batch"] = []
for i in range(3):
    r = timed(f"rustscan_{i}", [RUSTSCAN, "-a", TARGET, "-r", PORTS,
                                "-b", str(CAP_RATE), "-t", "2500",
                                "--no-banner", "-g"], 180)
    results["rustscan_10k_batch"].append({
        "wall": r["wall"], "rc": r["rc"],
        "opens": sorted(parse_generic_open(r["stdout"])),
    })

# --- nmap SYN (single run, deterministic; reference tool)
r = timed("nmap_sS_0", ["nmap", "-n", "-Pn", "--open", "-sS", "-T4",
                        "-p", PORTS, TARGET], 600)
results["nmap_sS_T4"] = [{
    "wall": r["wall"], "rc": r["rc"],
    "opens": sorted(parse_generic_open(r["stdout"])),
}]

with open("/root/bench/results.json", "w") as f:
    json.dump({"gt_open": sorted(GT_OPEN), "target": TARGET,
               "port_range": PORTS, "capacity_rate": CAP_RATE,
               "results": results}, f, indent=2)

print("\n=== SUMMARY ===")
for tool, runs in results.items():
    walls = [r["wall"] for r in runs]
    ok = all(set(r["opens"]) == GT_OPEN for r in runs)
    print(f"{tool}: runs={len(runs)} wall={walls} all_matches_gt={ok}")
