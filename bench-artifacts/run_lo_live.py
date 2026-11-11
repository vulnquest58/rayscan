import json, re, subprocess, time, os

OUT = "/root/bench/live"
PORTS = "1-65535"
results = {}

def timed(name, cmd, timeout_s):
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        rc, stdout = proc.returncode, proc.stdout
    except subprocess.TimeoutExpired as e:
        rc = f"TIMEOUT({timeout_s})"
        stdout = e.stdout.decode(errors="replace") if e.stdout else ""
    wall = round(time.perf_counter() - start, 3)
    with open(f"{OUT}/{name}.txt", "w") as f:
        f.write(f"# rc={rc} wall={wall}\n--- STDOUT ---\n{stdout}\n")
    print(f"{name}: rc={rc} wall={wall}s", flush=True)
    return {"rc": rc, "wall": wall, "stdout": stdout}

def rays_opens(s):
    try:
        rep = json.loads(s)
        return sorted(f"{x['host']}:{x['port']}" for x in rep.get("open", []))
    except Exception:
        return []

def nmap_opens(s):
    hosts = []
    host_now = ""
    for line in s.splitlines():
        m = re.match(r"Nmap scan report for (\S+)", line)
        if m:
            host_now = m.group(1)
        pm = re.match(r"(\d+)/tcp\s+open", line)
        if pm and host_now:
            hosts.append(f"{host_now}:{pm.group(1)}")
    return sorted(hosts)

R = "/mnt/e/VulnQuest_Pro/rayscan/target/release/rayscan"

for i in range(3):
    r = timed(f"lo_rayscan_{i}", [R, "scan", "--syn", "--connect-only", "--json",
                                  "--rate", "0", "--timeout", "1",
                                  "-t", "127.0.0.0/24", "-p", PORTS], 120)
    results[f"rayscan_lo_{i}"] = {"wall": r["wall"], "rc": r["rc"], "opens": rays_opens(r["stdout"])}

r = timed("lo_nmap_sT", ["nmap", "-n", "-Pn", "--open", "-sT", "-T4",
                         "-p", PORTS, "127.0.0.0/24"], 300)
results["nmap_sT_lo"] = {"wall": r["wall"], "rc": r["rc"], "opens": nmap_opens(r["stdout"])}

json.dump(results, open("/root/bench/live/loopback.json", "w"), indent=2)
print("\n=== LOOPBACK LIVE SUMMARY ===")
for k, v in results.items():
    print(f"{k:16s} wall={v['wall']:>7.2f}s opens[:6]={v['opens'][:6]} count={len(v['opens'])}")
