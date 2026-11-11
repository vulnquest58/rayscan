import json, re, subprocess, time, os

OUT = "/root/bench/live"
os.makedirs(OUT, exist_ok=True)
SCANME = "45.33.32.156"
results = {}

def timed(name, cmd, timeout_s):
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        rc = f"TIMEOUT({timeout_s})"
        stdout = e.stdout.decode(errors="replace") if e.stdout else ""
        stderr = e.stderr.decode(errors="replace") if e.stderr else ""
    wall = round(time.perf_counter() - start, 3)
    with open(f"{OUT}/{name}.txt", "w") as f:
        f.write(f"# rc={rc} wall={wall}\n--- STDOUT ---\n{stdout}\n--- STDERR ---\n{stderr}\n")
    print(f"{name}: rc={rc} wall={wall}s", flush=True)
    return {"rc": rc, "wall": wall, "stdout": stdout, "stderr": stderr}

# raw-out-of-WSL evidence: TCP connect to scanme:80 succeeds (HTML title)
r = timed("scanme_curl80", ["curl", "-sS", "-m", "8", "-o", "/dev/null", "-w",
                            "%{http_code} tcp=connect-ok", "http://45.33.32.156/"], 15)

# libcurl evidence, port 22
r = timed("scanme_curl22", ["curl", "-sS", "-m", "8", "-o", "/dev/null", "-w",
                            "%{http_code}", "http://45.33.32.156:22/"], 15)

def rays_opens(s):
    try:
        rep = json.loads(s)
        return sorted(f"{x['host']}:{x['port']}" for x in rep.get("open", []))
    except Exception:
        return []

def nmap_opens(s):
    return sorted({f"scanme:{m.group(1)}" for m in re.finditer(r"(\d+)/tcp\s+open", s)},
                  key=lambda x: int(x.split(":")[1]))

R = "/mnt/e/VulnQuest_Pro/rayscan/target/release/rayscan"

# rayscan default connect engine, full range
r = timed("scanme_rayscan_conn_full", [R, "scan", "--json", "-t", SCANME,
                                       "-p", "1-65535"], 900)
results["rayscan_conn_full"] = {"wall": r["wall"], "rc": r["rc"], "opens": rays_opens(r["stdout"])}

time.sleep(15)
# nmap connect-scan GT, full range
r = timed("scanme_nmap_sT_full", ["nmap", "-n", "-Pn", "--open", "-sT", "-T4",
                                  "-p", "1-65535", SCANME], 900)
results["nmap_sT_full"] = {"wall": r["wall"], "rc": r["rc"], "opens": nmap_opens(r["stdout"])}

time.sleep(15)
# light legs 1-1000
r = timed("scanme_rayscan_conn_light", [R, "scan", "--json", "-t", SCANME,
                                        "-p", "1-1000"], 180)
results["rayscan_conn_light"] = {"wall": r["wall"], "rc": r["rc"], "opens": rays_opens(r["stdout"])}

time.sleep(15)
r = timed("scanme_nmap_sT_light", ["nmap", "-n", "-Pn", "--open", "-sT", "-T4",
                                   "-p", "1-1000", SCANME], 300)
results["nmap_sT_light"] = {"wall": r["wall"], "rc": r["rc"], "opens": nmap_opens(r["stdout"])}

json.dump(results, open("/root/bench/live/connect_legs.json", "w"), indent=2)
print("\n=== CONNECT-ENGINE SUMMARY ===")
for k, v in results.items():
    print(f"{k:28s} wall={v['wall']:>7.2f}s rc={v['rc']} opens={v['opens']}")
