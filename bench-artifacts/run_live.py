import json, re, subprocess, time, os

OUT = "/root/bench/live"
os.makedirs(OUT, exist_ok=True)

SCANME = "45.33.32.156"   # scanme.nmap.org (A record)
HT = "scanme.hackertarget.com"
RATE = 3000  # gentle, per scanme.nmap.org "don't hammer"

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

def rays_opens(s):
    try:
        r = json.loads(s)
        return sorted(f"{x['host']}:{x['port']}" for x in r.get("open", []))
    except Exception:
        return []

def nmap_opens(s):
    return sorted({f"scanme:{m.group(1)}" for m in re.finditer(r"(\d+)/tcp\s+open", s)})

def masscan_opens(txt):
    found = set()
    for line in open(f"{OUT}/{txt}", errors="replace"):
        for m in re.finditer(r"Discovered open port (\d+)/tcp", line):
            found.add(f"scanme:{m.group(1)}")
    return sorted(found)

def rustscan_opens(s):
    found = set()
    for m in re.finditer(r"(\d+):(\d+)", s):
        found.add(f"scanme:{m.group(2)}")
    return sorted(found, key=lambda x: int(x.split(":")[1]))

R = "/mnt/e/VulnQuest_Pro/rayscan/target/release/rayscan"
results = {}

# --- scanme.nmap.org (45.33.32.156) full range 1-65535, ONE scan per tool
ts = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())

r = timed("scanme_rayscan_raw", [R, "scan", "--syn", "--connect-only", "--json",
                                 "--rate", str(RATE), "--timeout", "1",
                                 "-t", "45.33.32.156", "-p", "1-65535"], 300)
results["rayscan_raw_full"] = {"wall": r["wall"], "rc": r["rc"], "opens": rays_opens(r["stdout"])}
time.sleep(20)

r = timed("scanme_nmap_sS", ["nmap", "-n", "-Pn", "--open", "-sS", "-T4",
                             "-p", "1-65535", SCANME], 900)
results["nmap_sS_full"] = {"wall": r["wall"], "rc": r["rc"], "opens": nmap_opens(r["stdout"])}
time.sleep(20)

r = timed("scanme_masscan", ["masscan", SCANME, "-p1-65535", "--rate", str(RATE),
                             "--open-only"], 300)
mass_out = "scanme_masscan.txt"
results["masscan_full"] = {"wall": r["wall"], "rc": r["rc"], "opens": masscan_opens(mass_out)}
time.sleep(20)

r = timed("scanme_rayscan_verified", [R, "scan", "--syn", "--json", "--rate", str(RATE),
                                      "--timeout", "1", "-t", "45.33.32.156", "-p", "1-65535"], 600)
results["rayscan_verified_full"] = {"wall": r["wall"], "rc": r["rc"], "opens": rays_opens(r["stdout"])}

# --- rustscan full range (own connect engine)
r = timed("scanme_rustscan", ["/home/vuln/.cargo/bin/rustscan", "-a", SCANME,
                              "-r", "1-65535", "-b", "3000", "-t", "2500",
                              "--no-banner", "-g"], 600)
results["rustscan_full"] = {"wall": r["wall"], "rc": r["rc"], "opens": rustscan_opens(r["stdout"])}

# --- scanme.hackertarget.com light leg 1-1000
ht_ip = subprocess.run(["getent", "ahostsv4", HT], capture_output=True, text=True)
ht_addr = ht_ip.stdout.split()[0] if ht_ip.stdout else ""
print("hackertarget ip:", ht_addr, flush=True)
if ht_addr:
    r = timed("ht_rayscan_light", [R, "scan", "--syn", "--connect-only", "--json",
                                   "--rate", "1000", "--timeout", "1",
                                   "-t", ht_addr, "-p", "1-1000"], 180)
    results["rayscan_ht_light"] = {"wall": r["wall"], "rc": r["rc"], "opens": rays_opens(r["stdout"])}
    time.sleep(15)
    r = timed("ht_nmap_light", ["nmap", "-n", "-Pn", "--open", "-sS", "-T4",
                                "-p", "1-1000", HT], 30)
    results["nmap_ht_light"] = {"wall": r["wall"], "rc": r["rc"], "opens": nmap_opens(r["stdout"])}

meta = {"scanme_ip": SCANME, "hackertarget_ip": ht_addr, "rate_cap_pps": RATE,
        "started": ts, "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())}
json.dump({"meta": meta, "results": results},
          open("/root/bench/live/live_results.json", "w"), indent=2)

print("\n=== LIVE SUMMARY ===")
for k, v in results.items():
    print(f"{k:26s} wall={v['wall']:>7.2f}s rc={v['rc']} opens={v['opens']}")
