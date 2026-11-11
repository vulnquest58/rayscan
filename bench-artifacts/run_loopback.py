import json, subprocess, time

LOB = "127.0.0.1"
PORTS = "1-65535"
GT_LO = ["127.0.0.1:41113"]  # verified listener in earlier live tests
RAYS = "/mnt/e/VulnQuest_Pro/rayscan/target/release/rayscan"
out = {}

def timed(name, cmd, timeout_s):
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        rc = proc.returncode
        stdout = proc.stdout
    except subprocess.TimeoutExpired as e:
        rc = f"TIMEOUT({timeout_s})"
        stdout = e.stdout.decode(errors="replace") if e.stdout else ""
    wall = round(time.perf_counter() - start, 3)
    print(f"{name}: rc={rc} wall={wall}s", flush=True)
    return {"rc": rc, "wall": wall, "stdout": stdout}

def rays_opens(s):
    try:
        r = json.loads(s)
        return [f"{x['host']}:{x['port']}" for x in r.get("open", [])]
    except Exception:
        return []

results = {}

# rayscan /24 sweep full range, 3 runs
for i in range(3):
    r = timed(f"rayscan_lo_{i}", [RAYS, "scan", "--syn", "--connect-only", "--json",
                                  "--rate", "0", "--timeout", "1",
                                  "-t", "127.0.0.0/24", "-p", PORTS], 120)
    results[f"rayscan_lo_{i}"] = {"wall": r["wall"], "rc": r["rc"],
                                  "opens": rays_opens(r["stdout"])}

# nmap reference, 1 run
r = timed("nmap_lo_0", ["nmap", "-n", "-Pn", "--open", "-sS", "-T4",
                        "-p", PORTS, LOB], 300)
found = []
import re
for m in re.finditer(r"(\d+)/tcp\s+open", r["stdout"]):
    found.append(f"127.0.0.1:{m.group(1)}")
results["nmap_lo_0"] = {"wall": r["wall"], "rc": r["rc"], "opens": sorted(found)}

json.dump(results, open("/root/bench/results_loopback.json", "w"), indent=2)
print("\n=== LOOPBACK SUMMARY ===")
for k, v in results.items():
    print(k, v["wall"], "s opens:", v["opens"][:8], "count:", len(v["opens"]))
