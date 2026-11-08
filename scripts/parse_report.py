import json
import sys

filename = sys.argv[1] if len(sys.argv) > 1 else "reports/metasploitable2-v0.2.0-comprehensive.json"
with open(filename, "r", encoding="utf-8") as f:
    d = json.load(f)

print("=" * 100)
print(f"SCAN REPORT: {filename}")
print(f"Target: {d.get('target', 'N/A')} | Ports Scanned: {d.get('ports', 'N/A')}")
print(f"Elapsed Time: {d.get('elapsed_ms', 0)/1000:.2f}s")
summary = d.get("summary", {})
print(f"Summary: open={summary.get('open', 0)} closed={summary.get('closed', 0)} filtered={summary.get('filtered', 0)} silent={summary.get('silent', 0)}")
print("-" * 100)
print(f"{'PORT':<9} {'STATE':<7} {'CONF':<7} {'SERVICE':<12} {'PRODUCT / VERSION':<25} {'RTT':<9} {'EVIDENCE'}")
print("-" * 100)

open_ports = d.get("open", []) or d.get("results", [])
for r in open_ports:
    port = f"{r.get('port')}/tcp"
    state = r.get("state", "open")
    conf = f"{r.get('confidence', 0)*100:.0f}%"
    srv = r.get("service") or {}
    sname = srv.get("name", "-")
    sprod = srv.get("product") or ""
    sver = srv.get("version") or ""
    pv = f"{sprod} {sver}".strip() or "-"
    rtt = f"{r.get('latency_ms', 0):.2f}ms"
    ev = r.get("evidence", "")
    print(f"{port:<9} {state:<7} {conf:<7} {sname:<12} {pv:<25} {rtt:<9} {ev}")
    tls = r.get("tls")
    if tls:
        print(f"         └─ TLS: {tls.get('version')} {tls.get('cipher')} | Subject: {tls.get('subject')}")
    advs = r.get("advisories", [])
    for a in advs:
        cve_id = a.get("id") or a.get("cve")
        title = a.get("title") or a.get("summary")
        print(f"         └─ Advisory: {cve_id} [{a.get('severity')}] (CVSS {a.get('cvss')}): {title}")

print("-" * 100)
os_fps = d.get("os_fingerprints") or d.get("os")
if os_fps:
    print("OS FINGERPRINTS:")
    print(json.dumps(os_fps, indent=2))
    print("-" * 100)

defense = d.get("defense") or d.get("defense_assessment")
if defense:
    print("DEFENSE & MIDDLEBOX INTELLIGENCE:")
    print(json.dumps(defense, indent=2))
    print("=" * 100)
