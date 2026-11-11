import json

r = json.load(open("/root/bench/results.json"))
gt = {f"{r['target']}:{p}" for p in r["gt_open"]}
print("GT:", sorted(gt), "\n")
for tool, runs in r["results"].items():
    for i, run in enumerate(runs):
        got = set(run["opens"])
        miss = gt - got
        extra = got - gt
        verdict = "MATCH" if not miss and not extra else (
            "MISS " + ",".join(p.split(":")[1] for p in sorted(miss, key=lambda x: int(x.split(":")[1]))))
        if extra:
            verdict += " +EXTRA " + ",".join(sorted(extra))
        print(f"{tool} #{i}: wall={run['wall']:>7.2f}s rc={run['rc']} -> {verdict}")
