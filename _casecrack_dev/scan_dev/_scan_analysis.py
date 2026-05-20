import json, urllib.request
from collections import Counter, defaultdict

TOKEN = "YbX_VV84LaC7LSJYyToPYztXcmGvTg113fjwwmWbevE"
BASE = "http://localhost:8770"

def api(path):
    req = urllib.request.Request(BASE+path, headers={"Authorization": "Bearer " + TOKEN})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())

status = api("/api/standalone/status")
print("=== FINAL SCAN STATUS ===")
print("is_complete   :", status.get("is_complete"))
print("running       :", status.get("running"))
print("findings_count:", status.get("findings_count"))
print("running_phases:", status.get("running_phases"))
print("completed     :", status.get("completed_phases"))
phases = status.get("phase_status", {})
print("total phases  :", len(phases))
print()
print("=== PHASE STATUS BREAKDOWN ===")
ct = Counter(phases.values())
for s, n in sorted(ct.items()):
    print("  {:20s}: {}".format(s, n))
print()
print("=== NON-OK PHASES ===")
for ph, st in sorted(phases.items()):
    if st != "ok":
        print("  [{:12s}] {}".format(st, ph))

try:
    findings_resp = api("/api/standalone/findings")
    by_sev = defaultdict(list)
    by_cat = defaultdict(int)
    by_phase = defaultdict(list)
    for f in findings_resp.get("findings", []):
        sev = f.get("severity", "unknown")
        cat = f.get("category", "unknown")
        phase = f.get("phase", "unknown")
        title = f.get("title","")
        by_sev[sev].append(title)
        by_cat[cat] += 1
        by_phase[phase].append({"sev":sev,"title":title})
    print()
    print("=== FINDINGS BY SEVERITY ===")
    for sev in ["critical","high","medium","low","info","unknown"]:
        items = by_sev.get(sev, [])
        if items:
            print("  {:10s}: {:4d}".format(sev.upper(), len(items)))
    total = sum(len(v) for v in by_sev.values())
    print("  TOTAL      :", total)
    print()
    print("=== FINDINGS BY CATEGORY (top 25) ===")
    for cat, n in sorted(by_cat.items(), key=lambda x: -x[1])[:25]:
        print("  {:40s}: {}".format(cat, n))
    print()
    print("=== HIGH/CRITICAL FINDINGS ===")
    for sev in ["critical", "high"]:
        for title in sorted(set(by_sev.get(sev, []))):
            print("  [{}] {}".format(sev.upper(), title))
    print()
    print("=== MEDIUM FINDINGS ===")
    for title in sorted(set(by_sev.get("medium", []))):
        print("  [MEDIUM] {}".format(title))
except Exception as e:
    print("Findings API error:", e)
