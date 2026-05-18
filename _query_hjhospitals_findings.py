#!/usr/bin/env python3
"""Query hjhospitals scan findings and attack graph — run during/after scan."""
import urllib.request, json, sys
from collections import Counter

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE = "http://localhost:8770"

def get_token():
    with urllib.request.urlopen(BASE + "/api/token", timeout=10) as r:
        return json.loads(r.read())["token"]

def fetch(path, tok, timeout=30):
    req = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + tok})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

tok = get_token()
print("Token OK:", tok[:8], "...")

# Status
st = fetch("/api/standalone/status", tok)
print("\n=== SCAN STATUS ===")
print("  completed :", st.get("completed_phases"), "/", len(st.get("phase_status", {})))
print("  findings  :", st.get("findings_count"))
print("  running   :", st.get("running_phases", []))
print("  is_complete:", st.get("is_complete"))

ps = st.get("phase_status", {})
degraded = [p for p,s in ps.items() if s == "degraded"]
if degraded:
    print("  DEGRADED  :", degraded)

# Findings
try:
    fd = fetch("/api/findings/unified?limit=500", tok, timeout=60)
    findings = fd.get("findings", fd.get("data", []))
    print(f"\n=== FINDINGS ({len(findings)} total from unified endpoint) ===")
    sev = Counter(f.get("severity","?").upper() for f in findings)
    print("  By severity:", dict(sev.most_common()))

    print("\n--- CRITICAL ---")
    for f in findings:
        if f.get("severity","").upper() == "CRITICAL":
            print("  [CRIT]", f.get("title","?"))
            print("        ", (f.get("url") or f.get("target",""))[:120])

    print("\n--- HIGH ---")
    for f in findings:
        if f.get("severity","").upper() == "HIGH":
            print("  [HIGH]", f.get("title","?"))
            print("        ", (f.get("url") or f.get("target",""))[:120])

    print("\n--- MEDIUM (first 30) ---")
    count = 0
    for f in findings:
        if f.get("severity","").upper() == "MEDIUM":
            print("  [MED] ", f.get("title","?"))
            count += 1
            if count >= 30:
                break
except Exception as e:
    print("Findings fetch error:", e)

# Exploit graph
try:
    ag = fetch("/api/exploit-graph", tok, timeout=30)
    chains = ag.get("attack_chains", ag.get("chains", []))
    nodes  = ag.get("node_count", len(ag.get("nodes", [])))
    edges  = ag.get("edge_count", len(ag.get("edges", [])))
    print(f"\n=== EXPLOIT GRAPH ===")
    print(f"  nodes={nodes}  edges={edges}  chains={len(chains)}")
    for i, c in enumerate(chains[:20]):
        print(f"  Chain {i+1}:", json.dumps(c)[:300])
except Exception as e:
    print("Exploit graph error:", e)

# Exploit paths
try:
    paths = fetch("/api/exploit-graph/paths", tok, timeout=20)
    plist = paths.get("paths", [])
    print(f"\n=== EXPLOIT PATHS ({len(plist)} paths) ===")
    for i, p in enumerate(plist[:10]):
        print(f"  Path {i+1}:", json.dumps(p)[:300])
except Exception as e:
    print("Exploit paths error:", e)

print("\nDone.")
