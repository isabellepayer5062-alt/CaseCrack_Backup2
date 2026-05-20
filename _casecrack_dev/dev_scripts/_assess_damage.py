"""Assess damage: which modules from the pre-cleanup state are now missing?"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CC = ROOT / "CaseCrack"

# Pre-cleanup module lists
cls_data = json.load(open("true_dead_classification.json"))
all_pre = set(cls_data["runtime_reachable"] + cls_data["conditionally_reachable"] + cls_data["truly_dead"])

# Also add executed modules from pre-cleanup reality map
# (the truly_dead_classification was built from the same data)

def module_exists(mod):
    rel = mod.replace(".", "/")
    py = CC / f"{rel}.py"
    if py.exists():
        return True
    pkg = CC / rel / "__init__.py"
    if pkg.exists():
        return True
    return False

missing = []
for mod in sorted(all_pre):
    if not module_exists(mod):
        missing.append(mod)

# Categorize by original classification
rr = set(cls_data["runtime_reachable"])
cr = set(cls_data["conditionally_reachable"])
td = set(cls_data["truly_dead"])

# Also need executed modules - load from reality map backup
# The true_dead_classification was built from 856 dead modules
# Total was 1666, so 1666-856 = 810 executed
# But we don't have the old executed list anymore... 
# Let's check the triage JSON for reconnect modules
triage = json.load(open("dead_module_triage.json"))
reconnect_mods = set(f"tools.burp_enterprise.{e['module']}" for e in triage["reconnect"])

missing_rr = [m for m in missing if m in rr]
missing_cr = [m for m in missing if m in cr]
missing_td = [m for m in missing if m in td]
missing_reconnect = [m for m in missing if m in reconnect_mods]

PREFIX = "tools.burp_enterprise."
print(f"Total pre-cleanup modules checked: {len(all_pre)}")
print(f"Total missing from disk: {len(missing)}")
print(f"  Missing RUNTIME_REACHABLE: {len(missing_rr)}")
print(f"  Missing CONDITIONALLY_REACHABLE: {len(missing_cr)}")
print(f"  Missing TRULY_DEAD: {len(missing_td)}")
print(f"  Missing RECONNECT candidates: {len(missing_reconnect)}")

# Which subsystems lost modules?
from collections import Counter
missing_subs = Counter()
for m in missing:
    short = m.replace(PREFIX, "")
    parts = short.split(".")
    missing_subs[parts[0]] += 1

print(f"\nDamaged subsystems:")
for sub, count in missing_subs.most_common(20):
    print(f"  {sub}: {count} missing")

# Most critically: which reconnect candidates are gone?
if missing_reconnect:
    print(f"\n⚠️ MISSING RECONNECT CANDIDATES:")
    for m in sorted(missing_reconnect):
        print(f"  {m.replace(PREFIX, '')}")
