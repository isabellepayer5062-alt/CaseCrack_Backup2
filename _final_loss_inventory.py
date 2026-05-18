"""Final recovery accounting + group missing by subsystem for roadmap."""
import json
from collections import defaultdict
from pathlib import Path

WORKSPACE = Path(r"C:\Users\ya754\CaseCrack v1.0")
CC = WORKSPACE / "CaseCrack"
cls = json.load(open(WORKSPACE / "true_dead_classification.json"))
triage = json.load(open(WORKSPACE / "dead_module_triage.json"))

def mod_to_path(m): return CC / f"{m.replace('.', '/')}.py"

# Categorize current state
state = {"alive": [], "missing_rr": [], "missing_cr": [], "missing_reconnect": []}
for m in cls["runtime_reachable"]:
    (state["alive"] if mod_to_path(m).exists() else state["missing_rr"]).append(m)
for m in cls["conditionally_reachable"]:
    if mod_to_path(m).exists():
        state["alive"].append(m)
    else:
        state["missing_cr"].append(m)
for e in triage["reconnect"]:
    full = f"tools.burp_enterprise.{e['module']}"
    if not mod_to_path(full).exists():
        state["missing_reconnect"].append(full)

print("Recovery final state:")
print(f"  Alive (RR + CR): {len(state['alive'])} / {len(cls['runtime_reachable']) + len(cls['conditionally_reachable'])}")
print(f"  Missing RR: {len(state['missing_rr'])}")
print(f"  Missing CR: {len(state['missing_cr'])}")
print(f"  Missing reconnect: {len(state['missing_reconnect'])}")

# Group missing by subsystem (first segment after burp_enterprise)
missing_all = state["missing_rr"] + state["missing_cr"] + state["missing_reconnect"]
by_subsystem = defaultdict(list)
for m in missing_all:
    short = m.replace("tools.burp_enterprise.", "")
    parts = short.split(".")
    subsys = parts[0] if len(parts) > 1 else "(root)"
    by_subsystem[subsys].append(short)

print(f"\nMissing modules grouped by subsystem ({len(missing_all)} total):")
for subsys in sorted(by_subsystem, key=lambda s: -len(by_subsystem[s])):
    print(f"  {subsys}: {len(by_subsystem[subsys])}")

# Save authoritative loss inventory
out = WORKSPACE / "_final_loss_inventory.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump({
        "alive_count": len(state["alive"]),
        "missing_total": len(missing_all),
        "missing_runtime_reachable": state["missing_rr"],
        "missing_conditionally_reachable": state["missing_cr"],
        "missing_reconnect": state["missing_reconnect"],
        "by_subsystem": {k: sorted(v) for k, v in by_subsystem.items()},
    }, f, indent=2)
print(f"\nSaved: {out}")
