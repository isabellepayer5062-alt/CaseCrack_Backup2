"""Verify what's still missing is only garbage we intended to delete."""
import json
from pathlib import Path

WORKSPACE = Path(r"C:\Users\ya754\CaseCrack v1.0")
CC = WORKSPACE / "CaseCrack"

cls = json.load(open(WORKSPACE / "true_dead_classification.json"))
triage = json.load(open(WORKSPACE / "dead_module_triage.json"))
rmap = json.load(open(WORKSPACE / "execution_reality_map.json"))

def mod_to_path(mod_fqn: str) -> Path:
    return CC / f"{mod_fqn.replace('.', '/')}.py"

# Classify every module we knew about pre-damage
categories = {
    "runtime_reachable": cls["runtime_reachable"],
    "conditionally_reachable": cls["conditionally_reachable"],
    "truly_dead_garbage": [f"tools.burp_enterprise.{e['module']}" for e in triage["garbage"]],
    "truly_dead_cold": [f"tools.burp_enterprise.{e['module']}" for e in triage["cold_storage"]],
    "truly_dead_reconnect": [f"tools.burp_enterprise.{e['module']}" for e in triage["reconnect"]],
}

missing_by_cat = {}
for cat, mods in categories.items():
    missing = [m for m in mods if not mod_to_path(m).exists()]
    missing_by_cat[cat] = missing
    print(f"{cat}: {len(missing)}/{len(mods)} missing")

print(f"\n── Critical missing (should exist) ──")
critical_missing = (
    missing_by_cat["runtime_reachable"]
    + missing_by_cat["conditionally_reachable"]
    + missing_by_cat["truly_dead_reconnect"]
)
for m in critical_missing[:30]:
    print(f"  ❌  {m.replace('tools.burp_enterprise.', '')}")
print(f"Total critical missing: {len(critical_missing)}")

# Count _cold_storage
cs_dir = CC / "tools" / "burp_enterprise" / "_cold_storage"
if cs_dir.exists():
    cs_count = sum(1 for _ in cs_dir.rglob("*.py"))
    print(f"\n_cold_storage has {cs_count} files")
