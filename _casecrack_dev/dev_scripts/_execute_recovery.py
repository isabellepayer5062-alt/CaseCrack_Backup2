"""
Execute recovery from VS Code local history.

Restore strategy:
  - Restore all files that were classified as RUNTIME_REACHABLE
  - Restore all files that were classified as CONDITIONALLY_REACHABLE
  - Restore all files that were classified as RECONNECT candidates
  - Restore all files in COLD_STORAGE list (these already moved but we can verify)
  - Do NOT restore garbage files (the whole point was to delete them)
  - Restore any EXECUTED module that's now missing (collateral damage)
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

WORKSPACE = Path(r"C:\Users\ya754\CaseCrack v1.0")
CC = WORKSPACE / "CaseCrack"

# ── Load recovery plan ───────────────────────────────────────────────────────
plan = json.load(open(WORKSPACE / "_recovery_plan.json"))
print(f"Recovery plan has {plan['recoverable_count']} files")

# ── Load classification ──────────────────────────────────────────────────────
cls = json.load(open(WORKSPACE / "true_dead_classification.json"))
triage = json.load(open(WORKSPACE / "dead_module_triage.json"))

def mod_to_path(mod_fqn: str) -> Path:
    """Convert 'tools.burp_enterprise.X.Y' to CaseCrack/tools/burp_enterprise/X/Y.py"""
    rel = mod_fqn.replace(".", "/")
    return CC / f"{rel}.py"

# Modules that SHOULD exist after cleanup
should_exist: set[Path] = set()

# Runtime reachable
for m in cls["runtime_reachable"]:
    should_exist.add(mod_to_path(m))
# Conditionally reachable
for m in cls["conditionally_reachable"]:
    should_exist.add(mod_to_path(m))
# Reconnect candidates
for e in triage["reconnect"]:
    should_exist.add(mod_to_path(f"tools.burp_enterprise.{e['module']}"))

# Garbage set (do NOT restore)
garbage_set: set[Path] = set()
for e in triage["garbage"]:
    garbage_set.add(mod_to_path(f"tools.burp_enterprise.{e['module']}"))

# Cold-storage set (should now be in _cold_storage/, so original paths = garbage for this purpose)
cold_set: set[Path] = set()
for e in triage["cold_storage"]:
    cold_set.add(mod_to_path(f"tools.burp_enterprise.{e['module']}"))

print(f"Should exist: {len(should_exist)}")
print(f"Garbage (do not restore): {len(garbage_set)}")
print(f"Cold storage (skip): {len(cold_set)}")

# ── Execute recovery ─────────────────────────────────────────────────────────
restored = 0
skipped_garbage = 0
skipped_cold = 0
unknown_restored = 0  # files not in our classification (likely executed modules)
errors = []

for entry in plan["files"]:
    target = Path(entry["target"])
    snapshot = Path(entry["snapshot"])

    # Skip if target exists now
    if target.exists():
        continue

    # Skip garbage
    if target in garbage_set:
        skipped_garbage += 1
        continue

    # Skip cold (already moved)
    if target in cold_set:
        skipped_cold += 1
        continue

    # Restore
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(snapshot), str(target))
        if target in should_exist:
            restored += 1
        else:
            unknown_restored += 1
    except Exception as e:
        errors.append((str(target), str(e)))

print(f"\nRestored (classified): {restored}")
print(f"Restored (executed/unknown): {unknown_restored}")
print(f"Skipped garbage: {skipped_garbage}")
print(f"Skipped cold-storage: {skipped_cold}")
print(f"Errors: {len(errors)}")

if errors:
    print("\nErrors:")
    for t, e in errors[:10]:
        print(f"  {t}: {e}")

# ── Verify key recovery targets ──────────────────────────────────────────────
print("\n── Verification of key reconnect candidates ──")
critical = [
    "tools.burp_enterprise.agents.advanced_agent_patterns",
    "tools.burp_enterprise.agents.advanced_orchestration",
    "tools.burp_enterprise.exploit_chains.manual_audit_engine",
    "tools.burp_enterprise.recon_dashboard.cross_target_intelligence",
    "tools.burp_enterprise.exploitation.engine",
    "tools.burp_enterprise.agents.fork_spawn",
    "tools.burp_enterprise.agents.role_registry",
    "tools.burp_enterprise.agents.speculative_executor",
    "tools.burp_enterprise.agents.conflict_arbitration",
]
for m in critical:
    p = mod_to_path(m)
    status = "✅" if p.exists() else "❌"
    print(f"  {status}  {m.replace('tools.burp_enterprise.', '')}")
