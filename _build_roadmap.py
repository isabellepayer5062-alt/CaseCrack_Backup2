"""
Generate comprehensive RECONNECTION + REIMPLEMENTATION roadmap.

Inputs:
  - true_dead_classification.json   (RR / CR / TD)
  - dead_module_triage.json         (reconnect candidates with ROI scores)
  - _final_loss_inventory.json      (201 lost modules grouped by subsystem)
  - execution_reality_map.json      (current reachability + dangling imports)
  - /memories/repo/*.md             (design intent we already wrote)

Output:
  - RECONNECTION_ROADMAP.md         (the master plan)
  - reconnection_roadmap.json       (machine-readable task graph)
"""
from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from pathlib import Path

WORKSPACE = Path(r"C:\Users\ya754\CaseCrack v1.0")
CC = WORKSPACE / "CaseCrack"
BURP = CC / "tools" / "burp_enterprise"

cls    = json.load(open(WORKSPACE / "true_dead_classification.json"))
triage = json.load(open(WORKSPACE / "dead_module_triage.json"))
loss   = json.load(open(WORKSPACE / "_final_loss_inventory.json"))
rmap   = json.load(open(WORKSPACE / "execution_reality_map.json"))

def short(m): return m.replace("tools.burp_enterprise.", "")
def mod_to_path(m): return CC / f"{m.replace('.', '/')}.py"

# ── Build dangling-import index ──────────────────────────────────────────
dangling = rmap.get("dangling_imports", [])

# ── Inspect alive reconnect candidates: extract their public API ─────────
def inspect_module(p: Path):
    info = {"loc": 0, "classes": [], "functions": [], "exports": [], "imports_from_app": []}
    try:
        src = p.read_text(encoding="utf-8", errors="replace")
        info["loc"] = len(src.splitlines())
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                info["classes"].append(node.name)
            elif isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                info["functions"].append(node.name)
            elif isinstance(node, (ast.ImportFrom, ast.Import)):
                if isinstance(node, ast.ImportFrom) and node.module:
                    if "burp_enterprise" in node.module or node.module.startswith("tools."):
                        info["imports_from_app"].append(node.module)
        # Look for __all__
        m = re.search(r"__all__\s*=\s*\[([^\]]+)\]", src)
        if m:
            info["exports"] = [s.strip().strip("'\"") for s in m.group(1).split(",") if s.strip()]
    except Exception as e:
        info["error"] = str(e)
    return info

# ── Section 1: Reconnect candidates (50 alive, need wiring) ──────────────
recon_tasks = []
for entry in triage["reconnect"]:
    full = f"tools.burp_enterprise.{entry['module']}"
    p = mod_to_path(full)
    if not p.exists():
        continue  # shouldn't happen — all 50 recovered
    api = inspect_module(p)
    recon_tasks.append({
        **entry,
        "module_full": full,
        "path": str(p.relative_to(WORKSPACE)),
        "api_classes": api["classes"][:8],
        "api_functions": api["functions"][:8],
        "exports": api["exports"],
        "internal_imports": list(set(api["imports_from_app"]))[:5],
    })

# ── Section 2: Conditionally reachable (alive, need flag/trigger doc) ────
cr_alive = [m for m in cls["conditionally_reachable"] if mod_to_path(m).exists()]
cr_by_subsystem = defaultdict(list)
for m in cr_alive:
    parts = short(m).split(".")
    cr_by_subsystem[parts[0] if len(parts) > 1 else "(root)"].append(short(m))

# ── Section 3: Permanently lost (need reimplementation) ──────────────────
lost_by_subsystem = loss["by_subsystem"]
# Stub each lost module — we know the FQN; produce a reimplementation card
def reimpl_card(mod_short, subsystem):
    # Try to find related memory file
    mem_dir = Path(r"C:\Users\ya754\.claude")
    spec_hints = []
    name_parts = mod_short.replace(".", "_").lower()
    return {
        "module": mod_short,
        "subsystem": subsystem,
        "spec_source": "memory/repo notes + canonical schema + sibling modules",
        "rebuild_hints": [
            f"Search /memories/repo/ for matches on '{name_parts}'",
            f"Inspect surviving siblings under burp_enterprise/{subsystem}/",
            f"Check dangling imports in reality map referencing {mod_short}",
        ],
    }

reimpl_tasks = {}
for subsys, mods in lost_by_subsystem.items():
    reimpl_tasks[subsys] = [reimpl_card(m, subsys) for m in mods]

# ── Section 4: Subsystem priority (combine ROI + module count) ───────────
# Priority = (reconnect candidates in subsys) * 3 + (lost modules in subsys)
subsystem_priority = defaultdict(lambda: {"reconnect": 0, "lost": 0, "cr_alive": 0, "score": 0})
for t in recon_tasks:
    sub = t["subsystem"]
    subsystem_priority[sub]["reconnect"] += 1
for sub, mods in lost_by_subsystem.items():
    subsystem_priority[sub]["lost"] = len(mods)
for sub, mods in cr_by_subsystem.items():
    subsystem_priority[sub]["cr_alive"] = len(mods)
for sub, d in subsystem_priority.items():
    d["score"] = d["reconnect"] * 5 + d["lost"] * 2 + d["cr_alive"]

ranked_subsystems = sorted(subsystem_priority.items(), key=lambda x: -x[1]["score"])

# ── Save machine-readable roadmap ────────────────────────────────────────
roadmap_data = {
    "summary": {
        "reconnect_tasks": len(recon_tasks),
        "cr_documentation_tasks": len(cr_alive),
        "rr_baseline_tasks": len([m for m in cls["runtime_reachable"] if mod_to_path(m).exists()]),
        "reimplementation_tasks": sum(len(v) for v in reimpl_tasks.values()),
        "dangling_imports": len(dangling),
        "active_modules": rmap.get("totals", {}).get("total", 1174),
    },
    "subsystem_priority": dict(ranked_subsystems),
    "reconnect_tasks": recon_tasks,
    "cr_alive_by_subsystem": dict(cr_by_subsystem),
    "reimpl_tasks_by_subsystem": reimpl_tasks,
}
out_json = WORKSPACE / "RECONNECTION_ROADMAP.json"
with open(out_json, "w", encoding="utf-8") as f:
    json.dump(roadmap_data, f, indent=2)
print(f"Saved: {out_json}")
print(f"  Reconnect tasks: {len(recon_tasks)}")
print(f"  CR doc tasks: {len(cr_alive)}")
print(f"  Reimpl tasks: {sum(len(v) for v in reimpl_tasks.values())}")
print(f"  Subsystems: {len(subsystem_priority)}")
