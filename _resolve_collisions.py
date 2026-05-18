"""Resolve collisions: copy the single source file to ALL target modules sharing that filename."""
import json, shutil
from collections import defaultdict
from pathlib import Path

WORKSPACE = Path(r"C:\Users\ya754\CaseCrack v1.0")
CC = WORKSPACE / "CaseCrack"

cls = json.load(open(WORKSPACE / "true_dead_classification.json"))
def mod_to_path(m): return CC / f"{m.replace('.', '/')}.py"

# Re-derive missing AFTER smart recovery
missing = []
for m in cls["runtime_reachable"] + cls["conditionally_reachable"]:
    if not mod_to_path(m).exists():
        missing.append((m, mod_to_path(m)))

by_filename = defaultdict(list)
for m, p in missing:
    by_filename[p.name].append((m, p))

SOURCES = [
    Path(r"C:\Users\ya754\Shopigy\tools\burp_enterprise"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - PayPal\CaseCrack\tools\burp_enterprise"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Coinbase\CaseCrack\tools\burp_enterprise"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Copy\CaseCrack\tools\burp_enterprise"),
]
SOURCES = [s for s in SOURCES if s.exists()]

# Build filename -> newest available source
by_src = {}
for src_root in SOURCES:
    for py in src_root.rglob("*.py"):
        if "__pycache__" in str(py): continue
        try: mtime = py.stat().st_mtime
        except: mtime = 0
        if py.name not in by_src or by_src[py.name][1] < mtime:
            by_src[py.name] = (py, mtime)

restored = 0
no_source = []
for fname, modlist in by_filename.items():
    if fname not in by_src:
        no_source.extend(m for m, _ in modlist)
        continue
    src_path, _ = by_src[fname]
    for mod, target in modlist:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_path), str(target))
        restored += 1

print(f"Collision-resolved restorations: {restored}")
print(f"Still no source: {len(no_source)}")

# Final state count
final_missing = []
for m in cls["runtime_reachable"] + cls["conditionally_reachable"]:
    if not mod_to_path(m).exists():
        final_missing.append(m)
print(f"\nFINAL missing critical: {len(final_missing)}")
for m in final_missing[:30]:
    print(f"  {m.replace('tools.burp_enterprise.', '')}")
