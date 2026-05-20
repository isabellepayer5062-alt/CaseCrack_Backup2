"""
Smart recovery from flat-layout sources (Shopigy + backup copies).

The codebase used to be flat (all .py at burp_enterprise root). Files were
later organized into subpackages (cloud/, caap/, intel/, etc.). The
"reliable parent-dir match" check therefore failed for these.

Strategy:
1. For each missing module, gather all candidates by filename across:
   - Shopigy/tools/burp_enterprise
   - CaseCrack v1.0 - PayPal
   - CaseCrack v1.0 - Coinbase
   - CaseCrack v1.0 - Copy
   - OneDrive Shopigy
2. Detect collisions (same filename → multiple missing modules with that name)
3. For unique filenames, pick newest source
4. For collisions, leave for manual triage
5. Restore + verify
"""
from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path

WORKSPACE = Path(r"C:\Users\ya754\CaseCrack v1.0")
CC = WORKSPACE / "CaseCrack"

cls = json.load(open(WORKSPACE / "true_dead_classification.json"))
def mod_to_path(mod_fqn: str) -> Path:
    return CC / f"{mod_fqn.replace('.', '/')}.py"

missing = []
for m in cls["runtime_reachable"] + cls["conditionally_reachable"]:
    p = mod_to_path(m)
    if not p.exists():
        missing.append((m, p))

# Map filename -> list of (module_fqn, expected_path)
by_filename: dict[str, list[tuple[str, Path]]] = defaultdict(list)
for m, p in missing:
    by_filename[p.name].append((m, p))

# Source roots (flat layouts)
SOURCES = [
    Path(r"C:\Users\ya754\Shopigy\tools\burp_enterprise"),
    Path(r"C:\Users\ya754\OneDrive\Shopigy\tools\burp_enterprise"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - PayPal\CaseCrack\tools\burp_enterprise"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Coinbase\CaseCrack\tools\burp_enterprise"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Copy\CaseCrack\tools\burp_enterprise"),
]
SOURCES = [s for s in SOURCES if s.exists()]
print("Active sources:")
for s in SOURCES:
    print(f"  {s}")

# Build filename -> [(source_root, file_path, mtime)]
candidates: dict[str, list[tuple[Path, Path, float]]] = defaultdict(list)
for src_root in SOURCES:
    for py in src_root.rglob("*.py"):
        if "__pycache__" in str(py) or "_cold_storage" in str(py):
            continue
        try:
            mtime = py.stat().st_mtime
        except Exception:
            mtime = 0
        candidates[py.name].append((src_root, py, mtime))

# Classify each missing module
unique_recoverable = {}     # module -> (source_path, src_root)
collisions = {}              # module -> reason
no_source = []

for fname, modlist in by_filename.items():
    cands = candidates.get(fname, [])
    if not cands:
        for m, _ in modlist:
            no_source.append(m)
        continue

    if len(modlist) > 1:
        # Multiple missing modules share this filename — ambiguous which is which
        for m, _ in modlist:
            collisions[m] = f"filename '{fname}' is ambiguous across {len(modlist)} target modules"
        continue

    # Single module needs this filename — pick newest source
    cands.sort(key=lambda x: -x[2])
    src_root, src_path, mtime = cands[0]
    mod_fqn = modlist[0][0]
    unique_recoverable[mod_fqn] = (src_path, src_root)

print(f"\nMissing modules: {len(missing)}")
print(f"  Unique recoverable: {len(unique_recoverable)}")
print(f"  Collisions (ambiguous): {len(collisions)}")
print(f"  No source: {len(no_source)}")

# ── Execute restoration ──
restored = 0
errors = []
for mod, (src_path, src_root) in unique_recoverable.items():
    target = mod_to_path(mod)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_path), str(target))
        restored += 1
    except Exception as e:
        errors.append((mod, str(e)))

print(f"\nRestored: {restored}")
if errors:
    print(f"Errors: {len(errors)}")
    for m, e in errors[:5]:
        print(f"  {m}: {e}")

# Save final report
out = WORKSPACE / "_smart_recovery_report.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump({
        "restored": [
            {"module": m, "source": str(p), "from_root": str(r)}
            for m, (p, r) in unique_recoverable.items()
        ],
        "collisions": collisions,
        "no_source": no_source,
    }, f, indent=2)
print(f"\nReport: {out}")

# Show collision details (these are still "lost" until we manually disambiguate)
if collisions:
    print(f"\nFirst 10 collisions to inspect:")
    for m, reason in list(collisions.items())[:10]:
        print(f"  {m.replace('tools.burp_enterprise.', '')}: {reason}")
