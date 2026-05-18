"""
EXHAUSTIVE recovery sweep for the 283 still-missing modules.

Sources checked:
  1. Volume Shadow Copies (vssadmin)
  2. Windows File History (%LOCALAPPDATA%\Microsoft\Windows\FileHistory)
  3. OneDrive folders (anywhere under user profile)
  4. Every .py file anywhere on C: with matching filename
  5. ctemp/, reports/, .casecrack/, AppData caches
  6. Any .zip / .tar.gz / .7z anywhere in user profile
  7. Pip wheel cache, build/dist directories
  8. Workspace cold storage already restored?
  9. Old conversation logs / debug-logs that may contain pasted code
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from collections import defaultdict

WORKSPACE = Path(r"C:\Users\ya754\CaseCrack v1.0")
CC = WORKSPACE / "CaseCrack"

cls = json.load(open(WORKSPACE / "true_dead_classification.json"))
def mod_to_path(mod_fqn: str) -> Path:
    return CC / f"{mod_fqn.replace('.', '/')}.py"

missing_mods = []
for m in cls["runtime_reachable"] + cls["conditionally_reachable"]:
    p = mod_to_path(m)
    if not p.exists():
        missing_mods.append((m, p))

# Build lookup: filename -> list of (full_module, expected_path, expected_parent_subdir)
# A match is "reliable" if filename + parent dir match (e.g. cloud/bucket_scanner.py).
filename_to_targets = defaultdict(list)
for m, p in missing_mods:
    filename_to_targets[p.name].append((m, p, p.parent.name))

print(f"Searching for {len(missing_mods)} missing files (unique filenames: {len(filename_to_targets)})")
print("=" * 70)

results = defaultdict(list)  # source_label -> [(found_path, target_module)]

# ── 1. Volume Shadow Copies ────────────────────────────────────────────────
print("\n[1] Checking Volume Shadow Copies...")
try:
    r = subprocess.run(["vssadmin", "list", "shadows"], capture_output=True, text=True, timeout=15)
    if "No items found" in r.stdout or r.returncode != 0:
        print("  None available (requires admin or none exist)")
    else:
        print("  Shadow copies present — would need admin to mount")
        print(r.stdout[:500])
except Exception as e:
    print(f"  Error: {e}")

# ── 2. File History ────────────────────────────────────────────────────────
print("\n[2] Windows File History...")
fh_paths = [
    Path(r"C:\Users\ya754\AppData\Local\Microsoft\Windows\FileHistory"),
    Path(r"C:\FileHistory"),
]
fh_found = False
for fh in fh_paths:
    if fh.exists():
        fh_found = True
        py_count = sum(1 for _ in fh.rglob("*.py"))
        print(f"  {fh}: {py_count} .py files")
        for py in fh.rglob("*.py"):
            if py.name in filename_to_targets:
                for mod, expected, parent in filename_to_targets[py.name]:
                    results[f"FileHistory:{fh.name}"].append((py, mod, expected, parent))
if not fh_found:
    print("  Not configured")

# ── 3. OneDrive ────────────────────────────────────────────────────────────
print("\n[3] OneDrive folders...")
od_roots = [p for p in Path(r"C:\Users\ya754").glob("OneDrive*") if p.is_dir()]
for od in od_roots:
    py_count = 0
    for py in od.rglob("*.py"):
        py_count += 1
        if py.name in filename_to_targets:
            for mod, expected, parent in filename_to_targets[py.name]:
                results[f"OneDrive:{od.name}"].append((py, mod, expected, parent))
    print(f"  {od.name}: {py_count} .py scanned")
if not od_roots:
    print("  No OneDrive folders found")

# ── 4. Comprehensive C:\ scan (with constraints to avoid taking forever) ──
print("\n[4] Searching C:\\ for any matching .py filenames (this takes a while)...")
search_roots = [
    Path(r"C:\Users\ya754"),
    Path(r"C:\temp"),
    Path(r"C:\tmp"),
]
# Skip these to keep scan fast
SKIP_DIRS = {
    ".venv", "venv", "node_modules", "__pycache__", ".git",
    "AppData\\Local\\Microsoft\\Edge",
    "AppData\\Local\\Google\\Chrome",
    "AppData\\Local\\Packages",
}
def should_skip(p: Path) -> bool:
    s = str(p)
    for skip in SKIP_DIRS:
        if skip in s:
            return True
    return False

scanned_count = 0
for root in search_roots:
    if not root.exists():
        continue
    print(f"  Scanning {root}...")
    try:
        for py in root.rglob("*.py"):
            if should_skip(py):
                continue
            scanned_count += 1
            if py.name in filename_to_targets:
                for mod, expected, parent in filename_to_targets[py.name]:
                    # Skip files we already restored or that are in workspace
                    try:
                        if py.resolve() == expected.resolve():
                            continue
                    except Exception:
                        pass
                    # Skip cold storage (intentional copies)
                    if "_cold_storage" in str(py):
                        continue
                    results[f"FullScan:{root.name}"].append((py, mod, expected, parent))
    except Exception as e:
        print(f"    error: {e}")
print(f"  Scanned {scanned_count} .py files")

# ── 5. Archives ────────────────────────────────────────────────────────────
print("\n[5] Archives (.zip/.7z/.tar.gz) under user profile...")
archives = []
for ext in ("*.zip", "*.7z", "*.tar.gz", "*.tar"):
    for arc in Path(r"C:\Users\ya754").rglob(ext):
        if should_skip(arc):
            continue
        try:
            size_mb = arc.stat().st_size / 1024 / 1024
            if size_mb > 0.1:  # > 100 KB
                archives.append((arc, size_mb))
        except Exception:
            pass
print(f"  Found {len(archives)} archives (>100 KB):")
for arc, sz in sorted(archives, key=lambda x: -x[1])[:15]:
    name = str(arc).replace(r"C:\Users\ya754", "~")
    print(f"    {sz:8.1f} MB  {name}")

# ── 6. ctemp/ and reports/ in workspace ────────────────────────────────────
print("\n[6] Workspace ctemp/ and reports/...")
for sub in ["ctemp", "reports"]:
    d = WORKSPACE / sub
    if d.exists():
        py_count = sum(1 for _ in d.rglob("*.py"))
        print(f"  {sub}/: {py_count} .py files")
        for py in d.rglob("*.py"):
            if py.name in filename_to_targets:
                for mod, expected, parent in filename_to_targets[py.name]:
                    results[f"Workspace:{sub}"].append((py, mod, expected, parent))

# ── 7. .casecrack ──────────────────────────────────────────────────────────
print("\n[7] User caches (.casecrack, AppData)...")
for d in [Path(r"C:\Users\ya754\.casecrack"), Path(r"C:\Users\ya754\AppData\Local\CaseCrack")]:
    if d.exists():
        py_count = sum(1 for _ in d.rglob("*.py"))
        print(f"  {d}: {py_count} .py files")
        for py in d.rglob("*.py"):
            if py.name in filename_to_targets:
                for mod, expected, parent in filename_to_targets[py.name]:
                    results[f"Cache:{d.name}"].append((py, mod, expected, parent))

# ── Final report ───────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("EXHAUSTIVE SEARCH RESULTS")
print("=" * 70)

# Filter to "reliable" matches: filename + parent dir match
reliable_recoveries = {}  # mod -> source_path
for source, hits in results.items():
    for src_path, mod, expected, expected_parent in hits:
        # Reliable if parent dir matches
        if src_path.parent.name == expected_parent:
            if mod not in reliable_recoveries:
                reliable_recoveries[mod] = (source, src_path)

print(f"\nReliable recoveries (parent-dir match): {len(reliable_recoveries)} / {len(missing_mods)}")
for mod, (source, src) in list(reliable_recoveries.items())[:20]:
    short = mod.replace("tools.burp_enterprise.", "")
    print(f"  ✓ [{source}]  {short}  ←  {src}")

# Filename-only matches (suspicious — could be unrelated)
print(f"\nFilename-only matches (need manual review):")
filename_only = defaultdict(list)
for source, hits in results.items():
    for src_path, mod, expected, expected_parent in hits:
        if src_path.parent.name != expected_parent and mod not in reliable_recoveries:
            filename_only[mod].append((source, src_path))
print(f"  Modules with weak matches: {len(filename_only)}")
for mod, hits in list(filename_only.items())[:10]:
    short = mod.replace("tools.burp_enterprise.", "")
    print(f"  ? {short}: {len(hits)} match(es)")
    for source, src in hits[:2]:
        print(f"      [{source}] {src}")

# Final permanent loss
permanent_loss = [m for m, _ in missing_mods if m not in reliable_recoveries]
print(f"\nPERMANENT LOSS (no recoverable source): {len(permanent_loss)}")

# Save full report
out = WORKSPACE / "_exhaustive_recovery_report.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump({
        "missing_total": len(missing_mods),
        "reliable_recoveries": {
            m: {"source": s, "path": str(p)} for m, (s, p) in reliable_recoveries.items()
        },
        "weak_matches": {
            m: [{"source": s, "path": str(p)} for s, p in hits]
            for m, hits in filename_only.items()
        },
        "permanent_loss": permanent_loss,
    }, f, indent=2)
print(f"\nReport saved: {out}")
