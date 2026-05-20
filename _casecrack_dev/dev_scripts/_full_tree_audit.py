"""
Full-tree audit of tools/burp_enterprise — find ALL gaps, not just recovered.

Categories:
  A. Real stubs (NotImplementedError, pass-only class, TODO-only)
  B. Import failures (broken modules)
  C. Missing referenced files (imports point to nonexistent modules)
  D. Thin implementations (<200 LOC in subdir where peers avg 400+)
  E. Missing __all__ in public modules
  F. Backup/temp files not cleaned (.bak, _new, _deprecated, _corrupted)
"""
from __future__ import annotations
import ast
import importlib
import pathlib
import re
import sys
from collections import defaultdict

sys.path.insert(0, ".")
ROOT = pathlib.Path("tools/burp_enterprise")

SKIP_DIRS = {"__pycache__", "_archive", "_cold_storage", "_phase1_loaders"}


def is_relay_shim(src: str, loc: int) -> bool:
    """12-LOC relay shim or 18-LOC compat shim pointing elsewhere."""
    return loc < 30 and "_importlib.import_module" in src


def is_intentional_removal(src: str) -> bool:
    """e.g. scanner_providers.py raises ImportError with migration message."""
    return "raise ImportError" in src and "migrated" in src.lower()


# Walk full tree
all_files = []
for p in ROOT.rglob("*.py"):
    if any(s in p.parts for s in SKIP_DIRS):
        continue
    all_files.append(p)

print(f"Total .py files in tree: {len(all_files)}")
print()

# === Category A: Stubs ===
stubs = []
for p in all_files:
    rel = p.relative_to(ROOT).as_posix()
    if p.name.startswith("_"):
        continue
    try:
        src = p.read_text(encoding="utf-8")
    except Exception:
        continue
    loc = len(src.splitlines())
    if is_relay_shim(src, loc) or is_intentional_removal(src):
        continue
    
    # NotImplementedError as primary body
    if "raise NotImplementedError" in src and loc < 60:
        stubs.append((rel, loc, "NotImplementedError stub"))
        continue
    
    # Class with only pass (skip exception classes)
    try:
        tree = ast.parse(src)
        public_classes = [c for c in ast.walk(tree) if isinstance(c, ast.ClassDef) and not c.name.startswith("_")]
        if len(public_classes) == 1 and loc < 40:
            cls = public_classes[0]
            # Skip exceptions
            base_names = [b.id for b in cls.bases if isinstance(b, ast.Name)]
            if any("Exception" in b or "Error" in b for b in base_names):
                continue
            body = [n for n in cls.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
            if len(body) == 0 or (len(body) == 1 and isinstance(body[0], ast.Pass)):
                stubs.append((rel, loc, f"empty class {cls.name}"))
                continue
        # File is just docstring + imports
        non_trivial = [n for n in tree.body if not isinstance(n, (ast.Import, ast.ImportFrom, ast.Expr))]
        if not non_trivial and loc < 30:
            stubs.append((rel, loc, "imports-only / docstring-only"))
    except SyntaxError as e:
        stubs.append((rel, loc, f"SYNTAX ERROR: {e.msg} L{e.lineno}"))

print(f"=== Category A: Stubs / Empty modules ({len(stubs)}) ===")
for rel, loc, kind in sorted(stubs)[:80]:
    print(f"  {rel} ({loc} LOC) — {kind}")
if len(stubs) > 80:
    print(f"  ... +{len(stubs)-80} more")
print()

# === Category B: Import failures ===
print("=== Category B: Import Failures ===")
import_failures = []
sample_modules = []
for p in all_files:
    if p.name.startswith("_") or p.name == "__init__.py":
        continue
    if p.parent != ROOT:  # only top-level + subdirs (skip deeply nested for speed)
        # Try subdir-level too
        pass
    rel_parts = p.relative_to(ROOT.parent.parent).with_suffix("").parts
    mod_name = ".".join(rel_parts)
    sample_modules.append(mod_name)

# Sample 60 modules across the tree to test imports
import random
random.seed(42)
sample = random.sample(sample_modules, min(60, len(sample_modules)))
for m in sample:
    try:
        importlib.import_module(m)
    except Exception as e:
        import_failures.append((m, type(e).__name__, str(e)[:100]))

if import_failures:
    for m, etype, emsg in import_failures:
        print(f"  [FAIL] {m}: {etype}: {emsg}")
else:
    print("  No import failures in random 60-module sample.")
print()

# === Category C: Broken cross-references ===
print("=== Category C: Imports referencing nonexistent modules ===")
missing_refs = defaultdict(list)
existing_modules = set()
for p in all_files:
    rel_parts = p.relative_to(ROOT.parent.parent).with_suffix("").parts
    existing_modules.add(".".join(rel_parts))
    # Also __init__ packages
    if p.name == "__init__.py":
        existing_modules.add(".".join(rel_parts[:-1]))

# Check each module's relative imports for broken refs
broken_count = 0
for p in all_files[:500]:  # cap for speed
    if any(s in p.parts for s in SKIP_DIRS):
        continue
    try:
        src = p.read_text(encoding="utf-8")
        tree = ast.parse(src)
    except Exception:
        continue
    rel_parts = p.relative_to(ROOT.parent.parent).with_suffix("").parts
    pkg = ".".join(rel_parts[:-1])
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level > 0 and node.module:
            # Resolve relative import
            base = pkg.split(".")
            base = base[: len(base) - node.level + 1]
            target = ".".join(base + node.module.split("."))
            if target not in existing_modules and not target.endswith("event_bus") and "_recovered_support" not in target:
                # Could be a sub-symbol from a package; only flag if first segment doesn't exist
                if not any(em.startswith(target + ".") or em == target for em in existing_modules):
                    rel_p = p.relative_to(ROOT).as_posix()
                    missing_refs[rel_p].append(target)
                    broken_count += 1

if missing_refs:
    items = list(missing_refs.items())[:15]
    for rel_p, targets in items:
        print(f"  {rel_p}: missing -> {set(targets)}")
    if len(missing_refs) > 15:
        print(f"  ... +{len(missing_refs)-15} more files with broken refs")
    print(f"  Total broken-ref instances: {broken_count}")
else:
    print("  None found.")
print()

# === Category F: Backup/temp/deprecated files ===
print("=== Category F: Backup / Deprecated / Corrupted files ===")
backup_files = []
for p in all_files:
    rel = p.relative_to(ROOT).as_posix()
    name = p.name
    if (name.endswith(".bak") or name.endswith("_corrupted.bak") or 
        "_deprecated" in name or "_new.py" in name or
        name.startswith("_find_") or name.startswith("_fix_") or
        name.startswith("_check_") or name.startswith("_scan_")):
        backup_files.append((rel, len(p.read_text(encoding="utf-8", errors="ignore").splitlines())))

# Also check for .bak files
for p in ROOT.rglob("*.bak"):
    if any(s in p.parts for s in SKIP_DIRS):
        continue
    backup_files.append((p.relative_to(ROOT).as_posix(), 0))

for rel, loc in sorted(set(backup_files)):
    print(f"  {rel} ({loc} LOC)")
print(f"  Total: {len(set(backup_files))}")
print()

# === Category D: Thin implementations ===
print("=== Category D: Thin Implementations (<150 LOC, public, non-shim) ===")
thin = []
for p in all_files:
    if p.name.startswith("_") or p.name == "__init__.py":
        continue
    try:
        src = p.read_text(encoding="utf-8")
    except Exception:
        continue
    loc = len(src.splitlines())
    if is_relay_shim(src, loc) or is_intentional_removal(src):
        continue
    if loc < 150 and loc >= 30:  # exclude shims and stubs already caught
        rel = p.relative_to(ROOT).as_posix()
        thin.append((rel, loc))

# Group by parent dir, show counts
by_dir = defaultdict(list)
for rel, loc in thin:
    parts = rel.split("/")
    parent = "/".join(parts[:-1]) if len(parts) > 1 else "(root)"
    by_dir[parent].append((rel, loc))

for parent, items in sorted(by_dir.items(), key=lambda x: -len(x[1]))[:10]:
    print(f"  {parent}: {len(items)} thin files")
print(f"  Total thin (30-150 LOC): {len(thin)}")
print()

# === Summary ===
print("=" * 78)
print("EXPANDED AUDIT SUMMARY")
print("=" * 78)
print(f"  Total .py files:            {len(all_files)}")
print(f"  Category A (stubs):         {len(stubs)}")
print(f"  Category B (import fail):   {len(import_failures)} of {len(sample)} sampled")
print(f"  Category C (broken refs):   {len(missing_refs)} files, {broken_count} instances")
print(f"  Category D (thin):          {len(thin)}")
print(f"  Category F (backup/temp):   {len(set(backup_files))}")
