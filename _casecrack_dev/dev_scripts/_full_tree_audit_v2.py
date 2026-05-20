"""
Phase 2 audit:
- Comprehensive import test (try ALL public modules, not just sample)
- Categorize broken-ref findings (guarded vs unguarded)
- Identify the actual missing referenced packages (atlas, production_subsystems, etc.)
"""
from __future__ import annotations
import ast
import importlib
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, ".")
ROOT = pathlib.Path("tools/burp_enterprise")
SKIP_DIRS = {"__pycache__", "_archive", "_cold_storage", "_phase1_loaders"}


def is_inside_try(tree: ast.AST, target_node: ast.AST) -> bool:
    """Return True if target_node is inside a try block (any depth)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for child in ast.walk(node):
                if child is target_node:
                    return True
    return False


# Walk all .py files (excluding skip dirs and underscore-prefixed)
all_files = []
for p in ROOT.rglob("*.py"):
    if any(s in p.parts for s in SKIP_DIRS):
        continue
    all_files.append(p)

# === Comprehensive import test ===
print(f"=== Import test on ALL {sum(1 for p in all_files if not p.name.startswith('_') and p.name != '__init__.py')} public modules ===")
fails = []
public_count = 0
for p in all_files:
    if p.name.startswith("_") or p.name == "__init__.py":
        continue
    rel_parts = p.relative_to(ROOT.parent.parent).with_suffix("").parts
    mod_name = ".".join(rel_parts)
    public_count += 1
    try:
        importlib.import_module(mod_name)
    except Exception as e:
        fails.append((mod_name, type(e).__name__, str(e)[:120]))

print(f"  Tested: {public_count}")
print(f"  Failed: {len(fails)}")
for mod, etype, msg in fails[:30]:
    print(f"  [FAIL] {mod}: {etype}: {msg}")
if len(fails) > 30:
    print(f"  ... +{len(fails) - 30} more")
print()

# === Detailed broken-ref scan with try-block awareness ===
print("=== Broken cross-references (UNGUARDED only) ===")
existing_modules = set()
for p in all_files:
    rel_parts = p.relative_to(ROOT.parent.parent).with_suffix("").parts
    existing_modules.add(".".join(rel_parts))
    if p.name == "__init__.py":
        existing_modules.add(".".join(rel_parts[:-1]))

unguarded_broken = []
guarded_broken_count = 0
target_summary = defaultdict(int)

for p in all_files:
    try:
        src = p.read_text(encoding="utf-8")
        tree = ast.parse(src)
    except Exception:
        continue
    rel_parts = p.relative_to(ROOT.parent.parent).with_suffix("").parts
    pkg = ".".join(rel_parts[:-1])
    
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ImportFrom) and node.module):
            continue
        # Resolve target
        if node.level > 0:
            base = pkg.split(".")
            base = base[: len(base) - node.level + 1]
            target = ".".join(base + node.module.split("."))
        else:
            target = node.module
        # Skip stdlib / third-party
        if not target.startswith("tools."):
            continue
        # Resolved against existing modules
        if any(em == target or em.startswith(target + ".") for em in existing_modules):
            continue
        # Only care about non-stdlib internal misses
        target_summary[target] += 1
        if is_inside_try(tree, node):
            guarded_broken_count += 1
        else:
            rel_p = p.relative_to(ROOT).as_posix()
            unguarded_broken.append((rel_p, node.lineno, target))

print(f"  Guarded (try/except) broken refs: {guarded_broken_count}")
print(f"  UNGUARDED broken refs: {len(unguarded_broken)}")
for rel_p, ln, target in unguarded_broken[:20]:
    print(f"  [UNGUARDED] {rel_p}:{ln} -> {target}")
if len(unguarded_broken) > 20:
    print(f"  ... +{len(unguarded_broken) - 20} more")

print()
print("=== Most-referenced missing targets ===")
for target, count in sorted(target_summary.items(), key=lambda x: -x[1])[:15]:
    print(f"  {count:3d}x  {target}")
