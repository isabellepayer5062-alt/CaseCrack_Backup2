"""Check full shim chain: root-level backward-compat shims → final canonicals."""
from __future__ import annotations
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

root = pathlib.Path("tools/burp_enterprise")

# Pattern for backward-compat shims at root level
# "This module has been moved to `tools.burp_enterprise.subdir.module`"
moved_pattern = re.compile(
    r"tools\.burp_enterprise\.(\w+)\.(\w+)"
)

total = 0
broken_chain = []
ok_chain = []
both_shims = []  # both root and target are shims

for p in sorted(root.glob("*.py")):
    if p.name.startswith("__"):
        continue
    src = p.read_text(encoding="utf-8")
    n = len(src.splitlines())
    if n > 30:
        continue  # Not a shim
    m = moved_pattern.search(src)
    if not m:
        continue
    total += 1
    subdir_name, module_name = m.group(1), m.group(2)
    target = root / subdir_name / f"{module_name}.py"
    if not target.exists():
        broken_chain.append(f"  {p.name} -> {subdir_name}/{module_name}.py [MISSING FINAL TARGET]")
    else:
        target_src = target.read_text(encoding="utf-8")
        target_n = len(target_src.splitlines())
        if target_n <= 20:
            both_shims.append(f"  {p.name} -> {subdir_name}/{module_name}.py ({target_n}L = relay shim)")
        else:
            ok_chain.append(f"  {p.name} -> {subdir_name}/{module_name}.py ({target_n}L)")

print(f"Total root-level compat shims: {total}")
print(f"OK chain (real target): {len(ok_chain)}")
print(f"Both shims (relay-to-relay): {len(both_shims)}")
print(f"Broken chain (missing final): {len(broken_chain)}")
print()

if broken_chain:
    print("--- BROKEN CHAIN ---")
    for s in broken_chain:
        print(s)
    print()

if both_shims:
    print(f"--- DOUBLE-RELAY (first 10 of {len(both_shims)}) ---")
    for s in both_shims[:10]:
        print(s)
    print()

print(f"--- OK SAMPLE (first 10 of {len(ok_chain)}) ---")
for s in ok_chain[:10]:
    print(s)
