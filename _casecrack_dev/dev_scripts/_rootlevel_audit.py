"""Check LOC and quality of root-level canonical modules."""
from __future__ import annotations
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

root = pathlib.Path("tools/burp_enterprise")

# Get all root-level .py files
root_files = sorted(p for p in root.glob("*.py") if not p.name.startswith("__"))

print(f"Root-level modules: {len(root_files)}")
print()

# Categorize by LOC
stubs = []
thin = []
normal = []
large = []
for p in root_files:
    src = p.read_text(encoding="utf-8")
    n = len(src.splitlines())
    if n < 30:
        stubs.append((p.name, n))
    elif n < 100:
        thin.append((p.name, n))
    elif n < 500:
        normal.append((p.name, n))
    else:
        large.append((p.name, n))

print(f"Very small (<30L):   {len(stubs)}")
print(f"Thin (30-99L):       {len(thin)}")
print(f"Normal (100-499L):   {len(normal)}")
print(f"Large (500+L):       {len(large)}")
print()

if stubs:
    print("--- VERY SMALL (potential stubs) ---")
    for name, n in stubs:
        p = root / name
        src = p.read_text(encoding="utf-8")
        print(f"  {name} ({n}L): {src.strip()[:100]}")
    print()

if thin:
    print("--- THIN (30-99L) ---")
    for name, n in thin:
        print(f"  {name} ({n}L)")
