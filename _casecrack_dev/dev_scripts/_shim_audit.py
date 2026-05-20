"""Check relay shim targets exist at root level."""
from __future__ import annotations
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

shim_pattern = re.compile(
    r'_importlib\.import_module\(["\']'
    r'(tools\.burp_enterprise\.\w+)'
    r'["\']\)'
)

root = pathlib.Path("tools/burp_enterprise")
broken_shims: list[str] = []
ok_shims: list[str] = []

for sub in sorted(root.iterdir()):
    if not sub.is_dir() or sub.name.startswith("_") or sub.name == "__pycache__":
        continue
    for p in sorted(sub.glob("*.py")):
        src = p.read_text(encoding="utf-8")
        m = shim_pattern.search(src)
        if m:
            target_mod = m.group(1)
            target_stem = target_mod.replace("tools.burp_enterprise.", "")
            exists = (root / f"{target_stem}.py").exists() or (
                root / target_stem / "__init__.py"
            ).exists()
            entry = f"{sub.name}/{p.name} -> {target_mod}"
            if exists:
                ok_shims.append(entry)
            else:
                broken_shims.append(entry + " [TARGET MISSING]")

print(f"OK relay shims:     {len(ok_shims)}")
print(f"BROKEN relay shims: {len(broken_shims)}")
print()
print("--- BROKEN SHIMS ---")
for s in broken_shims:
    print(f"  {s}")
print()
print(f"--- OK SAMPLE (first 10) ---")
for s in ok_shims[:10]:
    print(f"  {s}")
