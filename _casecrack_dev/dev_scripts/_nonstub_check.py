"""Find low-LOC files that are NOT relay shims."""
from __future__ import annotations
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

shim_pattern = re.compile(r"_importlib\.import_module\(")

root = pathlib.Path("tools/burp_enterprise")
non_shim_stubs: list[tuple[str, int, str]] = []

for sub in sorted(root.iterdir()):
    if not sub.is_dir() or sub.name.startswith("_") or sub.name == "__pycache__":
        continue
    for p in sorted(sub.glob("*.py")):
        if p.name == "__init__.py":
            continue
        src = p.read_text(encoding="utf-8")
        n = len(src.splitlines())
        if n <= 20 and not shim_pattern.search(src):
            # Not a relay shim — show content
            non_shim_stubs.append((f"{sub.name}/{p.name}", n, src.strip()))

print(f"Non-relay-shim low-LOC files: {len(non_shim_stubs)}")
print()
for path, n, content in non_shim_stubs:
    print(f"=== {path} ({n}L) ===")
    print(content[:300])
    print()

# Also check the secrets/ directory which had 9-LOC stubs
print("=== secrets/ stubs ===")
sec = root / "secrets"
for p in sorted(sec.glob("*.py")):
    src = p.read_text(encoding="utf-8")
    n = len(src.splitlines())
    if n <= 15:
        print(f"  {p.name} ({n}L): {src.strip()[:120]}")
