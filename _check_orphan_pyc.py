"""Check if any .pyc files can actually recover lost .py files."""
from pathlib import Path
import re

CC = Path(r"C:\Users\ya754\CaseCrack v1.0\CaseCrack\tools\burp_enterprise")

# For each .pyc, compute what .py it corresponds to
# __pycache__/foo.cpython-313.pyc -> ../foo.py
recoverable_pyc = []
orphan_pyc = []

for pyc in CC.rglob("*.pyc"):
    if "_cold_storage" in str(pyc):
        continue
    parent = pyc.parent  # __pycache__
    if parent.name != "__pycache__":
        continue
    module_name = pyc.stem.split(".")[0]  # strip .cpython-313
    expected_py = parent.parent / f"{module_name}.py"
    if not expected_py.exists():
        orphan_pyc.append((pyc, expected_py))
    else:
        recoverable_pyc.append(pyc)

print(f"Total .pyc with surviving .py: {len(recoverable_pyc)}")
print(f"Orphan .pyc (no .py): {len(orphan_pyc)}")

if orphan_pyc:
    print(f"\nFirst 20 orphan .pyc files (recoverable via decompile):")
    for pyc, py in orphan_pyc[:20]:
        short = str(py).replace(str(CC) + "\\", "")
        print(f"  {short}")
