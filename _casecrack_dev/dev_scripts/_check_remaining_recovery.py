"""Check what's recoverable from .pyc files + backup copies for remaining 283 missing files."""
import json
from pathlib import Path

WORKSPACE = Path(r"C:\Users\ya754\CaseCrack v1.0")
CC = WORKSPACE / "CaseCrack"
BURP = CC / "tools" / "burp_enterprise"

cls = json.load(open(WORKSPACE / "true_dead_classification.json"))
def mod_to_path(mod_fqn: str) -> Path:
    return CC / f"{mod_fqn.replace('.', '/')}.py"

missing = []
for m in cls["runtime_reachable"] + cls["conditionally_reachable"]:
    p = mod_to_path(m)
    if not p.exists():
        missing.append((m, p))

print(f"Missing critical: {len(missing)}")

# ── Check .pyc availability ──
pyc_recoverable = []
for m, p in missing:
    # Expected .pyc at __pycache__/<name>.cpython-313.pyc
    pycache = p.parent / "__pycache__"
    pyc = pycache / f"{p.stem}.cpython-313.pyc"
    if pyc.exists():
        pyc_recoverable.append((m, p, pyc))

print(f"  Recoverable via .pyc: {len(pyc_recoverable)}")

# ── Check backup copies ──
backups = [
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Copy"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Coinbase"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - PayPal"),
]
backup_recoverable = {}
for b in backups:
    if not b.exists():
        continue
    count = 0
    found_list = []
    for m, p in missing:
        rel = p.relative_to(WORKSPACE)
        candidate = b / rel
        if candidate.exists():
            count += 1
            found_list.append((m, candidate))
    backup_recoverable[str(b)] = found_list
    print(f"  Recoverable via {b.name}: {count}")

# Union: what can we recover from SOMEWHERE?
recoverable_set = set()
for _, _, _ in pyc_recoverable:
    recoverable_set.add(_)
# Actually rebuild properly
any_recoverable = set()
for m, p, pyc in pyc_recoverable:
    any_recoverable.add(m)
for b_path, found in backup_recoverable.items():
    for m, _ in found:
        any_recoverable.add(m)

print(f"\nTotal recoverable from any source: {len(any_recoverable)} / {len(missing)}")

# Unrecoverable list
unrecoverable = [m for m, _ in missing if m not in any_recoverable]
print(f"Permanently lost: {len(unrecoverable)}")
if unrecoverable:
    print("\nFirst 20 permanently lost:")
    for m in unrecoverable[:20]:
        print(f"  {m.replace('tools.burp_enterprise.', '')}")
