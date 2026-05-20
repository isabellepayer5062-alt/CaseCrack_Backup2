"""Check backup directories for recovery."""
from pathlib import Path

backups = [
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Copy\CaseCrack\tools\burp_enterprise"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Coinbase\CaseCrack\tools\burp_enterprise"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - PayPal\CaseCrack\tools\burp_enterprise"),
]

current = Path(r"C:\Users\ya754\CaseCrack v1.0\CaseCrack\tools\burp_enterprise")
current_py = set()
for f in current.rglob("*.py"):
    if "__pycache__" not in str(f) and "_cold_storage" not in str(f):
        current_py.add(f.relative_to(current))

print(f"Current workspace: {len(current_py)} .py files")
print()

for backup in backups:
    if not backup.exists():
        print(f"{backup.parent.name}: NOT FOUND")
        continue
    backup_py = set()
    for f in backup.rglob("*.py"):
        if "__pycache__" not in str(f):
            backup_py.add(f.relative_to(backup))

    missing_in_current = backup_py - current_py
    print(f"{backup.parent.name}: {len(backup_py)} .py files, {len(missing_in_current)} recoverable")

# Use the best backup (most files)
best = None
best_count = 0
for backup in backups:
    if not backup.exists():
        continue
    count = 0
    for f in backup.rglob("*.py"):
        if "__pycache__" not in str(f):
            count += 1
    if count > best_count:
        best_count = count
        best = backup

if best:
    print(f"\nBest backup: {best.parent.name} ({best_count} files)")
    # Count files that can be recovered
    backup_py = set()
    for f in best.rglob("*.py"):
        if "__pycache__" not in str(f):
            backup_py.add(f.relative_to(best))
    recoverable = backup_py - current_py
    print(f"Recoverable: {len(recoverable)} files")
