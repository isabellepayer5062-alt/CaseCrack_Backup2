"""Search for recovery sources more broadly."""
import os
from pathlib import Path

# Fix the parent name in previous check
backups = [
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Copy"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - Coinbase"),
    Path(r"C:\Users\ya754\CaseCrack v1.0 - PayPal"),
]

# Look for ANY directory matching CaseCrack on the system
search_roots = [
    Path(r"C:\Users\ya754"),
    Path(r"C:\Users\ya754\OneDrive") if Path(r"C:\Users\ya754\OneDrive").exists() else None,
    Path(r"C:\Users\ya754\Documents"),
    Path(r"C:\Users\ya754\Desktop"),
    Path(r"C:\Users\ya754\Downloads"),
]

print("=== Searching for CaseCrack copies ===")
for root in search_roots:
    if root is None or not root.exists():
        continue
    try:
        for item in root.iterdir():
            if item.is_dir() and "casecrack" in item.name.lower():
                # Check if has burp_enterprise
                be = item / "CaseCrack" / "tools" / "burp_enterprise"
                if be.exists():
                    count = sum(1 for f in be.rglob("*.py") if "__pycache__" not in str(f))
                    print(f"  {item}: {count} .py files")
                else:
                    print(f"  {item}: no burp_enterprise")
    except PermissionError:
        pass

# Check Recycle Bin 
print("\n=== Recycle Bin ===")
try:
    import subprocess
    result = subprocess.run(
        ["powershell", "-Command", 
         "(New-Object -ComObject Shell.Application).NameSpace(10).Items() | Where-Object { $_.Name -like '*CaseCrack*' -or $_.Name -like '*.py' } | Select-Object -First 20 Name"],
        capture_output=True, text=True, timeout=30
    )
    print(result.stdout[:2000])
except Exception as e:
    print(f"Error: {e}")

# Check for recent zip/archive files
print("\n=== Recent archives in workspace ===")
ws = Path(r"C:\Users\ya754\CaseCrack v1.0")
for pattern in ("*.zip", "*.tar.gz", "*.7z", "*.bak"):
    for f in ws.glob(pattern):
        print(f"  {f}")
