"""
VS Code Local History Recovery
==============================

VS Code keeps per-file history at %APPDATA%\\Code\\User\\History\\<hash>\\
Each hash folder contains a `entries.json` that maps to the original file path,
plus timestamped snapshots of the file content.

Strategy:
1. Scan all 9863 history folders
2. Find entries where the original file path is in our deleted set
3. Copy the latest snapshot to restore the .py file
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from datetime import datetime

HISTORY = Path(r"C:\Users\ya754\AppData\Roaming\Code\User\History")
CC = Path(r"C:\Users\ya754\CaseCrack v1.0\CaseCrack")
WORKSPACE_ROOT = Path(r"C:\Users\ya754\CaseCrack v1.0")

# Build set of currently-existing .py files (what we don't need to recover)
existing = set()
for f in CC.rglob("*.py"):
    if "__pycache__" in str(f):
        continue
    try:
        existing.add(f.resolve())
    except Exception:
        pass

print(f"Currently existing: {len(existing)} .py files")

# Scan history
recoverable = {}  # target_path -> (latest_timestamp, snapshot_path)

scanned = 0
for folder in HISTORY.iterdir():
    if not folder.is_dir():
        continue
    scanned += 1
    entries_json = folder / "entries.json"
    if not entries_json.exists():
        continue
    try:
        data = json.loads(entries_json.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        continue

    resource = data.get("resource", "")
    if not resource:
        continue

    # Convert file URI to Path
    # Format: "file:///c%3A/Users/ya754/CaseCrack%20v1.0/..."
    if not resource.startswith("file:///"):
        continue

    from urllib.parse import unquote
    path_str = unquote(resource[8:])
    # Windows paths: file:///c:/... -> c:/...
    target_path = Path(path_str)

    # Only interested in workspace files
    try:
        if not str(target_path).lower().startswith(str(WORKSPACE_ROOT).lower()):
            continue
    except Exception:
        continue

    # Skip if file currently exists (not lost)
    try:
        if target_path.resolve() in existing:
            continue
    except Exception:
        pass

    # Only .py files inside CaseCrack/tools/burp_enterprise
    if not str(target_path).lower().endswith(".py"):
        continue
    if "burp_enterprise" not in str(target_path).lower():
        continue

    # Get the latest entry
    entries = data.get("entries", [])
    if not entries:
        continue
    # Each entry has an id (filename in folder) and timestamp
    latest = max(entries, key=lambda e: e.get("timestamp", 0))
    snapshot = folder / latest["id"]
    if not snapshot.exists():
        continue

    # Keep the newest across duplicate history entries
    ts = latest.get("timestamp", 0)
    if target_path not in recoverable or recoverable[target_path][0] < ts:
        recoverable[target_path] = (ts, snapshot)

print(f"Scanned: {scanned} history folders")
print(f"Recoverable files: {len(recoverable)}")

# Save plan
plan = {
    "recoverable_count": len(recoverable),
    "files": [
        {
            "target": str(tgt),
            "snapshot": str(snap),
            "timestamp_ms": ts,
            "timestamp_iso": datetime.fromtimestamp(ts / 1000).isoformat() if ts else None,
        }
        for tgt, (ts, snap) in sorted(recoverable.items(), key=lambda x: str(x[0]))
    ],
}
out = WORKSPACE_ROOT / "_recovery_plan.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump(plan, f, indent=2)

print(f"\nPlan saved: {out}")

# Show sample
if recoverable:
    print("\nSample recoverable files:")
    for tgt, (ts, snap) in sorted(recoverable.items())[:10]:
        short = str(tgt).replace(str(WORKSPACE_ROOT) + "\\", "")
        iso = datetime.fromtimestamp(ts / 1000).isoformat() if ts else "?"
        print(f"  [{iso[:19]}]  {short}")
