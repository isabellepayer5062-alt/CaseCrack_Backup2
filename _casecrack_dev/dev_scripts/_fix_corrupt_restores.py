"""Revert corrupt restorations + redo using AST-valid snapshots.

- Files with concatenation-corrupt snapshots: revert from .preregression.bak,
  then re-pick the largest AST-valid snapshot and write that.
- Verify AST-parses, no duplicate __future__.
"""
from __future__ import annotations
import ast, json, os, shutil, sys
from pathlib import Path
from urllib.parse import unquote

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
HIST = Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

WS_URI_PREFIXES = [
    "file:///c%3A/Users/ya754/CaseCrack%20v1.0/",
    "file:///C%3A/Users/ya754/CaseCrack%20v1.0/",
]
def decode_uri(u):
    for p in WS_URI_PREFIXES:
        if u.startswith(p):
            return WS / unquote(u[len(p):]).replace("/", os.sep)
    return None

def best_valid_snapshot(target_rel: str) -> Path | None:
    cands = []
    for ej in HIST.rglob("entries.json"):
        try: data = json.loads(ej.read_text(encoding="utf-8"))
        except Exception: continue
        uri = data.get("resource", "")
        if target_rel not in unquote(uri): continue
        hdir = ej.parent
        for ent in data.get("entries", []):
            fid = ent.get("id"); ts = ent.get("timestamp", 0)
            if not fid: continue
            p = hdir / fid
            if not p.exists(): continue
            cands.append((p.stat().st_size, ts, p))
    cands.sort(reverse=True)
    for size, ts, snap in cands:
        try:
            text = snap.read_text(encoding="utf-8", errors="replace")
        except Exception: continue
        if text.count("from __future__") > 1: continue
        try: ast.parse(text)
        except SyntaxError: continue
        return snap
    return None

CORRUPT_RESTORES = [
    "CaseCrack/tests/test_organism_health_gaps.py",
    "CaseCrack/tools/burp_enterprise/intel/github_client_base.py",
]

for rel in CORRUPT_RESTORES:
    disk = WS / rel.replace("/", os.sep)
    bak = disk.with_suffix(disk.suffix + ".preregression.bak")
    # 1. restore backup (original disk version)
    if bak.exists():
        shutil.copy2(bak, disk)
        print(f"REVERT    {rel} -> from backup ({disk.stat().st_size // 1024}KB)")
    # 2. find valid snapshot
    snap = best_valid_snapshot(rel)
    if snap is None:
        print(f"NO_VALID  {rel}")
        continue
    text = snap.read_text(encoding="utf-8", errors="replace")
    # 3. compare sizes — only replace if history is strictly larger AND valid
    disk_size = disk.stat().st_size if disk.exists() else 0
    snap_size = snap.stat().st_size
    if snap_size <= disk_size * 1.2:
        print(f"SKIP      {rel} (valid hist {snap_size//1024}KB <= disk {disk_size//1024}KB)")
        continue
    # write & verify
    disk.write_text(text, encoding="utf-8")
    try:
        ast.parse(disk.read_text(encoding="utf-8"))
    except SyntaxError as e:
        print(f"POSTERR   {rel}: {e}")
        shutil.copy2(bak, disk)
        continue
    print(f"RESTORED  {rel}  ({disk.stat().st_size // 1024}KB from valid snap)")
