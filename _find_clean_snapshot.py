"""Find largest AST-valid history snapshot for a specific resource."""
from __future__ import annotations
import ast, json, os, sys
from pathlib import Path
from urllib.parse import unquote

HIST = Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

target_rel = sys.argv[1].replace("\\", "/")  # e.g. CaseCrack/tools/.../github_client_base.py

candidates = []  # (size, ts, path)
for entries_json in HIST.rglob("entries.json"):
    try:
        data = json.loads(entries_json.read_text(encoding="utf-8"))
    except Exception:
        continue
    uri = data.get("resource", "")
    if target_rel not in unquote(uri):
        continue
    hdir = entries_json.parent
    for ent in data.get("entries", []):
        fid = ent.get("id"); ts = ent.get("timestamp", 0)
        if not fid: continue
        snap = hdir / fid
        if not snap.exists(): continue
        candidates.append((snap.stat().st_size, ts, snap))

candidates.sort(reverse=True)  # largest first
print(f"Found {len(candidates)} snapshots for {target_rel}\n")

for size, ts, snap in candidates[:15]:
    try:
        text = snap.read_text(encoding="utf-8", errors="replace")
        ast.parse(text)
        # count future imports to detect concatenation corruption
        futs = text.count("from __future__")
        status = "VALID" if futs <= 1 else f"CORRUPT({futs} __future__)"
    except SyntaxError as e:
        status = f"SYNERR:{e.lineno}"
    print(f"  {size:8d}  ts={ts}  {status}  {snap}")
