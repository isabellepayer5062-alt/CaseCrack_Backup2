"""Exhaustive coverage — TIGHT version.

Only matches history snapshots whose URI ends with the same path tail
(last 2 segments: parent_dir/file.py). Eliminates the basename-collision
false positives from v1 (e.g., 40+ unrelated __init__.py matched to one
huge snapshot).
"""
from __future__ import annotations
import ast, json, os, sys
from pathlib import Path
from urllib.parse import unquote
from collections import defaultdict

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
ROOT = WS / "CaseCrack"
HIST = Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

# tail2 (parent/name.py) -> [(size, ts, path, uri_decoded)]
snap_by_tail2: dict[str, list[tuple[int,int,Path,str]]] = defaultdict(list)
snap_by_tail3: dict[str, list[tuple[int,int,Path,str]]] = defaultdict(list)

n_snap = 0
for ej in HIST.rglob("entries.json"):
    try:
        data = json.loads(ej.read_text(encoding="utf-8"))
    except Exception:
        continue
    uri = data.get("resource", "")
    if not uri.endswith(".py"): continue
    dec = unquote(uri).replace("\\", "/")
    segs = [s for s in dec.split("/") if s]
    if len(segs) < 2: continue
    tail2 = "/".join(segs[-2:])
    tail3 = "/".join(segs[-3:]) if len(segs) >= 3 else tail2
    hdir = ej.parent
    for ent in data.get("entries", []):
        fid = ent.get("id"); ts = ent.get("timestamp", 0)
        if not fid: continue
        p = hdir / fid
        if not p.exists(): continue
        rec = (p.stat().st_size, ts, p, dec)
        snap_by_tail2[tail2].append(rec)
        snap_by_tail3[tail3].append(rec)
        n_snap += 1

print(f"[hist] {n_snap} snapshots, {len(snap_by_tail2)} unique tail2 paths", file=sys.stderr)

def ast_valid(text: str) -> bool:
    if text.count("from __future__") > 1: return False
    try: ast.parse(text); return True
    except SyntaxError: return False

def largest_valid(cands: list[tuple[int,int,Path,str]]) -> tuple[int,int,Path,str] | None:
    for rec in sorted(cands, key=lambda r: (-r[0], -r[1])):
        try: text = rec[2].read_text(encoding="utf-8", errors="replace")
        except Exception: continue
        if ast_valid(text): return rec
    return None

def top_syms(tree):
    s = set()
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            s.add(node.name)
        elif isinstance(node, ast.ClassDef):
            s.add(node.name)
            for m in node.body:
                if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    s.add(f"{node.name}.{m.name}")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id.isupper():
                    s.add(t.id)
    return s

out_rows = []
for disk in ROOT.rglob("*.py"):
    if "__pycache__" in disk.parts: continue
    rel = disk.relative_to(WS)
    relstr = str(rel).replace("\\", "/")
    segs = relstr.split("/")
    if len(segs) < 2: continue
    tail2 = "/".join(segs[-2:])
    tail3 = "/".join(segs[-3:]) if len(segs) >= 3 else tail2

    # Prefer tail3 (most specific); fall back to tail2
    cand = largest_valid(snap_by_tail3.get(tail3, [])) or largest_valid(snap_by_tail2.get(tail2, []))
    if not cand: continue

    hist_size, hist_ts, hist_path, hist_uri = cand
    # Extra sanity: hist_uri must end with tail2 (so it's the right parent dir)
    hist_segs = hist_uri.split("/")
    hist_tail2 = "/".join(hist_segs[-2:]) if len(hist_segs) >= 2 else ""
    if hist_tail2 != tail2:
        continue

    disk_size = disk.stat().st_size
    if hist_size < disk_size * 1.10: continue
    if hist_size < 4096: continue

    try: dtext = disk.read_text(encoding="utf-8", errors="ignore")
    except Exception: continue
    head = dtext[:2000].lower()
    if any(m in head for m in ("has been removed","thin facade","re-exports","split into",
                                "extracted from","relay shim","deprecated","moved to",
                                "replaced by","raise importerror")):
        continue
    if len(dtext) < 2500 and "import_module" in dtext:
        continue

    try:
        htext = hist_path.read_text(encoding="utf-8", errors="replace")
        ds = top_syms(ast.parse(dtext))
        hs = top_syms(ast.parse(htext))
    except Exception:
        continue
    only_hist = hs - ds; only_disk = ds - hs

    verdict = ("MINOR" if len(only_hist) <= 3 and len(only_disk) <= 3
               else "REFACTORED" if only_disk else "PURE_REGRESSION")

    out_rows.append((verdict, len(only_hist), len(only_disk),
                     disk_size, hist_size, relstr, str(hist_path), hist_uri,
                     "|".join(sorted(only_disk)[:5])))

order = {"PURE_REGRESSION":0, "REFACTORED":1, "MINOR":2}
out_rows.sort(key=lambda r: (order[r[0]], -r[4]))

with (WS / "_final_audit_coverage_tight.tsv").open("w", encoding="utf-8") as f:
    f.write("verdict\tonly_hist\tonly_disk\tdisk_size\thist_size\trel_path\tsnapshot\thist_uri\tdisk_only_syms\n")
    for r in out_rows:
        f.write("\t".join(str(x) for x in r) + "\n")

by_v = defaultdict(list)
for r in out_rows:
    by_v[r[0]].append(r)

print(f"\nTotal flagged: {len(out_rows)}")
for v in ("PURE_REGRESSION","REFACTORED","MINOR"):
    lst = by_v[v]
    print(f"\n=== {v}: {len(lst)} ===")
    for r in lst[:50]:
        print(f"  -{r[1]:3d}/+{r[2]:<2d}  {r[3]//1024:4d}KB->{r[4]//1024:4d}KB  {r[5]}")
