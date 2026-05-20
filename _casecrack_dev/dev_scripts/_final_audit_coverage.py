"""Exhaustive history coverage audit.

The URI-based audit can miss snapshots when:
- the file was moved (history stays at old URI)
- the URI uses slightly different encoding (Code vs. Code Insiders, drive case, ../)
- the file was recreated — newer history is indexed under a new hash dir

This scanner additionally indexes ALL `.py` snapshots by BASENAME (and by
a "path tail" of the last N segments) and, for every disk file that was
either recovered or is suspected REFACTORED, reports the largest
AST-valid candidate from ANY match route.

Writes `_final_audit_coverage.tsv` with one row per (rel_path, strategy)
whenever a larger valid snapshot exists than what v3 found.
"""
from __future__ import annotations
import ast, json, os, sys, re
from pathlib import Path
from urllib.parse import unquote
from collections import defaultdict

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
ROOT = WS / "CaseCrack"
HIST = Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

# ---------------- Index EVERY snapshot ----------------
# snap_id -> (size, ts, path, resource_uri)
snap_by_basename: dict[str, list[tuple[int,int,Path,str]]] = defaultdict(list)
snap_by_tail2: dict[str, list[tuple[int,int,Path,str]]] = defaultdict(list)  # "parent/name.py"
snap_by_tail3: dict[str, list[tuple[int,int,Path,str]]] = defaultdict(list)
snap_by_uri: dict[str, list[tuple[int,int,Path,str]]] = defaultdict(list)

n_snap = 0
for ej in HIST.rglob("entries.json"):
    try:
        data = json.loads(ej.read_text(encoding="utf-8"))
    except Exception:
        continue
    uri = data.get("resource", "")
    if not uri.endswith(".py"):
        continue
    # decode path tail
    path_part = unquote(uri)
    basename = path_part.rsplit("/", 1)[-1]
    segs = path_part.rsplit("/", 3)
    tail2 = "/".join(segs[-2:]) if len(segs) >= 2 else basename
    tail3 = "/".join(segs[-3:]) if len(segs) >= 3 else tail2
    hdir = ej.parent
    for ent in data.get("entries", []):
        fid = ent.get("id"); ts = ent.get("timestamp", 0)
        if not fid: continue
        p = hdir / fid
        if not p.exists(): continue
        size = p.stat().st_size
        rec = (size, ts, p, uri)
        snap_by_basename[basename].append(rec)
        snap_by_tail2[tail2].append(rec)
        snap_by_tail3[tail3].append(rec)
        snap_by_uri[uri].append(rec)
        n_snap += 1

print(f"[hist] {n_snap} snapshots indexed across {len(snap_by_basename)} basenames", file=sys.stderr)

def ast_valid(text: str) -> bool:
    if text.count("from __future__") > 1:
        return False
    try:
        ast.parse(text)
        return True
    except SyntaxError:
        return False

def largest_valid(cands: list[tuple[int,int,Path,str]]) -> tuple[int,int,Path,str] | None:
    for size, ts, p, uri in sorted(cands, key=lambda r: (-r[0], -r[1])):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if ast_valid(text):
            return (size, ts, p, uri)
    return None

# ---------------- Walk disk ----------------
out_rows = []
total_better = 0

# Scan ALL .py files in workspace (not just CaseCrack) to catch anything
for disk in ROOT.rglob("*.py"):
    if "__pycache__" in disk.parts:
        continue
    try:
        rel = disk.relative_to(WS)
    except ValueError:
        continue
    relstr = str(rel).replace("\\", "/")
    disk_size = disk.stat().st_size
    basename = disk.name
    tail2 = "/".join(relstr.rsplit("/", 2)[-2:])
    tail3 = "/".join(relstr.rsplit("/", 3)[-3:])

    # Collect best-valid candidate from each strategy
    best = {}
    for strat, bucket, key in (
        ("basename", snap_by_basename, basename),
        ("tail2",    snap_by_tail2,    tail2),
        ("tail3",    snap_by_tail3,    tail3),
    ):
        cands = bucket.get(key, [])
        if not cands: continue
        cand = largest_valid(cands)
        if cand:
            best[strat] = cand

    if not best:
        continue

    # Pick the globally-largest valid across all strategies
    overall = max(best.values(), key=lambda r: r[0])
    overall_size = overall[0]

    # Only flag if history has substantially more content than disk
    if overall_size < disk_size * 1.10:
        continue
    if overall_size < 4096:
        continue

    # Skip intentional relays/facades
    try:
        dtext = disk.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    head = dtext[:2000].lower()
    if any(m in head for m in ("has been removed","thin facade","re-exports","split into","extracted from","relay shim","deprecated","moved to","replaced by","raise importerror")):
        continue
    # small relay shim
    if len(dtext) < 2500 and "import_module" in dtext:
        continue

    # Compare symbol sets
    try:
        htext = overall[2].read_text(encoding="utf-8", errors="replace")
        dtree = ast.parse(dtext)
        htree = ast.parse(htext)
    except Exception:
        continue

    def top_syms(tree):
        s = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                s.add(node.name)
            elif isinstance(node, ast.ClassDef):
                s.add(node.name)
                for m in node.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        s.add(f"{node.name}.{m.name}")
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id.isupper():
                        s.add(t.id)
        return s

    ds = top_syms(dtree); hs = top_syms(htree)
    only_hist = hs - ds; only_disk = ds - hs

    verdict = (
        "MINOR" if len(only_hist) <= 3 and len(only_disk) <= 3
        else "REFACTORED" if only_disk
        else "PURE_REGRESSION"
    )

    # Note which strategy found it (useful to know if basename/tail picked up extra)
    strategy_sizes = {k: v[0] for k, v in best.items()}
    best_strat = max(strategy_sizes, key=strategy_sizes.get)

    out_rows.append((
        verdict,
        len(only_hist), len(only_disk),
        disk_size, overall_size,
        relstr, str(overall[2]), best_strat, overall[3]
    ))
    total_better += 1

# Sort: pure regressions first, by hist_size desc
order = {"PURE_REGRESSION":0, "REFACTORED":1, "MINOR":2}
out_rows.sort(key=lambda r: (order[r[0]], -r[4]))

with (WS / "_final_audit_coverage.tsv").open("w", encoding="utf-8") as f:
    f.write("verdict\tonly_hist\tonly_disk\tdisk_size\thist_size\trel_path\tsnapshot\tstrategy\thist_uri\n")
    for r in out_rows:
        f.write("\t".join(str(x) for x in r) + "\n")

by_v = defaultdict(list)
for r in out_rows:
    by_v[r[0]].append(r)

print(f"\nTotal files where history has more content than disk: {total_better}")
for v in ("PURE_REGRESSION","REFACTORED","MINOR"):
    lst = by_v[v]
    print(f"\n=== {v}: {len(lst)} ===")
    for r in lst[:40]:
        uri_tail = r[8].rsplit("/", 3)[-3:] if "/" in r[8] else [r[8]]
        print(f"  -{r[1]:3d}/+{r[2]:<2d}  {r[3]//1024:4d}KB->{r[4]//1024:4d}KB  via={r[7]:<8s}  {r[5]}")
