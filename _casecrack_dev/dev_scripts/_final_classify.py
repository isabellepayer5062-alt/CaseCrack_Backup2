"""Deep classify: for each regression, check if disk has NEW symbols too,
or if it's a pure subset of history (true regression).

Writes _final_audit_classified.tsv with column 'verdict':
  - PURE_REGRESSION: disk symbols ⊂ history symbols
  - REFACTORED: both sides have unique symbols (needs manual review)
  - MINOR: few symbols differ
"""
from __future__ import annotations
import ast, sys
from pathlib import Path

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")

def top_symbols(src: str) -> set[str]:
    try:
        tree = ast.parse(src)
    except Exception:
        return set()
    out = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.add(node.name)
        elif isinstance(node, ast.ClassDef):
            out.add(node.name)
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.add(f"{node.name}.{m.name}")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id.isupper():
                    out.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id.isupper():
            out.add(node.target.id)
    return out

rows = []
tsv = WS / "_final_audit_regressions.tsv"
with tsv.open(encoding="utf-8") as f:
    header = f.readline().rstrip("\n").split("\t")
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 7:
            rows.append(dict(zip(header, parts)))

out = []
for r in rows:
    rel = Path(r["rel_path"])
    disk = WS / rel
    snap = Path(r["snapshot"])
    if not disk.exists() or not snap.exists():
        continue
    try:
        ds = top_symbols(disk.read_text(encoding="utf-8", errors="ignore"))
        hs = top_symbols(snap.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        continue
    only_disk = ds - hs
    only_hist = hs - ds
    if len(only_hist) <= 3 and len(only_disk) <= 3:
        verdict = "MINOR"
    elif only_disk:
        verdict = "REFACTORED"
    else:
        verdict = "PURE_REGRESSION"
    out.append((verdict, len(only_hist), len(only_disk), int(r["refs"]),
                float(r["ratio"]), str(rel), sorted(only_disk)[:6]))

# Sort: pure regressions first, then by refs, then by missing count
order = {"PURE_REGRESSION": 0, "REFACTORED": 1, "MINOR": 2}
out.sort(key=lambda r: (order[r[0]], -r[3], -r[1]))

with (WS / "_final_audit_classified.tsv").open("w", encoding="utf-8") as f:
    f.write("verdict\tonly_hist\tonly_disk\trefs\tratio\trel_path\tdisk_only_syms\n")
    for r in out:
        f.write(f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\t{r[4]:.2f}\t{r[5]}\t{'|'.join(r[6])}\n")

by_v = {}
for r in out:
    by_v.setdefault(r[0], []).append(r)

for v in ("PURE_REGRESSION","REFACTORED","MINOR"):
    lst = by_v.get(v,[])
    print(f"\n=== {v}: {len(lst)} files ===")
    for r in lst[:50]:
        print(f"  refs={r[3]:2d}  -{r[1]:3d}/+{r[2]:<2d}  ratio={r[4]:.2f}  {r[5]}")
        if r[0] == "REFACTORED" and r[6]:
            print(f"      disk-only: {', '.join(r[6][:5])}")
