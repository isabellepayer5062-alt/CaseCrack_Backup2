"""Restore 10 PURE_REGRESSION files from tight-audit coverage TSV."""
from __future__ import annotations
import ast, shutil, sys
from pathlib import Path

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")

rows = []
with (WS / "_final_audit_coverage_tight.tsv").open(encoding="utf-8") as f:
    hdr = f.readline().rstrip("\n").split("\t")
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 8:
            rows.append(dict(zip(hdr, parts)))

pures = [r for r in rows if r["verdict"] == "PURE_REGRESSION"]
print(f"Restoring {len(pures)} PURE_REGRESSION files\n")

ok = 0
for r in pures:
    relstr = r["rel_path"]
    disk = WS / relstr.replace("/", "\\")
    snap = Path(r["snapshot"])
    if not snap.exists():
        print(f"MISS      {relstr}")
        continue
    try:
        text = snap.read_text(encoding="utf-8", errors="replace")
        if text.count("from __future__") > 1:
            print(f"CORRUPT   {relstr}")
            continue
        ast.parse(text)
    except SyntaxError as e:
        print(f"SYNERR    {relstr}: {e}")
        continue
    if disk.exists():
        bak = disk.with_suffix(disk.suffix + ".pregap2.bak")
        if not bak.exists():
            shutil.copy2(disk, bak)
    disk.parent.mkdir(parents=True, exist_ok=True)
    disk.write_text(text, encoding="utf-8")
    try:
        ast.parse(disk.read_text(encoding="utf-8"))
    except SyntaxError as e:
        print(f"POSTERR   {relstr}: {e}")
        if bak.exists(): shutil.copy2(bak, disk)
        continue
    print(f"RESTORED  {relstr}  ({disk.stat().st_size//1024}KB, -{r['only_hist']} syms regained)")
    ok += 1

print(f"\n{ok}/{len(pures)} restored")
