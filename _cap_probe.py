"""Capability trigger probe.

Given disk path + history snapshot, list symbols only-in-history and
show a live-caller grep across CaseCrack/ for each missing symbol.
This is the decision input for whether a Bucket-C merge is justified.
"""
from __future__ import annotations
import ast, re, sys, subprocess
from pathlib import Path

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
ROOT = WS / "CaseCrack"

def top_syms(tree):
    out = {}
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            out[node.name] = ("func", node)
        elif isinstance(node, ast.ClassDef):
            out[node.name] = ("class", node)
            for m in node.body:
                if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    out[f"{node.name}.{m.name}"] = ("method", m)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and (t.id.isupper() or t.id.startswith("_")):
                    out[t.id] = ("const", node)
    return out

def grep_count(name: str) -> int:
    # count files mentioning the bare identifier (not the owning file)
    pat = re.compile(rf"\b{re.escape(name)}\b")
    n = 0
    for p in ROOT.rglob("*.py"):
        try:
            if pat.search(p.read_text(encoding="utf-8", errors="ignore")):
                n += 1
        except Exception:
            pass
    return n

def main(disk_rel: str, hist_path: str):
    disk = WS / disk_rel
    hist = Path(hist_path)
    dtree = ast.parse(disk.read_text(encoding="utf-8"))
    htree = ast.parse(hist.read_text(encoding="utf-8", errors="replace"))
    d = top_syms(dtree); h = top_syms(htree)
    only_hist = set(h) - set(d)
    print(f"\n=== {disk_rel} ===")
    print(f"disk {len(d)} syms, hist {len(h)} syms, only_hist {len(only_hist)}")
    # Filter dunder/leading-underscore methods — rarely externally called
    interesting = [s for s in sorted(only_hist)
                   if not s.split(".")[-1].startswith("_")]
    print(f"\n-- public-ish only-in-hist symbols ({len(interesting)}) with external file-count --")
    self_stem = disk.stem
    for s in interesting:
        tail = s.split(".")[-1]
        n = grep_count(tail)
        # Subtract self-file hit
        print(f"  {s:45s}  files_ref={n}")
    print(f"\n-- private/dunder only-in-hist ({len(only_hist)-len(interesting)}) --")
    for s in sorted(only_hist):
        if s.split(".")[-1].startswith("_"):
            print(f"  {s}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
