"""Per-file symbol + signature comparison between disk and history snapshot."""
from __future__ import annotations
import ast, sys, os, json
from pathlib import Path
from urllib.parse import unquote

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")

def top_symbols(src: str) -> dict[str, str]:
    """Return {name: kind} for top-level defs and classes."""
    try:
        tree = ast.parse(src)
    except Exception as e:
        return {"__parse_error__": str(e)}
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = "func"
        elif isinstance(node, ast.ClassDef):
            out[node.name] = "class"
            # capture methods too
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[f"{node.name}.{m.name}"] = "method"
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id.isupper():
                    out[t.id] = "const"
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id.isupper():
            out[node.target.id] = "const"
    return out

def compare(disk_path: Path, snap_path: Path) -> dict:
    d = disk_path.read_text(encoding="utf-8", errors="ignore")
    h = snap_path.read_text(encoding="utf-8", errors="ignore")
    ds = top_symbols(d); hs = top_symbols(h)
    only_hist = sorted(set(hs) - set(ds))
    only_disk = sorted(set(ds) - set(hs))
    return {
        "disk_lines": d.count("\n"),
        "hist_lines": h.count("\n"),
        "only_history": only_hist,
        "only_disk": only_disk,
        "n_missing_in_disk": len(only_hist),
    }

if __name__ == "__main__":
    # Read the regressions TSV, compare top N
    rows = []
    tsv = WS / "_final_audit_regressions.tsv"
    with tsv.open(encoding="utf-8") as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 7:
                rows.append(dict(zip(header, parts)))

    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    # Process all, flag severity
    out = []
    for r in rows[:limit]:
        rel = Path(r["rel_path"])
        snap = Path(r["snapshot"])
        disk = WS / rel
        if not disk.exists() or not snap.exists():
            continue
        try:
            cmp = compare(disk, snap)
        except Exception as e:
            print(f"ERR {rel}: {e}")
            continue
        out.append((int(cmp["n_missing_in_disk"]), float(r["ratio"]), int(r["refs"]),
                    str(rel), cmp["only_history"][:12]))
    out.sort(reverse=True)
    # Write detailed TSV
    with (WS / "_final_audit_symbol_diff.tsv").open("w", encoding="utf-8") as f:
        f.write("n_missing\tratio\trefs\trel_path\tfirst_missing_syms\n")
        for r in out:
            f.write(f"{r[0]}\t{r[1]:.2f}\t{r[2]}\t{r[3]}\t{'|'.join(r[4])}\n")

    print(f"Processed {len(out)} files")
    print("\n=== TOP 40 BY MISSING SYMBOL COUNT ===")
    for r in out[:40]:
        print(f"  {r[0]:3d} missing  ratio={r[1]:.2f}  refs={r[2]:2d}  {r[3]}")
        if r[4]:
            print(f"      -> {', '.join(r[4][:8])}")
