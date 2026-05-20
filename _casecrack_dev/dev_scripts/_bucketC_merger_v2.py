"""Bucket-C merger v2 — import-aware, dataclass-safe.

Additions vs v1:
  - Merge missing imports from disk into history's import block.
  - Skip disk-unique methods whose name collides with a history
    class field annotation (dataclass-safe).
"""
from __future__ import annotations
import ast, shutil
from pathlib import Path

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
HIST_ROOT = Path(r"C:\Users\ya754\AppData\Roaming\Code\User\History")

TARGETS = [
    ("CaseCrack/tools/burp_enterprise/inference/gpu_governor.py", r"-321de56d\4cUG.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_manager.py", r"859617b\VNIq.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/model_registry.py", r"13ff49c9\O4kx.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/model_downloader.py", r"-52893bef\7tSv.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/finetune_exporter.py", r"-7275cefc\Kzu3.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/vram_selector.py", r"37be9f7c\qeBh.py"),
    ("CaseCrack/tools/burp_enterprise/inference/kv_cache.py", r"-52f8b352\rVkn.py"),
    ("CaseCrack/tools/burp_enterprise/tool_registry/registry.py", r"4050eaaa\TJ0D.py"),
    ("CaseCrack/tools/burp_enterprise/reasoning/kv_checkpoint.py", r"f3d22b1\Zxfe.py"),
    ("CaseCrack/tools/burp_enterprise/inference/engine.py", r"-33dd2d26\B01d.py"),
    ("CaseCrack/tools/burp_enterprise/database/data_migration.py", r"3ef0668f\GL6a.py"),
]

def src_of(node, src): return ast.get_source_segment(src, node) or ""

def toplevel_map(tree):
    out = {}
    for n in tree.body:
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            out[n.name] = n
    return out

def class_field_annotations(cls: ast.ClassDef) -> set[str]:
    out = set()
    for m in cls.body:
        if isinstance(m, ast.AnnAssign) and isinstance(m.target, ast.Name):
            out.add(m.target.id)
    return out

def class_members(cls: ast.ClassDef):
    out = {}
    for m in cls.body:
        if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)):
            out[m.name] = m
        elif isinstance(m, ast.ClassDef):
            out[m.name] = m
    return out

def collect_imports(tree: ast.Module, src: str) -> tuple[list[str], set[str]]:
    """Return (list of import-statement source strings, set of imported names)."""
    stmts = []
    names = set()
    for n in tree.body:
        if isinstance(n, ast.Import):
            stmts.append(src_of(n, src))
            for a in n.names:
                names.add(a.asname or a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            stmts.append(src_of(n, src))
            for a in n.names:
                names.add(a.asname or a.name)
    return stmts, names

def last_import_lineno(tree: ast.Module) -> int:
    last = 0
    for n in tree.body:
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            last = max(last, n.end_lineno)
    return last

def merge(disk_path: Path, hist_path: Path):
    # Prefer pre-merge backup as the authentic disk source
    bak = disk_path.with_suffix(disk_path.suffix + ".prebucketC.bak")
    src_path = bak if bak.exists() else disk_path
    dsrc = src_path.read_text(encoding="utf-8")
    hsrc = hist_path.read_text(encoding="utf-8", errors="replace")
    dtree = ast.parse(dsrc)
    htree = ast.parse(hsrc)

    dtop = toplevel_map(dtree)
    htop = toplevel_map(htree)

    # Disk-unique top-level items (not in history)
    # Skip PRIVATE (_-prefixed) — they're superseded implementation details that
    # often reference disk-era naming (e.g., renamed enums) and have no external
    # references. Public symbols are preserved.
    disk_only_top = [(n, dtop[n]) for n in dtop
                     if n not in htop and not n.startswith("_")]

    # Collect names referenced by disk_only_top bodies — we need their imports
    ref_names: set[str] = set()
    for _, node in disk_only_top:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                ref_names.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                # find root Name
                cur = sub
                while isinstance(cur, ast.Attribute):
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    ref_names.add(cur.id)

    # For classes in BOTH, find disk-only methods but skip if method name
    # collides with a history dataclass field annotation.
    class_patches = []
    for name, dnode in dtop.items():
        if not isinstance(dnode, ast.ClassDef): continue
        hnode = htop.get(name)
        if not isinstance(hnode, ast.ClassDef): continue
        hmembers = class_members(hnode)
        dmembers = class_members(dnode)
        h_field_annots = class_field_annotations(hnode)
        new_methods = []
        for mname, mnode in dmembers.items():
            if mname in hmembers: continue
            if mname.startswith("__") and mname.endswith("__"): continue
            if mname in h_field_annots:
                # parallel-implementation accessor — dataclass-unsafe
                continue
            seg = src_of(mnode, dsrc)
            if not seg: continue
            # Track names referenced by method for import-merge
            for sub in ast.walk(mnode):
                if isinstance(sub, ast.Name):
                    ref_names.add(sub.id)
            indented = "\n".join(("    "+l if l.strip() else l) for l in seg.splitlines())
            new_methods.append(indented)
        if new_methods:
            class_patches.append((name, new_methods))

    # Collect disk's imports, filter to only those that bring missing names
    d_stmts, d_names = collect_imports(dtree, dsrc)
    h_stmts, h_names = collect_imports(htree, hsrc)

    missing_imports: list[str] = []
    for stmt in d_stmts:
        # parse the stmt in isolation to see which names it brings
        try:
            st = ast.parse(stmt).body[0]
        except Exception:
            continue
        bringing = set()
        if isinstance(st, ast.Import):
            for a in st.names:
                bringing.add(a.asname or a.name.split(".")[0])
        elif isinstance(st, ast.ImportFrom):
            for a in st.names:
                bringing.add(a.asname or a.name)
        needed = (bringing - h_names) & ref_names
        if needed:
            missing_imports.append(stmt)

    # Build output
    lines = hsrc.splitlines()
    # Insert missing imports after last import line
    if missing_imports:
        last = last_import_lineno(htree)
        insert = ["", "# ==== disk-sourced imports (for preserved disk-unique symbols) ===="]
        insert.extend(missing_imports)
        lines = lines[:last] + insert + lines[last:]

    # Apply class patches
    for cls_name, methods in class_patches:
        cur = "\n".join(lines)
        t = ast.parse(cur)
        target = next((n for n in t.body
                       if isinstance(n, ast.ClassDef) and n.name == cls_name), None)
        if target is None: continue
        insert_at = target.end_lineno
        block = [""] + methods
        lines = lines[:insert_at] + block + lines[insert_at:]

    # Append disk-unique top-level items
    if disk_only_top:
        lines.append("")
        lines.append("# ==== disk-unique top-level symbols (preserved) ====")
        for _, node in disk_only_top:
            seg = src_of(node, dsrc)
            lines.append("")
            lines.extend(seg.splitlines())

    merged = "\n".join(lines) + "\n"
    ast.parse(merged)  # raise if broken
    return merged

def main():
    for rel, hsub in TARGETS:
        disk = WS / rel
        hist = HIST_ROOT / hsub
        print(f"\n=== {rel} ===")
        try:
            merged = merge(disk, hist)
        except Exception as e:
            print(f"  FAIL: {e}"); continue
        bak = disk.with_suffix(disk.suffix + ".prebucketC.bak")
        if not bak.exists():
            shutil.copy2(disk, bak)
        disk.write_text(merged, encoding="utf-8")
        print(f"  OK size={len(merged)}")

if __name__ == "__main__":
    main()
