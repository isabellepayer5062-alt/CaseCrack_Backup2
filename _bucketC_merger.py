"""Automated bucket-C merger.

Strategy: history version is the richer base. For each (disk, hist):
  1. Parse both.
  2. Identify disk-unique classes/funcs/methods (by qualified name).
  3. Start with history source verbatim.
  4. Append disk-unique top-level functions/classes at EOF.
  5. For disk-unique methods of existing classes: insert the method
     source just before the class ends.
  6. py_compile the result. If OK, write to disk with backup.

Caveats / manually excluded:
  - Does NOT touch __init__.py (architecture-specific).
  - Dataclass fields: if disk has extra fields on a dataclass that
    history also defines, we keep the HISTORY dataclass (history
    usually has superset).
  - Properties and methods with identical names in both → keep history.
"""
from __future__ import annotations
import ast, shutil, sys
from pathlib import Path

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
HIST_ROOT = Path(r"C:\Users\ya754\AppData\Roaming\Code\User\History")

TARGETS = [
    # Easy — history much richer, few disk additions
    ("CaseCrack/tools/burp_enterprise/inference/gpu_governor.py", r"-321de56d\4cUG.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_manager.py", r"859617b\VNIq.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/model_registry.py", r"13ff49c9\O4kx.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/model_downloader.py", r"-52893bef\7tSv.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/finetune_exporter.py", r"-7275cefc\Kzu3.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/vram_selector.py", r"37be9f7c\qeBh.py"),
    ("CaseCrack/tools/burp_enterprise/inference/kv_cache.py", r"-52f8b352\rVkn.py"),
    # Moderate
    ("CaseCrack/tools/burp_enterprise/tool_registry/registry.py", r"4050eaaa\TJ0D.py"),
    ("CaseCrack/tools/burp_enterprise/reasoning/kv_checkpoint.py", r"f3d22b1\Zxfe.py"),
    ("CaseCrack/tools/burp_enterprise/inference/engine.py", r"-33dd2d26\B01d.py"),
    ("CaseCrack/tools/burp_enterprise/database/data_migration.py", r"3ef0668f\GL6a.py"),
]

def src_of(node, src: str) -> str:
    seg = ast.get_source_segment(src, node)
    return seg or ""

def class_members(cls: ast.ClassDef) -> dict[str, ast.AST]:
    out = {}
    for m in cls.body:
        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[m.name] = m
        elif isinstance(m, ast.ClassDef):
            out[m.name] = m
    return out

def toplevel_map(tree: ast.Module) -> dict[str, ast.AST]:
    out = {}
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[n.name] = n
    return out

def merge(disk_path: Path, hist_path: Path) -> tuple[bool, str, str]:
    dsrc = disk_path.read_text(encoding="utf-8")
    hsrc = hist_path.read_text(encoding="utf-8", errors="replace")
    try:
        dtree = ast.parse(dsrc)
        htree = ast.parse(hsrc)
    except SyntaxError as e:
        return False, "", f"parse failed: {e}"

    dtop = toplevel_map(dtree)
    htop = toplevel_map(htree)

    # Disk-unique top-level symbols
    new_toplevel: list[str] = []
    for name, node in dtop.items():
        if name in htop:
            continue
        seg = src_of(node, dsrc)
        if seg:
            new_toplevel.append(seg)

    # For classes in BOTH, find disk-only methods
    class_patches: list[tuple[str, list[str]]] = []
    for name, dnode in dtop.items():
        if not isinstance(dnode, ast.ClassDef):
            continue
        if name not in htop or not isinstance(htop[name], ast.ClassDef):
            continue
        hmembers = class_members(htop[name])
        dmembers = class_members(dnode)
        new_methods: list[str] = []
        for mname, mnode in dmembers.items():
            if mname in hmembers:
                continue
            if mname.startswith("__") and mname.endswith("__"):
                # skip dunders usually — e.g. __post_init__ is dangerous to splice
                continue
            seg = src_of(mnode, dsrc)
            if seg:
                # indent by 4 (class body)
                indented = "\n".join(("    " + line) if line.strip() else line
                                     for line in seg.splitlines())
                new_methods.append(indented)
        if new_methods:
            class_patches.append((name, new_methods))

    # Build merged source:
    # start from history source
    lines = hsrc.splitlines(keepends=False)

    # Apply class patches: insert methods before class ends.
    # Use class.end_lineno - insert new methods just before.
    # Re-parse after each insertion to keep offsets correct.
    for cls_name, methods in class_patches:
        cur = "\n".join(lines)
        try:
            t = ast.parse(cur)
        except SyntaxError as e:
            return False, "", f"reparse after patch failed: {e}"
        target = None
        for n in t.body:
            if isinstance(n, ast.ClassDef) and n.name == cls_name:
                target = n; break
        if target is None:
            continue
        insert_at = target.end_lineno  # 1-based, exclusive line for body
        # Insert methods before that line
        block = ["", *methods]  # blank line separator
        new_lines = lines[:insert_at] + block + lines[insert_at:]
        lines = new_lines

    if new_toplevel:
        lines.append("")
        lines.append("# ==== disk-unique top-level symbols (preserved from previous disk version) ====")
        for seg in new_toplevel:
            lines.append("")
            lines.extend(seg.splitlines())

    merged = "\n".join(lines) + "\n"

    # Validate AST
    try:
        ast.parse(merged)
    except SyntaxError as e:
        return False, merged, f"merged AST invalid: {e}"

    return True, merged, ""

def main():
    results = []
    for rel, hsub in TARGETS:
        disk = WS / rel
        hist = HIST_ROOT / hsub
        print(f"\n=== {rel} ===")
        if not disk.exists() or not hist.exists():
            print("  SKIP: missing file"); continue
        ok, merged, err = merge(disk, hist)
        if not ok:
            print(f"  FAIL: {err}")
            results.append((rel, "FAIL", err))
            continue
        # back up
        bak = disk.with_suffix(disk.suffix + ".prebucketC.bak")
        if not bak.exists():
            shutil.copy2(disk, bak)
        disk.write_text(merged, encoding="utf-8")
        print(f"  OK: disk_size={len(merged)}")
        results.append((rel, "OK", f"size={len(merged)}"))

    print("\n\nSUMMARY")
    for r in results:
        print(" ", r)

if __name__ == "__main__":
    main()
