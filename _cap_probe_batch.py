"""Batch capability probe for remaining Bucket C files.

For each (disk_rel, hist_snapshot):
  - parse both
  - list only-in-hist public symbols
  - for each, grep `CaseCrack/` for callers outside owning file
  - list disk-unique public symbols + their external caller count
"""
from __future__ import annotations
import ast, re, sys
from pathlib import Path

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
ROOT = WS / "CaseCrack"
HIST_ROOT = Path(r"C:\Users\ya754\AppData\Roaming\Code\User\History")

# (disk_rel_from_WS, hist_subpath)
TARGETS = [
    ("CaseCrack/tools/burp_enterprise/database/data_migration.py",
     r"3ef0668f\GL6a.py"),
    ("CaseCrack/tools/burp_enterprise/tool_registry/registry.py",
     r"4050eaaa\TJ0D.py"),
    ("CaseCrack/tools/burp_enterprise/reasoning/kv_checkpoint.py",
     r"f3d22b1\Zxfe.py"),
    ("CaseCrack/tools/burp_enterprise/inference/engine.py",
     r"-33dd2d26\B01d.py"),
    ("CaseCrack/tools/burp_enterprise/inference/kv_cache.py",
     r"-52f8b352\rVkn.py"),
    ("CaseCrack/tools/burp_enterprise/inference/gpu_governor.py",
     r"-321de56d\4cUG.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_manager.py",
     r"859617b\VNIq.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/model_registry.py",
     r"13ff49c9\O4kx.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/model_downloader.py",
     r"-52893bef\7tSv.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/finetune_exporter.py",
     r"-7275cefc\Kzu3.py"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/vram_selector.py",
     r"37be9f7c\qeBh.py"),
    ("CaseCrack/tools/burp_enterprise/__init__.py",
     r"-3bcd2844\XCHc.py"),
]

def top_syms(tree):
    out = []
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            out.append(node.name)
        elif isinstance(node, ast.ClassDef):
            out.append(node.name)
            for m in node.body:
                if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    out.append(f"{node.name}.{m.name}")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id.isupper():
                    out.append(t.id)
    return set(out)

# cache file contents for grep
ALL_PY: list[tuple[Path,str]] = []
for p in ROOT.rglob("*.py"):
    try:
        ALL_PY.append((p, p.read_text(encoding="utf-8", errors="ignore")))
    except Exception:
        pass

def grep_refs(name: str, exclude_owner: Path) -> int:
    pat = re.compile(rf"\b{re.escape(name)}\b")
    n = 0
    for p, t in ALL_PY:
        if p == exclude_owner: continue
        if pat.search(t): n += 1
    return n

def is_public(s: str) -> bool:
    return not s.split(".")[-1].startswith("_")

def probe(disk_rel: str, hist_sub: str):
    disk = WS / disk_rel
    hist = HIST_ROOT / hist_sub
    print("\n" + "="*70)
    print(f"FILE: {disk_rel}")
    print(f"HIST: {hist_sub}")
    print("="*70)
    try:
        dsrc = disk.read_text(encoding="utf-8")
        hsrc = hist.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print("ERROR:", e); return
    try:
        d = top_syms(ast.parse(dsrc))
        h = top_syms(ast.parse(hsrc))
    except SyntaxError as e:
        print("SYNTAX:", e); return
    only_h = {s for s in (h - d) if is_public(s)}
    only_d = {s for s in (d - h) if is_public(s)}
    print(f"disk={len(d)} hist={len(h)} only_hist_public={len(only_h)} only_disk_public={len(only_d)}")
    print(f"sizes: disk={len(dsrc)} hist={len(hsrc)}")
    # markers in disk
    markers = [m for m in ["__EVENTBUS_INJECTED__","__TIER2_HELPERS_INJECTED__",
                            "__TIER4A_ERRORS__","__TIER2_INSTRUMENTED__",
                            "__SPRINT5_UPGRADES_INJECTED__","__SPRINT6_UPGRADES_INJECTED__"]
               if m in dsrc]
    print(f"disk_markers: {markers}")

    print(f"\n-- only_in_hist (public) {len(only_h)}:")
    for s in sorted(only_h):
        tail = s.split(".")[-1]
        n = grep_refs(tail, disk)
        flag = " <-- LIVE CALLERS" if n >= 1 else ""
        print(f"    {s:50s} ext_refs={n}{flag}")

    print(f"\n-- only_in_disk (public) {len(only_d)}:")
    for s in sorted(only_d):
        tail = s.split(".")[-1]
        n = grep_refs(tail, disk)
        flag = " <-- LIVE CALLERS (keep!)" if n >= 1 else ""
        print(f"    {s:50s} ext_refs={n}{flag}")

for t in TARGETS:
    probe(*t)
