"""Compare top-level def/class names between disk and history snapshot."""
from __future__ import annotations

import ast
import sys
from pathlib import Path


def symbols(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return {f"<PARSE_ERROR: {exc}>"}
    out: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(f"{type(node).__name__[:-3]}:{node.name}")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out.add(f"Const:{t.id}")
    return out


PAIRS = [
    (r"tools\burp_enterprise\recon_dashboard\atlas_api.py",
     r"C:\Users\ya754\AppData\Roaming\Code\User\History\5f0d7241\3msW.py"),
    (r"tools\burp_enterprise\exploit_chains\payload_synthesis_engine.py",
     r"C:\Users\ya754\AppData\Roaming\Code\User\History\-b3e0feb\90Xn.py"),
    (r"tools\burp_enterprise\tool_wrappers\_docker.py",
     r"C:\Users\ya754\AppData\Roaming\Code\User\History\-3bcb2a1b\9Qt5.py"),
    (r"tools\burp_enterprise\exploit_chains\chain_executor.py",
     r"C:\Users\ya754\AppData\Roaming\Code\User\History\2d60b182\98jZ.py"),
    (r"tools\burp_enterprise\core_infra\canonical_finding.py",
     r"C:\Users\ya754\AppData\Roaming\Code\User\History\-5441ee2d\DD5B.py"),
    (r"tools\burp_enterprise\database\data_migration.py",
     r"C:\Users\ya754\AppData\Roaming\Code\User\History\3ef0668f\GL6a.py"),
    (r"tools\burp_enterprise\recon_dashboard\finding_dedup.py",
     r"C:\Users\ya754\AppData\Roaming\Code\User\History\47e19bf\yPZ5.py"),
]

REPO = Path(r"c:\Users\ya754\CaseCrack v1.0\CaseCrack")

for rel, hist in PAIRS:
    disk = REPO / rel
    d = symbols(disk)
    h = symbols(Path(hist))
    only_disk = d - h
    only_hist = h - d
    print(f"\n=== {rel} ===")
    print(f"  disk symbols: {len(d)}   history symbols: {len(h)}")
    print(f"  ONLY on disk    ({len(only_disk):3d}): {sorted(only_disk)[:12]}")
    print(f"  ONLY in history ({len(only_hist):3d}): {sorted(only_hist)[:12]}")
