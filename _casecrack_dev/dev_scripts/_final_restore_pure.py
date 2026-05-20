"""Restore PURE_REGRESSION files from VS Code history snapshot.

Only files where disk has NO unique top-level symbols relative to history
(history is a strict superset). For each:
  1. AST-parse the history snapshot to verify it is valid Python
  2. Backup current disk copy to <path>.preregression.bak
  3. Copy snapshot bytes to disk
  4. Re-AST-parse the written file
"""
from __future__ import annotations
import ast, shutil, sys
from pathlib import Path

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")

PURE = [
    ("CaseCrack/tools/burp_enterprise/decision_orchestrator.py",                        "refs=6"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/model_cli.py",         "refs=1"),
    ("CaseCrack/tools/burp_enterprise/inference/model_management/model_benchmarker.py", "refs=1"),
    ("CaseCrack/tests/test_organism_health_gaps.py",                                     "refs=0"),
    ("CaseCrack/tools/burp_enterprise/intel/github_client_base.py",                     "refs=0"),
    ("CaseCrack/tools/burp_enterprise/output/findings_formatter.py",                    "refs=0"),
    ("CaseCrack/tools/burp_enterprise/mcp/mcp_server.py",                               "refs=0"),
    ("CaseCrack/tools/burp_enterprise/agents/bayesian_prioritizer.py",                  "refs=0"),
]

# Load snapshot paths from _final_audit_regressions.tsv
snap_lookup: dict[str, str] = {}
with (WS / "_final_audit_regressions.tsv").open(encoding="utf-8") as f:
    header = f.readline()
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 5:
            snap_lookup[parts[3].replace("\\", "/")] = parts[4]

ok = 0
fail = 0
for relstr, meta in PURE:
    disk = WS / relstr.replace("/", "\\")
    snap = snap_lookup.get(relstr)
    if not snap:
        print(f"NO_SNAP   {relstr}")
        fail += 1
        continue
    snap_path = Path(snap)
    if not snap_path.exists():
        print(f"MISS      {relstr}")
        fail += 1
        continue
    try:
        text = snap_path.read_text(encoding="utf-8", errors="strict")
        ast.parse(text)
    except UnicodeDecodeError:
        text = snap_path.read_text(encoding="utf-8", errors="replace")
        try:
            ast.parse(text)
        except SyntaxError as e:
            print(f"SYNERR    {relstr}: {e}")
            fail += 1
            continue
    except SyntaxError as e:
        print(f"SYNERR    {relstr}: {e}")
        fail += 1
        continue

    # Backup current disk
    if disk.exists():
        bak = disk.with_suffix(disk.suffix + ".preregression.bak")
        shutil.copy2(disk, bak)

    disk.parent.mkdir(parents=True, exist_ok=True)
    disk.write_text(text, encoding="utf-8")

    # Verify
    try:
        ast.parse(disk.read_text(encoding="utf-8"))
    except SyntaxError as e:
        print(f"POSTERR   {relstr}: {e}")
        fail += 1
        continue
    ds = disk.stat().st_size
    print(f"RESTORED  {relstr}  ({ds // 1024} KB)  {meta}")
    ok += 1

print(f"\nRestored {ok}/{len(PURE)} files  ({fail} failures)")
