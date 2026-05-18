#!/usr/bin/env python3
"""
Dependency Graph Sanitization  —  Phase 4 of Wiring Stabilization
==================================================================

Answers: "Which dangling imports can we fix vs. which should we kill?"

Strategy:
  1. Load the execution reality map from Phase 1
  2. For each dangling import FROM a reachable module:
     - If it's a known rename/move → fix the import
     - If the target module doesn't exist → make it a safe conditional import
     - If the referencing module is dead → mark for kill list
  3. Generate a surgical fix script

Run:
    .venv\\Scripts\\python.exe dependency_sanitizer.py
    .venv\\Scripts\\python.exe dependency_sanitizer.py --apply
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CC = ROOT / "CaseCrack"
PKG = CC / "tools" / "burp_enterprise"
if str(CC) not in sys.path:
    sys.path.insert(0, str(CC))


# ═════════════════════════════════════════════════════════════════════
# KNOWN RENAMES / MOVES — verified by codebase archaeology
# ═════════════════════════════════════════════════════════════════════

KNOWN_RENAMES: dict[str, str] = {
    # Old path → correct current path
    "tools.burp_enterprise.runner": "tools.burp_enterprise.recon_dashboard.runner",
    "tools.burp_enterprise.server": "tools.burp_enterprise.recon_dashboard.server",
    "tools.burp_enterprise.state": "tools.burp_enterprise.recon_dashboard.state_manager",
    "tools.burp_enterprise.phase_commands": "tools.burp_enterprise.recon_dashboard.phase_commands",
    "tools.burp_enterprise.phase_handlers": "tools.burp_enterprise.recon_dashboard.phase_handlers",
    "tools.burp_enterprise.phase_data_store": "tools.burp_enterprise.recon_dashboard.phase_data_store",
    "tools.burp_enterprise.command_executor": "tools.burp_enterprise.recon_dashboard.command_executor",
    "tools.burp_enterprise.finding_pipeline": "tools.burp_enterprise.recon_dashboard.finding_pipeline",
    "tools.burp_enterprise.finding_parsers": "tools.burp_enterprise.recon_dashboard.finding_parsers",
    "tools.burp_enterprise.report_generator": "tools.burp_enterprise.recon_dashboard.report_generator",
    "tools.burp_enterprise.scan_config": "tools.burp_enterprise.recon_dashboard.scan_config",
    "tools.burp_enterprise.scheduler": "tools.burp_enterprise.recon_dashboard.scheduler",
    "tools.burp_enterprise.interface": "tools.burp_enterprise.recon_dashboard.interface",
    "tools.burp_enterprise.prompt_chains": "tools.burp_enterprise.recon_dashboard.prompt_chains",
    "tools.llm_bridge": "tools.burp_enterprise.agents.llm_bridge",
    "tools.recon_dashboard": "tools.burp_enterprise.recon_dashboard",
    "tools.worker": "tools.burp_enterprise.recon_dashboard.runner",
}

# Modules that were deliberately deleted and should be conditional-imported
DELIBERATELY_REMOVED: set[str] = {
    "tools.burp_enterprise.scanner_providers",
    "tools.burp_enterprise.adapter",
    "tools.burp_enterprise.embedder",
    "tools.burp_enterprise.db_persistence",
    "tools.burp_enterprise.kv_checkpoint",
    "tools.burp_enterprise.vector_index",
    "tools.licensing",
}


@dataclass
class DanglingFix:
    """A specific fix for a dangling import."""
    file_path: Path
    line_number: int
    original_line: str
    action: str            # "rename", "guard", "remove"
    new_line: str | None   # for rename
    missing_module: str
    current_module: str | None  # for rename


def _find_import_sites(
    src_path: Path, target_module: str
) -> list[tuple[int, str, ast.stmt]]:
    """Find lines in src_path that import target_module."""
    try:
        src = src_path.read_text(encoding="utf-8-sig", errors="replace")
        tree = ast.parse(src, filename=str(src_path))
    except Exception:
        return []

    lines = src.splitlines()
    results = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == target_module or alias.name.startswith(target_module + "."):
                    line_text = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                    results.append((node.lineno, line_text, node))
        elif isinstance(node, ast.ImportFrom):
            full = node.module or ""
            if node.level:
                # Resolve relative
                rel = src_path.relative_to(CC).with_suffix("")
                mod_parts = ".".join(rel.parts).split(".")
                base = mod_parts[:max(1, len(mod_parts) - node.level)]
                full = ".".join(base + ([node.module] if node.module else []))
            if full == target_module or full.startswith(target_module + "."):
                line_text = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                results.append((node.lineno, line_text, node))

    return results


def _is_already_guarded(src_path: Path, line_no: int) -> bool:
    """Check if an import line is already inside a try/except block."""
    try:
        lines = src_path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except Exception:
        return False
    # Look at previous lines for try:
    for i in range(max(0, line_no - 5), line_no):
        if i < len(lines) and lines[i].strip().startswith("try:"):
            return True
    return False


def analyze_dangling_imports() -> tuple[list[DanglingFix], dict[str, Any]]:
    """Analyze all dangling imports and generate fixes."""
    # Load reality map if available
    reality_map_path = ROOT / "execution_reality_map.json"
    reality_data = {}
    reachable_modules = set()
    if reality_map_path.exists():
        reality_data = json.loads(reality_map_path.read_text(encoding="utf-8"))
        reachable_modules = set(reality_data.get("executed_modules", []))

    # Build import graph
    from execution_reality_map import build_import_graph
    adj, nodes, syntax_errors = build_import_graph()

    # Find dangling imports
    dangling: dict[str, list[str]] = defaultdict(list)
    for src, deps in adj.items():
        for dep in deps:
            if dep.startswith("tools.") and dep not in nodes:
                dangling[dep].append(src)

    fixes: list[DanglingFix] = []
    stats = {
        "total_dangling": len(dangling),
        "fixable_renames": 0,
        "guardable": 0,
        "from_dead_modules": 0,
        "already_guarded": 0,
    }

    for missing, referencing_modules in sorted(dangling.items()):
        for ref_mod in referencing_modules:
            # Convert module path to file path
            parts = ref_mod.replace(".", os.sep)
            candidates = [
                CC / (parts + ".py"),
                CC / parts / "__init__.py",
            ]
            src_path = None
            for c in candidates:
                if c.exists():
                    src_path = c
                    break
            if not src_path:
                continue

            # Find the actual import lines
            import_sites = _find_import_sites(src_path, missing)

            for line_no, line_text, _node in import_sites:
                # Strategy 1: Known rename → fix the import
                if missing in KNOWN_RENAMES:
                    new_target = KNOWN_RENAMES[missing]
                    new_line = line_text.replace(
                        missing.rsplit(".", 1)[-1] if "from" in line_text else missing,
                        new_target.rsplit(".", 1)[-1] if "from" in line_text else new_target,
                    )
                    # More robust: replace the full module path
                    new_line = line_text.replace(missing, new_target)
                    fixes.append(DanglingFix(
                        file_path=src_path,
                        line_number=line_no,
                        original_line=line_text,
                        action="rename",
                        new_line=new_line,
                        missing_module=missing,
                        current_module=new_target,
                    ))
                    stats["fixable_renames"] += 1

                # Strategy 2: Deliberately removed → guard with try/except
                elif missing in DELIBERATELY_REMOVED:
                    if _is_already_guarded(src_path, line_no):
                        stats["already_guarded"] += 1
                    else:
                        fixes.append(DanglingFix(
                            file_path=src_path,
                            line_number=line_no,
                            original_line=line_text,
                            action="guard",
                            new_line=None,
                            missing_module=missing,
                            current_module=None,
                        ))
                        stats["guardable"] += 1

                # Strategy 3: Dead module referencing missing → just note it
                elif ref_mod not in reachable_modules:
                    stats["from_dead_modules"] += 1

                # Strategy 4: Reachable module referencing unknown missing → guard
                else:
                    if _is_already_guarded(src_path, line_no):
                        stats["already_guarded"] += 1
                    else:
                        fixes.append(DanglingFix(
                            file_path=src_path,
                            line_number=line_no,
                            original_line=line_text,
                            action="guard",
                            new_line=None,
                            missing_module=missing,
                            current_module=None,
                        ))
                        stats["guardable"] += 1

    return fixes, stats


def apply_fixes(fixes: list[DanglingFix], dry_run: bool = True) -> list[str]:
    """Apply the generated fixes.  Returns log of actions."""
    log: list[str] = []

    # Group fixes by file
    by_file: dict[Path, list[DanglingFix]] = defaultdict(list)
    for fix in fixes:
        by_file[fix.file_path].append(fix)

    for fpath, file_fixes in by_file.items():
        try:
            lines = fpath.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except Exception as e:
            log.append(f"SKIP {fpath}: {e}")
            continue

        # Sort fixes by line number descending so we don't shift lines
        file_fixes.sort(key=lambda f: f.line_number, reverse=True)

        modified = False
        for fix in file_fixes:
            idx = fix.line_number - 1
            if idx >= len(lines):
                continue

            if fix.action == "rename" and fix.new_line:
                old = lines[idx]
                lines[idx] = fix.new_line
                action = f"RENAME {fpath.relative_to(CC)}:{fix.line_number} — {fix.missing_module} → {fix.current_module}"
                log.append(action)
                modified = True

            elif fix.action == "guard":
                indent = len(lines[idx]) - len(lines[idx].lstrip())
                pad = " " * indent
                original = lines[idx]
                guarded = [
                    f"{pad}try:",
                    f"{pad}    {original.strip()}",
                    f"{pad}except ImportError:",
                    f"{pad}    pass  # {fix.missing_module} not available",
                ]
                lines[idx:idx+1] = guarded
                action = f"GUARD  {fpath.relative_to(CC)}:{fix.line_number} — {fix.missing_module}"
                log.append(action)
                modified = True

        if modified and not dry_run:
            fpath.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return log


def generate_report(fixes: list[DanglingFix], stats: dict[str, Any], log: list[str]) -> dict:
    return {
        "stats": stats,
        "fixes": [
            {
                "file": str(f.file_path.relative_to(CC)),
                "line": f.line_number,
                "action": f.action,
                "missing": f.missing_module,
                "target": f.current_module,
            }
            for f in fixes
        ],
        "applied_log": log,
    }


def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="Dependency Graph Sanitizer")
    p.add_argument("--apply", action="store_true", help="Actually apply fixes (default: dry run)")
    args = p.parse_args()

    print("Analyzing dangling imports...", flush=True)
    fixes, stats = analyze_dangling_imports()

    print(f"\n  Total dangling targets: {stats['total_dangling']}")
    print(f"  Fixable renames:        {stats['fixable_renames']}")
    print(f"  Need guard (try/except): {stats['guardable']}")
    print(f"  Already guarded:        {stats['already_guarded']}")
    print(f"  From dead modules:      {stats['from_dead_modules']}")

    dry_run = not args.apply
    mode = "DRY RUN" if dry_run else "APPLYING"
    print(f"\n{mode}: {len(fixes)} fixes...", flush=True)
    log = apply_fixes(fixes, dry_run=dry_run)

    for entry in log[:50]:
        print(f"  {entry}")
    if len(log) > 50:
        print(f"  ... and {len(log) - 50} more")

    report = generate_report(fixes, stats, log)
    out = ROOT / "dependency_sanitizer_report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\n{'═'*60}")
    print(f"  DEPENDENCY SANITIZATION: {len(fixes)} fixes identified")
    print(f"  {stats['fixable_renames']} renames │ {stats['guardable']} guards │ {stats['from_dead_modules']} dead-module refs")
    if dry_run:
        print(f"  Run with --apply to execute fixes")
    else:
        print(f"  ✅ {len(log)} fixes applied")
    print(f"{'═'*60}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
