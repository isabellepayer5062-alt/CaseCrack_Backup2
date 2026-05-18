"""
Dead Module Cleanup: Cold-storage move + Garbage deletion.

Reads dead_module_triage.json and:
  1. Moves 56 cold-storage modules to CaseCrack/tools/burp_enterprise/_cold_storage/
  2. Deletes 278 garbage modules
  3. Cleans up empty __init__.py parents left behind
  4. Reports results

Safety: Does NOT touch reconnect candidates or any live modules.
"""

from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CC   = ROOT / "CaseCrack"
PKG  = CC / "tools" / "burp_enterprise"
COLD = PKG / "_cold_storage"

TRIAGE = ROOT / "dead_module_triage.json"


def module_to_paths(short_module: str) -> list[Path]:
    """Convert a short module name to candidate file paths."""
    # short_module is like "agents.advanced_agent_patterns"
    # full is "tools.burp_enterprise.agents.advanced_agent_patterns"
    full = f"tools.burp_enterprise.{short_module}"
    rel = full.replace(".", "/")

    paths: list[Path] = []
    # As a .py file
    py = CC / f"{rel}.py"
    if py.exists():
        paths.append(py)
    # As a package directory
    pkg_dir = CC / rel
    if pkg_dir.is_dir():
        paths.append(pkg_dir)
    return paths


def move_to_cold_storage(modules: list[dict]) -> tuple[int, int, list[str]]:
    """Move cold-storage modules into _cold_storage/ preserving subdir structure."""
    moved_files = 0
    moved_dirs = 0
    errors: list[str] = []

    COLD.mkdir(parents=True, exist_ok=True)

    for entry in modules:
        short = entry["module"]
        paths = module_to_paths(short)

        if not paths:
            errors.append(f"NOT FOUND: {short}")
            continue

        for src in paths:
            # Compute relative path from PKG
            try:
                rel = src.relative_to(PKG)
            except ValueError:
                errors.append(f"OUTSIDE PKG: {src}")
                continue

            dst = COLD / rel
            dst.parent.mkdir(parents=True, exist_ok=True)

            try:
                if src.is_dir():
                    if dst.exists():
                        shutil.rmtree(dst)
                    shutil.move(str(src), str(dst))
                    moved_dirs += 1
                else:
                    shutil.move(str(src), str(dst))
                    moved_files += 1
            except Exception as e:
                errors.append(f"MOVE FAILED: {src} -> {dst}: {e}")

    return moved_files, moved_dirs, errors


def delete_garbage(modules: list[dict]) -> tuple[int, int, list[str]]:
    """
    Delete garbage modules.

    SAFETY: Only ever deletes leaf .py files. Never removes a package
    directory via rmtree — doing so would wipe live sibling modules.
    A bug in a previous version of this function deleted ~770 modules
    (recovered via VS Code local history, 2026-04-16). Do NOT reintroduce
    rmtree on directories here. If a package `__init__.py` is garbage,
    delete only that file; orphaned empty package dirs are cleaned up
    later by cleanup_empty_dirs().
    """
    deleted_files = 0
    deleted_dirs = 0  # always 0 now — kept for call-site compatibility
    errors: list[str] = []

    for entry in modules:
        short = entry["module"]
        paths = module_to_paths(short)

        if not paths:
            continue

        for src in paths:
            try:
                if src.is_dir():
                    # Only remove the __init__.py inside a package directory,
                    # never the directory itself. Siblings may be live.
                    init_py = src / "__init__.py"
                    if init_py.exists():
                        init_py.unlink()
                        deleted_files += 1
                    # Intentionally do NOT rmtree(src). Empty dirs are
                    # removed later by cleanup_empty_dirs().
                else:
                    src.unlink()
                    deleted_files += 1
            except Exception as e:
                errors.append(f"DELETE FAILED: {src}: {e}")

    return deleted_files, deleted_dirs, errors


def cleanup_empty_dirs(base: Path) -> int:
    """Remove empty directories (bottom-up), skip __pycache__."""
    removed = 0
    for d in sorted(base.rglob("*"), key=lambda p: -len(p.parts)):
        if not d.is_dir():
            continue
        if d.name == "__pycache__":
            continue
        if d.name == "_cold_storage":
            continue
        # Check if directory is empty (or only has __pycache__)
        children = list(d.iterdir())
        real_children = [c for c in children if c.name != "__pycache__"]
        if not real_children:
            # Remove __pycache__ if it's the only child
            pycache = d / "__pycache__"
            if pycache.exists():
                shutil.rmtree(pycache)
            # Now remove the empty dir
            try:
                d.rmdir()
                removed += 1
            except OSError:
                pass
    return removed


def main():
    with open(TRIAGE) as f:
        data = json.load(f)

    cold_modules = data["cold_storage"]
    garbage_modules = data["garbage"]

    print("=" * 70)
    print("  DEAD MODULE CLEANUP")
    print("=" * 70)
    print()

    # ── Phase 1: Cold Storage ────────────────────────────────────────────
    print(f"  📦 Moving {len(cold_modules)} cold-storage modules to _cold_storage/")
    mf, md, merr = move_to_cold_storage(cold_modules)
    print(f"     Moved: {mf} files, {md} directories")
    if merr:
        print(f"     Errors: {len(merr)}")
        for e in merr[:10]:
            print(f"       {e}")
    print()

    # ── Phase 2: Garbage Deletion ────────────────────────────────────────
    print(f"  🗑️  Deleting {len(garbage_modules)} garbage modules")
    df, dd, derr = delete_garbage(garbage_modules)
    print(f"     Deleted: {df} files, {dd} directories")
    if derr:
        print(f"     Errors: {len(derr)}")
        for e in derr[:10]:
            print(f"       {e}")
    print()

    # ── Phase 3: Empty directory cleanup ─────────────────────────────────
    print("  🧹 Cleaning empty directories...")
    removed = cleanup_empty_dirs(PKG)
    print(f"     Removed: {removed} empty directories")
    print()

    # ── Summary ──────────────────────────────────────────────────────────
    total_ops = mf + md + df + dd
    total_errors = len(merr) + len(derr)
    print("─" * 70)
    print(f"  DONE: {total_ops} operations, {total_errors} errors")
    print(f"  Cold storage: {COLD}")

    # Count cold storage contents
    cold_files = list(COLD.rglob("*.py"))
    print(f"  Cold storage files: {len(cold_files)}")
    print()

    # Write cleanup log
    log = {
        "cold_storage_moved_files": mf,
        "cold_storage_moved_dirs": md,
        "cold_storage_errors": merr,
        "garbage_deleted_files": df,
        "garbage_deleted_dirs": dd,
        "garbage_errors": derr,
        "empty_dirs_removed": removed,
    }
    log_path = ROOT / "dead_module_cleanup_log.json"
    with open(log_path, "w") as f:
        json.dump(log, f, indent=2)
    print(f"  Log saved: {log_path}")


if __name__ == "__main__":
    main()
