"""
_audit_vs_code_history_regressions.py — Sprint A1.28 pre-flight audit.

For every file touched in the ~30-commit recovery phase, compare:
  (a) current on-disk size/mtime/sha256
  (b) latest VS Code History snapshot for that file's resource

Flag:
  HISTORY_NEWER  — history snapshot has later mtime than disk file
  HISTORY_LARGER — history snapshot is >= 1.5x larger than disk
  HISTORY_ABSENT — no history for this file (can't audit)
  OK             — disk matches history sha256 OR disk is newer + similar size

Produces:
  _audit_history_regressions.tsv — one row per file
  _audit_history_regressions_top.tsv — only HISTORY_NEWER / HISTORY_LARGER rows,
                                        sorted by size delta (biggest gap first)
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(r"c:\Users\ya754\CaseCrack v1.0\CaseCrack")
HIST = Path(os.environ["APPDATA"]) / "Code" / "User" / "History"
OUT_ALL = REPO / "_audit_history_regressions.tsv"
OUT_TOP = REPO / "_audit_history_regressions_top.tsv"

# Commits that constitute the "recovery phase" (A1 sprints)
# Ask git for every file touched across recent recovery commits.
SINCE = "2026-04-16"


def recovery_phase_files() -> set[Path]:
    r = subprocess.run(
        ["git", "log", f"--since={SINCE}", "--name-only", "--pretty=format:"],
        cwd=REPO, capture_output=True, text=True, check=True,
    )
    files: set[Path] = set()
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("_") or line.endswith(".md"):
            continue
        if not (line.startswith("tools/") or line.startswith("tests/")):
            continue
        if not line.endswith(".py"):
            continue
        p = REPO / line
        if p.is_file():
            files.add(p)
    return files


def all_module_files() -> set[Path]:
    """Every .py under tools/burp_enterprise + tests (excludes __pycache__)."""
    files: set[Path] = set()
    for root in [REPO / "tools" / "burp_enterprise", REPO / "tests"]:
        if not root.exists():
            continue
        for p in root.rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            files.add(p)
    return files


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def is_relay_shim(path: Path) -> bool:
    """Detect thin backward-compat shims pointing at the real module."""
    try:
        sz = path.stat().st_size
        if sz > 4096:
            return False
        txt = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    # __getattr__ + importlib style
    if "import_module" in txt and "__getattr__" in txt:
        return True
    # Explicit "from .X import Y, Z, ..." re-export shim
    lowered = txt.lower()
    if ("backward-compatible" in lowered or "backward-compatibility" in lowered
            or "import shim" in lowered or "re-exports" in lowered):
        return True
    return False


def index_history() -> dict[str, tuple[Path, int, int, str]]:
    """Return {absolute_resource_path_lower: (latest_snapshot_path, size, mtime, sha)}."""
    idx: dict[str, tuple[Path, int, int]] = {}
    # Iterate every entries.json under HIST
    for ej in HIST.glob("*/entries.json"):
        try:
            data = json.loads(ej.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        resource = data.get("resource", "")
        entries = data.get("entries") or []
        if not resource or not entries:
            continue
        # Resource is a file:/// URI
        if resource.startswith("file:///"):
            res_path = resource[len("file:///"):].replace("/", os.sep)
            # Windows: 'c%3A/Users/...' possibly url-encoded colon
            res_path = res_path.replace("%3A", ":").replace("%3a", ":").replace("%20", " ")
        else:
            continue
        key = res_path.lower()
        # Latest entry = max timestamp
        latest = max(entries, key=lambda e: e.get("timestamp", 0))
        snap = ej.parent / latest["id"]
        if not snap.exists():
            continue
        ts = latest.get("timestamp", 0)
        sz = snap.stat().st_size
        prev = idx.get(key)
        if prev is None or ts > prev[2]:
            idx[key] = (snap, sz, ts)
    return idx


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "recovery"
    if mode == "all":
        files = all_module_files()
    else:
        files = recovery_phase_files()
    print(f"Scanning {len(files)} {mode} files...", file=sys.stderr)
    print("Indexing VS Code History (can take ~30s)...", file=sys.stderr)
    hist = index_history()
    print(f"History indexed: {len(hist)} unique resources", file=sys.stderr)

    rows: list[tuple[str, str, int, int, float, float, str]] = []
    # status, relpath, disk_size, hist_size, size_ratio, age_delta_days, hist_snapshot
    for p in sorted(files):
        rel = p.relative_to(REPO).as_posix()
        disk_size = p.stat().st_size
        disk_mtime = p.stat().st_mtime
        if is_relay_shim(p):
            rows.append(("OK_RELAY_SHIM", rel, disk_size, 0, 0.0, 0.0, ""))
            continue
        disk_sha = sha256(p)
        key = str(p).lower()
        snap_info = hist.get(key)
        if snap_info is None:
            rows.append(("HISTORY_ABSENT", rel, disk_size, 0, 0.0, 0.0, ""))
            continue
        snap_path, snap_size, snap_ts = snap_info
        snap_mtime = snap_ts / 1000.0  # ms -> s
        # Compare content
        try:
            snap_sha = sha256(snap_path)
        except Exception:
            snap_sha = ""
        if snap_sha == disk_sha:
            rows.append(("OK_IDENTICAL", rel, disk_size, snap_size, 1.0, 0.0, str(snap_path)))
            continue
        size_ratio = snap_size / max(disk_size, 1)
        age_delta_days = (snap_mtime - disk_mtime) / 86400.0
        if snap_mtime > disk_mtime and size_ratio >= 1.5:
            status = "HISTORY_NEWER_LARGER"
        elif snap_mtime > disk_mtime:
            status = "HISTORY_NEWER"
        elif size_ratio >= 1.5:
            status = "HISTORY_LARGER"
        elif disk_mtime > snap_mtime and disk_size >= snap_size * 0.9:
            status = "OK_DISK_NEWER"
        else:
            status = "DIFF_MINOR"
        rows.append((status, rel, disk_size, snap_size, size_ratio, age_delta_days, str(snap_path)))

    # Write all
    with OUT_ALL.open("w", encoding="utf-8", newline="") as f:
        f.write("status\tpath\tdisk_size\thist_size\tsize_ratio\thist_newer_days\thist_snapshot\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")

    # Top = regressions sorted by size gap
    priority = {
        "HISTORY_NEWER_LARGER": 0,
        "HISTORY_LARGER": 1,
        "HISTORY_NEWER": 2,
    }
    top = [r for r in rows if r[0] in priority]
    top.sort(key=lambda r: (priority[r[0]], -(r[3] - r[2])))
    with OUT_TOP.open("w", encoding="utf-8", newline="") as f:
        f.write("status\tpath\tdisk_size\thist_size\tsize_ratio\thist_newer_days\thist_snapshot\n")
        for r in top:
            f.write("\t".join(str(x) for x in r) + "\n")

    # Summary
    from collections import Counter
    c = Counter(r[0] for r in rows)
    print("\n=== AUDIT SUMMARY ===")
    for status, n in sorted(c.items(), key=lambda x: -x[1]):
        print(f"  {status:24s} {n}")
    print(f"\nFull:  {OUT_ALL}")
    print(f"Top:   {OUT_TOP} ({len(top)} candidates to review)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
