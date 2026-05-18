"""Final comprehensive history-vs-disk audit (2026-04-21 follow-up).

Indexes every VS Code History snapshot (URL-decoded) keyed by path tail
and compares against current disk state across the workspace, for ALL
file extensions of interest.

Outputs:
  _final_sweep_missing.tsv     - on-history, not-on-disk
  _final_sweep_regressed.tsv   - on-disk smaller than history (>1.5x ratio)
  _final_sweep_summary.txt
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.parse
from collections import defaultdict
from pathlib import Path

HISTORY_ROOT = Path(os.environ["APPDATA"]) / "Code" / "User" / "History"
WORKSPACE_ROOT = Path(r"C:\Users\ya754\CaseCrack v1.0")

# Extensions we care about (production code + assets)
EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".html", ".css", ".scss",
        ".json", ".yaml", ".yml", ".md", ".sql", ".sh", ".ps1", ".toml",
        ".cfg", ".ini", ".rs", ".go"}

# Paths we want to consider "in workspace" when filtering history matches.
# Anything matching one of these tail prefixes counts.
WORKSPACE_TAIL_HINTS = (
    "casecrack/",
    "casecrack v1.0/",
    "tools/burp_enterprise/",
    "tests/",
    "frontend/",
    "src/",
)


def is_relay_shim(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    if len(text) > 4096:
        return False
    has_import_module = "import_module(" in text
    has_from_import = "from " in text and "import" in text
    body_lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    return len(body_lines) < 30 and (has_import_module or has_from_import)


def index_history():
    """Return dict: tail2 (parent/file) -> list[(timestamp, size, snap_path, full_decoded_uri)]."""
    by_tail = defaultdict(list)
    by_tail3 = defaultdict(list)
    n_entries = 0
    n_snaps = 0
    for entries_json in HISTORY_ROOT.rglob("entries.json"):
        n_entries += 1
        try:
            data = json.loads(entries_json.read_text(encoding="utf-8"))
        except Exception:
            continue
        resource = data.get("resource", "")
        if not resource:
            continue
        # decode %20 etc, strip file:/// scheme
        decoded = urllib.parse.unquote(resource)
        if decoded.startswith("file:///"):
            decoded = decoded[len("file:///"):]
        decoded_lower = decoded.lower().replace("\\", "/")
        ext = Path(decoded_lower).suffix
        if ext not in EXTS:
            continue
        parts = decoded_lower.split("/")
        if len(parts) < 2:
            continue
        tail2 = "/".join(parts[-2:])
        tail3 = "/".join(parts[-3:]) if len(parts) >= 3 else tail2
        for entry in data.get("entries", []):
            snap_id = entry.get("id")
            ts = entry.get("timestamp", 0)
            if not snap_id:
                continue
            snap_path = entries_json.parent / snap_id
            if not snap_path.exists():
                continue
            try:
                size = snap_path.stat().st_size
            except OSError:
                continue
            n_snaps += 1
            by_tail[tail2].append((ts, size, snap_path, decoded_lower))
            by_tail3[tail3].append((ts, size, snap_path, decoded_lower))
    print(f"[history] indexed {n_entries} entries.json, {n_snaps} snapshots, "
          f"{len(by_tail)} unique tail2 keys", file=sys.stderr)
    return by_tail, by_tail3


def index_disk():
    """Return dict: tail2 -> list[(size, abs_path)] for files under workspace."""
    by_tail = defaultdict(list)
    by_tail3 = defaultdict(list)
    skip_dirs = {".git", ".venv", "__pycache__", "node_modules", ".pytest_cache",
                 ".hypothesis", ".benchmarks", "dist", "build", ".mypy_cache",
                 ".ruff_cache", "_archive", "_archive_legacy", "ctemp",
                 ".langgraph_agent_checkpoints", ".langgraph_cross_scan_memory",
                 ".venator_checkpoints", ".exploit_cache", ".vuln_cache"}
    for root, dirs, files in os.walk(WORKSPACE_ROOT):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fn in files:
            ext = Path(fn).suffix.lower()
            if ext not in EXTS:
                continue
            full = Path(root) / fn
            try:
                size = full.stat().st_size
            except OSError:
                continue
            rel = full.relative_to(WORKSPACE_ROOT).as_posix().lower()
            parts = rel.split("/")
            tail2 = "/".join(parts[-2:])
            tail3 = "/".join(parts[-3:]) if len(parts) >= 3 else tail2
            by_tail[tail2].append((size, full))
            by_tail3[tail3].append((size, full))
    return by_tail, by_tail3


def in_workspace_uri(decoded_uri: str) -> bool:
    return any(hint in decoded_uri for hint in WORKSPACE_TAIL_HINTS)


def latest_workspace_snap(snaps):
    """Pick latest workspace-scoped snapshot from list."""
    ws = [s for s in snaps if in_workspace_uri(s[3])]
    if not ws:
        return None
    ws.sort(key=lambda s: s[0], reverse=True)
    return ws[0]


def biggest_workspace_snap(snaps):
    ws = [s for s in snaps if in_workspace_uri(s[3])]
    if not ws:
        return None
    ws.sort(key=lambda s: s[1], reverse=True)
    return ws[0]


def main():
    hist_t2, hist_t3 = index_history()
    disk_t2, disk_t3 = index_disk()

    print(f"[disk] {sum(len(v) for v in disk_t2.values())} files, "
          f"{len(disk_t2)} unique tail2", file=sys.stderr)

    missing_rows = []  # workspace-scoped tail not present on disk
    regressed_rows = []  # disk file smaller than history

    # Pass 1: missing — history has it, disk doesn't (workspace-scoped)
    for tail, snaps in hist_t2.items():
        if tail in disk_t2:
            continue
        snap = biggest_workspace_snap(snaps)
        if not snap:
            continue
        ts, size, snap_path, uri = snap
        if size < 1024:  # tiny snapshots are almost always stubs
            continue
        missing_rows.append((tail, size, ts, str(snap_path), uri))

    # Pass 2: regressed — disk file smaller than latest workspace snap
    for tail, disk_files in disk_t2.items():
        if tail not in hist_t2:
            continue
        snap = latest_workspace_snap(hist_t2[tail])
        if not snap:
            continue
        hist_ts, hist_size, hist_path, hist_uri = snap
        # take largest disk file with this tail
        disk_files.sort(reverse=True)
        disk_size, disk_path = disk_files[0]
        if hist_size <= disk_size * 1.5:
            continue
        if hist_size < 4096:
            continue
        # ignore relay shims on disk (intentional thin)
        if disk_path.suffix == ".py" and is_relay_shim(disk_path):
            continue
        regressed_rows.append((tail, disk_size, hist_size, hist_size / max(disk_size, 1),
                               str(disk_path), str(hist_path), hist_uri))

    missing_rows.sort(key=lambda r: -r[1])
    regressed_rows.sort(key=lambda r: -r[3])

    out_missing = WORKSPACE_ROOT / "_final_sweep_missing.tsv"
    with out_missing.open("w", encoding="utf-8") as f:
        f.write("tail\thist_size\ttimestamp\tsnap_path\toriginal_uri\n")
        for row in missing_rows:
            f.write("\t".join(str(x) for x in row) + "\n")

    out_regressed = WORKSPACE_ROOT / "_final_sweep_regressed.tsv"
    with out_regressed.open("w", encoding="utf-8") as f:
        f.write("tail\tdisk_size\thist_size\tratio\tdisk_path\tsnap_path\toriginal_uri\n")
        for row in regressed_rows:
            f.write("\t".join(str(x) for x in row) + "\n")

    summary = WORKSPACE_ROOT / "_final_sweep_summary.txt"
    with summary.open("w", encoding="utf-8") as f:
        f.write(f"History snapshots indexed: {sum(len(v) for v in hist_t2.values())}\n")
        f.write(f"Disk files scanned: {sum(len(v) for v in disk_t2.values())}\n")
        f.write(f"Missing-from-disk candidates: {len(missing_rows)}\n")
        f.write(f"Regressed-on-disk candidates: {len(regressed_rows)}\n\n")
        f.write("=== Top 30 missing by size ===\n")
        for row in missing_rows[:30]:
            f.write(f"  {row[1]:>9}  {row[0]}\n")
        f.write("\n=== Top 30 regressed by ratio ===\n")
        for row in regressed_rows[:30]:
            f.write(f"  {row[3]:5.2f}x  disk={row[1]:>8}  hist={row[2]:>8}  {row[0]}\n")

    print(f"[done] missing={len(missing_rows)}  regressed={len(regressed_rows)}")
    print(f"  -> {out_missing.name}")
    print(f"  -> {out_regressed.name}")
    print(f"  -> {summary.name}")


if __name__ == "__main__":
    main()
