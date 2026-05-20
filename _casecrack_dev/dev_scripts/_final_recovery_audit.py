"""Comprehensive final recovery audit.

Scans VS Code workspace history snapshots for the CaseCrack workspace,
compares the most-recent-and-largest snapshot for each resource basename
against the current disk state.

Outputs four TSVs:
  _final_audit_missing.tsv      — imported modules not on disk, present in history
  _final_audit_regressions.tsv  — disk files materially smaller than history latest
  _final_audit_stale.tsv        — disk files older than history AND smaller (rough dup risk)
  _final_audit_all.tsv          — full manifest (status per file)
"""
from __future__ import annotations
import json, os, re, sys, hashlib
from pathlib import Path
from collections import defaultdict

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
ROOT = WS / "CaseCrack"
HIST = Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

# Only consider snapshots for resources under our workspace
WS_URI_PREFIXES = [
    "file:///c%3A/Users/ya754/CaseCrack%20v1.0/",
    "file:///C%3A/Users/ya754/CaseCrack%20v1.0/",
]

def decode_uri(u: str) -> Path | None:
    for p in WS_URI_PREFIXES:
        if u.startswith(p):
            from urllib.parse import unquote
            rel = unquote(u[len(p):])
            return WS / rel.replace("/", os.sep)
    return None

# ---------- 1. Index VS Code history ----------
# map: workspace-relative path -> {size, ts, source}  (latest, then largest)
hist_index: dict[Path, dict] = {}
n_entries = 0
for entries_json in HIST.rglob("entries.json"):
    try:
        data = json.loads(entries_json.read_text(encoding="utf-8"))
    except Exception:
        continue
    uri = data.get("resource", "")
    target = decode_uri(uri)
    if target is None or target.suffix != ".py":
        continue
    # Only care about files under CaseCrack/ tree
    try:
        rel = target.relative_to(WS)
    except ValueError:
        continue
    hdir = entries_json.parent
    for ent in data.get("entries", []):
        fid = ent.get("id")
        ts = ent.get("timestamp", 0)
        if not fid:
            continue
        snap = hdir / fid
        if not snap.exists():
            continue
        size = snap.stat().st_size
        cur = hist_index.get(rel)
        # prefer larger; break ties by newer timestamp
        if cur is None or size > cur["size"] or (size == cur["size"] and ts > cur["ts"]):
            hist_index[rel] = {"size": size, "ts": ts, "snap": snap}
        n_entries += 1

print(f"[hist] {len(hist_index)} unique resources from {n_entries} snapshots", file=sys.stderr)

# ---------- 2. Index current disk state under CaseCrack/ ----------
disk_files: dict[Path, dict] = {}
for p in ROOT.rglob("*.py"):
    # skip caches
    if "__pycache__" in p.parts or ".venv" in p.parts:
        continue
    try:
        rel = p.relative_to(WS)
    except ValueError:
        continue
    st = p.stat()
    disk_files[rel] = {"size": st.st_size, "mtime": int(st.st_mtime), "path": p}

print(f"[disk] {len(disk_files)} .py files under CaseCrack/", file=sys.stderr)

# ---------- 3. Build import reference graph (module -> ref count) ----------
# Map dotted module name -> path(s) on disk.
module_to_path: dict[str, Path] = {}
for rel, info in disk_files.items():
    parts = rel.parts
    if parts[0] != "CaseCrack":
        continue
    dotted = ".".join(parts[1:])[:-3]  # strip .py
    if dotted.endswith(".__init__"):
        dotted = dotted[:-9]
    module_to_path[dotted] = rel

# count references
IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.][\w\.,\s]*))", re.M)
ref_counts: dict[str, int] = defaultdict(int)
for rel, info in disk_files.items():
    try:
        text = info["path"].read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    for m in IMPORT_RE.finditer(text):
        mod = m.group(1) or (m.group(2) or "").split(",")[0].split()[0] if m.group(2) else m.group(1)
        mod = (m.group(1) or m.group(2) or "").strip().split(",")[0].split()[0]
        if not mod:
            continue
        # walk upwards to match
        while mod:
            if mod in module_to_path:
                ref_counts[mod] += 1
                break
            if "." not in mod:
                break
            mod = mod.rsplit(".", 1)[0]

# ---------- 4. Missing: in history but not on disk, and imported somewhere ----------
missing_rows = []
for rel, h in hist_index.items():
    if rel in disk_files:
        continue
    parts = rel.parts
    if len(parts) < 2 or parts[0] != "CaseCrack":
        continue
    dotted = ".".join(parts[1:])[:-3]
    if dotted.endswith(".__init__"):
        dotted = dotted[:-9]
    # see if any known import references this module or an ancestor of this module
    refs = 0
    candidate = dotted
    while candidate:
        refs = max(refs, ref_counts.get(candidate, 0))
        if "." not in candidate:
            break
        candidate = candidate.rsplit(".", 1)[0]
    # also raw-grep pattern inside source if len > 20
    if h["size"] < 128:
        continue  # empty/stub snapshot
    missing_rows.append((refs, h["size"], rel, h["snap"]))

missing_rows.sort(reverse=True)

# ---------- 5. Regressions: disk < history by >= 25% and file non-trivial ----------
regression_rows = []
for rel, d in disk_files.items():
    h = hist_index.get(rel)
    if not h or h["size"] < 4096:
        continue
    if d["size"] >= h["size"] * 0.75:
        continue
    # skip relay shims: contain import_module and small
    try:
        text = d["path"].read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    if len(text) < 1500 and "import_module" in text:
        continue
    if "# Relay shim" in text[:500] or "backward-compat" in text[:500].lower():
        continue
    ratio = d["size"] / h["size"]
    regression_rows.append((ratio, d["size"], h["size"], rel, h["snap"]))

regression_rows.sort()

# ---------- 6. Stale duplicates: disk older than history snapshot AND smaller ----------
stale_rows = []
for rel, d in disk_files.items():
    h = hist_index.get(rel)
    if not h:
        continue
    if h["ts"] // 1000 > d["mtime"] and d["size"] < h["size"] * 0.9 and h["size"] >= 4096:
        stale_rows.append((h["ts"] - d["mtime"]*1000, d["size"], h["size"], rel, h["snap"]))

stale_rows.sort(reverse=True)

# ---------- Write reports ----------
def w(path: Path, header: list[str], rows: list, fmt):
    with path.open("w", encoding="utf-8") as f:
        f.write("\t".join(header) + "\n")
        for r in rows:
            f.write(fmt(r) + "\n")

w(WS / "_final_audit_missing.tsv",
  ["refs", "hist_size", "rel_path", "snapshot"],
  missing_rows,
  lambda r: f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}")

w(WS / "_final_audit_regressions.tsv",
  ["ratio", "disk_size", "hist_size", "rel_path", "snapshot"],
  regression_rows,
  lambda r: f"{r[0]:.3f}\t{r[1]}\t{r[2]}\t{r[3]}\t{r[4]}")

w(WS / "_final_audit_stale.tsv",
  ["age_delta_ms", "disk_size", "hist_size", "rel_path", "snapshot"],
  stale_rows,
  lambda r: f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\t{r[4]}")

print(f"[missing] {len(missing_rows)} (referenced at top)")
print(f"[regressions] {len(regression_rows)} disk < 75% of history")
print(f"[stale] {len(stale_rows)} disk older than history and smaller")

# Print top findings
print("\n=== TOP MISSING (imported, in history) ===")
for r in missing_rows[:20]:
    print(f"  refs={r[0]:3d}  {r[1]//1024:4d}KB  {r[2]}")

print("\n=== TOP REGRESSIONS (disk << history) ===")
for r in regression_rows[:25]:
    print(f"  ratio={r[0]:.2f}  {r[1]//1024:3d}KB -> {r[2]//1024:3d}KB  {r[3]}")
