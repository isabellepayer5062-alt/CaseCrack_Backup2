"""Comprehensive final recovery audit — V2.

Filters out intentional splits/facades/relays to surface true regressions.
"""
from __future__ import annotations
import json, os, re, sys, ast
from pathlib import Path
from collections import defaultdict
from urllib.parse import unquote

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
ROOT = WS / "CaseCrack"
HIST = Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

WS_URI_PREFIXES = [
    "file:///c%3A/Users/ya754/CaseCrack%20v1.0/",
    "file:///C%3A/Users/ya754/CaseCrack%20v1.0/",
]

def decode_uri(u: str) -> Path | None:
    for p in WS_URI_PREFIXES:
        if u.startswith(p):
            rel = unquote(u[len(p):])
            return WS / rel.replace("/", os.sep)
    return None

# ---------- Index history ----------
hist_index: dict[Path, dict] = {}
for entries_json in HIST.rglob("entries.json"):
    try:
        data = json.loads(entries_json.read_text(encoding="utf-8"))
    except Exception:
        continue
    target = decode_uri(data.get("resource", ""))
    if target is None or target.suffix != ".py":
        continue
    try:
        rel = target.relative_to(WS)
    except ValueError:
        continue
    hdir = entries_json.parent
    for ent in data.get("entries", []):
        fid = ent.get("id"); ts = ent.get("timestamp", 0)
        if not fid: continue
        snap = hdir / fid
        if not snap.exists(): continue
        size = snap.stat().st_size
        cur = hist_index.get(rel)
        # prefer largest; tie-break by newest timestamp
        if cur is None or size > cur["size"] or (size == cur["size"] and ts > cur["ts"]):
            hist_index[rel] = {"size": size, "ts": ts, "snap": snap}

print(f"[hist] {len(hist_index)} resources", file=sys.stderr)

# ---------- Index disk ----------
disk_files: dict[Path, dict] = {}
dir_set: set[Path] = set()
for p in ROOT.rglob("*.py"):
    if "__pycache__" in p.parts: continue
    rel = p.relative_to(WS)
    st = p.stat()
    disk_files[rel] = {"size": st.st_size, "mtime": int(st.st_mtime), "path": p}
for p in ROOT.rglob("*"):
    if p.is_dir():
        try: dir_set.add(p.relative_to(WS))
        except ValueError: pass

print(f"[disk] {len(disk_files)} .py files", file=sys.stderr)

# ---------- Build imports graph ----------
module_to_rel: dict[str, Path] = {}
for rel in disk_files:
    parts = rel.parts
    if parts[0] != "CaseCrack": continue
    dotted = ".".join(parts[1:])[:-3]
    if dotted.endswith(".__init__"):
        dotted = dotted[:-9]
    module_to_rel[dotted] = rel

# count refs: for each import statement in the codebase, walk up the dotted path
IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))", re.M)
ref_to_modules: dict[str, set[str]] = defaultdict(set)  # dotted module -> set of referring files
for rel, info in disk_files.items():
    try:
        text = info["path"].read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    for m in IMPORT_RE.finditer(text):
        mod = (m.group(1) or m.group(2) or "").strip()
        if not mod: continue
        cand = mod
        while cand:
            if cand.startswith("tools.") or cand.startswith("CaseCrack."):
                # normalize: tools.X -> CaseCrack.tools.X
                norm = cand if cand.startswith("CaseCrack.") else "CaseCrack." + cand
                dotted = norm[len("CaseCrack."):]
                if dotted in module_to_rel:
                    ref_to_modules[dotted].add(str(rel))
                    break
            cand = cand.rsplit(".", 1)[0] if "." in cand else ""

# ---------- Heuristics ----------
INTENTIONAL_MARKERS = [
    "has been removed",
    "thin facade",
    "re-exports",
    "split into",
    "extracted from",
    "backward-compat",
    "relay shim",
    "deprecated",
    "moved to",
    "replaced by",
]

def is_intentional(text: str) -> bool:
    head = text[:2000].lower()
    return any(m in head for m in INTENTIONAL_MARKERS)

def is_relay_shim(text: str) -> bool:
    if len(text) > 2500: return False
    if "import_module" in text: return True
    if text.count("from .") > 0 and text.count("\n") < 60 and "import" in text:
        return True
    return False

# ---------- Analyze ----------
missing_rows = []  # (refs, hist_size, rel, snap, reason)
regression_rows = []  # (ratio, disk_size, hist_size, rel, snap, note)

for rel, h in hist_index.items():
    parts = rel.parts
    if len(parts) < 2 or parts[0] != "CaseCrack": continue
    if h["size"] < 256: continue
    dotted = ".".join(parts[1:])[:-3]
    if dotted.endswith(".__init__"):
        dotted = dotted[:-9]

    if rel not in disk_files:
        # MISSING: skip if replaced by same-named package dir
        pkg_dir = rel.with_suffix("")
        if pkg_dir in dir_set:
            continue
        # skip if dotted or its parent is known as a module (package init may provide it)
        refs = len(ref_to_modules.get(dotted, set()))
        # also look for raw text references in case import graph missed (e.g., importlib)
        raw_refs = refs
        missing_rows.append((raw_refs, h["size"], str(rel), str(h["snap"])))
    else:
        d = disk_files[rel]
        if h["size"] < 4096: continue
        if d["size"] >= h["size"] * 0.75: continue
        try:
            text = d["path"].read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if is_intentional(text):
            continue
        if is_relay_shim(text):
            continue
        # Additional: skip if file begins with `raise ImportError` (removed marker)
        if "raise ImportError" in text[:500]:
            continue
        # AST sanity on history snapshot
        try:
            snap_text = h["snap"].read_text(encoding="utf-8", errors="ignore")
            ast.parse(snap_text)
        except Exception:
            note = "hist_unparseable"
        else:
            note = "ok"
        ratio = d["size"] / h["size"]
        refs = len(ref_to_modules.get(dotted, set()))
        regression_rows.append((ratio, d["size"], h["size"], str(rel), str(h["snap"]), refs, note))

missing_rows.sort(reverse=True)
regression_rows.sort()

# ---------- Write ----------
def w(path: Path, header: list[str], rows: list):
    with path.open("w", encoding="utf-8") as f:
        f.write("\t".join(header) + "\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")

w(WS / "_final_audit_missing.tsv",
  ["refs", "hist_size", "rel_path", "snapshot"],
  missing_rows)
w(WS / "_final_audit_regressions.tsv",
  ["ratio", "disk_size", "hist_size", "rel_path", "snapshot", "refs", "note"],
  regression_rows)

print(f"[missing-real] {len(missing_rows)}")
print(f"[regressions-real] {len(regression_rows)}")

print("\n=== TOP MISSING (by refs) ===")
for r in missing_rows[:30]:
    print(f"  refs={r[0]:3d}  {r[1]//1024:4d}KB  {r[2]}")

print("\n=== TOP REGRESSIONS (disk << history) ===")
for r in regression_rows[:40]:
    print(f"  {r[0]:.2f}  {r[1]//1024:4d}KB -> {r[2]//1024:4d}KB  refs={r[5]:3d}  {r[3]}")
