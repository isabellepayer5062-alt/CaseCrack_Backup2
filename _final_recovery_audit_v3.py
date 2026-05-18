"""Re-audit with AST-valid + non-concatenated snapshot constraint.

Reuses the history index but picks the LARGEST AST-VALID snapshot per
resource (rejecting concatenation corruption where `from __future__`
appears more than once, which has been observed in several snapshots).

Outputs _final_audit_regressions_v2.tsv.
"""
from __future__ import annotations
import ast, json, os, sys, re
from pathlib import Path
from urllib.parse import unquote
from collections import defaultdict

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

# Collect ALL snapshots (not just largest)
all_snaps: dict[Path, list[tuple[int,int,Path]]] = defaultdict(list)
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
        all_snaps[rel].append((snap.stat().st_size, ts, snap))

print(f"[hist] {len(all_snaps)} resources", file=sys.stderr)

def pick_best(snaps: list[tuple[int,int,Path]]) -> tuple[int,int,Path] | None:
    """Largest snapshot that (a) AST-parses and (b) has <=1 __future__ import."""
    snaps_sorted = sorted(snaps, key=lambda x: (-x[0], -x[1]))
    for size, ts, snap in snaps_sorted:
        try:
            text = snap.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if text.count("from __future__") > 1:
            continue  # concatenation corruption
        try:
            ast.parse(text)
        except SyntaxError:
            continue
        return (size, ts, snap)
    return None

hist_index: dict[Path, dict] = {}
for rel, snaps in all_snaps.items():
    best = pick_best(snaps)
    if best is None:
        continue
    hist_index[rel] = {"size": best[0], "ts": best[1], "snap": best[2]}

print(f"[hist-valid] {len(hist_index)} resources with AST-valid snapshot", file=sys.stderr)

# Disk + refs (same as v2)
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

module_to_rel: dict[str, Path] = {}
for rel in disk_files:
    parts = rel.parts
    if parts[0] != "CaseCrack": continue
    dotted = ".".join(parts[1:])[:-3]
    if dotted.endswith(".__init__"):
        dotted = dotted[:-9]
    module_to_rel[dotted] = rel

IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))", re.M)
ref_to_modules: dict[str, set[str]] = defaultdict(set)
for rel, info in disk_files.items():
    try:
        text = info["path"].read_text(encoding="utf-8", errors="ignore")
    except Exception: continue
    for m in IMPORT_RE.finditer(text):
        mod = (m.group(1) or m.group(2) or "").strip()
        if not mod: continue
        cand = mod
        while cand:
            if cand.startswith("tools.") or cand.startswith("CaseCrack."):
                norm = cand if cand.startswith("CaseCrack.") else "CaseCrack." + cand
                dotted = norm[len("CaseCrack."):]
                if dotted in module_to_rel:
                    ref_to_modules[dotted].add(str(rel))
                    break
            cand = cand.rsplit(".", 1)[0] if "." in cand else ""

INTENTIONAL_MARKERS = ["has been removed","thin facade","re-exports","split into","extracted from","backward-compat","relay shim","deprecated","moved to","replaced by"]
def is_intentional(text: str) -> bool:
    head = text[:2000].lower()
    return any(m in head for m in INTENTIONAL_MARKERS)
def is_relay_shim(text: str) -> bool:
    if len(text) > 2500: return False
    if "import_module" in text: return True
    return False

def top_symbols(src: str) -> set[str]:
    try: tree = ast.parse(src)
    except Exception: return set()
    out = set()
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            out.add(node.name)
        elif isinstance(node, ast.ClassDef):
            out.add(node.name)
            for m in node.body:
                if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    out.add(f"{node.name}.{m.name}")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id.isupper():
                    out.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id.isupper():
            out.add(node.target.id)
    return out

regression_rows = []
missing_rows = []
for rel, h in hist_index.items():
    parts = rel.parts
    if len(parts) < 2 or parts[0] != "CaseCrack": continue
    if h["size"] < 256: continue
    dotted = ".".join(parts[1:])[:-3]
    if dotted.endswith(".__init__"): dotted = dotted[:-9]

    if rel not in disk_files:
        pkg_dir = rel.with_suffix("")
        if pkg_dir in dir_set:
            continue
        refs = len(ref_to_modules.get(dotted, set()))
        missing_rows.append((refs, h["size"], str(rel), str(h["snap"])))
        continue

    d = disk_files[rel]
    if h["size"] < 4096: continue
    if d["size"] >= h["size"] * 0.75: continue
    try:
        text = d["path"].read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    if is_intentional(text): continue
    if is_relay_shim(text): continue
    if "raise ImportError" in text[:500]: continue

    ds = top_symbols(text)
    hs = top_symbols(h["snap"].read_text(encoding="utf-8", errors="replace"))
    only_disk = ds - hs
    only_hist = hs - ds
    if len(only_hist) <= 3 and len(only_disk) <= 3:
        verdict = "MINOR"
    elif only_disk:
        verdict = "REFACTORED"
    else:
        verdict = "PURE_REGRESSION"
    refs = len(ref_to_modules.get(dotted, set()))
    regression_rows.append((verdict, len(only_hist), len(only_disk), refs,
                            d["size"]/h["size"], d["size"], h["size"],
                            str(rel), str(h["snap"]),
                            "|".join(sorted(only_disk)[:5])))

order = {"PURE_REGRESSION":0,"REFACTORED":1,"MINOR":2}
regression_rows.sort(key=lambda r: (order[r[0]], -r[3], -r[1]))
missing_rows.sort(reverse=True)

with (WS / "_final_audit_regressions_v2.tsv").open("w", encoding="utf-8") as f:
    f.write("verdict\tonly_hist\tonly_disk\trefs\tratio\tdisk_size\thist_size\trel_path\tsnapshot\tdisk_only_syms\n")
    for r in regression_rows:
        f.write("\t".join(str(x) for x in r) + "\n")

with (WS / "_final_audit_missing_v2.tsv").open("w", encoding="utf-8") as f:
    f.write("refs\thist_size\trel_path\tsnapshot\n")
    for r in missing_rows:
        f.write("\t".join(str(x) for x in r) + "\n")

by_v = defaultdict(list)
for r in regression_rows:
    by_v[r[0]].append(r)

for v in ("PURE_REGRESSION","REFACTORED","MINOR"):
    lst = by_v[v]
    print(f"\n=== {v}: {len(lst)} ===")
    for r in lst[:60]:
        print(f"  refs={r[3]:2d}  -{r[1]:3d}/+{r[2]:<2d}  {int(r[5]/1024):3d}KB->{int(r[6]/1024):3d}KB  {r[7]}")

print(f"\nMissing (with refs>0): {sum(1 for r in missing_rows if r[0]>0)}")
