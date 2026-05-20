"""Chase all transitive missing deps for persistent_agent (and any other just-restored files)."""
import ast, json, os, pathlib, re, sys

sys.path.insert(0, ".")
ROOT = pathlib.Path(__file__).parent
HIST = pathlib.Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

def find_hist(filename: str):
    """Find best snapshot for a given .py filename across all history (URL-decoded)."""
    pat = filename.lower()
    best = None
    for d in HIST.iterdir():
        ej = d / "entries.json"
        if not ej.exists(): continue
        try: data = json.loads(ej.read_text("utf-8", errors="replace"))
        except: continue
        res = data.get("resource", "")
        # URL-decode %20 etc
        import urllib.parse
        res_dec = urllib.parse.unquote(res).lower()
        if pat not in res_dec: continue
        for e in data.get("entries", []):
            s = d / e.get("id", "")
            if s.exists():
                if best is None or s.stat().st_size > best.stat().st_size:
                    best = s
    return best

def missing_be_imports(py_file: pathlib.Path):
    """Return set of missing tools.burp_enterprise.X module paths for a file."""
    try:
        src = py_file.read_text("utf-8", errors="replace")
        tree = ast.parse(src)
    except: return set()
    missing = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom): continue
        m = node.module or ""
        if "tools.burp_enterprise" not in m: continue
        p = ROOT / m.replace(".", "/")
        if not p.with_suffix(".py").exists() and not (p / "__init__.py").exists():
            missing.add(m)
    return missing

# BFS from persistent_agent
queue = {ROOT / "tools/burp_enterprise/persistent_agent.py"}
visited = set()
all_missing: dict[str, pathlib.Path | None] = {}

while queue:
    p = queue.pop()
    if str(p) in visited: continue
    visited.add(str(p))
    if not p.exists(): continue
    for mod in missing_be_imports(p):
        rel = mod.replace(".", "/")
        candidate = ROOT / (rel + ".py")
        if str(candidate) not in visited and mod not in all_missing:
            # try to find in history
            snap = find_hist(rel.split("/")[-1] + ".py")
            all_missing[mod] = snap
            if snap:
                # will restore — then chase its deps too
                queue.add(candidate)

print(f"Transitive missing deps for persistent_agent: {len(all_missing)}")
for mod, snap in sorted(all_missing.items()):
    size = f"{snap.stat().st_size:,}B" if snap else "NO_HISTORY"
    print(f"  {size:>12}  {mod}")
