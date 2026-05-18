"""
Find and restore all modules that were missed by the original index scanner
due to URL-encoding (%20) in history resource paths.
Specifically targets modules listed in the old _final_audit_missing.tsv.
"""
import ast, json, os, pathlib, urllib.parse

ROOT = pathlib.Path(__file__).parent / "CaseCrack"
BE = ROOT / "tools" / "burp_enterprise"
HIST = pathlib.Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

def strip_bom(b: bytes) -> bytes:
    return b[3:] if b[:3] == b'\xef\xbb\xbf' else b

def ast_top_syms(src: str) -> set[str]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return set()
    s = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            s.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    s.add(t.id)
    return s

# Build a URL-decoded index: canonical rel_path -> list of snaps
decoded_idx: dict[str, list[pathlib.Path]] = {}
for d in HIST.iterdir():
    ej = d / "entries.json"
    if not ej.exists(): continue
    try:
        data = json.loads(ej.read_text("utf-8", errors="replace"))
    except: continue
    res = urllib.parse.unquote(data.get("resource", ""))
    # Case-insensitive match for CaseCrack workspace
    import re
    m = re.search(r'CaseCrack[/\\](.+\.py)$', res, re.IGNORECASE)
    if not m: continue
    rel = m.group(1).replace("\\", "/")
    for e in data.get("entries", []):
        snap = d / e.get("id", "")
        if snap.exists():
            decoded_idx.setdefault(rel, []).append(snap)

# Key list: all modules that should be in burp_enterprise based on missing TSV + known gaps
# Specifically: check if disk file is missing but history has it
missing_restored = []
checked = 0

for rel, snaps in sorted(decoded_idx.items()):
    if not ("tools/burp_enterprise" in rel) and not ("tools\\burp_enterprise" in rel):
        continue
    if not rel.endswith(".py"):
        continue
    # Skip temp/audit files
    import re
    basename = rel.split("/")[-1].split("\\")[-1]
    if re.match(r'_[a-z]', basename) and basename not in ["__init__.py"]:
        continue
    # Check if file is missing on disk
    disk = ROOT / rel.replace("\\", "/")
    if disk.exists():
        continue
    checked += 1
    # Pick best snapshot
    best = max(snaps, key=lambda s: s.stat().st_size)
    raw = strip_bom(best.read_bytes())
    src = raw.decode("utf-8", errors="replace")
    try:
        ast.parse(src)
        syms = ast_top_syms(src)
        disk.parent.mkdir(parents=True, exist_ok=True)
        disk.write_bytes(raw)
        print(f"RESTORED  ({best.stat().st_size:7,}B, {len(syms):3} syms): {rel}")
        missing_restored.append(rel)
    except SyntaxError as e:
        print(f"SKIP/PARSE_ERR: {rel}: {e}")

print(f"\nChecked {checked} missing files with URL-decoded history.")
print(f"Restored: {len(missing_restored)}")
