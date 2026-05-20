import ast, json, re
from pathlib import Path

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")
PKG = WS / "CaseCrack" / "tools" / "burp_enterprise"

texts = {}
for fp in PKG.rglob("*.py"):
    try:
        rel = str(fp.relative_to(WS)).replace("\\", "/")
        texts[rel] = fp.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        pass
print(f"{len(texts)} files indexed")

# Tokenize each file ONCE
tok_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
file_tokens = {rel: set(tok_re.findall(txt)) for rel, txt in texts.items()}
# Inverse index: token -> set of files
token_to_files = {}
for rel, toks in file_tokens.items():
    for t in toks:
        token_to_files.setdefault(t, set()).add(rel)
print(f"{len(token_to_files)} unique tokens")

defs_idx = {}
def add_def(name, rel, line, kind):
    defs_idx.setdefault(name, []).append((rel, line, kind))

parse_failed = 0
for rel, txt in texts.items():
    try:
        tree = ast.parse(txt)
    except SyntaxError:
        parse_failed += 1
        continue
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            add_def(node.name, rel, node.lineno, "func")
        elif isinstance(node, ast.ClassDef):
            add_def(node.name, rel, node.lineno, "class")
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    add_def(f"{node.name}.{m.name}", rel, m.lineno, "method")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    add_def(t.id, rel, node.lineno, "assign")
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            add_def(node.target.id, rel, node.lineno, "assign")
print(f"{len(defs_idx)} defined symbols; {parse_failed} unparsable")

merge_map = json.loads((WS / "_merge_map.json").read_text(encoding="utf-8"))
report = []
for entry in merge_map:
    self_rel = entry["rel_path"]
    syms = []
    for sym in entry["hist_only"]:
        defs_other = [d for d in defs_idx.get(sym, []) if d[0] != self_rel]
        if defs_other:
            cls, evidence = "MIGRATED", defs_other[:3]
        else:
            bare = sym.split(".")[-1]
            refs = token_to_files.get(bare, set()) - {self_rel}
            if refs:
                cls, evidence = "REFERENCED", sorted(refs)[:3]
            else:
                cls, evidence = "MISSING", []
        syms.append({"symbol": sym, "class": cls, "evidence": evidence})
    mig = sum(1 for s in syms if s["class"] == "MIGRATED")
    miss = sum(1 for s in syms if s["class"] == "MISSING")
    refd = sum(1 for s in syms if s["class"] == "REFERENCED")
    report.append({
        "bucket": entry["bucket"], "rel_path": self_rel,
        "hist_only_total": len(entry["hist_only"]),
        "migrated_count": mig, "missing_count": miss, "referenced_count": refd,
        "symbols": syms,
    })

(WS / "_sibling_grep_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

fully_mig = [r for r in report if r["hist_only_total"] > 0 and r["missing_count"] == 0
             and r["referenced_count"] == 0 and r["migrated_count"] > 0]
fully_miss = [r for r in report if r["hist_only_total"] > 0 and r["migrated_count"] == 0
              and r["referenced_count"] == 0 and r["missing_count"] > 0]
mixed = [r for r in report if r["hist_only_total"] > 0
         and r not in fully_mig and r not in fully_miss]

print(f"\n=== AUDIT RESULTS ===")
print(f"Fully MIGRATED (skip):   {len(fully_mig)}")
print(f"Mixed (partial backport): {len(mixed)}")
print(f"Fully MISSING:           {len(fully_miss)}")
print(f"Already merged:          {sum(1 for r in report if r[chr(39)+'hist_only_total'+chr(39)]==0)}")

print("\n--- Fully MIGRATED files ---")
for r in sorted(fully_mig, key=lambda x: x["bucket"]):
    locs = sorted({s["evidence"][0][0] for s in r["symbols"] if s["evidence"]})
    print(f"[{r['bucket']}] {r['rel_path']} (hist={r['hist_only_total']})")
    for l in locs[:3]: print(f"    -> {l}")

print("\n--- Mixed files (by MISSING desc) ---")
for r in sorted(mixed, key=lambda x: (x["bucket"], -x["missing_count"])):
    print(f"[{r['bucket']}] {r['rel_path']} hist={r['hist_only_total']} MIG={r['migrated_count']} REF={r['referenced_count']} MISS={r['missing_count']}")

print("\n--- Fully MISSING files ---")
for r in sorted(fully_miss, key=lambda x: (x["bucket"], -x["missing_count"])):
    print(f"[{r['bucket']}] {r['rel_path']} hist={r['hist_only_total']}")
