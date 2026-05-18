"""Build per-file merge map for the 42 REFACTORED files.

For each file, emit a JSON blob containing:
  - rel_path
  - disk_size, hist_size
  - disk_top_symbols  (full set: classes, methods, functions, UPPERCASE consts)
  - hist_top_symbols
  - intersection (overlap)
  - only_disk (disk-unique — newer work to PRESERVE)
  - only_hist (history-unique — candidates to BACKPORT)
  - per-symbol signature diffs for OVERLAPPING functions/methods
    (so we know which ones changed shape on disk vs history)
  - heuristic risk bucket: A (behavior-critical) / B (support) / C (safe)
    based on:
       * package path (agents/, exploit_chains/, llm*, decision_*) -> A
       * inference/, reasoning/, memory/, tool_registry/         -> B
       * tests/, _spa_shell, dalfox_provider, generic, atlas_api -> C

Outputs:
  _merge_map.json       — full structured data
  _merge_map_summary.md — human-readable
"""
from __future__ import annotations
import ast, json, sys
from pathlib import Path

WS = Path(r"C:\Users\ya754\CaseCrack v1.0")

# ---- Risk bucket rules ----
A_PATTERNS = [
    "/agents/llm_bridge",
    "/agents/advanced_agent_patterns",
    "/exploit_chains/payload_arbiter",
    "/exploit_chains/weight_tuner",
    "/exploit_chains/payload_synthesis_engine",
    "/exploit_chains/genetic_forge",
    "/exploit_chains/grammar_synthesizer",
    "/exploit_chains/llm_synthesizer",
    "/exploit_chains/synthesis_context",
    "/exploit_chains/synthesis_feedback",
    "/exploit_chains/synthesis_tracer",
    "/exploit_chains/execution_scheduler",
    "/exploit_chains/failure_pattern",
    "/hypothesis_engine.py",
    "/learning_loop_engine.py",
    "/recon_dashboard/server.py",
    "/synthesis_safety.py",
]
B_PATTERNS = [
    "/inference/",
    "/reasoning/",
    "/memory/",
    "/tool_registry/",
    "/database/data_migration",
    "/__init__.py",
]
C_PATTERNS = [
    "/tests/",
    "/_spa_shell.py",
    "/dalfox_provider.py",
    "/platforms/generic.py",
    "/recon_dashboard/atlas_api.py",
    "/recon_dashboard/report_generator.py",
    "/exploit_chains/exploit_graph.py",
]

def bucket_for(rel: str) -> str:
    for p in A_PATTERNS:
        if p in rel: return "A"
    for p in C_PATTERNS:
        if p in rel: return "C"
    for p in B_PATTERNS:
        if p in rel: return "B"
    return "B"  # default to medium-risk

# ---- AST helpers ----
def func_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Render function signature as a string: name(a, b=..., *args, **kw) -> ret"""
    parts = []
    args = node.args
    pos = [a.arg for a in args.posonlyargs]
    if pos: parts.append("/".join(pos) + ", /")
    norm = [a.arg for a in args.args]
    parts.extend(norm)
    if args.vararg: parts.append("*" + args.vararg.arg)
    elif args.kwonlyargs: parts.append("*")
    parts.extend(a.arg for a in args.kwonlyargs)
    if args.kwarg: parts.append("**" + args.kwarg.arg)
    sig = f"{node.name}({', '.join(parts)})"
    return sig

def collect_symbols(text: str) -> dict:
    """Return {symbol_name: {'kind': ..., 'sig': ..., 'lineno': ...}}"""
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return {"__parse_error__": {"kind": "error", "msg": str(e)}}
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = {"kind": "func", "sig": func_signature(node), "lineno": node.lineno}
        elif isinstance(node, ast.ClassDef):
            out[node.name] = {"kind": "class", "sig": f"class {node.name}", "lineno": node.lineno}
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qn = f"{node.name}.{m.name}"
                    out[qn] = {"kind": "method", "sig": func_signature(m), "lineno": m.lineno}
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id.isupper():
                    out[t.id] = {"kind": "const", "sig": t.id, "lineno": node.lineno}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id.isupper():
            out[node.target.id] = {"kind": "const", "sig": node.target.id, "lineno": node.lineno}
    return out

# ---- Load REFACTORED rows from tight TSV ----
rows = []
with (WS / "_final_audit_coverage_tight.tsv").open(encoding="utf-8") as f:
    hdr = f.readline().rstrip("\n").split("\t")
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 8:
            rows.append(dict(zip(hdr, parts)))

refactored = [r for r in rows if r["verdict"] == "REFACTORED"]
print(f"Building merge map for {len(refactored)} REFACTORED files...", file=sys.stderr)

merge_map = []
for r in refactored:
    relstr = r["rel_path"]
    disk = WS / relstr.replace("/", "\\")
    snap = Path(r["snapshot"])
    if not disk.exists() or not snap.exists():
        continue
    try:
        dtext = disk.read_text(encoding="utf-8", errors="ignore")
        htext = snap.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        continue

    ds = collect_symbols(dtext)
    hs = collect_symbols(htext)
    if "__parse_error__" in ds or "__parse_error__" in hs:
        continue

    overlap = sorted(set(ds) & set(hs))
    only_disk = sorted(set(ds) - set(hs))
    only_hist = sorted(set(hs) - set(ds))

    # signature diffs in overlap (functions/methods only)
    sig_changes = []
    for name in overlap:
        if ds[name]["kind"] in ("func", "method") and ds[name]["sig"] != hs[name]["sig"]:
            sig_changes.append({
                "name": name,
                "disk_sig": ds[name]["sig"],
                "hist_sig": hs[name]["sig"],
            })

    bucket = bucket_for(relstr)

    merge_map.append({
        "bucket": bucket,
        "rel_path": relstr,
        "disk_size": int(r["disk_size"]),
        "hist_size": int(r["hist_size"]),
        "snapshot": r["snapshot"],
        "disk_only": only_disk,
        "hist_only": only_hist,
        "overlap_count": len(overlap),
        "signature_changes": sig_changes,
    })

# Sort: A first (highest risk), then by hist_only count desc
order = {"A": 0, "B": 1, "C": 2}
merge_map.sort(key=lambda m: (order[m["bucket"]], -len(m["hist_only"])))

(WS / "_merge_map.json").write_text(json.dumps(merge_map, indent=2), encoding="utf-8")

# ---- Human-readable summary ----
lines = ["# Merge Map — 42 REFACTORED files\n"]
by_bucket = {"A": [], "B": [], "C": []}
for m in merge_map:
    by_bucket[m["bucket"]].append(m)

bucket_desc = {
    "A": "Behavior-critical — manual semantic merge required",
    "B": "Support logic — selective function-by-function merge",
    "C": "Safe divergence — minimal merge or accept disk version",
}

for b in ("A", "B", "C"):
    lst = by_bucket[b]
    lines.append(f"\n## Bucket {b}: {bucket_desc[b]} ({len(lst)} files)\n")
    lines.append("| File | Disk→Hist KB | disk-only | hist-only | sig-changes |")
    lines.append("|------|--------------|-----------|-----------|-------------|")
    for m in lst:
        lines.append(
            f"| `{m['rel_path']}` "
            f"| {m['disk_size']//1024}→{m['hist_size']//1024} "
            f"| {len(m['disk_only'])} "
            f"| {len(m['hist_only'])} "
            f"| {len(m['signature_changes'])} |"
        )

(WS / "_merge_map_summary.md").write_text("\n".join(lines), encoding="utf-8")

print(f"Wrote _merge_map.json ({len(merge_map)} files)")
print(f"  Bucket A (critical): {len(by_bucket['A'])}")
print(f"  Bucket B (support):  {len(by_bucket['B'])}")
print(f"  Bucket C (safe):     {len(by_bucket['C'])}")
print(f"\nSee _merge_map_summary.md")
