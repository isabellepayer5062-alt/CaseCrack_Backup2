"""
Comprehensive pipeline passthrough gap audit — Phase 2.
Covers all areas potentially missed in Phase 1 investigation.
"""
from __future__ import annotations
import ast, importlib, inspect, pathlib, re, sys, textwrap, traceback

ROOT     = pathlib.Path("CaseCrack/tools/burp_enterprise")
PIPELINE = ROOT / "pipeline"
OUTPUT   = ROOT / "output"
SCANNERS = ROOT / "scanners"
RECON    = ROOT / "recon"

# ── helper ────────────────────────────────────────────────────────────────────
def read(p: pathlib.Path) -> str:
    return p.read_text("utf-8", "replace") if p.exists() else ""

def hdr(title: str) -> None:
    print(f"\n{'='*72}")
    print(f"=== {title}")
    print('='*72)

# ══════════════════════════════════════════════════════════════════════════════
# GAP A: Scanner module import resolution
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-A: Scanner module import resolution (does module_dotpath resolve?)")

hooks_src = read(SCANNERS / "scanner_hooks.py")
# extract registry tuples
registry_entries = re.findall(
    r'\(\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\s*\)',
    hooks_src
)
print(f"  Total registry entries: {len(registry_entries)}")

# Check how _discover_scanners resolves module names
orch_src = read(PIPELINE / "full_scan_orchestrator.py")
idx = orch_src.find("def _discover_scanners")
discover_snippet = orch_src[idx:idx+3000]
print("\n  _discover_scanners resolution logic:")
for line in discover_snippet.split("\n"):
    stripped = line.strip()
    if stripped and ("import" in stripped or "module" in stripped.lower()
                     or "dotpath" in stripped or "getattr" in stripped
                     or "importlib" in stripped):
        print(f"    {stripped[:120]}")

# ══════════════════════════════════════════════════════════════════════════════
# GAP B: _extract_findings coverage — what return types each scanner produces
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-B: _extract_findings coverage — scanner return type survey")

# Find all result classes across the codebase
result_classes: dict[str, list[str]] = {}  # module_key -> result class names

# Scan every py file under burp_enterprise for classes with 'findings' field
for py in sorted(ROOT.rglob("*.py")):
    try:
        src = py.read_text("utf-8", "replace")
    except Exception:
        continue
    classes = re.findall(r"^class (\w+)", src, re.MULTILINE)
    for cls in classes:
        # Check if it has a 'findings' field (dataclass or property)
        m = re.search(
            r"class " + re.escape(cls) + r"[^:]*:(.*?)(?=^class |\Z)",
            src, re.DOTALL | re.MULTILINE
        )
        if not m:
            continue
        body = m.group(1)
        has_findings = bool(re.search(r"findings\s*[=:]", body))
        has_to_dict  = "def to_dict" in body
        has_vuln     = bool(re.search(r"vulnerabilities\s*[=:]", body))
        has_results  = bool(re.search(r"results\s*[=:]", body))
        has_issues   = bool(re.search(r"issues\s*[=:]", body))
        key = str(py.relative_to(ROOT))
        if has_findings or has_vuln or has_results or has_issues:
            result_classes.setdefault(key, [])
            attrs = []
            if has_findings: attrs.append("findings")
            if has_vuln:     attrs.append("vulnerabilities")
            if has_results:  attrs.append("results")
            if has_issues:   attrs.append("issues")
            result_classes[key].append(f"{cls}[{','.join(attrs)}]")

# Which scanner methods return result classes NOT covered by _extract_findings?
# The current _extract_findings checks: findings, vulnerabilities, results, issues
# and list. What else?
uncovered: list[str] = []
for py_key, cls_list in result_classes.items():
    for cls_info in cls_list:
        cls_name = cls_info.split("[")[0]
        attrs_str = cls_info[len(cls_name)+1:-1]
        covered_attrs = {"findings", "vulnerabilities", "results", "issues"}
        has_covered = bool(covered_attrs & set(attrs_str.split(",")))
        if not has_covered:
            uncovered.append(f"  {py_key}: {cls_name}")

# Find the result classes that scanners actually return by checking scan methods
print("\n  Checking scan method return annotations for each registered scanner:")
needs_broadening: list[tuple[str,str,str,str]] = []  # (module, cls, method, ret_type)

for mod_path, cls_name, method_name, scanner_name in registry_entries:
    # Resolve module file path
    cands = [
        ROOT / (mod_path.replace(".", "/") + ".py"),
        SCANNERS / (mod_path.replace(".", "/") + ".py"),
    ]
    src_file = next((c for c in cands if c.exists()), None)
    if not src_file:
        continue
    src = read(src_file)
    # Find class + method
    cls_idx = src.find(f"class {cls_name}")
    if cls_idx == -1:
        continue
    cls_body = src[cls_idx:cls_idx+10000]
    meth_match = re.search(
        r"def " + re.escape(method_name) + r"\s*\([^)]*\)\s*->\s*([^\n:]+):",
        cls_body
    )
    if meth_match:
        ret = meth_match.group(1).strip()
        # Is it a primitive type or a list?
        covered = any(t in ret.lower() for t in [
            "list", "dict", "none", "any", "bool", "str", "int", "float",
            "findings", "vulnerabilities"
        ])
        if not covered:
            needs_broadening.append((mod_path, cls_name, method_name, ret))
            print(f"    UNCOVERED: {scanner_name}: {cls_name}.{method_name}() -> {ret}")

if not needs_broadening:
    print("    All scan return types appear coverable by _extract_findings")

# ══════════════════════════════════════════════════════════════════════════════
# GAP C: finding_dedup severity preservation
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-C: finding_dedup — severity preservation when merging duplicates")

dedup_files = [
    ROOT / "output" / "finding_dedup.py",
    ROOT / "pipeline" / "finding_dedup.py",
    SCANNERS / "finding_dedup.py",
]
for fp in dedup_files:
    if fp.exists():
        src = read(fp)
        print(f"\n  File: {fp.relative_to(ROOT)}")
        # Check if it preserves highest severity
        has_severity_merge = bool(re.search(
            r"max\s*\(.*severity|severity.*max|sev.*order|rank.*sev", src, re.I))
        has_severity_keep = "severity" in src and (
            "keep" in src or "highest" in src or "max_sev" in src)
        has_severity_overwrite = bool(re.search(
            r'merged\[.severity.\]\s*=|update.*severity|severity.*=.*existing',
            src, re.I
        ))
        print(f"    has_severity_merge logic: {has_severity_merge}")
        print(f"    has_severity_keep logic:  {has_severity_keep}")
        print(f"    has_severity_overwrite:   {has_severity_overwrite}")
        # Find the merge/dedup function
        dedup_fns = re.findall(r"def (dedup|merge|deduplicate|_merge)\w*", src, re.I)
        print(f"    dedup functions: {dedup_fns}")
        # Show severity handling inline
        for fn in dedup_fns[:2]:
            idx = src.find(f"def {fn}")
            if idx != -1:
                snippet = src[idx:idx+800]
                sev_lines = [l.strip() for l in snippet.split("\n")
                             if "severity" in l.lower()]
                if sev_lines:
                    print(f"    {fn}() severity lines:")
                    for sl in sev_lines[:6]:
                        print(f"      {sl[:100]}")

# ══════════════════════════════════════════════════════════════════════════════
# GAP D: CrossCuttingMiddleware — does it call finding_enrichment?
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-D: CrossCuttingMiddleware — severity enrichment call chain")

for cc_file in [
    OUTPUT / "cross_cutting.py",
    PIPELINE / "cross_cutting.py",
    ROOT / "cross_cutting.py",
]:
    if cc_file.exists():
        src = read(cc_file)
        print(f"\n  File: {cc_file.relative_to(ROOT)}")
        calls_enrich   = "enrich_finding" in src or "finding_enrichment" in src
        calls_severity = "severity" in src
        calls_assess   = "assess_severity" in src or "SeverityAssessor" in src
        uses_middleware = "Middleware" in src
        print(f"    calls enrich_finding/finding_enrichment: {calls_enrich}")
        print(f"    calls assess_severity/SeverityAssessor:  {calls_assess}")
        print(f"    has severity logic:                      {calls_severity}")
        # Find process_finding
        idx = src.find("def process_finding")
        if idx != -1:
            snippet = src[idx:idx+1000]
            print(f"    process_finding body (first 800 chars):")
            for line in snippet.split("\n")[1:20]:
                if line.strip():
                    print(f"      {line[:110]}")

# ══════════════════════════════════════════════════════════════════════════════
# GAP E: ReconPipeline findings handoff — does it reach reporters?
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-E: ReconPipeline findings handoff")

rp = RECON / "recon_pipeline.py"
if rp.exists():
    src = read(rp)
    print(f"  File size: {len(src)} chars, ~{len(src.split(chr(10)))} lines")
    print(f"  Bare excepts: {src.count('except:')}")
    # Check for result/findings output
    checks = {
        "enrich_finding":       "enrich_finding" in src,
        "finding_pipeline":     "finding_pipeline" in src,
        "emit_finding/_emit":   "emit_finding" in src or "._emit(" in src,
        "findings_store":       "findings_store" in src,
        "module_results":       "module_results" in src,
        "OrchestratorResult":   "OrchestratorResult" in src,
        "returns findings list": bool(re.search(r"return.*finding", src)),
    }
    for k, v in checks.items():
        print(f"  {k}: {v}")
    # Find what ReconPipeline.run() returns
    idx = src.find("class ReconPipeline")
    if idx != -1:
        cls_src = src[idx:idx+15000]
        run_idx = cls_src.find("def run(")
        if run_idx != -1:
            run_snippet = cls_src[run_idx:run_idx+1000]
            ret_lines = [l.strip() for l in run_snippet.split("\n") if "return" in l]
            print(f"  ReconPipeline.run() return statements: {ret_lines[:5]}")

# ══════════════════════════════════════════════════════════════════════════════
# GAP F: Reporter output paths — what fields do reporters read?
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-F: Reporter output paths — do they read all_findings or module_results?")

reporter_files = [
    OUTPUT / "reporter.py",
    OUTPUT / "json_report.py",
    OUTPUT / "html_report.py",
]
for rf in reporter_files:
    if rf.exists():
        src = read(rf)
        print(f"\n  {rf.name}:")
        for field in ["all_findings", "module_results", "findings", "correlation_report",
                      "normalized_findings", "attack_chains"]:
            count = src.count(field)
            if count:
                print(f"    '{field}': {count} uses")

# ══════════════════════════════════════════════════════════════════════════════
# GAP G: Scanner instantiation — which scanners will fail _instantiate()?
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-G: Scanner __init__ signatures — will _instantiate() succeed?")

# _instantiate() tries: cls(), cls(url=...), cls(session), cls(url_str)
# Anything requiring a mandatory positional arg other than url will fail silently
risky: list[str] = []
for mod_path, cls_name, method_name, scanner_name in registry_entries:
    cands = [
        ROOT / (mod_path.replace(".", "/") + ".py"),
        SCANNERS / (mod_path.replace(".", "/") + ".py"),
    ]
    src_file = next((c for c in cands if c.exists()), None)
    if not src_file:
        continue
    src = read(src_file)
    cls_idx = src.find(f"class {cls_name}")
    if cls_idx == -1:
        continue
    cls_body = src[cls_idx:cls_idx+5000]
    init_match = re.search(r"def __init__\s*\(self(?:,\s*([^)]+))?\)", cls_body)
    if init_match:
        params_str = init_match.group(1) or ""
        # Find params without defaults
        params = [p.strip() for p in params_str.split(",") if p.strip()]
        # Remove type annotations
        mandatory = []
        for p in params:
            # strip annotation
            p_name = re.sub(r":.*", "", p).strip()
            p_name = re.sub(r"\s*=.*", "", p_name).strip()  # strip default
            if "=" not in p and p_name and p_name not in ("*", "**kwargs", "*args"):
                # check it's not just a type annotation leftover
                if not p.strip().startswith("*"):
                    clean = p.split(":")[0].split("=")[0].strip()
                    if clean and clean not in ("cls", "self"):
                        mandatory.append(clean)
        KNOWN_URL = {"url", "target", "base_url", "domain", "host", "target_url",
                     "start_url", "endpoint"}
        non_url_mandatory = [p for p in mandatory if p not in KNOWN_URL]
        if non_url_mandatory:
            risky.append(f"  {scanner_name}: {cls_name}.__init__(self, {params_str[:80]})")
            print(f"  RISKY: {scanner_name}: {cls_name}.__init__ needs {non_url_mandatory}")

if not risky:
    print("  All scanner __init__ signatures look compatible with _instantiate()")

# ══════════════════════════════════════════════════════════════════════════════
# GAP H: Scanner module resolution — does "xss" map to root xss.py?
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-H: Module resolution — does module key 'xss' resolve correctly?")

for mod_key in ["xss", "weak_hash_detector", "defensive_monitoring_tester",
                 "xss_tester", "http2_fingerprint"]:
    root_file    = ROOT / f"{mod_key}.py"
    scanner_file = SCANNERS / f"{mod_key}.py"
    network_file = ROOT / "network" / f"{mod_key}.py"
    print(f"  '{mod_key}':")
    print(f"    root/{mod_key}.py:                {root_file.exists()}")
    print(f"    scanners/{mod_key}.py:             {scanner_file.exists()}")
    print(f"    network/{mod_key}.py:              {network_file.exists()}")
    if root_file.exists():
        src = read(root_file)
        is_shim = "backward-compatibility shim" in src.lower() or "__getattr__" in src
        print(f"    root file is shim: {is_shim}")
        if is_shim:
            m = re.search(r'import_module\("([^"]+)"\)', src)
            print(f"    shim target: {m.group(1) if m else 'UNKNOWN'}")

# ══════════════════════════════════════════════════════════════════════════════
# GAP I: _process_findings_through_pipeline — what does it do?
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-I: _process_findings_through_pipeline — full inspection")

idx = orch_src.find("def _process_findings_through_pipeline")
if idx != -1:
    snippet = orch_src[idx:idx+3000]
    print(snippet[:3000])

# ══════════════════════════════════════════════════════════════════════════════
# GAP J: Phase 1 summary — what still calls the old enrichment path?
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-J: Callers of enrich_finding vs finding_enrichment across pipeline")

for py in sorted((ROOT / "output").rglob("*.py")):
    src = read(py)
    for symbol in ["enrich_finding", "SeverityAssessor", "assess_severity",
                   "finding_enrichment"]:
        if symbol in src:
            fns = re.findall(r"def (\w+)", src)
            print(f"  {py.relative_to(ROOT)}: has '{symbol}'")
            break

# ══════════════════════════════════════════════════════════════════════════════
# GAP K: Silent scanner failures — continue_on_error swallows exceptions
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-K: Silent error swallowing in _run_single_inner / _run_phase")

for fn in ["_run_single_inner", "_run_single", "_run_phase"]:
    idx = orch_src.find(f"def {fn}")
    if idx != -1:
        snippet = orch_src[idx:idx+800]
        except_count = snippet.count("except")
        log_lines = [l.strip() for l in snippet.split("\n") if "logger" in l]
        print(f"  {fn}: {except_count} except blocks, {len(log_lines)} log lines")
        for ll in log_lines[:3]:
            print(f"    {ll[:100]}")

# ══════════════════════════════════════════════════════════════════════════════
# GAP L: Finding normalization — are all finding fields standardised?
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-L: Finding normalization — NormalizedFinding / finding_normalizer")

norm_files = [
    ROOT / "output" / "finding_normalizer.py",
    ROOT / "pipeline" / "finding_normalizer.py",
    ROOT / "output" / "normalized_finding.py",
]
for nf in norm_files:
    if nf.exists():
        src = read(nf)
        print(f"  Found: {nf.relative_to(ROOT)} ({len(src)} chars)")

# ══════════════════════════════════════════════════════════════════════════════
# GAP M: _run_phase concurrency — findings from parallel scanners merged?
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-M: Concurrency — are parallel scanner findings fully merged?")

idx = orch_src.find("def _run_phase")
if idx != -1:
    snippet = orch_src[idx:idx+1500]
    has_thread = "Thread" in snippet or "executor" in snippet or "future" in snippet
    has_gather = "gather" in snippet or "as_completed" in snippet
    print(f"  Uses threading/executor: {has_thread}")
    print(f"  Uses gather/as_completed: {has_gather}")
    for line in snippet.split("\n")[:30]:
        if line.strip() and any(k in line for k in
                                 ["Thread","executor","future","gather","submit","result"]):
            print(f"  {line[:110]}")

# ══════════════════════════════════════════════════════════════════════════════
# GAP N: Finding field completeness — mandatory fields for reporters
# ══════════════════════════════════════════════════════════════════════════════
hdr("GAP-N: Reporter mandatory fields — what fields must findings have?")

if (OUTPUT / "reporter.py").exists():
    src = read(OUTPUT / "reporter.py")
    # Find fields accessed on findings
    field_accesses = re.findall(r'finding\[["\']([\w_]+)["\']\]|finding\.get\(["\']([\w_]+)["\']',
                                 src)
    fields = sorted(set(f[0] or f[1] for f in field_accesses))
    print(f"  Fields accessed by reporter.py: {fields}")

if (OUTPUT / "json_report.py").exists():
    src2 = read(OUTPUT / "json_report.py")
    field_accesses2 = re.findall(r'finding\[["\']([\w_]+)["\']\]|finding\.get\(["\']([\w_]+)["\']',
                                  src2)
    fields2 = sorted(set(f[0] or f[1] for f in field_accesses2))
    print(f"  Fields accessed by json_report.py: {fields2}")

print("\n=== DONE ===")
