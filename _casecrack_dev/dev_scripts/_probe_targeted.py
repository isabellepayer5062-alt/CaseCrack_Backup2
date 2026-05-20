"""Targeted probe for: get_middleware, AnalysisResult, finding_stream enrich, reporter flow."""
from __future__ import annotations
import pathlib, re

ROOT     = pathlib.Path("CaseCrack/tools/burp_enterprise")
PIPELINE = ROOT / "pipeline"
OUTPUT   = ROOT / "output"

def read(p): return p.read_text("utf-8", "replace") if p.exists() else ""
def hdr(t): print(f"\n{'='*70}\n=== {t}\n{'='*70}")

# ── 1. root cross_cutting.py full contents ──────────────────────────────────
hdr("1. root cross_cutting.py — full contents")
cc = ROOT / "cross_cutting.py"
src = read(cc)
print(f"Size: {len(src)} chars")
print(src)

# ── 2. output/finding_stream.py — does it call enrich_finding? ──────────────
hdr("2. output/finding_stream.py — enrich/SeverityAssessor usage")
fs = OUTPUT / "finding_stream.py"
src = read(fs)
for i, line in enumerate(src.split("\n")):
    if "enrich" in line.lower() or "severity" in line.lower() or "assessor" in line.lower():
        print(f"  line {i+1}: {line.rstrip()}")

# ── 3. reporter.py — how it gets findings from OrchestratorResult ───────────
hdr("3. reporter.py — how it receives findings")
rp = OUTPUT / "reporter.py"
src = read(rp)
# Find __init__ of main reporter class
classes = re.findall(r"^class (\w+)", src, re.MULTILINE)
print(f"Classes: {classes}")
# Find any method that takes OrchestratorResult or result
for term in ["OrchestratorResult", "all_findings", "module_results",
             "result.findings", "scan_result"]:
    occ = src.count(term)
    if occ:
        print(f"  '{term}': {occ} occurrences")
# Show first class __init__
for cls in classes[:2]:
    idx = src.find(f"class {cls}")
    if idx != -1:
        snippet = src[idx:idx+1000]
        init_idx = snippet.find("def __init__")
        if init_idx != -1:
            print(f"\n{cls}.__init__:")
            print(snippet[init_idx:init_idx+400])

# ── 4. AnalysisResult returned by TrafficAnalyzer.analyze — full class ──────
hdr("4. AnalysisResult full class")
for f in ROOT.rglob("analyzer.py"):
    src2 = read(f)
    idx = src2.find("class AnalysisResult")
    if idx != -1:
        print(f"In: {f.relative_to(ROOT)}")
        print(src2[idx:idx+600])
        # Also show TrafficAnalyzer.analyze
        idx2 = src2.find("def analyze")
        if idx2 != -1:
            print("\nTrafficAnalyzer.analyze:")
            print(src2[idx2:idx2+400])
        break

# ── 5. Does enrich_finding get called from finding_enrichment.py? ────────────
hdr("5. enrich_finding call sites — who actually calls it?")
for py in sorted(ROOT.rglob("*.py")):
    src3 = read(py)
    if "enrich_finding" in src3 and py.name != "finding_enrichment.py":
        count = src3.count("enrich_finding")
        print(f"  {py.relative_to(ROOT)}: {count}x")
        # Show context
        idx = src3.find("enrich_finding")
        while idx != -1:
            line_start = src3.rfind("\n", 0, idx) + 1
            line_end = src3.find("\n", idx)
            print(f"    line: {src3[line_start:line_end].strip()[:100]}")
            idx = src3.find("enrich_finding", idx+1)
            if idx - (src3.rfind("\n", 0, idx)+1) > 1000:
                break

# ── 6. Where does get_middleware live? ───────────────────────────────────────
hdr("6. get_middleware — where is it defined?")
for py in sorted(ROOT.rglob("*.py")):
    src4 = read(py)
    if "def get_middleware" in src4:
        print(f"  DEFINED IN: {py.relative_to(ROOT)}")
        idx = src4.find("def get_middleware")
        print(src4[idx:idx+400])

# Check if it's anywhere at all
found = False
for py in sorted(ROOT.rglob("*.py")):
    if "get_middleware" in read(py):
        found = True
        break
if not found:
    print("  get_middleware NOT FOUND anywhere in codebase!")
else:
    print("\nFiles that reference get_middleware:")
    for py in sorted(ROOT.rglob("*.py")):
        src5 = read(py)
        if "get_middleware" in src5:
            print(f"  {py.relative_to(ROOT)}")

# ── 7. What do the reporters actually read from the scan result? ─────────────
hdr("7. json_report.py — JSONReport class and add_findings")
jrp = OUTPUT / "json_report.py"
src = read(jrp)
idx = src.find("class JSONReport")
if idx != -1:
    print(src[idx:idx+1000])
idx2 = src.find("def add_findings")
if idx2 != -1:
    print("\nadd_findings:")
    print(src[idx2:idx2+400])

# ── 8. How does the orchestrator call reporters? ─────────────────────────────
hdr("8. Orchestrator → Reporter call")
orch = PIPELINE / "full_scan_orchestrator.py"
src = read(orch)
for term in ["reporter", "Reporter", "generate_report", "json_report", "write_report",
             "create_report", "JsonReport", "JSONReport", "HtmlReport"]:
    count = src.count(term)
    if count:
        idx = src.find(term)
        print(f"  '{term}': {count}x, first at:")
        line_start = src.rfind("\n", 0, idx) + 1
        line_end = src.find("\n", idx)
        print(f"    {src[line_start:line_end].strip()[:120]}")

print("\n=== DONE ===")
