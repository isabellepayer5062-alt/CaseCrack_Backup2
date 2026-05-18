"""Deep dive into the 5 critical gaps identified in Phase 2 probe."""
from __future__ import annotations
import pathlib, re

ROOT     = pathlib.Path("CaseCrack/tools/burp_enterprise")
PIPELINE = ROOT / "pipeline"
OUTPUT   = ROOT / "output"

def read(p): return p.read_text("utf-8", "replace") if p.exists() else ""
def hdr(t): print(f"\n{'='*70}\n=== {t}\n{'='*70}")

# ── 1. XSSReport + AnalysisResult fields ────────────────────────────────────
hdr("1. XSSReport and AnalysisResult — do they have 'findings' attr?")

p_xss = ROOT / "xss.py"
src = read(p_xss)
idx = src.find("class XSSReport")
if idx != -1:
    snippet = src[idx:idx+600]
    print("XSSReport fields:")
    for line in snippet.split("\n")[:20]:
        print(f"  {line}")

# AnalysisResult — find it
for f in ROOT.rglob("analyzer.py"):
    src2 = read(f)
    idx2 = src2.find("class AnalysisResult")
    if idx2 != -1:
        print(f"\nAnalysisResult in {f.relative_to(ROOT)}:")
        for line in src2[idx2:idx2+400].split("\n")[:15]:
            print(f"  {line}")
        break

# ── 2. CrossCuttingMiddleware.process_finding — full body ───────────────────
hdr("2. CrossCuttingMiddleware.process_finding — full body")

for cc_file in [OUTPUT/"cross_cutting.py", PIPELINE/"cross_cutting.py", ROOT/"cross_cutting.py"]:
    if cc_file.exists():
        src = read(cc_file)
        idx = src.find("def process_finding")
        if idx != -1:
            print(f"File: {cc_file.relative_to(ROOT)}")
            print(src[idx:idx+1500])
            break

# ── 3. finding_dedup.py full contents ───────────────────────────────────────
hdr("3. finding_dedup.py full contents")

dp = OUTPUT / "finding_dedup.py"
if dp.exists():
    src = read(dp)
    print(f"Size: {len(src)} chars")
    print(src[:3000])

# ── 4. How reporters receive findings ────────────────────────────────────────
hdr("4. Reporter.generate / json_report input parameter")

for rfile in [OUTPUT/"reporter.py", OUTPUT/"json_report.py"]:
    if rfile.exists():
        src = read(rfile)
        print(f"\n--- {rfile.name} ---")
        # Find generate/write/render method
        for meth in ["def generate", "def write", "def render", "def build",
                     "def create_report", "def __init__"]:
            idx = src.find(meth)
            if idx != -1:
                print(f"  {meth}:")
                print(src[idx:idx+400])
                break

# ── 5. How _discover_scanners builds module import path ──────────────────────
hdr("5. _discover_scanners full import path construction")

orch_src = read(PIPELINE / "full_scan_orchestrator.py")
idx = orch_src.find("def _discover_scanners")
print(orch_src[idx:idx+2500])

# ── 6. where enrich_finding is defined and what it does ─────────────────────
hdr("6. enrich_finding definition + does anything call it?")

ef = OUTPUT / "finding_enrichment.py"
if ef.exists():
    src = read(ef)
    idx = src.find("def enrich_finding")
    if idx != -1:
        print("enrich_finding signature + first 20 lines:")
        print(src[idx:idx+500])
    # check what calls it
    print("\nFiles in pipeline/ that import/call enrich_finding:")
    for pyf in PIPELINE.rglob("*.py"):
        s = read(pyf)
        if "enrich_finding" in s:
            print(f"  {pyf.relative_to(ROOT)}")

# ── 7. cross_cutting.py — what does it call? ────────────────────────────────
hdr("7. cross_cutting.py full contents (pipeline/)")

cc = PIPELINE / "cross_cutting.py"
if cc.exists():
    src = read(cc)
    print(f"Size: {len(src)} chars")
    print(src[:4000])

# ── 8. finding_stream / audit_trail path ─────────────────────────────────────
hdr("8. Does finding_stream / audit_trail apply severity enrichment?")

for name in ["finding_stream.py", "audit_trail.py", "event_bus.py"]:
    for d in [PIPELINE, OUTPUT, ROOT]:
        p = d / name
        if p.exists():
            src = read(p)
            print(f"\n{p.relative_to(ROOT)}: {len(src)} chars")
            has_enrich = "enrich" in src or "SeverityAssessor" in src
            print(f"  has enrich/SeverityAssessor: {has_enrich}")
            idx = src.find("def ")
            if idx != -1:
                fns = re.findall(r"def (\w+)", src)
                print(f"  functions: {fns[:10]}")
            break

# ── 9. Check: does cross_cutting.py have get_middleware? ─────────────────────
hdr("9. get_middleware in cross_cutting files")

for cc_file in [OUTPUT/"cross_cutting.py", PIPELINE/"cross_cutting.py", ROOT/"cross_cutting.py"]:
    if cc_file.exists():
        src = read(cc_file)
        has_get_mw = "def get_middleware" in src or "get_middleware" in src
        has_class  = bool(re.findall(r"class \w+Middleware", src))
        classes    = re.findall(r"^class (\w+)", src, re.MULTILINE)
        print(f"\n{cc_file.relative_to(ROOT)}: classes={classes}, get_middleware={has_get_mw}")
        # Show class hierarchy
        idx = src.find("class ")
        if idx != -1:
            print(src[idx:idx+800])

print("\n=== DONE ===")
