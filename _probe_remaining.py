"""Check finding_dedup severity merge, TrafficAnalyzer, and ReconPipeline.run."""
from __future__ import annotations
import pathlib, re

ROOT = pathlib.Path("CaseCrack/tools/burp_enterprise")
def read(p): return p.read_text("utf-8", "replace") if p.exists() else ""
def hdr(t): print(f"\n{'='*70}\n=== {t}\n{'='*70}")

# 1. finding_dedup — FindingDeduplicator.filter severity merge
hdr("1. FindingDeduplicator — full filter method")
dp = ROOT / "output" / "finding_dedup.py"
src = read(dp)
idx = src.find("class FindingDeduplicator")
if idx != -1:
    snippet = src[idx:idx+4000]
    print(snippet[:4000])

# 2. TrafficAnalyzer — is there any URL-accepting method?
hdr("2. TrafficAnalyzer — all methods, URL-based scan?")
p_an = ROOT / "analyzer.py"
src = read(p_an)
# full class listing
idx = src.find("class TrafficAnalyzer")
if idx != -1:
    class_src = src[idx:idx+6000]
    # find all method signatures
    for m in re.finditer(r"    def (\w+)\s*\(self,?\s*([^)]*)\)", class_src):
        print(f"  {m.group(1)}({m.group(2)[:80]})")
    # check if scan_url or full_scan exists
    for method_name in ["scan_url", "scan", "full_scan", "assess", "analyze_url"]:
        if f"def {method_name}" in class_src:
            print(f"  ** FOUND: {method_name}")

# 3. ReconPipeline.run() — return value and callers
hdr("3. ReconPipeline.run() — return, output shape, and callers")
rp = ROOT / "recon" / "recon_pipeline.py"
src = read(rp)
lines = src.split("\n")
idx_class = src.find("class ReconPipeline")
if idx_class != -1:
    class_src = src[idx_class:idx_class+50000]
    run_idx = class_src.find("def run(")
    if run_idx != -1:
        run_src = class_src[run_idx:run_idx+2500]
        print("ReconPipeline.run():")
        print(run_src[:2500])

# Also check who calls ReconPipeline.run()
hdr("4. Who calls ReconPipeline / ReconPipeline().run()?")
for py in sorted(ROOT.rglob("*.py")):
    src2 = read(py)
    if "ReconPipeline" in src2:
        uses = src2.count("ReconPipeline")
        print(f"  {py.relative_to(ROOT)}: {uses}x")
        for line in src2.split("\n"):
            if "ReconPipeline" in line:
                print(f"    {line.strip()[:110]}")

# 5. correlation_engine — dedup merge severity
hdr("5. correlation_engine — FindingNormalizer / dedup severity handling")
ce = ROOT / "output" / "correlation_engine.py"
src = read(ce)
idx = src.find("def _finding_hash")
if idx != -1:
    print("_finding_hash:")
    print(src[idx:idx+400])
# Find any merge/dedup block
for marker in ["_merge_dups", "deduplicate", "merge_finding", "_dedup"]:
    idx = src.find(f"def {marker}")
    if idx != -1:
        print(f"\n{marker}:")
        print(src[idx:idx+600])
        break

# 6. XSSReport — does _extract_findings actually work on it?
hdr("6. XSSReport.findings — type of items (finding dicts or objects?)")
p_xss = ROOT / "xss.py"
src = read(p_xss)
idx = src.find("class XSSFinding")
if idx != -1:
    snippet = src[idx:idx+500]
    print("XSSFinding class:")
    for line in snippet.split("\n")[:20]:
        print(f"  {line}")
    # Does it have to_dict?
    print(f"  has to_dict: {'def to_dict' in snippet}")

# 7. Check ReconPipeline return type  
hdr("7. ReconPipeline return type / findings format")
rp_src = read(ROOT / "recon" / "recon_pipeline.py")
# Find return statements in run()
run_idx = rp_src.find("def run(")
if run_idx != -1:
    run_body = rp_src[run_idx:run_idx+3000]
    ret_lines = [l.strip() for l in run_body.split("\n") if l.strip().startswith("return")]
    print(f"Return statements in run():")
    for r in ret_lines[:10]:
        print(f"  {r[:100]}")
    # Find def run signature
    sig_end = run_body.find(":")
    print(f"\nRun signature: {run_body[:sig_end]}")

print("\n=== DONE ===")
