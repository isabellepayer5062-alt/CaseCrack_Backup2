"""Final targeted probe — core_infra, TrafficAnalyzer, scanner_hooks enrichment."""
from __future__ import annotations
import pathlib, re

ROOT = pathlib.Path("CaseCrack/tools/burp_enterprise")

def read(p): return p.read_text("utf-8", "replace") if p.exists() else ""
def hdr(t): print(f"\n{'='*70}\n=== {t}\n{'='*70}")

# 1. core_infra/cross_cutting.py — process_finding body
hdr("1. core_infra/cross_cutting.py — process_finding body")
cc = ROOT / "core_infra" / "cross_cutting.py"
src = read(cc)
print(f"Size: {len(src)} chars")
idx = src.find("def process_finding")
if idx != -1:
    print(src[idx:idx+1200])
else:
    print("process_finding NOT FOUND")
    classes = re.findall(r"^class (\w+)", src, re.MULTILINE)
    fns = re.findall(r"^    def (\w+)", src, re.MULTILINE)
    print(f"Classes: {classes}")
    print(f"Methods: {fns[:20]}")

# 2. TrafficAnalyzer — all public methods with signatures
hdr("2. TrafficAnalyzer — all public methods")
p_an = ROOT / "analyzer.py"
src = read(p_an)
# is it a shim?
is_shim = "backward-compatibility shim" in src.lower() or "__getattr__" in src
print(f"analyzer.py is shim: {is_shim}")
if is_shim:
    m = re.search(r'import_module\("([^"]+)"\)', src)
    real = m.group(1) if m else "UNKNOWN"
    print(f"Shim target: {real}")
    real_path = real.replace("tools.burp_enterprise.", "").replace(".", "/") + ".py"
    rp = ROOT / real_path
    if rp.exists():
        src = read(rp)
        print(f"Real file: {real_path} ({len(src)} chars)")

idx_class = src.find("class TrafficAnalyzer")
if idx_class != -1:
    class_src = src[idx_class:idx_class+5000]
    methods = re.findall(r"^\s{4}def (\w+)\s*\(self[^)]*\)", class_src, re.MULTILINE)
    print(f"TrafficAnalyzer methods: {methods[:15]}")
    # Show scan/analyze method signatures
    for meth in methods:
        m = re.search(r"def " + re.escape(meth) + r"\s*\(self([^)]*)\)", class_src)
        if m:
            params = m.group(1).strip()
            if params and not meth.startswith("_"):
                print(f"  {meth}({params[:80]})")

# 3. scanner_hooks.py — what does the enrichment wrapper do?
hdr("3. scanner_hooks.py — enrichment wrapper code")
sh = ROOT / "scanners" / "scanner_hooks.py"
src = read(sh)
# Find the enrichment wrapping section
idx = src.find("enrich_findings")
if idx != -1:
    # Show surrounding context
    start = max(0, src.rfind("\ndef ", 0, idx))
    print(src[start:start+800])

# 4. _enrich_findings_with_risk in orchestrator
hdr("4. _enrich_findings_with_risk in orchestrator")
orch = ROOT / "pipeline" / "full_scan_orchestrator.py"
src = read(orch)
idx = src.find("def _enrich_findings_with_risk")
if idx != -1:
    print(src[idx:idx+600])

# 5. Check if _process_findings_through_pipeline really works (imports)
hdr("5. Import chain: pipeline.cross_cutting -> tools.burp_enterprise.cross_cutting -> core_infra")
for path, desc in [
    (ROOT / "pipeline" / "cross_cutting.py", "pipeline shim"),
    (ROOT / "cross_cutting.py", "root shim"),
    (ROOT / "core_infra" / "cross_cutting.py", "core_infra real"),
]:
    src = read(path)
    print(f"\n{desc} ({path.name}): {len(src)} chars")
    # Does it have get_middleware?
    print(f"  has get_middleware: {'def get_middleware' in src}")
    # Does it have CrossCuttingMiddleware?
    print(f"  has CrossCuttingMiddleware: {'class CrossCuttingMiddleware' in src}")
    # How does it export?
    imports = re.findall(r"^(?:from|import) .+", src, re.MULTILINE)
    for imp in imports[:5]:
        print(f"  {imp}")

# 6. finding_enrichment.py — is enrich_finding called by scanner_hooks correctly?
hdr("6. scanner_hooks.py enrichment integration — full patch code")
sh_src = read(ROOT / "scanners" / "scanner_hooks.py")
idx = sh_src.find("def patch_scanners")
if idx != -1:
    snippet = sh_src[idx:idx+3000]
    # Show the wrapping/enrichment part
    enrich_start = snippet.find("enrich")
    if enrich_start != -1:
        block_start = max(0, snippet.rfind("\n        ", 0, enrich_start))
        print(snippet[max(0, enrich_start-200):enrich_start+600])

# 7. Check what happens when xss.py XSSScanner is instantiated
hdr("7. XSSScanner.__init__ — can it be instantiated with no args?")
p_xss = ROOT / "xss.py"
src = read(p_xss)
idx = src.find("class XSSScanner")
class_src = src[idx:idx+3000]
init_match = re.search(r"def __init__\s*\(self([^)]*)\)", class_src)
if init_match:
    print(f"__init__(self{init_match.group(1)})")
    # Check if all params have defaults
    params = init_match.group(1)
    print(f"All have defaults: {'=' in params or not params.strip()}")

print("\n=== DONE ===")
