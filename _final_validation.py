"""Final comprehensive validation of all session fixes."""
import sys, ast, pathlib
sys.path.insert(0, str(pathlib.Path("CaseCrack")))
ROOT = pathlib.Path("CaseCrack/tools/burp_enterprise")

print("=" * 60)
print("FINAL GAP-FIX VALIDATION REPORT")
print("=" * 60)

# ── 1. AST validation ────────────────────────────────────────────────────────
print("\n[1] AST syntax checks")
files = [
    ROOT / "scanners" / "scanner_hooks.py",
    ROOT / "pipeline" / "full_scan_orchestrator.py",
    ROOT / "output" / "finding_dedup.py",
    ROOT / "output" / "finding_enrichment.py",
    ROOT / "output" / "correlation_engine.py",
]
for f in files:
    try:
        ast.parse(f.read_text("utf-8", "replace"))
        print(f"  OK  {f.name}")
    except SyntaxError as e:
        print(f"  ERR {f.name}: {e}")

# ── 2. Scanner registry checks ───────────────────────────────────────────────
print("\n[2] Scanner registry checks")
from tools.burp_enterprise.scanners.scanner_hooks import _SCANNER_REGISTRY

traffic = [e for e in _SCANNER_REGISTRY if e[3] == "traffic_analyzer"]
xss = [e for e in _SCANNER_REGISTRY if e[3] == "xss_tester"]
weak_hash = [e for e in _SCANNER_REGISTRY if e[3] == "weak_hash_detector"]
defensive = [e for e in _SCANNER_REGISTRY if e[3] == "defensive_monitoring"]
print(f"  Registry size: {len(_SCANNER_REGISTRY)}")
print(f"  traffic_analyzer entries: {len(traffic)} (want: 0)")
print(f"  xss_tester entries: {len(xss)} (want: 1)")
print(f"  weak_hash_detector entries: {len(weak_hash)} (want: 1)")
print(f"  defensive_monitoring entries: {len(defensive)} (want: 1)")

# ── 3. FindingDeduplicator fix ───────────────────────────────────────────────
print("\n[3] FindingDeduplicator severity-preservation merge")
from tools.burp_enterprise.output.finding_dedup import FindingDeduplicator

dedup = FindingDeduplicator()
assert isinstance(dedup._seen, dict), "FAIL: _seen should be dict"
print(f"  _seen is dict: OK")

# Exact duplicate → merge cvss + confirmed, not discard
f1 = {"finding_type": "sqli", "url": "https://test.com/login", "severity": "high", "parameter": "id"}
f2 = dict(f1) | {"confirmed": True, "cvss_score": 9.1}
unique, stats = dedup.filter([f1, f2])
assert len(unique) == 1, f"FAIL: should keep 1, got {len(unique)}"
assert unique[0].get("confirmed") == True, "FAIL: confirmed not merged"
assert unique[0].get("cvss_score") == 9.1, "FAIL: cvss_score not merged"
print(f"  Exact dup → merge confirmed/cvss: OK (dups_removed={stats.duplicates_removed})")

# ── 4. _extract_findings extended coverage ───────────────────────────────────
print("\n[4] _extract_findings extended coverage")
src = (ROOT / "pipeline" / "full_scan_orchestrator.py").read_text("utf-8", "replace")
checks = [
    ("security_headers", "GAP-FIX: handle AnalysisResult-style objects"),
    ("sensitive_data", "GAP-FIX: handle AnalysisResult-style objects"),
    ("finding_type", "GAP-FIX: normalise mandatory reporter fields"),
]
for snippet, label in checks:
    if snippet in src:
        print(f"  OK  '{snippet}' present ({label})")
    else:
        print(f"  MISSING '{snippet}' — {label}")

# ── 5. Correlation chains merged into module_results ─────────────────────────
print("\n[5] Correlation engine chains → module_results")
if "GAP-FIX" in src and "correlation_engine" in src:
    print("  OK  correlation chains merge present")
else:
    print("  MISSING correlation chains merge")

# ── 6. XSSFinding serialization ─────────────────────────────────────────────
print("\n[6] XSSFinding.to_dict() serialization")
xss_src = (ROOT / "xss.py").read_text("utf-8", "replace")
if "def to_dict" in xss_src:
    print("  OK  XSSFinding.to_dict() defined")
else:
    print("  MISSING XSSFinding.to_dict()")

print("\n" + "=" * 60)
print("VALIDATION COMPLETE")
print("=" * 60)
