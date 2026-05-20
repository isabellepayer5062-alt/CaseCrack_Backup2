"""Comprehensive analysis: recovered/reimplemented modules — issues + gaps."""
from __future__ import annotations
import ast
import pathlib
import re
import sys
from collections import defaultdict

ROOT = pathlib.Path("tools/burp_enterprise")

# Tier 2 recovered modules (27) per memory note
TIER2_RECOVERED = {
    "network": ["dns_resolver", "http_fingerprint", "proxy_chain", "ssl_analyzer", "traffic_analyzer"],
    "integrations": ["ci_cd_pipeline", "defect_dojo", "jira_client", "slack_notifier", "sonarqube", "webhook_dispatcher"],
    "caap": ["caap_coordinator", "chat_interface", "compliance_checker", "discovery_agent",
             "exploitation_agent", "hypothesis_engine", "knowledge_graph", "recon_agent", "session_orchestrator"],
    "testing_tools": ["api_fuzzer", "benchmark_runner", "compliance_validator", "integration_harness",
                      "load_tester", "mock_server", "regression_tracker"],
}

# Sprint 4 = scanners (timing/rate/response/vuln/web_cache)
SPRINT4_SCANNERS = ["timing_attack_scanner", "rate_limit_tester", "response_time_analyzer",
                    "vuln_intel_advisor", "web_cache_tester"]
# Sprint 5 = testing_tools (encoder, interactive_mode, intercept)
SPRINT5_TESTING = ["encoder", "interactive_mode", "intercept"]
# Sprint 6 = output (11 modules)
SPRINT6_OUTPUT = ["cvss_calculator", "evidence_collector", "json_report", "remediation_advisor",
                  "sarif_output", "assessment_templates", "attack_narrative", "chain_render",
                  "executive_summary", "html_report", "pdf_export"]


def analyze_module(path: pathlib.Path) -> dict:
    """Analyze one module: LOC, classes, methods, hardening markers, smells."""
    if not path.exists():
        return {"exists": False}
    try:
        src = path.read_text(encoding="utf-8")
    except Exception as e:
        return {"exists": True, "read_error": str(e)}
    
    loc = len(src.splitlines())
    info = {
        "exists": True,
        "loc": loc,
        "has_eventbus": "# __EVENTBUS_INJECTED__" in src,
        "has_tier2": "# __TIER2_HELPERS_INJECTED__" in src,
        "has_tier4a": "# __TIER4A_ERRORS__" in src,
        "has_tier2_instrumented": "# __TIER2_INSTRUMENTED__" in src,
        "has_sprint5_upgrades": "# __SPRINT5_UPGRADES_INJECTED__" in src,
        "has_sprint6_upgrades": "# __SPRINT6_UPGRADES_INJECTED__" in src,
        "has_logger": bool(re.search(r"logger\s*=\s*logging\.getLogger", src)),
        "has_all": "__all__" in src,
        "stub_pass_only": False,
        "todo_count": len(re.findall(r"\bTODO\b|\bFIXME\b|\bXXX\b", src)),
        "naked_except": len(re.findall(r"except\s*:\s*$|except\s+Exception\s*:\s*pass", src, re.MULTILINE)),
        "print_statements": len(re.findall(r"^\s*print\(", src, re.MULTILINE)),
    }
    
    # Parse classes/dataclasses
    try:
        tree = ast.parse(src)
        classes = []
        dataclasses_total = 0
        dataclasses_with_to_dict = 0
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            classes.append(cls.name)
            is_dc = any(
                (isinstance(d, ast.Name) and d.id == "dataclass")
                or (isinstance(d, ast.Attribute) and d.attr == "dataclass")
                for d in cls.decorator_list
            )
            if is_dc and not cls.name.startswith("_"):
                dataclasses_total += 1
                if any(isinstance(n, ast.FunctionDef) and n.name == "to_dict" for n in cls.body):
                    dataclasses_with_to_dict += 1
        info["class_count"] = len(classes)
        info["dataclass_total"] = dataclasses_total
        info["dataclass_with_to_dict"] = dataclasses_with_to_dict
        # Detect "stub-only" modules: 1 class, body is just pass / docstring
        if len(classes) <= 1 and loc < 20:
            info["stub_pass_only"] = True
    except SyntaxError as e:
        info["syntax_error"] = str(e)
    return info


print("=" * 78)
print("COMPREHENSIVE ANALYSIS — Reimplemented/Recovered Modules + Remaining Gaps")
print("=" * 78)

# ---- PART 1: TIER 2 RECOVERED (27 modules) ----
print("\n## Part 1: Tier 2 Recovered Modules (27)\n")
tier2_issues = []
tier2_summary = []
for sub, names in TIER2_RECOVERED.items():
    for n in names:
        p = ROOT / sub / f"{n}.py"
        info = analyze_module(p)
        rel = f"{sub}/{n}.py"
        if not info.get("exists"):
            tier2_issues.append(f"  MISSING FILE: {rel}")
            continue
        markers = []
        if not info.get("has_tier2"):
            markers.append("no_tier2")
        if not info.get("has_eventbus"):
            markers.append("no_eventbus")
        if not info.get("has_tier4a"):
            markers.append("no_tier4a")
        if not info.get("has_tier2_instrumented"):
            markers.append("no_instrument")
        dc_gap = info.get("dataclass_total", 0) - info.get("dataclass_with_to_dict", 0)
        if dc_gap > 0:
            markers.append(f"dc_to_dict_gap={dc_gap}")
        if info.get("stub_pass_only"):
            markers.append("STUB")
        if info.get("syntax_error"):
            markers.append(f"SYNTAX_ERR")
        flag = " | ".join(markers) if markers else "OK"
        tier2_summary.append((rel, info.get("loc", 0), flag))

# Print tier 2 summary
loc_sum = sum(x[1] for x in tier2_summary)
ok_count = sum(1 for x in tier2_summary if x[2] == "OK")
print(f"  Total: {len(tier2_summary)} modules, {loc_sum} LOC, {ok_count} fully clean")
print()
for rel, loc, flag in tier2_summary:
    if flag != "OK":
        print(f"  [ISSUE] {rel} ({loc} LOC): {flag}")
for issue in tier2_issues:
    print(issue)

# ---- PART 2: SPRINT 4 (scanners) ----
print("\n## Part 2: Sprint 4 — Scanners (5)\n")
for n in SPRINT4_SCANNERS:
    p = ROOT / "scanners" / f"{n}.py"
    info = analyze_module(p)
    rel = f"scanners/{n}.py"
    markers = []
    if not info.get("has_tier2"):
        markers.append("no_tier2")
    if not info.get("has_eventbus"):
        markers.append("no_eventbus")
    if not info.get("has_tier4a"):
        markers.append("no_tier4a")
    dc_gap = info.get("dataclass_total", 0) - info.get("dataclass_with_to_dict", 0)
    if dc_gap > 0:
        markers.append(f"dc_to_dict_gap={dc_gap}")
    flag = " | ".join(markers) if markers else "OK"
    print(f"  {rel} ({info.get('loc', 0)} LOC): {flag}")

# ---- PART 3: SPRINT 5 (testing_tools recovered) ----
print("\n## Part 3: Sprint 5 — testing_tools (3 + 7 upgraded)\n")
all_s5 = SPRINT5_TESTING + ["api_fuzzer", "benchmark_runner", "compliance_validator",
                              "integration_harness", "load_tester", "mock_server", "regression_tracker"]
for n in all_s5:
    p = ROOT / "testing_tools" / f"{n}.py"
    info = analyze_module(p)
    rel = f"testing_tools/{n}.py"
    markers = []
    if not info.get("has_tier2"):
        markers.append("no_tier2")
    if not info.get("has_eventbus"):
        markers.append("no_eventbus")
    if not info.get("has_tier4a"):
        markers.append("no_tier4a")
    if not info.get("has_sprint5_upgrades") and n not in SPRINT5_TESTING:
        markers.append("no_s5_upgrades")
    dc_gap = info.get("dataclass_total", 0) - info.get("dataclass_with_to_dict", 0)
    if dc_gap > 0:
        markers.append(f"dc_to_dict_gap={dc_gap}")
    flag = " | ".join(markers) if markers else "OK"
    print(f"  {rel} ({info.get('loc', 0)} LOC): {flag}")

# ---- PART 4: SPRINT 6 (output) ----
print("\n## Part 4: Sprint 6 — Output (11)\n")
for n in SPRINT6_OUTPUT:
    p = ROOT / "output" / f"{n}.py"
    info = analyze_module(p)
    rel = f"output/{n}.py"
    markers = []
    if not info.get("has_tier2"):
        markers.append("no_tier2")
    if not info.get("has_eventbus"):
        markers.append("no_eventbus")
    if not info.get("has_tier4a"):
        markers.append("no_tier4a")
    if not info.get("has_sprint6_upgrades"):
        markers.append("no_s6_upgrades")
    dc_gap = info.get("dataclass_total", 0) - info.get("dataclass_with_to_dict", 0)
    if dc_gap > 0:
        markers.append(f"dc_to_dict_gap={dc_gap}")
    flag = " | ".join(markers) if markers else "OK"
    print(f"  {rel} ({info.get('loc', 0)} LOC): {flag}")

# ---- PART 5: REMAINING STUBS / MISSING ----
print("\n## Part 5: Remaining Stubs / Suspected Missing\n")
# Find any *.py file in burp_enterprise that is <20 LOC and contains 'pass' or 'NotImplementedError'
suspects = []
for p in ROOT.rglob("*.py"):
    if "__pycache__" in p.parts or "_archive" in p.parts or "_cold_storage" in p.parts:
        continue
    if p.name.startswith("_"):
        continue
    try:
        src = p.read_text(encoding="utf-8")
    except Exception:
        continue
    loc = len(src.splitlines())
    rel = p.relative_to(ROOT).as_posix()
    # Skip relay shims (12-LOC pattern) and compat shims (18-LOC pattern)
    if "_importlib.import_module" in src and loc < 30:
        continue
    if loc < 25 and "NotImplementedError" in src:
        suspects.append((rel, loc, "NotImplementedError"))
    elif loc < 15 and "pass" in src and "import" not in src:
        suspects.append((rel, loc, "pass-only stub"))
    elif loc < 20 and re.search(r"^\s*pass\s*$", src, re.MULTILINE) and "class " in src:
        # Class with body = pass
        try:
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    body = [n for n in node.body if not isinstance(n, ast.Expr) or not isinstance(n.value, ast.Constant)]
                    if len(body) == 1 and isinstance(body[0], ast.Pass):
                        suspects.append((rel, loc, f"class {node.name}: pass"))
                        break
        except Exception:
            pass

if suspects:
    for rel, loc, kind in suspects[:30]:
        print(f"  STUB: {rel} ({loc} LOC) — {kind}")
    if len(suspects) > 30:
        print(f"  ... and {len(suspects) - 30} more")
else:
    print("  No obvious stubs found.")

print(f"\n  Total suspect stubs/missing: {len(suspects)}")
