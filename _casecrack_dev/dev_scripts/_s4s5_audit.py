"""Sprint 4/5 module quality audit."""
from __future__ import annotations
import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

S4_MODULES = [
    "timing_attack_scanner", "rate_limit_tester", "response_time_analyzer",
    "vuln_intel_advisor", "web_cache_tester",
]
S5_MODULES = [
    "api_fuzzer", "benchmark_runner", "compliance_validator", "encoder",
    "integration_harness", "interactive_mode", "intercept",
]

def audit_module(path: pathlib.Path, sprint: int) -> None:
    if not path.exists():
        print(f"  [MISS] {path.name}")
        return
    src = path.read_text(encoding="utf-8")
    n = len(src.splitlines())
    has_helper = (
        ("_robust_stats" in src) if sprint == 4 else ("_sprint5_upgrades" in src)
    )
    has_tier2 = "__TIER2_HELPERS_INJECTED__" in src
    has_tier4 = "__TIER4A_ERRORS__" in src
    has_eventbus = "__EVENTBUS_INJECTED__" in src

    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        print(f"  [SYNERR] {path.name}: {e}")
        return

    dcs = [
        (c.name, "to_dict" in {m.name for m in ast.walk(c) if isinstance(m, ast.FunctionDef)})
        for c in ast.walk(tree)
        if isinstance(c, ast.ClassDef)
    ]
    missing_td = [c for c, has in dcs if not has and not c.startswith("_")]

    issues = []
    if not has_helper:
        issues.append(f"no sprint{sprint} helpers")
    if not has_tier2:
        issues.append("no_tier2")
    if not has_tier4:
        issues.append("no_tier4")
    if not has_eventbus:
        issues.append("no_eventbus")
    if missing_td:
        issues.append(f"no to_dict: {missing_td}")

    status = "OK  " if not issues else "WARN"
    print(f"  [{status}] {path.stem} ({n}L): {', '.join(issues) or 'clean'}")


print("=== SPRINT 4 SCANNERS ===")
base4 = pathlib.Path("tools/burp_enterprise/scanners")
for name in S4_MODULES:
    audit_module(base4 / f"{name}.py", sprint=4)

print()
print("=== SPRINT 5 TESTING_TOOLS ===")
base5 = pathlib.Path("tools/burp_enterprise/testing_tools")
for name in S5_MODULES:
    audit_module(base5 / f"{name}.py", sprint=5)
