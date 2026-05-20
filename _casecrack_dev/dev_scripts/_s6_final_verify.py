"""Final Sprint 6 quality verification."""
from __future__ import annotations
import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

MODULES = [
    "cvss_calculator", "evidence_collector", "json_report",
    "remediation_advisor", "sarif_output", "assessment_templates",
    "attack_narrative", "chain_render", "executive_summary",
    "html_report", "pdf_export",
]
BASE = pathlib.Path("tools/burp_enterprise/output")

all_pass = True
for name in MODULES:
    src = (BASE / f"{name}.py").read_text(encoding="utf-8")
    t2 = "__TIER2_HELPERS_INJECTED__" in src
    t4 = "__TIER4A_ERRORS__" in src
    eb = "__EVENTBUS_INJECTED__" in src
    s6 = "__SPRINT6_UPGRADES_INJECTED__" in src

    tree = ast.parse(src)
    dcs_without_td = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        is_dc = any(
            isinstance(d, ast.Name) and d.id == "dataclass"
            for d in cls.decorator_list
        )
        if not is_dc:
            continue
        methods = {m.name for m in ast.walk(cls) if isinstance(m, ast.FunctionDef)}
        if "to_dict" not in methods:
            dcs_without_td.append(cls.name)

    issues = []
    if not t2:
        issues.append("no TIER2")
    if not t4:
        issues.append("no TIER4A")
    if not eb:
        issues.append("no EVENTBUS")
    if not s6:
        issues.append("no SPRINT6")
    if dcs_without_td:
        issues.append(f"DC missing to_dict: {dcs_without_td}")

    status = "OK  " if not issues else "WARN"
    if issues:
        all_pass = False
    detail = ", ".join(issues) if issues else "all checks pass"
    print(f"  [{status}] {name}: {detail}")

print()
print("RESULT:", "ALL PASS" if all_pass else "ISSUES FOUND")
