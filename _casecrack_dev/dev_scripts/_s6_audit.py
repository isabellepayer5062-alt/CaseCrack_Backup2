"""Deep quality audit of Sprint 6 output modules."""
from __future__ import annotations
import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from tools.burp_enterprise.output import (
    cvss_calculator, evidence_collector, json_report,
    remediation_advisor, sarif_output, assessment_templates,
    attack_narrative, chain_render, executive_summary,
    html_report, pdf_export,
)

modules = {
    "cvss_calculator": cvss_calculator,
    "evidence_collector": evidence_collector,
    "json_report": json_report,
    "remediation_advisor": remediation_advisor,
    "sarif_output": sarif_output,
    "assessment_templates": assessment_templates,
    "attack_narrative": attack_narrative,
    "chain_render": chain_render,
    "executive_summary": executive_summary,
    "html_report": html_report,
    "pdf_export": pdf_export,
}

BASE = pathlib.Path("tools/burp_enterprise/output")

for name, mod in modules.items():
    issues = []
    src = (BASE / f"{name}.py").read_text(encoding="utf-8")

    # 1. __all__ populated
    all_ = getattr(mod, "__all__", [])
    if not all_:
        issues.append("empty __all__")

    # 2. Sprint 6 injection marker present
    if "__SPRINT6_UPGRADES_INJECTED__" not in src:
        issues.append("missing SPRINT6 injection block")

    # 3. Sprint 5-style hardening blocks
    has_tier2 = "__TIER2_HELPERS_INJECTED__" in src
    has_tier4 = "__TIER4A_ERRORS__" in src
    has_eventbus = "__EVENTBUS_INJECTED__" in src
    if not has_tier2 and not has_tier4:
        issues.append("missing TIER2/TIER4A hardening blocks")

    # 4. Classes without to_dict / to_json
    tree = ast.parse(src)
    bad_classes = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        methods = {
            n.name for n in ast.walk(cls) if isinstance(n, ast.FunctionDef)
        }
        # Skip pure enum classes or abstract bases
        if cls.name.endswith(("Action", "Enum", "Level")) and not methods - {"__new__"}:
            continue
        if "to_dict" not in methods and "to_json" not in methods:
            bad_classes.append(cls.name)
    if bad_classes:
        issues.append(f"classes without to_dict: {bad_classes}")

    # 5. Base class integration: does it use the Sprint 6 helpers at all?
    sprint6_names = [
        "CVSSTemporalMetrics", "CVSSEnvironmentalMetrics", "CVSSValidator",
        "PersistentEvidenceStore", "DigestAttestation",
        "JSONSchemaValidator", "SchemaMigrator",
        "ContextualPrioritizer", "ExploitMaturity",
        "SARIFEnricher", "CWEMapper",
        "TemplateValidator", "VersionedTemplateRegistry",
        "NarrativeGraph", "ConfidenceWording",
        "GraphValidator", "CriticalPathScorer",
        "ConfigurableSummaryGenerator", "EnvironmentRiskModel",
        "AccessibilityChecker", "ThemeRegistry",
        "RenderingProfileRegistry", "PageIntegrityChecker",
    ]
    has_sprint6_usage = any(n in src for n in sprint6_names)
    if not has_sprint6_usage:
        issues.append("Sprint 6 helpers imported but not used in base class body")

    status = "OK  " if not issues else "WARN"
    print(f"[{status}] {name}  ({len(all_)} exports)")
    for issue in issues:
        print(f"       ! {issue}")
