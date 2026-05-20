"""Audit Sprint 4/5 modules for dataclass to_dict gaps — filter out service/error classes."""
from __future__ import annotations
import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

# Only flag @dataclass-decorated classes
MODULES = {
    "scanners": [
        "timing_attack_scanner", "rate_limit_tester",
        "response_time_analyzer", "vuln_intel_advisor", "web_cache_tester",
    ],
    "testing_tools": [
        "api_fuzzer", "benchmark_runner", "compliance_validator",
        "encoder", "integration_harness", "interactive_mode", "intercept",
    ],
}

ROOT = pathlib.Path("tools/burp_enterprise")

for subdir, names in MODULES.items():
    print(f"=== {subdir} ===")
    for name in names:
        path = ROOT / subdir / f"{name}.py"
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            # Only proper @dataclass-decorated classes
            is_dc = any(
                isinstance(d, ast.Name) and d.id == "dataclass"
                for d in cls.decorator_list
            )
            if not is_dc:
                continue
            methods = {
                m.name for m in ast.walk(cls) if isinstance(m, ast.FunctionDef)
            }
            has_td = "to_dict" in methods
            status = "OK  " if has_td else "MISS"
            fields = [
                n.target.id if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)
                else "?"
                for n in cls.body
                if isinstance(n, ast.AnnAssign)
            ][:5]  # first 5 fields
            print(f"  [{status}] {name}.{cls.name}  fields={fields}")
    print()
