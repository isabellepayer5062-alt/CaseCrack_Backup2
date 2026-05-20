"""Try importing each Phase 1 'exists-but-not-wired' module in isolation."""
from __future__ import annotations
import importlib
import sys
import traceback

sys.path.insert(0, r"c:\Users\ya754\CaseCrack v1.0\CaseCrack")

MODULES = [
    "tools.burp_enterprise.graph.multi_agent.tests.test_multi_agent",
    "tools.burp_enterprise.recon_dashboard.routes_intelligence_experience",
    "tools.burp_enterprise.recon_dashboard.routes_agent",
    "tools.burp_enterprise.recon_dashboard.phase_handlers.advanced",
    "tools.burp_enterprise.recon_dashboard.phase_handlers.security_testing",
    "tools.burp_enterprise.recon_dashboard.routes_assessment",
    "tools.burp_enterprise.recon_dashboard.routes_exploit_graph",
    "tools.burp_enterprise.recon_dashboard.state_serializers",
    "tools.burp_enterprise.recon_dashboard.routes_reasoning",
    "tools.burp_enterprise.knowledge_resilience",
    "tools.burp_enterprise.recon_dashboard.infra_monitor",
    "tools.burp_enterprise.recon_dashboard.session_store",
]

results = []
for m in MODULES:
    try:
        importlib.import_module(m)
        results.append((m, "OK", None))
    except Exception as e:
        # Get the most relevant frame
        tb_lines = traceback.format_exception_only(type(e), e)
        results.append((m, "FAIL", "".join(tb_lines).strip()))

ok = sum(1 for _, s, _ in results if s == "OK")
fail = sum(1 for _, s, _ in results if s == "FAIL")
print(f"OK: {ok}/{len(MODULES)}   FAIL: {fail}/{len(MODULES)}\n")
print("=" * 80)
for m, status, err in results:
    print(f"[{status}] {m}")
    if err:
        print(f"       -> {err[:200]}")
