"""Real reachability check: import recon_dashboard (and other parents)
and see which Phase 1 modules actually appear in sys.modules."""
from __future__ import annotations
import importlib
import sys

sys.path.insert(0, r"c:\Users\ya754\CaseCrack v1.0\CaseCrack")

# Modules that the audit said "exists but not wired"
SUSPECTS = [
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.routes_intelligence_experience"),
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.routes_agent"),
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.phase_handlers.advanced"),
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.phase_handlers.security_testing"),
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.routes_assessment"),
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.routes_exploit_graph"),
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.state_serializers"),
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.routes_reasoning"),
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.infra_monitor"),
    ("tools.burp_enterprise.recon_dashboard", "tools.burp_enterprise.recon_dashboard.session_store"),
    ("tools.burp_enterprise", "tools.burp_enterprise.knowledge_resilience"),
]

# Import each parent once
parents = sorted({p for p, _ in SUSPECTS})
parent_status = {}
for p in parents:
    try:
        importlib.import_module(p)
        parent_status[p] = "ok"
    except Exception as e:
        parent_status[p] = f"FAIL: {e}"
        print(f"!! parent {p} failed: {e}")

print()
print(f"{'Reachable':>10}  {'Module'}")
print("=" * 80)
for parent, child in SUSPECTS:
    if parent_status.get(parent, "").startswith("FAIL"):
        print(f"{'(parent broken)':>10}  {child}")
        continue
    reachable = child in sys.modules
    print(f"{'YES' if reachable else 'NO':>10}  {child}")
