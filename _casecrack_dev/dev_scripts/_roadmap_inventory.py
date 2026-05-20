"""
Comprehensive module inventory for RECONNECTION_ROADMAP update.
Checks: existence, LOC, public class/function count for all modules mentioned
in the roadmap Phase 3 (lost modules) and Phase 1 (reconnect tasks).
"""
import pathlib, ast, sys, json

ROOT = pathlib.Path("tools/burp_enterprise")
SKIP = {"__pycache__", "_archive", "_cold_storage"}

def get_loc(p: pathlib.Path) -> int:
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
        return sum(1 for ln in lines if ln.strip() and not ln.strip().startswith("#"))
    except Exception:
        return 0

def get_public_api(p: pathlib.Path) -> list:
    """Return list of public class and function names."""
    names = []
    try:
        src = p.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_") and isinstance(node, ast.ClassDef):
                    names.append(f"class:{node.name}")
                elif not node.name.startswith("_") and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Only top-level functions
                    # Check parent is module (depth 1)
                    pass
        # Top-level only
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                names.append(f"C:{node.name}")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                names.append(f"f:{node.name}")
    except Exception:
        pass
    return names

def check_module(subpath: str) -> dict:
    """subpath like 'agents/auth_context' or 'agents/auth_context.py'"""
    if not subpath.endswith(".py"):
        subpath += ".py"
    p = ROOT / subpath
    if p.exists():
        loc = get_loc(p)
        api = get_public_api(p)
        return {"exists": True, "path": str(p.relative_to(ROOT)), "loc": loc, "api_count": len(api), "api": api[:5]}
    # check __init__.py for package
    pkg = ROOT / subpath.replace(".py", "") / "__init__.py"
    if pkg.exists():
        loc = get_loc(pkg)
        return {"exists": True, "path": str(pkg.relative_to(ROOT)), "loc": loc, "api_count": 0, "api": [], "is_pkg": True}
    return {"exists": False, "path": subpath, "loc": 0, "api_count": 0, "api": []}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: Lost modules (all 25 subsystems from roadmap)
# ─────────────────────────────────────────────────────────────────────────────
PHASE3_MODULES = {
    "agents": [
        "agents/auth_context", "agents/autonomous_exploitation",
        "agents/browser_workflow_extractor", "agents/business_logic_scanner",
        "agents/chain_impact_scorer", "agents/crawl_secrets_pipeline",
        "agents/creative_exploit_heuristics", "agents/discovery_bridge",
        "agents/evolutionary_fuzzer", "agents/exploit_graph",
        "agents/long_running_orchestrator", "agents/opportunity_scoring",
        "agents/payload_intelligence", "agents/race_harness",
        "agents/reverse_analytics",
        # 5 more from JSON
        "agents/autonomous_exploitation_v2", "agents/llm_cache",
        "agents/llm_clients", "agents/llm_routing", "agents/llm_tracking",
    ],
    "scanners": [
        "scanners/business_logic_ai", "scanners/business_logic_scanner",
        "scanners/captcha_bypass", "scanners/csp_analyzer",
        "scanners/defensive_monitoring_tester", "scanners/error_intelligence",
        "scanners/error_page_analyzer", "scanners/fail_secure_tester",
        "scanners/graphql_schema_cache", "scanners/grpc_exploit_tester",
        "scanners/log_endpoint_scanner", "scanners/mass_assignment_tester",
        "scanners/network_safety", "scanners/oauth_recon",
        "scanners/oob_interaction",
        # 11 more:
        "scanners/path_traversal_scanner", "scanners/privilege_escalation_scanner",
        "scanners/prototype_pollution_scanner", "scanners/redirect_chain_scanner",
        "scanners/request_smuggling_scanner", "scanners/ssti_scanner",
        "scanners/subdomain_takeover_scanner", "scanners/timing_oracle_scanner",
        "scanners/upload_exploit_scanner", "scanners/waf_evasion_scanner",
        "scanners/xxe_scanner",
    ],
    "core_infra": [
        "core_infra/compliance_pkg", "core_infra/confidence_engine",
        "core_infra/context_manager", "core_infra/cross_cutting",
        "core_infra/error_intelligence", "core_infra/event_bus",
        "core_infra/exploit_graph", "core_infra/finding_stream",
        "core_infra/js_ast_analyzer", "core_infra/module_registry",
        "core_infra/preflight", "core_infra/scanner_utilities",
        "core_infra/secret_patterns", "core_infra/severity_engine",
        "core_infra/telemetry",
    ],
    "pipeline": [
        "pipeline/config", "pipeline/cross_cutting", "pipeline/ct_monitor",
        "pipeline/distributed_recon", "pipeline/dns_intel",
        "pipeline/enterprise_scale_executor", "pipeline/event_bus",
        "pipeline/licensing", "pipeline/long_running_orchestrator",
        "pipeline/orchestrator_bridge", "pipeline/recovery_bridge",
        "pipeline/scan_intelligence", "pipeline/scanner_hooks",
        "pipeline/scanner_utilities", "pipeline/task_queue",
    ],
    "recon": [
        "recon/cross_cutting", "recon/event_bus", "recon/git_history_scanner",
        "recon/graphql_recon", "recon/headless_crawler", "recon/http3_scanner",
        "recon/http_client", "recon/ipv6_scanner", "recon/juicy_files",
        "recon/kerberos_scanner", "recon/phase_health", "recon/scanner_hooks",
        "recon/second_order_detector", "recon/supply_chain_intel",
        "recon/telemetry",
    ],
    "secrets": [
        "secrets/canary_detector", "secrets/crawl_secrets_pipeline",
        "secrets/credential_enumerator", "secrets/cross_fork_scanner",
        "secrets/custom_detector", "secrets/custom_detector_loader",
        "secrets/docker_image_scanner", "secrets/docker_layer_analyzer",
        "secrets/entropy_analyzer", "secrets/entropy_intelligence",
        "secrets/git_deep_scanner", "secrets/keyword_prefilter",
        "secrets/network_safety", "secrets/secret_patterns",
        "secrets/secret_verifier",
        "secrets/trufflehog_integration",  # +1 more
    ],
    "output": [
        "output/atlas", "output/base_finding", "output/chain_executor",
        "output/compliance_mapper", "output/composite_rule_engine",
        "output/confidence_engine", "output/event_integration",
        "output/exploit_graph", "output/exploit_graph_renderer",
        "output/finding_correlator", "output/finding_dedup",
        "output/finding_enrichment", "output/response_classifier",
        "output/severity_engine",
    ],
    "caap": [
        "caap/browser_exploitation_engine", "caap/caap_chains",
        "caap/caap_hypothesis", "caap/caap_models", "caap/caap_parser",
        "caap/exploitation_data", "caap/screenshot", "caap/state_graph",
        "caap/ui_interaction_engine",
    ],
    "discovery_pkg": [
        "discovery_pkg/browser_extension_recon", "discovery_pkg/captcha_bypass",
        "discovery_pkg/discovery_bridge", "discovery_pkg/postman_scanner",
        "discovery_pkg/postmessage_analyzer", "discovery_pkg/state_graph",
        "discovery_pkg/subdomain_takeover_ext", "discovery_pkg/template_fingerprint",
        "discovery_pkg/workflow_modeler",
    ],
    "misc": [
        "misc/audit_trail_tester", "misc/baseline_manager", "misc/install_helper",
        "misc/juicy_files", "misc/licensing", "misc/network_safety",
        "misc/preflight", "misc/resource_monitor", "misc/tool_wrapper_bridge",
        "misc/workflow_modeler",
    ],
    "intel": [
        "intel/azure_devops_deep_recon", "intel/bitbucket_deep_recon",
        "intel/gitlab_deep_recon", "intel/iot_discovery", "intel/source_code_search",
        "intel/supply_chain_deep", "intel/supply_chain_intel",
    ],
    "exploit_chains": [
        "exploit_chains/chain_impact_scorer", "exploit_chains/chain_matcher",
        "exploit_chains/chain_packs",
    ],
    "cloud": [
        "cloud/bucket_scanner", "cloud/cloud_asset_discovery",
        "cloud/cloud_inventory", "cloud/container", "cloud/container_recon",
        "cloud/iam_attack_paths", "cloud/ipv6_scanner", "cloud/kerberos_scanner",
        "cloud/network_safety",
    ],
    "testing_tools": [
        "testing_tools/advanced_racer", "testing_tools/captcha_bypass",
        "testing_tools/evolutionary_fuzzer", "testing_tools/payload_intelligence",
        "testing_tools/race_harness", "testing_tools/recursive_decoder",
        "testing_tools/screenshot",
    ],
    "integrations": [
        "integrations/config", "integrations/dependency_health",
        "integrations/event_integration", "integrations/notification_webhooks",
        "integrations/nuclei_health", "integrations/nuclei_template_generator",
        "integrations/updater",
    ],
    "network": [
        "network/http2_fingerprint", "network/http3_scanner",
        "network/http3_security", "network/http_client",
        "network/multi_perspective", "network/network_mapper",
        "network/recon_transport",
    ],
    "database": [
        "database/db_consolidation_migrate", "database/db_migrations",
    ],
    "inference": [
        "inference/model_management",
    ],
    "session_auth": [
        "session_auth/auth_context", "session_auth/license_keygen",
        "session_auth/session_state_manager",
    ],
    "swarm": [
        "swarm/multi_gpu",  # package
    ],
    "graph": [],  # 0 reconnect listed as lost
    "osint_providers": [],
    "mcp": ["mcp/atlas_mcp_bridge"],
    "loop": [],
}

# Phase 1: Reconnect tasks (these exist, just need wiring) — check their LOC
PHASE1_MODULES = [
    ("agents", "agents/advanced_agent_patterns", 1321),
    ("recon_dashboard", "recon_dashboard/cross_target_intelligence", 627),
    ("recon_dashboard", "recon_dashboard/phase_handlers/intelligence", 522),
    ("exploit_chains", "exploit_chains/manual_audit_engine", 1640),
    ("agents", "agents/advanced_orchestration", 1127),
    ("agents", "agents/deterministic_replay", 606),
    ("database", "database/data_migration", 559),
    ("graph", "graph/multi_agent/tests/test_multi_agent", 431),
    ("recon_dashboard", "recon_dashboard/routes_intelligence_experience", 335),
    ("recon_dashboard", "recon_dashboard/routes_persistent_agent", 1147),
    ("recon_dashboard", "recon_dashboard/target_scoring", 691),
    ("exploitation", "exploitation/engine", 628),
    ("swarm", "swarm/multi_gpu/messenger", 534),
    ("swarm", "swarm/multi_gpu/model_sharder", 499),
    ("swarm", "swarm/multi_gpu/scheduler", 584),
    ("swarm", "swarm/multi_gpu/topology", 710),
    ("agents", "agents/conflict_arbitration", 685),
    ("agents", "agents/fork_spawn", 1099),
    ("agents", "agents/role_registry", 634),
    ("agents", "agents/speculative_executor", 768),
    ("graph", "graph/production", 573),
    ("swarm", "swarm/multi_gpu/governor", 466),
    ("recon_dashboard", "recon_dashboard/routes_agent", 376),
    ("recon_dashboard", "recon_dashboard/routes_multi_agent", 493),
    ("exploitation", "exploitation/chains", 326),
    ("exploitation", "exploitation/impact", 548),
    ("inference", "inference/kv_cache", 277),
    ("recon_dashboard", "recon_dashboard/phase_handlers/advanced", 1229),
    ("recon_dashboard", "recon_dashboard/phase_handlers/discovery", 609),
    ("recon_dashboard", "recon_dashboard/phase_handlers/security_testing", 1178),
    ("recon_dashboard", "recon_dashboard/routes_assessment", 219),
    ("recon_dashboard", "recon_dashboard/routes_cross_target", 335),
    ("recon_dashboard", "recon_dashboard/routes_exploit_graph", 262),
    ("recon_dashboard", "recon_dashboard/routes_target_scoring", 249),
    ("recon_dashboard", "recon_dashboard/state_serializers", 662),
    ("recon_dashboard", "recon_dashboard/routes_reasoning", 198),
    ("core_infra", "core_infra/chaos_testing_v2", 1032),
    ("osint_providers", "osint_providers/netintel_client", 615),
    ("osint_providers", "osint_providers/schemas", 346),
    ("adversarial_validation_agent", "adversarial_validation_agent", 1137),
    ("intel", "intel/github_client_base", 388),
    ("knowledge_resilience", "knowledge_resilience", 1163),
    ("strategy_horizon_optimizer", "strategy_horizon_optimizer", 618),
    ("validation_fleet", "validation_fleet", 2578),
    ("tool_wrappers", "tool_wrappers/_evidence", 107),
    ("cli", "cli/daemon", 377),
    ("discovery_pkg", "discovery_pkg/subdomain_external", 273),
    ("recon_dashboard", "recon_dashboard/infra_monitor", 387),
    ("recon_dashboard", "recon_dashboard/routes_operator", 238),
    ("recon_dashboard", "recon_dashboard/session_store", 210),
]

# Newly created modules from remediation sessions
NEWLY_CREATED = [
    ("network", "network/dns_resolver", 0),
    ("network", "network/http_fingerprint", 0),
    ("network", "network/proxy_chain", 0),
    ("network", "network/ssl_analyzer", 0),
    ("network", "network/traffic_analyzer", 0),
    ("integrations", "integrations/ci_cd_pipeline", 0),
    ("integrations", "integrations/defect_dojo", 0),
    ("integrations", "integrations/jira_client", 0),
    ("integrations", "integrations/slack_notifier", 0),
    ("integrations", "integrations/sonarqube", 0),
    ("integrations", "integrations/webhook_dispatcher", 0),
    ("caap", "caap/caap_coordinator", 0),
    ("caap", "caap/chat_interface", 0),
    ("caap", "caap/compliance_checker", 0),
    ("caap", "caap/discovery_agent", 0),
    ("caap", "caap/exploitation_agent", 0),
    ("caap", "caap/hypothesis_engine", 0),
    ("caap", "caap/knowledge_graph", 0),
    ("caap", "caap/recon_agent", 0),
    ("caap", "caap/session_orchestrator", 0),
    ("testing_tools", "testing_tools/api_fuzzer", 0),
    ("testing_tools", "testing_tools/benchmark_runner", 0),
    ("testing_tools", "testing_tools/compliance_validator", 0),
    ("testing_tools", "testing_tools/integration_harness", 0),
    ("testing_tools", "testing_tools/load_tester", 0),
    ("testing_tools", "testing_tools/mock_server", 0),
    ("testing_tools", "testing_tools/regression_tracker", 0),
]

# LOC thresholds: below this is "stub" (needs expansion)
LOC_STUB_THRESHOLD = 100
LOC_MINIMAL_THRESHOLD = 200

print("=" * 70)
print("PHASE 3: LOST MODULE STATUS")
print("=" * 70)
total_lost = 0
recovered = 0
stub_only = 0
truly_missing = 0

p3_results = {}
for subsys, modules in PHASE3_MODULES.items():
    if not modules:
        continue
    subsys_results = []
    for m in modules:
        r = check_module(m)
        r["module"] = m
        total_lost += 1
        if r["exists"] and r["loc"] >= LOC_STUB_THRESHOLD:
            recovered += 1
            r["status"] = "RECOVERED"
        elif r["exists"] and r["loc"] > 0:
            stub_only += 1
            r["status"] = f"STUB ({r['loc']} LOC)"
        else:
            truly_missing += 1
            r["status"] = "MISSING"
        subsys_results.append(r)
    p3_results[subsys] = subsys_results

# Print summary by subsystem
for subsys, results in p3_results.items():
    missing = [r for r in results if r["status"] == "MISSING"]
    stubs = [r for r in results if r["status"].startswith("STUB")]
    done = [r for r in results if r["status"] == "RECOVERED"]
    print(f"\n### {subsys} ({len(results)} modules)")
    print(f"   ✅ Recovered: {len(done)}  ⚠️ Stub: {len(stubs)}  ❌ Missing: {len(missing)}")
    for r in results:
        icon = "✅" if r["status"] == "RECOVERED" else ("⚠️" if r["status"].startswith("STUB") else "❌")
        api_sample = ", ".join(r["api"][:3]) if r["api"] else ""
        print(f"   {icon} {r['module'].split('/')[-1]:40s}  {r['loc']:5d} LOC  {api_sample[:50]}")

print(f"\nPHASE 3 TOTALS: {total_lost} modules")
print(f"  ✅ Recovered (≥100 LOC): {recovered}")
print(f"  ⚠️ Stub (<100 LOC):     {stub_only}")
print(f"  ❌ Missing:             {truly_missing}")

print("\n" + "=" * 70)
print("PHASE 1: RECONNECT TASK LOC AUDIT")
print("=" * 70)
phase1_ok = phase1_short = phase1_missing = 0
p1_results = []
for subsys, path, expected_loc in PHASE1_MODULES:
    r = check_module(path)
    r["module"] = path
    r["expected_loc"] = expected_loc
    if not r["exists"]:
        phase1_missing += 1
        r["status"] = "MISSING"
        icon = "❌"
    elif r["loc"] < expected_loc * 0.5:
        phase1_short += 1
        r["status"] = f"SHORT ({r['loc']}/{expected_loc})"
        icon = "⚠️"
    elif r["loc"] < expected_loc * 0.8:
        phase1_short += 1
        r["status"] = f"UNDER ({r['loc']}/{expected_loc})"
        icon = "⚠️"
    else:
        phase1_ok += 1
        r["status"] = f"OK ({r['loc']}/{expected_loc})"
        icon = "✅"
    p1_results.append((subsys, r))
    pct = int(r["loc"] / expected_loc * 100) if expected_loc > 0 else 0
    print(f"  {icon} {path:55s} {r['loc']:5d}/{expected_loc:<5d} LOC ({pct}%)")

print(f"\nPHASE 1 TOTALS: {len(PHASE1_MODULES)} reconnect tasks")
print(f"  ✅ At/near expected LOC (≥80%): {phase1_ok}")
print(f"  ⚠️ Below expected LOC (<80%):   {phase1_short}")
print(f"  ❌ Missing:                     {phase1_missing}")

print("\n" + "=" * 70)
print("NEWLY CREATED MODULES (Sessions ~2026-04-17 to present)")
print("=" * 70)
for subsys, path, _ in NEWLY_CREATED:
    r = check_module(path)
    icon = "✅" if r["exists"] else "❌"
    print(f"  {icon} {path:55s} {r['loc']:5d} LOC")

# Save JSON for roadmap update
output = {
    "phase3": p3_results,
    "phase1_totals": {"ok": phase1_ok, "short": phase1_short, "missing": phase1_missing},
    "phase3_totals": {"recovered": recovered, "stub": stub_only, "missing": truly_missing},
}
pathlib.Path("_roadmap_inventory.json").write_text(json.dumps(output, indent=2, default=str))
print("\n✅ Saved _roadmap_inventory.json")
