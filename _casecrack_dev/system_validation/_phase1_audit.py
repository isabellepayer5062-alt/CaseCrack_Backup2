"""Audit Phase 1 reconnect tasks: which modules exist on disk vs need reimpl,
and which are already referenced in their subsystem __init__.py."""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path("c:/Users/ya754/CaseCrack v1.0/CaseCrack/tools/burp_enterprise")

# (subsystem_pkg_dir, dotted_module_path, public_api_excerpt, score)
TASKS = [
    ("agents", "agents.advanced_agent_patterns", ["FuseState", "FuseCircuit", "ResolveOnceGuard"], 85),
    ("recon_dashboard", "recon_dashboard.cross_target_intelligence", ["CrossTargetMemory"], 85),
    ("recon_dashboard", "recon_dashboard.phase_handlers.intelligence", [], 75),
    ("exploit_chains", "exploit_chains.manual_audit_engine", ["DecisionSnapshot", "InterestType", "WalkedDecision"], 72),
    ("agents", "agents.advanced_orchestration", ["EscalationStage", "EscalationRecord", "OutputSlotReservation"], 70),
    ("agents", "agents.deterministic_replay", ["DecisionRNG", "DecisionFrame", "JournalSnapshot"], 70),
    ("database", "database.data_migration", ["MigrationEngine", "MigrationReport", "TableMigrationResult"], 65),
    ("graph", "graph.multi_agent.tests.test_multi_agent", [], 65),
    ("recon_dashboard", "recon_dashboard.routes_intelligence_experience", [], 65),
    ("recon_dashboard", "recon_dashboard.routes_persistent_agent", [], 65),
    ("recon_dashboard", "recon_dashboard.target_scoring", ["ExploitPath", "TargetScore", "CampaignBudget"], 65),
    ("exploitation", "exploitation.engine", ["ExploitationEngine"], 62),
    ("swarm", "swarm.multi_gpu.messenger", ["TransportType", "RouteStatus", "DeliveryStatus"], 62),
    ("swarm", "swarm.multi_gpu.model_sharder", ["ShardStrategy", "ShardStatus", "LayerAssignment"], 62),
    ("swarm", "swarm.multi_gpu.scheduler", ["PlacementStrategy", "MigrationReason", "AgentPlacement"], 62),
    ("swarm", "swarm.multi_gpu.topology", ["InterconnectType", "GPUHealth", "GPUDevice"], 62),
    ("agents", "agents.conflict_arbitration", ["ConflictType", "ScanMode", "Winner"], 60),
    ("agents", "agents.fork_spawn", ["AgentOrigin", "SpawnOutcome", "CoordinatorPhase"], 60),
    ("agents", "agents.role_registry", ["RoleID", "TemperatureArchetype", "RoleMetadata"], 60),
    ("agents", "agents.speculative_executor", ["SpeculationStatus", "SpeculationOutcome", "OverlayContext"], 60),
    ("graph", "graph.production", ["HealthStatus", "GraphHealthCheck", "GraphCircuitBreaker"], 60),
    ("swarm", "swarm.multi_gpu.governor", ["MultiGPUState", "MultiGPUConfig", "MultiGPUSummary"], 57),
    ("recon_dashboard", "recon_dashboard.routes_agent", [], 55),
    ("recon_dashboard", "recon_dashboard.routes_multi_agent", [], 55),
    ("exploitation", "exploitation.chains", ["AttackChainExecutor"], 52),
    ("exploitation", "exploitation.impact", ["ImpactDemonstrator"], 52),
    ("inference", "inference.kv_cache", ["KVQuantType", "KVCacheConfig", "ModelArchInfo"], 50),
    ("recon_dashboard", "recon_dashboard.phase_handlers.advanced", [], 50),
    ("recon_dashboard", "recon_dashboard.phase_handlers.discovery", [], 50),
    ("recon_dashboard", "recon_dashboard.phase_handlers.security_testing", [], 50),
    ("recon_dashboard", "recon_dashboard.routes_assessment", [], 50),
    ("recon_dashboard", "recon_dashboard.routes_cross_target", [], 50),
    ("recon_dashboard", "recon_dashboard.routes_exploit_graph", [], 50),
    ("recon_dashboard", "recon_dashboard.routes_target_scoring", [], 50),
    ("recon_dashboard", "recon_dashboard.state_serializers", [], 50),
    ("recon_dashboard", "recon_dashboard.routes_reasoning", [], 48),
    ("core_infra", "core_infra.chaos_testing_v2", ["FaultType", "FaultOutcome", "ChaosConfig"], 47),
    ("osint_providers", "osint_providers.netintel_client", ["NetIntelClient"], 47),
    ("osint_providers", "osint_providers.schemas", ["CrtshEntry", "InternetDBResponse", "BGPViewIP"], 47),
    ("__root__", "adversarial_validation_agent", ["ChallengeVerdict", "ProbeType", "RationalizationPattern"], 45),
    ("intel", "intel.github_client_base", ["BaseGitHubClient", "_SearchRateLimiter"], 45),
    ("__root__", "knowledge_resilience", ["FederationManifest", "KnowledgeFederation", "FlywheelGuard"], 45),
    ("__root__", "strategy_horizon_optimizer", ["ArcState", "DependencyType", "ResourcePoolPolicy"], 45),
    ("__root__", "validation_fleet", ["ConsensusVerdict", "ValidatorType", "IndividualVerdict"], 45),
    ("tool_wrappers", "tool_wrappers._evidence", [], 43),
    ("cli", "cli.daemon", ["StreamingWriter"], 40),
    ("discovery_pkg", "discovery_pkg.subdomain_external", ["ExternalToolResult"], 40),
    ("recon_dashboard", "recon_dashboard.infra_monitor", [], 40),
    ("recon_dashboard", "recon_dashboard.routes_operator", [], 40),
    ("recon_dashboard", "recon_dashboard.session_store", [], 40),
]

results = []
for subsys, dotted, api, score in TASKS:
    rel = dotted.replace(".", "/") + ".py"
    p = ROOT / rel
    exists = p.exists()
    loc = 0
    if exists:
        try:
            loc = sum(1 for _ in p.open(encoding="utf-8"))
        except Exception:
            loc = -1
    if subsys == "__root__":
        init = ROOT / "__init__.py"
    else:
        init = ROOT / subsys / "__init__.py"
    init_has_ref = False
    if init.exists():
        try:
            txt = init.read_text(encoding="utf-8", errors="ignore")
            leaf = dotted.rsplit(".", 1)[-1]
            init_has_ref = leaf in txt
        except Exception:
            pass
    results.append(
        {
            "subsystem": subsys,
            "module": dotted,
            "score": score,
            "exists": exists,
            "loc": loc,
            "init_exists": init.exists(),
            "init_has_ref": init_has_ref,
            "api": api,
        }
    )

exists_count = sum(1 for r in results if r["exists"])
wired_count = sum(1 for r in results if r["init_has_ref"])
print(f"Total tasks: {len(results)}")
print(f"Module file exists on disk: {exists_count}/{len(results)}")
print(f"Already referenced in subsystem __init__: {wired_count}/{len(results)}")
print(f"Missing on disk (need reimpl): {len(results) - exists_count}")
print()
print("=== MISSING ON DISK ===")
for r in results:
    if not r["exists"]:
        print(f"  [score {r['score']:>2}] {r['module']:60s} init_exists={r['init_exists']}")
print()
print("=== EXISTS BUT NOT WIRED ===")
for r in results:
    if r["exists"] and not r["init_has_ref"]:
        print(f"  [score {r['score']:>2}] {r['module']:60s} loc={r['loc']:5d}  init_exists={r['init_exists']}")
print()
print("=== ALREADY WIRED ===")
for r in results:
    if r["exists"] and r["init_has_ref"]:
        print(f"  [score {r['score']:>2}] {r['module']:60s} loc={r['loc']:5d}")

out = Path("c:/Users/ya754/CaseCrack v1.0/_phase1_audit.json")
out.write_text(json.dumps(results, indent=2), encoding="utf-8")
print(f"\nFull audit -> {out}")
