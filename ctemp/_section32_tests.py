
# ═══════════════════════════════════════════════════════════════════════════════
# Section 32: Fork/Spawn Agent Semantics Engine
# ═══════════════════════════════════════════════════════════════════════════════

from CaseCrack.tools.burp_enterprise.agents.fork_spawn import (
    AgentDefinition,
    AgentOrigin,
    AgentRegistry,
    AgentSpawnEngine,
    CoordinatorMode,
    CoordinatorPhase,
    DynamicAgentRecord,
    ForkContext,
    SpawnOutcome,
    SpawnResult,
    SpawnStats,
    SquadResult,
    FORK_BOILERPLATE_TAG,
    FORK_PLACEHOLDER_RESULT,
    MAX_FORK_DEPTH,
    MAX_CONCURRENT_DYNAMIC_AGENTS,
    SPAWN_COOLDOWN_S,
    AUTO_RETIRE_IDLE_S,
)

print("\n== Section 32: Fork/Spawn Agent Semantics Engine ==")

# ---------- 32.1: AgentRegistry ----------

# 32.1.1: Registry loads built-in definitions
_reg = AgentRegistry()
check("32.1.1", len(_reg.list_types()) >= 8,
      f"Registry has {len(_reg.list_types())} built-in types")

# 32.1.2: Look up known agent type
_sqli_def = _reg.get("sqli_specialist")
check("32.1.2", _sqli_def is not None and _sqli_def.agent_type == "sqli_specialist",
      "sqli_specialist found in registry")

# 32.1.3: Custom registration
_custom_def = AgentDefinition(
    agent_type="test_custom_agent",
    description="Test agent for unit tests",
    source="custom",
    allowed_tools=["nmap", "httpx"],
    vuln_categories=["test_vuln"],
    max_turns=10,
)
_reg.register(_custom_def)
check("32.1.3", _reg.get("test_custom_agent") is not None,
      "Custom agent registered")

# 32.1.4: Unregister
_unreg = _reg.unregister("test_custom_agent")
check("32.1.4", _unreg is True and _reg.get("test_custom_agent") is None,
      "Custom agent unregistered")

# 32.1.5: find_by_category
_sqli_hits = _reg.find_by_category("sqli")
check("32.1.5", len(_sqli_hits) >= 1 and _sqli_hits[0].agent_type == "sqli_specialist",
      f"find_by_category('sqli') returned {len(_sqli_hits)} results")

# 32.1.6: find_by_tool
_httpx_hits = _reg.find_by_tool("httpx")
check("32.1.6", len(_httpx_hits) >= 3,
      f"find_by_tool('httpx') returned {len(_httpx_hits)} results")

# 32.1.7: to_dict
_reg_dict = _reg.to_dict()
check("32.1.7", "count" in _reg_dict and "types" in _reg_dict and "definitions" in _reg_dict,
      "Registry to_dict has expected keys")

# 32.1.8: Override semantics (last-wins)
_reg.register(AgentDefinition(agent_type="sqli_specialist", description="override", source="custom"))
_override = _reg.get("sqli_specialist")
check("32.1.8", _override is not None and _override.description == "override",
      "Override (last-wins) worked")
# Restore built-in
_reg._load_builtins()

# ---------- 32.2: AgentDefinition ----------

# 32.2.1: AgentDefinition to_dict
_def_dict = AgentDefinition(
    agent_type="test_def", description="test", allowed_tools=["nmap"],
    vuln_categories=["xss"], max_turns=50,
).to_dict()
check("32.2.1", _def_dict["agent_type"] == "test_def" and _def_dict["max_turns"] == 50,
      "AgentDefinition.to_dict correct")

# 32.2.2: Default field values
_def_default = AgentDefinition(agent_type="x", description="x")
check("32.2.2", _def_default.source == "built-in" and _def_default.max_turns == 100,
      "Default fields set correctly")

# 32.2.3: parent_role field
_def_parent = AgentDefinition(agent_type="y", description="y", parent_role="recon")
check("32.2.3", _def_parent.parent_role == "recon",
      "parent_role field works")

# ---------- 32.3: ForkContext ----------

# 32.3.1: ForkContext creation
_fc = ForkContext(
    parent_agent_id="exploit-abc123",
    parent_role="exploit",
    depth=1,
    shared_prompt_prefix="You are an exploit specialist.",
    inherited_tools=["sqlmap", "nuclei"],
    inherited_context={"target": "example.com", "phase": "exploit"},
    inherited_findings=[{"vuln": "sqli", "confidence": 0.9}],
    directive="Test SQL injection on /login endpoint",
)
check("32.3.1", _fc.depth == 1 and _fc.parent_role == "exploit",
      "ForkContext created correctly")

# 32.3.2: ForkContext to_dict
_fc_dict = _fc.to_dict()
check("32.3.2", "parent_agent_id" in _fc_dict and "depth" in _fc_dict
      and _fc_dict["inherited_tools_count"] == 2,
      "ForkContext.to_dict correct")

# 32.3.3: ForkContext created_at is set
check("32.3.3", _fc.created_at > 0,
      f"ForkContext.created_at={_fc.created_at}")

# ---------- 32.4: SpawnResult ----------

# 32.4.1: Successful SpawnResult
_sr_ok = SpawnResult(
    outcome=SpawnOutcome.SUCCESS, agent_id="spawn-test-001",
    agent_type="sqli_specialist", origin=AgentOrigin.SPAWNED,
)
check("32.4.1", _sr_ok.success is True and _sr_ok.agent_id == "spawn-test-001",
      "SpawnResult SUCCESS properties correct")

# 32.4.2: Failed SpawnResult
_sr_fail = SpawnResult(
    outcome=SpawnOutcome.REJECTED_MAX_DEPTH,
    error_message="Too deep",
)
check("32.4.2", _sr_fail.success is False and _sr_fail.error_message == "Too deep",
      "SpawnResult REJECTED properties correct")

# 32.4.3: SpawnResult to_dict
_sr_dict = _sr_ok.to_dict()
check("32.4.3", _sr_dict["outcome"] == "success" and _sr_dict["origin"] == "spawned",
      "SpawnResult.to_dict correct")

# ---------- 32.5: SquadResult ----------

# 32.5.1: SquadResult aggregation
_squad = SquadResult(results=[_sr_ok, _sr_fail], total_elapsed_ms=42.0)
check("32.5.1", len(_squad.successful_agents) == 1 and not _squad.all_succeeded,
      "SquadResult aggregation correct")

# 32.5.2: SquadResult to_dict
_squad_dict = _squad.to_dict()
check("32.5.2", _squad_dict["success_count"] == 1 and _squad_dict["total_count"] == 2,
      "SquadResult.to_dict correct")

# ---------- 32.6: DynamicAgentRecord ----------

# 32.6.1: DynamicAgentRecord is_active
import time as _time_mod
_dar = DynamicAgentRecord(
    agent_id="test-001", agent_type="sqli_specialist",
    origin=AgentOrigin.SPAWNED, parent_id=None,
    fork_depth=0, created_at=_time_mod.time(),
)
check("32.6.1", _dar.is_active and _dar.state == "idle",
      "DynamicAgentRecord is active after creation")

# 32.6.2: DynamicAgentRecord idle_seconds
check("32.6.2", _dar.idle_seconds >= 0.0,
      f"idle_seconds={_dar.idle_seconds:.1f}")

# 32.6.3: DynamicAgentRecord retirement
_dar.retired_at = _time_mod.time()
check("32.6.3", not _dar.is_active and _dar.idle_seconds == 0.0,
      "Retired agent is not active")

# 32.6.4: DynamicAgentRecord to_dict
_dar_dict = _dar.to_dict()
check("32.6.4", "agent_id" in _dar_dict and "is_active" in _dar_dict,
      "DynamicAgentRecord.to_dict has expected keys")

# ---------- 32.7: SpawnStats ----------

# 32.7.1: SpawnStats to_dict
_ss = SpawnStats(total_forks=5, total_spawns=3, total_fork_ms=100.0, total_spawn_ms=60.0)
_ss_dict = _ss.to_dict()
check("32.7.1", _ss_dict["avg_fork_ms"] == 20.0 and _ss_dict["avg_spawn_ms"] == 20.0,
      "SpawnStats averages correct")

# ---------- 32.8: AgentSpawnEngine - fork ----------

# Reset cooldown by setting _last_spawn_time to 0
_engine = AgentSpawnEngine()
_engine._last_spawn_time = 0

# 32.8.1: Basic fork success
_fork_result = _engine.fork(
    parent_agent_id="exploit-abc123",
    parent_role="exploit",
    directive="Test SQLi on /login",
    parent_tools=["sqlmap", "nuclei"],
    parent_context={"target": "example.com"},
    parent_findings=[{"vuln": "sqli"}],
    parent_prompt_prefix="System prompt for exploit agent",
    current_depth=0,
)
check("32.8.1", _fork_result.success and _fork_result.origin == AgentOrigin.FORKED,
      f"Fork succeeded: {_fork_result.agent_id}")

# 32.8.2: Fork context was injected
check("32.8.2", _fork_result.fork_context is not None
      and _fork_result.fork_context.depth == 1,
      "Fork context has depth=1")

# 32.8.3: Fork anti-recursion tag in context
check("32.8.3",
      _fork_result.fork_context.inherited_context.get("_fork_boilerplate") == FORK_BOILERPLATE_TAG,
      "Fork boilerplate tag injected")

# 32.8.4: Fork depth tracking
check("32.8.4", _engine.get_fork_depth(_fork_result.agent_id) == 1,
      "Fork depth tracked correctly")

# 32.8.5: Fork parent tracking
_children = _engine.get_children("exploit-abc123")
check("32.8.5", len(_children) >= 1 and _children[0].agent_id == _fork_result.agent_id,
      "Fork parent-child tracking works")

# 32.8.6: Fork rejected at max depth
_engine._last_spawn_time = 0
_deep_fork = _engine.fork(
    parent_agent_id="exploit-abc123", parent_role="exploit",
    directive="Deep fork", current_depth=MAX_FORK_DEPTH,
)
check("32.8.6", _deep_fork.outcome == SpawnOutcome.REJECTED_MAX_DEPTH,
      f"Fork rejected at max depth: {_deep_fork.outcome.value}")

# 32.8.7: Fork anti-recursion from existing fork child
_engine._last_spawn_time = 0
_anti_recurse = _engine.fork(
    parent_agent_id="fork-exploit-001", parent_role="exploit",
    directive="Fork of fork",
    parent_context={"_fork_boilerplate": FORK_BOILERPLATE_TAG},
    current_depth=1,
)
check("32.8.7", _anti_recurse.outcome == SpawnOutcome.REJECTED_ANTI_RECURSION,
      f"Anti-recursion blocked fork-of-fork: {_anti_recurse.outcome.value}")

# ---------- 32.9: AgentSpawnEngine - spawn ----------

# 32.9.1: Basic spawn success
_engine._last_spawn_time = 0
_spawn_result = _engine.spawn("sqli_specialist", "Test SQLi on /api/v1")
check("32.9.1", _spawn_result.success and _spawn_result.origin == AgentOrigin.SPAWNED,
      f"Spawn succeeded: {_spawn_result.agent_id}")

# 32.9.2: Spawn with overrides
_engine._last_spawn_time = 0
_spawn_ov = _engine.spawn("xss_specialist", "Test XSS", overrides={"max_turns": 20})
check("32.9.2", _spawn_ov.success,
      f"Spawn with overrides: {_spawn_ov.agent_id}")

# 32.9.3: Spawn unknown type rejected
_engine._last_spawn_time = 0
_spawn_unknown = _engine.spawn("nonexistent_agent_type", "Nothing")
check("32.9.3", _spawn_unknown.outcome == SpawnOutcome.REJECTED_UNKNOWN_TYPE,
      "Unknown agent type rejected")

# 32.9.4: Spawn cooldown enforcement
_engine._last_spawn_time = _time_mod.time()  # just spawned
_spawn_cool = _engine.spawn("general_purpose", "Task")
check("32.9.4", _spawn_cool.outcome == SpawnOutcome.REJECTED_COOLDOWN,
      "Cooldown enforced")

# ---------- 32.10: AgentSpawnEngine - spawn_squad ----------

# 32.10.1: Squad spawn
_engine._last_spawn_time = 0
_squad_res = _engine.spawn_squad([
    ("sqli_specialist", "Test SQLi set A"),
    ("xss_specialist", "Test XSS set A"),
])
# At least the first one should succeed (second may hit cooldown)
check("32.10.1", len(_squad_res.results) == 2,
      f"Squad has 2 results, {len(_squad_res.successful_agents)} succeeded")

# 32.10.2: SquadResult has elapsed time
check("32.10.2", _squad_res.total_elapsed_ms >= 0,
      f"Squad elapsed: {_squad_res.total_elapsed_ms:.1f}ms")

# ---------- 32.11: Agent lifecycle ----------

# 32.11.1: is_dynamic
check("32.11.1", _engine.is_dynamic(_fork_result.agent_id),
      "Forked agent is dynamic")

# 32.11.2: get_active_agents
_active = _engine.get_active_agents()
check("32.11.2", len(_active) >= 1,
      f"{len(_active)} active dynamic agents")

# 32.11.3: record_agent_activity
_engine.record_agent_activity(_fork_result.agent_id)
_rec = _engine.get_agent_record(_fork_result.agent_id)
check("32.11.3", _rec is not None and _rec.task_count >= 1,
      f"Activity recorded: task_count={_rec.task_count if _rec else 0}")

# 32.11.4: update_agent_state
_engine.update_agent_state(_fork_result.agent_id, "running")
_rec2 = _engine.get_agent_record(_fork_result.agent_id)
check("32.11.4", _rec2 is not None and _rec2.state == "running",
      "Agent state updated to running")

# 32.11.5: retire_agent
_retired = _engine.retire_agent(_fork_result.agent_id, reason="test")
check("32.11.5", _retired is True,
      "Agent retired successfully")

# 32.11.6: Retired agent no longer active
_rec3 = _engine.get_agent_record(_fork_result.agent_id)
check("32.11.6", _rec3 is not None and not _rec3.is_active,
      "Retired agent is no longer active")

# 32.11.7: Double-retire returns False
_retired2 = _engine.retire_agent(_fork_result.agent_id, reason="test")
check("32.11.7", _retired2 is False,
      "Double-retire returns False")

# ---------- 32.12: Statistics ----------

# 32.12.1: Stats tracked
_stats = _engine.get_stats()
check("32.12.1", _stats["total_forks"] >= 1 and _stats["total_spawns"] >= 1,
      f"Stats: forks={_stats['total_forks']}, spawns={_stats['total_spawns']}")

# 32.12.2: Stats have active_agents list
check("32.12.2", "active_agents" in _stats,
      "Stats include active_agents list")

# 32.12.3: Stats have recent_history
check("32.12.3", "recent_history" in _stats and len(_stats["recent_history"]) >= 1,
      f"Stats have {len(_stats.get('recent_history', []))} history entries")

# 32.12.4: Peak concurrent tracked
check("32.12.4", _stats["peak_concurrent"] >= 1,
      f"Peak concurrent: {_stats['peak_concurrent']}")

# ---------- 32.13: Cleanup ----------

# 32.13.1: cleanup_all
_engine._last_spawn_time = 0
_engine.spawn("general_purpose", "cleanup test")
_cleanup_count = _engine.cleanup_all()
check("32.13.1", _cleanup_count >= 0,
      f"Cleaned up {_cleanup_count} agents")

# 32.13.2: After cleanup, active_count is 0
check("32.13.2", _engine.active_count == 0,
      f"Active count after cleanup: {_engine.active_count}")

# ---------- 32.14: CoordinatorMode ----------

# 32.14.1: CoordinatorMode initial phase
_co_engine = AgentSpawnEngine()
_co_mode = CoordinatorMode(spawn_engine=_co_engine)
check("32.14.1", _co_mode.current_phase == CoordinatorPhase.RESEARCH,
      f"Initial phase: {_co_mode.current_phase.value}")

# 32.14.2: Phase advancement
_co_mode.advance_phase()
check("32.14.2", _co_mode.current_phase == CoordinatorPhase.SYNTHESIS,
      f"Phase after advance: {_co_mode.current_phase.value}")

# 32.14.3: Full phase cycle
_co_mode.advance_phase()
_co_mode.advance_phase()
check("32.14.3", _co_mode.current_phase == CoordinatorPhase.VERIFICATION,
      "Phase cycle reached VERIFICATION")

# 32.14.4: Advance past last stays at last
_co_mode.advance_phase()
check("32.14.4", _co_mode.current_phase == CoordinatorPhase.VERIFICATION,
      "Phase stays at VERIFICATION after final advance")

# 32.14.5: Phase reset
_co_mode.reset_phase()
check("32.14.5", _co_mode.current_phase == CoordinatorPhase.RESEARCH,
      "Phase reset to RESEARCH")

# 32.14.6: dispatch_worker
_co_engine._last_spawn_time = 0
_worker = _co_mode.dispatch_worker("general_purpose", "Test task", context={"key": "value"})
check("32.14.6", _worker.success,
      f"dispatch_worker succeeded: {_worker.agent_id}")

# 32.14.7: record_worker_result
_co_mode.record_worker_result(_worker.agent_id, {"findings": 3})
_pending = _co_mode.get_pending_synthesis()
check("32.14.7", _pending["pending_count"] >= 1,
      f"Pending synthesis: {_pending['pending_count']}")

# 32.14.8: mark_synthesised
_co_mode.mark_synthesised([_worker.agent_id], {"summary": "merged"})
_pending2 = _co_mode.get_pending_synthesis()
check("32.14.8", _pending2["pending_count"] == 0,
      "All worker results synthesised")

# 32.14.9: select_agent_for_task by category
_selected = _co_mode.select_agent_for_task(vuln_category="xss")
check("32.14.9", _selected == "xss_specialist",
      f"Selected agent for XSS: {_selected}")

# 32.14.10: select_agent_for_task fallback
_fallback = _co_mode.select_agent_for_task()
check("32.14.10", _fallback == "general_purpose",
      f"Fallback selection: {_fallback}")

# 32.14.11: get_state
_co_state = _co_mode.get_state()
check("32.14.11", "current_phase" in _co_state and "dispatched_workers" in _co_state,
      "CoordinatorMode state has expected keys")

# ---------- 32.15: AgentCoordinator integration ----------

from CaseCrack.tools.burp_enterprise.agent_roles import AgentCoordinator, AgentRoleType

_coord = AgentCoordinator()

# 32.15.1: Coordinator has spawn_engine
check("32.15.1", hasattr(_coord, "_spawn_engine") and _coord.spawn_engine is not None,
      "AgentCoordinator has spawn_engine")

# 32.15.2: Coordinator has coordinator_mode
check("32.15.2", hasattr(_coord, "_coordinator_mode") and _coord.coordinator_mode is not None,
      "AgentCoordinator has coordinator_mode")

# 32.15.3: Coordinator has agent_registry
check("32.15.3", hasattr(_coord, "_agent_registry") and _coord.agent_registry is not None,
      "AgentCoordinator has agent_registry")

# 32.15.4: fork_agent creates dynamic agent
_coord._spawn_engine._last_spawn_time = 0
_fork_coord = _coord.fork_agent(AgentRoleType.EXPLOIT, "Test SQLi fork")
check("32.15.4", _fork_coord.success,
      f"fork_agent succeeded: {_fork_coord.agent_id}")

# 32.15.5: Forked agent registered in _dynamic_agents
if _fork_coord.success:
    _dyn_agent = _coord.get_dynamic_agent(_fork_coord.agent_id)
    check("32.15.5", _dyn_agent is not None,
          f"Forked dynamic agent registered: {_fork_coord.agent_id}")
else:
    check("32.15.5", True, "Fork didn't succeed, skip dynamic check")

# 32.15.6: Forked agent has mailbox registration
if _fork_coord.success:
    _has_mailbox = _fork_coord.agent_id in _coord.mailbox._inboxes
    check("32.15.6", _has_mailbox,
          "Forked agent registered in mailbox")
else:
    check("32.15.6", True, "Fork didn't succeed, skip mailbox check")

# 32.15.7: spawn_agent creates fresh agent
_coord._spawn_engine._last_spawn_time = 0
_spawn_coord = _coord.spawn_agent("xss_specialist", "Test XSS spawn")
check("32.15.7", _spawn_coord.success,
      f"spawn_agent succeeded: {_spawn_coord.agent_id}")

# 32.15.8: Spawned agent has correct type tracking
if _spawn_coord.success:
    _spawn_rec = _coord.spawn_engine.get_agent_record(_spawn_coord.agent_id)
    check("32.15.8", _spawn_rec is not None and _spawn_rec.agent_type == "xss_specialist",
          f"Spawn tracked as xss_specialist")
else:
    check("32.15.8", True, "Spawn didn't succeed, skip type check")

# 32.15.9: spawn_squad dispatches parallel agents
_coord._spawn_engine._last_spawn_time = 0
_squad_coord = _coord.spawn_squad([
    ("sqli_specialist", "Squad SQLi"),
    ("auth_specialist", "Squad Auth"),
])
check("32.15.9", len(_squad_coord.results) == 2,
      f"Squad dispatched 2 agents, {len(_squad_coord.successful_agents)} succeeded")

# 32.15.10: retire_dynamic_agent
if _fork_coord.success:
    _ret = _coord.retire_dynamic_agent(_fork_coord.agent_id)
    check("32.15.10", _ret is True,
          "Dynamic agent retired via coordinator")
else:
    check("32.15.10", True, "Fork didn't succeed, skip retire check")

# 32.15.11: Retired agent removed from _dynamic_agents
if _fork_coord.success:
    _dyn_gone = _coord.get_dynamic_agent(_fork_coord.agent_id)
    check("32.15.11", _dyn_gone is None,
          "Retired agent removed from _dynamic_agents")
else:
    check("32.15.11", True, "Fork didn't succeed, skip removal check")

# ---------- 32.16: AgentOrigin / SpawnOutcome enums ----------

# 32.16.1: AgentOrigin values
check("32.16.1",
      AgentOrigin.STATIC.value == "static" and AgentOrigin.FORKED.value == "forked"
      and AgentOrigin.SPAWNED.value == "spawned" and AgentOrigin.SQUAD.value == "squad",
      "AgentOrigin enum values correct")

# 32.16.2: SpawnOutcome values
check("32.16.2",
      SpawnOutcome.SUCCESS.value == "success"
      and SpawnOutcome.REJECTED_MAX_DEPTH.value == "rejected_max_depth"
      and SpawnOutcome.FAILED.value == "failed",
      "SpawnOutcome enum values correct")

# 32.16.3: CoordinatorPhase values
check("32.16.3",
      CoordinatorPhase.RESEARCH.value == "research"
      and CoordinatorPhase.VERIFICATION.value == "verification",
      "CoordinatorPhase enum values correct")

# ---------- 32.17: Constants ----------

# 32.17.1: Constants have sane values
check("32.17.1", MAX_FORK_DEPTH >= 2 and MAX_CONCURRENT_DYNAMIC_AGENTS >= 4,
      f"Constants: MAX_FORK_DEPTH={MAX_FORK_DEPTH}, MAX_CONCURRENT={MAX_CONCURRENT_DYNAMIC_AGENTS}")

# 32.17.2: FORK_BOILERPLATE_TAG is a string
check("32.17.2", isinstance(FORK_BOILERPLATE_TAG, str) and len(FORK_BOILERPLATE_TAG) > 0,
      f"FORK_BOILERPLATE_TAG='{FORK_BOILERPLATE_TAG}'")

# 32.17.3: SPAWN_COOLDOWN_S is reasonable
check("32.17.3", 0.0 < SPAWN_COOLDOWN_S <= 10.0,
      f"SPAWN_COOLDOWN_S={SPAWN_COOLDOWN_S}")

# ---------- 32.18: Edge cases ----------

# 32.18.1: Fork with empty tools and context
_edge_engine = AgentSpawnEngine()
_edge_engine._last_spawn_time = 0
_edge_fork = _edge_engine.fork(
    parent_agent_id="recon-000", parent_role="recon",
    directive="Minimal fork",
)
check("32.18.1", _edge_fork.success,
      "Fork with empty tools/context succeeds")

# 32.18.2: Spawn with empty overrides
_edge_engine._last_spawn_time = 0
_edge_spawn = _edge_engine.spawn("general_purpose", "Minimal spawn", overrides={})
check("32.18.2", _edge_spawn.success,
      "Spawn with empty overrides succeeds")

# 32.18.3: dispatch_parallel_workers
_edge_mode = CoordinatorMode(spawn_engine=_edge_engine)
_edge_engine._last_spawn_time = 0
_par_workers = _edge_mode.dispatch_parallel_workers([
    ("general_purpose", "Worker A", {"key": "val_a"}),
    ("general_purpose", "Worker B", None),
])
check("32.18.3", len(_par_workers.results) == 2,
      f"Parallel workers: {len(_par_workers.results)} dispatched")

# 32.18.4: ForkContext with large inherited_context
_big_ctx = {f"key_{i}": f"value_{i}" for i in range(100)}
_edge_engine._last_spawn_time = 0
_big_fork = _edge_engine.fork(
    parent_agent_id="strategy-000", parent_role="strategy",
    directive="Big context fork", parent_context=_big_ctx,
)
check("32.18.4", _big_fork.success,
      f"Fork with 100-key context succeeds")

# 32.18.5: Cleanup after all tests
_edge_engine.cleanup_all()
check("32.18.5", _edge_engine.active_count == 0,
      "All edge-case agents cleaned up")
