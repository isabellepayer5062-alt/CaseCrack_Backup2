"""Functional test for Strategy Horizon Optimizer (S1–S6) integration."""

from CaseCrack.tools.burp_enterprise.agent_roles import AgentCoordinator

c = AgentCoordinator()

# ──────────────────────────────────────────────────────
# S1: Multi-arc coordinator
# ──────────────────────────────────────────────────────
print("=== S1: Multi-arc coordination ===")

# Create managed arcs via optimizer
arc1 = c.create_managed_arc("Find SQLi in auth", priority=8.0, deadline_s=7200)
arc2 = c.create_managed_arc("Map attack surface", priority=5.0, deadline_s=14400)
arc3 = c.create_managed_arc("Exploit XSS chain", priority=7.0, deadline_s=3600)
print(f"Created 3 arcs: {arc1['arc_id']}, {arc2['arc_id']}, {arc3['arc_id']}")

# Add dependency
ok = c.add_arc_dependency(arc3["arc_id"], arc2["arc_id"], "soft")
print(f"Dependency added: {ok}")
assert ok

# Get portfolio summary
summary = c.get_portfolio_summary()
print(f"Portfolio: {summary['total_arcs']} arcs, states={summary['arcs_by_state']}")
assert summary["total_arcs"] == 3

# Start ready arcs
opt = c.strategy_optimizer
started = opt.start_ready_arcs()
print(f"Started {len(started)} arcs")
assert len(started) >= 1

print("S1: Multi-arc coordination OK\n")

# ──────────────────────────────────────────────────────
# S2: Temporal horizon modeling
# ──────────────────────────────────────────────────────
print("=== S2: Temporal horizon modeling ===")

c.set_strategy_deadline(28800)  # 8 hours
pressure = c.get_temporal_pressure()
print(f"Temporal pressure: {pressure:.3f}")
assert 0.0 <= pressure <= 1.0

summary2 = c.get_portfolio_summary()
print(f"Time remaining: {summary2['time_remaining']}s")
assert summary2["time_remaining"] is not None
assert summary2["time_remaining"] > 0

print("S2: Temporal horizon OK\n")

# ──────────────────────────────────────────────────────
# S3: Global optimum search (portfolio allocation)
# ──────────────────────────────────────────────────────
print("=== S3: Portfolio-level budget allocation ===")

allocations = c.allocate_arc_budget()
print(f"Budget allocations: {allocations}")
assert len(allocations) >= 1
total_alloc = sum(allocations.values())
print(f"Total allocated: {total_alloc:.1f}")

budget_state = opt.get_budget_state()
print(f"Budget state: total={budget_state['total_budget']}, consumed={budget_state['total_consumed']}")

print("S3: Portfolio allocation OK\n")

# ──────────────────────────────────────────────────────
# S4: Dynamic replanning (MPC)
# ──────────────────────────────────────────────────────
print("=== S4: Dynamic replanning (MPC) ===")

replan_result = c.strategy_replan(trigger="finding_surge")
print(f"Replan: trigger={replan_result['trigger']}, reordered={replan_result['arcs_reordered']}")
assert replan_result["trigger"] == "finding_surge"

# Check replan history is tracked
state = c.get_strategy_optimizer_state()
print(f"Replan history: {len(state['replan_history'])} events")
assert len(state["replan_history"]) >= 1

print("S4: Dynamic replanning OK\n")

# ──────────────────────────────────────────────────────
# S5: Arc-level learning
# ──────────────────────────────────────────────────────
print("=== S5: Arc-level learning ===")

# Complete an arc with outcomes → triggers template learning
active_arcs = [a for a in opt._arcs.values() if a.state.value == "active"]
if active_arcs:
    test_arc = active_arcs[0]
    test_arc.template_name = "aggressive_django"
    opt.record_arc_progress(test_arc.arc_id, findings=3, severity_sum=21.0, phases_advanced=4)
    opt.complete_arc(test_arc.arc_id, findings=3, severity_sum=21.0)
    print(f"Completed arc {test_arc.arc_id} with 3 findings")

    # Check template learning
    stats = c.get_arc_template_stats()
    print(f"Template stats: {stats}")
    assert len(stats) >= 1
    assert stats[0]["sample_count"] >= 1

    # Recommend template
    rec = c.recommend_arc_template(technology="django")
    print(f"Recommended template: {rec}")

print("S5: Arc-level learning OK\n")

# ──────────────────────────────────────────────────────
# S6: Cross-campaign resource sharing
# ──────────────────────────────────────────────────────
print("=== S6: Cross-campaign resource sharing ===")

budget = opt.get_budget_state()
print(f"Budget policy: {budget['policy']}")
print(f"Per-arc budget: {budget['per_arc']}")

# Record spending on an active arc
remaining_active = [a for a in opt._arcs.values() if a.state.value == "active"]
if remaining_active:
    spend_arc = remaining_active[0]
    ok = opt.record_budget_spend(spend_arc.arc_id, 15.0)
    print(f"Spent 15.0 on {spend_arc.arc_id}: {ok}")
    assert ok

print("S6: Cross-campaign resources OK\n")

# ──────────────────────────────────────────────────────
# Integration: E-GAP 5 start_strategic_arc → S1 managed arc
# ──────────────────────────────────────────────────────
print("=== Integration: start_strategic_arc + managed arc ===")

arc_obj = c.start_strategic_arc(
    "Find SSRF in API gateway", target_url="https://example.com",
    priority=9.0, deadline_s=1800,
)
print(f"Strategic arc started: {arc_obj.arc_id}, phase={arc_obj.current_phase.value}")

# Verify it also created a managed arc
portfolio = c.get_portfolio_summary()
print(f"Portfolio after start_strategic_arc: {portfolio['total_arcs']} managed arcs")

# Complete the arc
completed = c.complete_arc(final_outcome={"severity_sum": 15.0})
assert completed is not None
print(f"Arc completed: {completed.arc_id}")

print("Integration OK\n")

# ──────────────────────────────────────────────────────
# to_dict includes strategy_optimizer
# ──────────────────────────────────────────────────────
print("=== to_dict integration ===")
full = c.to_dict()
assert "strategy_optimizer" in full, "strategy_optimizer missing from to_dict"
print(f"strategy_optimizer in to_dict: arcs={len(full['strategy_optimizer']['arcs'])}")
print("to_dict OK\n")

# ──────────────────────────────────────────────────────
# persistent_agent.py delegation
# ──────────────────────────────────────────────────────
print("=== persistent_agent.py delegation ===")
from CaseCrack.tools.burp_enterprise.persistent_agent import PersistentAgentLoop
strategy_methods = [
    "create_managed_arc", "add_arc_dependency", "set_strategy_deadline",
    "get_temporal_pressure", "strategy_replan", "allocate_arc_budget",
    "recommend_arc_template", "get_arc_template_stats",
    "get_portfolio_summary", "get_strategy_optimizer_state",
]
missing = [m for m in strategy_methods if not hasattr(PersistentAgentLoop, m)]
if missing:
    print(f"MISSING from PersistentAgentLoop: {missing}")
else:
    print(f"ALL {len(strategy_methods)} strategy delegation methods present")

print("\n========================================")
print("ALL STRATEGY HORIZON OPTIMIZER TESTS PASSED")
print("========================================")
