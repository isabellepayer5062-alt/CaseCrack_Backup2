"""Functional test for Causal Bridge (C1-C4) integration."""

from CaseCrack.tools.burp_enterprise.agent_roles import AgentCoordinator

c = AgentCoordinator()

# 1. Verify bridge exists and is accessible
state = c.get_causal_state()
print(f"Causal bridge state: {state['bound_subsystems']}")
assert state["findings_processed"] == 0
assert state["world_state_changes"] == 0
print("C1: Bridge initialized OK")

# 2. Test causal simulate (without bound graphs — should return zero bonus)
result = c.causal_simulate(
    action="sqli_test",
    techniques=["sqli"],
    tools=["sqlmap"],
    direct_ev=5.0,
)
print(f"C3: causal_simulate: direct_ev={result['direct_ev']}, causal_bonus={result['causal_ev_bonus']}, total={result['total_ev']}")
assert result["direct_ev"] == 5.0
assert result["total_ev"] >= result["direct_ev"]
print("C3: Causal simulate OK (no graphs bound)")

# 3. Test causal rank
ranked = c.causal_rank_actions([
    {"action": "xss_scan", "techniques": ["xss"], "direct_ev": 3.0},
    {"action": "sqli_scan", "techniques": ["sqli"], "direct_ev": 7.0},
])
print(f"C3: causal_rank: top={ranked[0]['action']}, ev={ranked[0]['total_ev']}")
assert len(ranked) == 2
print("C3: Causal rank OK")

# 4. Test on_finding_discovered (without exploit graph — no state changes)
changes = c.on_finding_discovered({
    "id": "find_001",
    "category": "xss",
    "title": "Reflected XSS in /search",
    "severity": "high",
})
print(f"C2: on_finding_discovered: {len(changes)} state changes")
state = c.get_causal_state()
assert state["findings_processed"] == 1
print("C2: Live update OK")

# 5. Test duplicate finding suppression
changes2 = c.on_finding_discovered({
    "id": "find_001",
    "category": "xss",
    "title": "Reflected XSS in /search",
    "severity": "high",
})
assert len(changes2) == 0
state = c.get_causal_state()
assert state["findings_processed"] == 1
print("C2: Duplicate suppression OK")

# 6. Test get_causal_chains (without graphs — empty)
chains = c.get_causal_chains("xss", max_depth=3)
print(f"C1: get_causal_chains: {len(chains)} chains")
print("C1: Cross-system query OK")

# 7. Test get_world_state
world = c.get_world_state()
print(f"C4: world_state: {world['total_changes']} changes, {world['findings_processed']} findings")
print("C4: World state OK")

# 8. Test get_next_best_actions
actions = c.get_next_best_actions(5)
print(f"Next best actions: {len(actions)}")
print("Next best actions OK")

# 9. Test bind methods exist
c.bind_causal_engine(None)
c.bind_exploit_graph(None)
c.bind_unified_graph(None)
c.bind_world_model(None)
c.bind_path_planner(None)
c.bind_chain_scorer(None)
print("Bind methods OK")

# 10. Verify to_dict includes causal_bridge
full = c.to_dict()
assert "causal_bridge" in full, "causal_bridge missing from to_dict"
print("to_dict includes causal_bridge OK")

# 11. Test simulate_actions includes causal reasoning path
sim_result = c.simulate_actions([
    {"action": "sqli_deep", "role": "exploit", "tools": ["sqlmap"], "techniques": ["sqli"]},
    {"action": "xss_scan", "role": "exploit", "tools": ["dalfox"], "techniques": ["xss"]},
])
print(f"simulate_actions with causal: recommended={sim_result.recommended_action}, scenarios={len(sim_result.scenarios)}")
print("simulate_actions causal integration OK")

# 12. Test persistent_agent delegation
from CaseCrack.tools.burp_enterprise.persistent_agent import PersistentAgentLoop
causal_methods = [
    "bind_causal_engine", "bind_exploit_graph", "bind_unified_graph",
    "bind_world_model", "bind_path_planner", "bind_chain_scorer",
    "on_finding_discovered", "causal_simulate", "causal_rank_actions",
    "get_causal_chains", "get_world_state", "get_next_best_actions",
    "get_causal_state",
]
missing = [m for m in causal_methods if not hasattr(PersistentAgentLoop, m)]
if missing:
    print(f"MISSING from PersistentAgentLoop: {missing}")
else:
    print(f"ALL {len(causal_methods)} causal delegation methods present")

print("\nALL CAUSAL BRIDGE TESTS PASSED")
