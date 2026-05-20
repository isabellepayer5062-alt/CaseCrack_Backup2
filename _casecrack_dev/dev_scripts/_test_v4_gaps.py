"""Functional test for v4-GAP 1-4 implementations."""

from CaseCrack.tools.burp_enterprise.agent_roles import AgentCoordinator

c = AgentCoordinator()

# v4-GAP 1: Meta-Learning
ctx = {"technologies": ["wordpress", "php"], "waf_vendor": "cloudflare", "platform": "aws"}
patterns = c.extract_meta_patterns(ctx)
print(f"GAP1 extract_meta_patterns: {len(patterns)} patterns")
bias = c.get_policy_bias(ctx)
print(f"GAP1 get_policy_bias: suppress={bias['suppress']}, prioritize={bias['prioritize']}")
c.reinforce_meta_pattern(ctx, "xss", True)
print("GAP1 reinforce_meta_pattern: OK")
state = c.get_meta_patterns()
print(f"GAP1 get_meta_patterns: {state['total_patterns']} patterns")

# v4-GAP 2: Hypothesis Engine
hyps = c.generate_hypotheses(ctx, "example.com")
print(f"GAP2 generate_hypotheses: {len(hyps)} hypotheses")
if hyps:
    hid = hyps[0]["hypothesis_id"]
    ok = c.simulate_hypothesis(hid, {"success_probability": 0.8})
    print(f"GAP2 simulate_hypothesis: {ok}")
    result = c.validate_hypothesis(hid, {"finding": "xss_reflected"}, True)
    print(f"GAP2 validate_hypothesis: {result['status'] if result else None}")
actionable = c.get_actionable_hypotheses(0.3)
print(f"GAP2 get_actionable_hypotheses: {len(actionable)}")
hstate = c.get_hypothesis_state()
print(f"GAP2 hypothesis_state: {hstate['total_hypotheses']} total, {hstate['status_counts']}")

# v4-GAP 3: Economic Optimization
score = c.score_action_value("sql_injection_test", ["sqlmap"], 2, "high", 120.0)
print(f"GAP3 score_action_value: density={score['value_density']}")
candidates = [
    {"action": "xss_scan", "tools": ["dalfox"], "predicted_findings": 3, "predicted_severity": "medium", "predicted_duration_s": 60},
    {"action": "sqli_scan", "tools": ["sqlmap"], "predicted_findings": 1, "predicted_severity": "critical", "predicted_duration_s": 180},
]
ranked = c.rank_actions_by_value(candidates)
print(f"GAP3 rank_actions_by_value: top={ranked[0]['candidate']['action']}")
c.record_actual_value("xss_scan", 8.0, 2.5)
report = c.get_economic_report()
print(f"GAP3 economic_report: efficiency={report['overall_efficiency']}")

# v4-GAP 4: Audit Layer
tid = c.record_decision_trace("test", {"key": "value"}, "chose_a", ["reason1"], 0.9, [{"action": "b"}])
print(f"GAP4 record_decision_trace: trace_id={tid}")
explained = c.explain_decision(tid)
print(f"GAP4 explain_decision: original_action={explained['original_action']}")
decisions = c.query_decisions("test", limit=5)
print(f"GAP4 query_decisions: {len(decisions)} traces")
summary = c.get_decision_summary()
print(f"GAP4 decision_summary: {summary['total_decisions']} decisions, types={list(summary['type_counts'].keys())}")
astate = c.get_audit_state()
print(f"GAP4 audit_state: {astate['total_decisions']} decisions in log")

# to_dict includes all
full = c.to_dict()
assert "meta_patterns" in full, "meta_patterns missing from to_dict"
assert "hypothesis_engine" in full, "hypothesis_engine missing from to_dict"
assert "economic_optimizer" in full, "economic_optimizer missing from to_dict"
assert "audit_log" in full, "audit_log missing from to_dict"
print("\nALL 4 v4-GAPs VERIFIED OK")
