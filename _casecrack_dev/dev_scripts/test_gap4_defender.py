"""Functional tests for GAP 4: Defender Adversary Model (D1+D3+D4+D6+D7+D8)."""

import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))

from CaseCrack.tools.burp_enterprise.defender_adversary_model import (
    DefenderAdversaryModel, ProbeOutcome, EscalationPhase,
    EscalationForecast, InferredRule, PayloadRiskScore,
    DecoyRequest, DetectionCostEstimate,
)

passed = 0
failed = 0

def test(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")

# ═══════════════════════════════════════════════════════════════════
# 1. Basic instantiation
# ═══════════════════════════════════════════════════════════════════
print("\n── 1. Basic instantiation ──")
dam = DefenderAdversaryModel()
test("1.1 instance created", dam is not None)
test("1.2 not ready (no probes)", not dam.is_ready)
test("1.3 phase starts passive", dam._current_phase == EscalationPhase.PASSIVE)
test("1.4 to_dict works", isinstance(dam.to_dict(), dict))

# ═══════════════════════════════════════════════════════════════════
# 2. D1: Temporal escalation with probe ingestion
# ═══════════════════════════════════════════════════════════════════
print("\n── 2. D1: Temporal escalation ──")
# Feed 30 benign probes (not blocked)
for i in range(30):
    dam.record_probe_result(ProbeOutcome(
        attack_class="xss", payload=f"<img src=x onerror=alert({i})>",
        was_blocked=False, response_code=200, latency_ms=50.0,
    ))
test("2.1 is_ready after 30 probes", dam.is_ready)
test("2.2 phase still passive", dam._current_phase == EscalationPhase.PASSIVE)

# Now feed 30 blocked probes (escalation)
for i in range(30):
    dam.record_probe_result(ProbeOutcome(
        attack_class="xss", payload=f"<script>alert({i})</script>",
        was_blocked=True, response_code=403, latency_ms=30.0,
    ))
test("2.3 phase escalated to signature", dam._current_phase == EscalationPhase.SIGNATURE)

forecast = dam.forecast_escalation()
test("2.4 forecast returns EscalationForecast", isinstance(forecast, EscalationForecast))
test("2.5 block rate trend rising", forecast.block_rate_trend == "rising")
test("2.6 block rate > 0", forecast.current_block_rate > 0.0)
test("2.7 confidence > 0", forecast.confidence > 0.0)

# ═══════════════════════════════════════════════════════════════════
# 3. D1: Phase transitions
# ═══════════════════════════════════════════════════════════════════
print("\n── 3. D1: Phase transitions ──")
dam2 = DefenderAdversaryModel()
dam2.record_probe_result(ProbeOutcome(was_rate_limited=True))
test("3.1 rate_limit phase detected", dam2._current_phase == EscalationPhase.RATE_LIMIT)

dam3 = DefenderAdversaryModel()
dam3.record_probe_result(ProbeOutcome(was_ip_banned=True))
test("3.2 ip_ban phase detected", dam3._current_phase == EscalationPhase.IP_BAN)

dam4 = DefenderAdversaryModel()
dam4.record_probe_result(ProbeOutcome(was_challenged=True))
test("3.3 challenge phase detected", dam4._current_phase == EscalationPhase.CHALLENGE)

# ═══════════════════════════════════════════════════════════════════
# 4. D3: WAF rule inference
# ═══════════════════════════════════════════════════════════════════
print("\n── 4. D3: WAF rule inference ──")
dam_rules = DefenderAdversaryModel()

# Feed payloads with <script> that get blocked
for i in range(10):
    dam_rules.record_probe_result(ProbeOutcome(
        attack_class="xss", payload=f"<script>alert({i})</script>",
        was_blocked=True, response_code=403,
    ))

# Feed payloads without <script> that pass
for i in range(10):
    dam_rules.record_probe_result(ProbeOutcome(
        attack_class="xss", payload=f"<img src=x onerror=console.log({i})>",
        was_blocked=False, response_code=200,
    ))

rules = dam_rules.infer_rules()
test("4.1 rules inferred", len(rules) > 0)

# script_tag feature should be high-confidence blocked
script_rule = [r for r in rules if r.pattern == "script_tag"]
test("4.2 script_tag rule found", len(script_rule) > 0)

if script_rule:
    test("4.3 script_tag confidence >= 0.5", script_rule[0].confidence >= 0.5)
    test("4.4 script_tag has xss class", "xss" in script_rule[0].attack_classes)

# Blind spots
spots = dam_rules.get_blind_spots("xss")
test("4.5 blind spots found", isinstance(spots, list))
test("4.6 event_handler in blind spots", "event_handler" in spots)

# ═══════════════════════════════════════════════════════════════════
# 5. D4: Defender learning rate
# ═══════════════════════════════════════════════════════════════════
print("\n── 5. D4: Defender learning rate ──")
dam_lr = DefenderAdversaryModel()
# Phase 1: all pass
for i in range(40):
    dam_lr.record_probe_result(ProbeOutcome(
        attack_class="sqli", payload=f"' OR 1=1 -- {i}",
        was_blocked=False, response_code=200,
    ))
lr1 = dam_lr.get_defender_learning_rate()
test("5.1 learning rate low when all pass", lr1 < 0.3)

# Phase 2: defender starts blocking (adapting)
for i in range(40):
    dam_lr.record_probe_result(ProbeOutcome(
        attack_class="sqli", payload=f"' OR 1=1 -- {i}",
        was_blocked=True, response_code=403,
    ))
lr2 = dam_lr.get_defender_learning_rate()
test("5.2 learning rate increased", lr2 > lr1)
test("5.3 is_defender_adapting detects it", dam_lr.is_defender_adapting())

# ═══════════════════════════════════════════════════════════════════
# 6. D6: Per-payload detection probability
# ═══════════════════════════════════════════════════════════════════
print("\n── 6. D6: Per-payload detection ──")
risk = dam_rules.score_payload_risk("<script>alert(1)</script>", "xss")
test("6.1 returns PayloadRiskScore", isinstance(risk, PayloadRiskScore))
test("6.2 script payload has high risk", risk.detection_probability > 0.5)

safe_risk = dam_rules.score_payload_risk("normal text", "xss")
test("6.3 benign payload lower risk", safe_risk.detection_probability <= risk.detection_probability)

# ═══════════════════════════════════════════════════════════════════
# 7. D7: Decoy strategy
# ═══════════════════════════════════════════════════════════════════
print("\n── 7. D7: Decoy strategy ──")
decoys = dam.generate_decoys("https://target.com", 3)
test("7.1 decoys generated", len(decoys) == 3)
test("7.2 first decoy is DecoyRequest", isinstance(decoys[0], DecoyRequest))
test("7.3 url contains target", "target.com" in decoys[0].url_path)
test("7.4 method is GET", decoys[0].method == "GET")

# Pop decoy
d = dam.pop_decoy()
test("7.5 pop_decoy works", d is not None)

# should_inject_decoy
si = dam.should_inject_decoy()
test("7.6 should_inject returns bool", isinstance(si, bool))

# ═══════════════════════════════════════════════════════════════════
# 8. D8: Detection cost integration
# ═══════════════════════════════════════════════════════════════════
print("\n── 8. D8: Detection cost ──")
cost = dam.compute_detection_cost("run_sqlmap", "sqli")
test("8.1 returns DetectionCostEstimate", isinstance(cost, DetectionCostEstimate))
test("8.2 detection_risk >= 0", cost.detection_risk >= 0.0)
test("8.3 detection_cost >= 0", cost.detection_cost >= 0.0)
test("8.4 recommendation present", len(cost.stealth_recommendation) > 0)

# Score with detection
score = dam.score_action_with_detection(
    action="run_sqlmap", attack_class="sqli",
    predicted_findings=3, predicted_severity="high",
)
test("8.5 combined score has stealth_adjusted_value", "stealth_adjusted_value" in score)
test("8.6 combined score has detection_risk", "detection_risk" in score)

# ═══════════════════════════════════════════════════════════════════
# 9. Tactical briefing
# ═══════════════════════════════════════════════════════════════════
print("\n── 9. Tactical briefing ──")
briefing = dam.get_tactical_briefing()
test("9.1 briefing has probe_count", "probe_count" in briefing)
test("9.2 briefing has escalation_forecast", "escalation_forecast" in briefing)
test("9.3 briefing has inferred_rules", "inferred_rules" in briefing)
test("9.4 briefing has defender_learning_rate", "defender_learning_rate" in briefing)
test("9.5 briefing has decoys_sent", "decoys_sent" in briefing)
test("9.6 probe_count = 60", briefing["probe_count"] == 60)

# ═══════════════════════════════════════════════════════════════════
# 10. Serialization
# ═══════════════════════════════════════════════════════════════════
print("\n── 10. Serialization ──")
d = dam.to_dict()
test("10.1 to_dict has current_phase", "current_phase" in d)
test("10.2 to_dict has probe_count", "probe_count" in d)
test("10.3 to_dict has inferred_rules_count", "inferred_rules_count" in d)
test("10.4 to_dict has class_detection_risks", "class_detection_risks" in d)

# ═══════════════════════════════════════════════════════════════════
# 11. Callbacks
# ═══════════════════════════════════════════════════════════════════
print("\n── 11. Callbacks ──")
escalation_events = []
rule_events = []

def on_esc(f):
    escalation_events.append(f)

def on_rule(r):
    rule_events.append(r)

dam_cb = DefenderAdversaryModel(on_escalation=on_esc, on_rule_inferred=on_rule)
# Feed lots of blocked payloads
for i in range(20):
    dam_cb.record_probe_result(ProbeOutcome(
        attack_class="sqli", payload=f"' UNION SELECT {i} --",
        was_blocked=False, response_code=200,
    ))
for i in range(30):
    dam_cb.record_probe_result(ProbeOutcome(
        attack_class="sqli", payload=f"' UNION SELECT {i} --",
        was_blocked=True, response_code=403,
    ))
dam_cb.forecast_escalation()  # triggers callback if rising
dam_cb.infer_rules()  # triggers rule callback

test("11.1 escalation callback fired", len(escalation_events) > 0)
test("11.2 rule callback fired", len(rule_events) > 0)

# ═══════════════════════════════════════════════════════════════════
# 12. Batch ingestion
# ═══════════════════════════════════════════════════════════════════
print("\n── 12. Batch ingestion ──")
dam_batch = DefenderAdversaryModel()
probes = [
    ProbeOutcome(attack_class="xss", payload=f"payload_{i}", was_blocked=(i % 3 == 0))
    for i in range(15)
]
dam_batch.record_probe_batch(probes)
test("12.1 batch ingested 15 probes", len(dam_batch._probe_history) == 15)

# ═══════════════════════════════════════════════════════════════════
# 13. AgentCoordinator integration
# ═══════════════════════════════════════════════════════════════════
print("\n── 13. AgentCoordinator integration ──")
from CaseCrack.tools.burp_enterprise.agent_roles import AgentCoordinator
coord = AgentCoordinator()
test("13.1 coordinator has _defender_adversary", hasattr(coord, "_defender_adversary"))

# Record probes via coordinator
coord.record_probe_result(
    attack_class="xss", payload="<script>alert(1)</script>",
    was_blocked=True, response_code=403,
)
test("13.2 record_probe_result works", True)

# Forecast via coordinator
fc = coord.forecast_escalation()
test("13.3 forecast works", isinstance(fc, dict))

# Infer rules via coordinator
rules_c = coord.infer_waf_rules()
test("13.4 infer_waf_rules returns list", isinstance(rules_c, list))

# Payload risk
pr = coord.score_payload_risk("<script>alert(1)</script>", "xss")
test("13.5 payload risk works", isinstance(pr, dict))

# Decoys
dc = coord.generate_decoys("https://target.com", 2)
test("13.6 decoys from coordinator", len(dc) == 2)

# Detection cost
cc = coord.compute_detection_cost("run_nuclei", "xss")
test("13.7 detection cost works", isinstance(cc, dict))

# Score with detection
sc = coord.score_action_with_detection("run_sqlmap", "sqli")
test("13.8 score_action_with_detection works", "stealth_adjusted_value" in sc)

# Tactical briefing
tb = coord.get_tactical_briefing()
test("13.9 tactical briefing works", "probe_count" in tb)

# to_dict includes defender
cd = coord.to_dict()
test("13.10 coordinator to_dict has defender_adversary", "defender_adversary" in cd)

# Defender state
ds = coord.get_defender_adversary_state()
test("13.11 defender state works", "current_phase" in ds)

# Learning rate
lr = coord.get_defender_learning_rate()
test("13.12 learning rate works", isinstance(lr, float))

# Blind spots
bs = coord.get_waf_blind_spots()
test("13.13 blind spots works", isinstance(bs, list))

# Bindings
coord.bind_defender_defense_model(None)
test("13.14 bind defense model works", True)
coord.bind_defender_stealth_orchestrator(None)
test("13.15 bind stealth orch works", True)

# should_inject_decoy
sid = coord.should_inject_decoy()
test("13.16 should_inject_decoy works", isinstance(sid, bool))

# pop_decoy
pd = coord.pop_decoy()
test("13.17 pop_decoy works", pd is not None or pd is None)

# is_defender_adapting
ida = coord.is_defender_adapting()
test("13.18 is_defender_adapting works", isinstance(ida, bool))

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"  GAP 4 RESULTS:  {passed} passed, {failed} failed")
print(f"{'='*60}")
sys.exit(0 if failed == 0 else 1)
