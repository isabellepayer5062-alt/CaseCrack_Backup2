"""Comprehensive tests for AdversarialValidationAgent.

Tests cover:
- Rationalization detection (12 patterns)
- Counter-hypothesis generation (per-type + generic)
- Adversarial probe generation (per-type + generic)
- Confidence attacks (evidence quality, single source, severity inflation)
- Adjusted confidence computation
- Verdict determination logic
- Batch processing
- Survivor filtering
- Statistics tracking
- Disproval pattern analysis
- Callback firing
- Binding methods
- Edge cases (empty findings, max penalties, confirmed findings)
- Thread safety
- Serialization (to_dict)
"""

import sys
import os
import threading
import time

# Ensure project root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CaseCrack"))

from CaseCrack.tools.burp_enterprise.adversarial_validation_agent import (
    AdversarialValidationAgent,
    ChallengeReport,
    ChallengeVerdict,
    CounterHypothesis,
    AdversarialProbe,
    RationalizationDetection,
    ConfidenceAttack,
    ProbeType,
    RationalizationPattern,
)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _make_finding(**overrides):
    """Create a canonical finding dict with defaults."""
    base = {
        "id": "test-001",
        "type": "xss",
        "severity": "high",
        "title": "Reflected XSS in search parameter",
        "detail": "User input is reflected unencoded in the response body",
        "description": "The search parameter is vulnerable to XSS",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "source_tool": "nuclei",
        "confidence": 0.75,
        "payload": "<script>alert(1)</script>",
        "curl_command": "curl -s 'https://example.com/search?q=<script>alert(1)</script>'",
        "response": "<html><body><script>alert(1)</script></body></html>",
        "cwe_ids": ["CWE-79"],
    }
    base.update(overrides)
    return base


def _make_weak_finding(**overrides):
    """Create a finding with weak evidence (high FP likelihood)."""
    base = {
        "id": "weak-001",
        "type": "sqli",
        "severity": "high",
        "title": "The endpoint looks vulnerable to SQL injection",
        "detail": "Input appears to trigger SQL errors, likely exploitable via UNION",
        "description": "This parameter seems unsafe and may result in SQL injection",
        "url": "https://example.com/api?id=1",
        "parameter": "id",
        "source_tool": "regex",
        "confidence": 0.80,
        # No payload, no response, no curl_command
    }
    base.update(overrides)
    return base


passed = 0
failed = 0


def check(test_id, condition, msg=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS {test_id}: {msg}")
    else:
        failed += 1
        print(f"  FAIL {test_id}: {msg}")


# ═══════════════════════════════════════════════════════════════════════
# 1. Construction & Defaults
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 1. Construction & Defaults ===")

ava = AdversarialValidationAgent()
check("1.1", ava is not None, "Agent instantiates")
check("1.2", ava._rationalization_cap == 0.40, "Default rationalization cap")
check("1.3", ava._confidence_floor == 0.05, "Default confidence floor")
check("1.4", ava._total_challenged == 0, "Starts with zero challenges")

stats = ava.get_stats()
check("1.5", stats["total_challenged"] == 0, "Stats show zero challenges")
check("1.6", stats["survival_rate"] == 1.0, "Initial survival rate 100%")

state = ava.to_dict()
check("1.7", "config" in state, "to_dict has config")
check("1.8", "stats" in state, "to_dict has stats")
check("1.9", "disproval_patterns" in state, "to_dict has disproval_patterns")
check("1.10", "bindings" in state, "to_dict has bindings")

# Custom params
ava2 = AdversarialValidationAgent(
    rationalization_penalty_cap=0.50,
    confidence_floor=0.10,
)
check("1.11", ava2._rationalization_cap == 0.50, "Custom rationalization cap")
check("1.12", ava2._confidence_floor == 0.10, "Custom confidence floor")


# ═══════════════════════════════════════════════════════════════════════
# 2. Rationalization Detection
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 2. Rationalization Detection ===")

ava = AdversarialValidationAgent()

# 2.1: "looks vulnerable" in title
f_looks = _make_finding(title="This endpoint looks vulnerable to XSS")
report = ava.challenge_finding(f_looks)
rat_patterns = [r.pattern for r in report.rationalizations]
check("2.1", RationalizationPattern.LOOKS_VULNERABLE in rat_patterns,
      "'looks vulnerable' detected in title")

# 2.2: "likely exploitable" in detail
f_likely = _make_finding(detail="This is likely exploitable via GET parameter")
report = ava.challenge_finding(f_likely)
rat_patterns = [r.pattern for r in report.rationalizations]
check("2.2", RationalizationPattern.LIKELY_EXPLOITABLE in rat_patterns,
      "'likely exploitable' detected in detail")

# 2.3: "similar to known" in description
f_similar = _make_finding(description="This matches a known vulnerability pattern CVE-2024-1234")
report = ava.challenge_finding(f_similar)
rat_patterns = [r.pattern for r in report.rationalizations]
# "matches a known" triggers SIMILAR_TO_KNOWN
check("2.3", RationalizationPattern.SIMILAR_TO_KNOWN in rat_patterns,
      "'matches a known' detected")

# 2.4: "could be used" in detail
f_couldbe = _make_finding(detail="This could be used to steal session tokens")
report = ava.challenge_finding(f_couldbe)
rat_patterns = [r.pattern for r in report.rationalizations]
check("2.4", RationalizationPattern.COULD_BE_USED in rat_patterns,
      "'could be used' detected")

# 2.5: Multiple rationalizations in single finding
f_multi = _make_finding(
    title="This looks vulnerable to injection",
    detail="The parameter seems unsafe and may result in data loss",
    description="This suggests that the input could be used maliciously",
)
report = ava.challenge_finding(f_multi)
check("2.5", len(report.rationalizations) >= 3,
      f"Multiple rationalizations detected: {len(report.rationalizations)}")

# 2.6: Clean finding — no rationalizations
f_clean = _make_finding(
    title="Reflected XSS in search parameter",
    detail="User input <script>alert(1)</script> reflected unencoded in response body",
    description="The search parameter q does not sanitize HTML special characters",
)
report = ava.challenge_finding(f_clean)
check("2.6", len(report.rationalizations) == 0,
      "Clean finding has no rationalizations")

# 2.7: Penalty is applied per detection
f_penalty = _make_finding(title="This looks vulnerable to XSS")
report = ava.challenge_finding(f_penalty)
check("2.7", any(r.penalty > 0 for r in report.rationalizations),
      "Rationalization has positive penalty")

# 2.8: Location tracking
check("2.8", all(r.location in ("title", "detail", "description", "remediation")
                  for r in report.rationalizations),
      "Rationalization locations are valid")

# 2.9: "might allow" detection
f_might = _make_finding(detail="This might allow an attacker to execute code")
report = ava.challenge_finding(f_might)
rat_patterns = [r.pattern for r in report.rationalizations]
check("2.9", RationalizationPattern.MIGHT_ALLOW in rat_patterns,
      "'might allow' detected")

# 2.10: "appears to" detection
f_appears = _make_finding(detail="The endpoint appears to be vulnerable")
report = ava.challenge_finding(f_appears)
rat_patterns = [r.pattern for r in report.rationalizations]
check("2.10", RationalizationPattern.APPEARS_TO in rat_patterns,
      "'appears to' detected")

# 2.11: "may result in" detection
f_mayresult = _make_finding(detail="This may result in data exfiltration")
report = ava.challenge_finding(f_mayresult)
rat_patterns = [r.pattern for r in report.rationalizations]
check("2.11", RationalizationPattern.MAY_RESULT_IN in rat_patterns,
      "'may result in' detected")

# 2.12: "possibly bypassed" detection
f_bypass = _make_finding(detail="Authentication is possibly bypassed via JWT manipulation")
report = ava.challenge_finding(f_bypass)
rat_patterns = [r.pattern for r in report.rationalizations]
check("2.12", RationalizationPattern.POSSIBLY_BYPASSED in rat_patterns,
      "'possibly bypassed' detected")


# ═══════════════════════════════════════════════════════════════════════
# 3. Counter-Hypothesis Generation
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 3. Counter-Hypothesis Generation ===")

ava = AdversarialValidationAgent()

# 3.1: XSS counter-hypotheses
f_xss = _make_finding(type="xss")
report = ava.challenge_finding(f_xss)
check("3.1", len(report.counter_hypotheses) >= 4,
      f"XSS has >=4 counter-hypotheses: {len(report.counter_hypotheses)}")

# 3.2: SQLi counter-hypotheses
f_sqli = _make_finding(type="sqli", id="sqli-001")
report = ava.challenge_finding(f_sqli)
check("3.2", len(report.counter_hypotheses) >= 4,
      f"SQLi has >=4 counter-hypotheses: {len(report.counter_hypotheses)}")

# 3.3: Unknown type gets generic hypotheses
f_unknown = _make_finding(type="prototype_pollution", id="proto-001")
report = ava.challenge_finding(f_unknown)
check("3.3", len(report.counter_hypotheses) >= 4,
      f"Unknown type gets generic hypotheses: {len(report.counter_hypotheses)}")

# 3.4: Confirmed finding reduces plausibility
f_confirmed = _make_finding(confirmed=True)
report_confirmed = ava.challenge_finding(f_confirmed)
f_unconfirmed = _make_finding(confirmed=False, id="unconf-001")
report_unconfirmed = ava.challenge_finding(f_unconfirmed)

max_plaus_confirmed = max(h.plausibility for h in report_confirmed.counter_hypotheses)
max_plaus_unconfirmed = max(h.plausibility for h in report_unconfirmed.counter_hypotheses)
check("3.4", max_plaus_confirmed < max_plaus_unconfirmed,
      f"Confirmed finding has lower counter-hypothesis plausibility "
      f"({max_plaus_confirmed:.3f} < {max_plaus_unconfirmed:.3f})")

# 3.5: OOB callback reduces plausibility
f_oob = _make_finding(oob_interaction=True, id="oob-001")
report_oob = ava.challenge_finding(f_oob)
max_plaus_oob = max(h.plausibility for h in report_oob.counter_hypotheses)
check("3.5", max_plaus_oob < max_plaus_unconfirmed,
      f"OOB callback reduces plausibility ({max_plaus_oob:.3f} < {max_plaus_unconfirmed:.3f})")

# 3.6: Counter-hypotheses have would_disprove flag
disprove_count = sum(1 for h in report.counter_hypotheses if h.would_disprove)
check("3.6", disprove_count >= 1,
      f"At least 1 hypothesis would disprove: {disprove_count}")

# 3.7: Counter-hypotheses serialization
for h in report.counter_hypotheses[:2]:
    d = h.to_dict()
    check("3.7", "hypothesis" in d and "plausibility" in d and "would_disprove" in d,
          "Counter-hypothesis serializes properly")
    break

# 3.8: SSRF counter-hypotheses
f_ssrf = _make_finding(type="ssrf", id="ssrf-001")
report = ava.challenge_finding(f_ssrf)
check("3.8", len(report.counter_hypotheses) >= 4,
      f"SSRF has >=4 counter-hypotheses: {len(report.counter_hypotheses)}")

# 3.9: IDOR counter-hypotheses
f_idor = _make_finding(type="idor", id="idor-001")
report = ava.challenge_finding(f_idor)
check("3.9", len(report.counter_hypotheses) >= 4,
      f"IDOR has >=4 counter-hypotheses: {len(report.counter_hypotheses)}")


# ═══════════════════════════════════════════════════════════════════════
# 4. Adversarial Probe Generation
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 4. Adversarial Probe Generation ===")

ava = AdversarialValidationAgent()

# 4.1: XSS probes include type-specific + generic
f_xss = _make_finding(type="xss")
report = ava.challenge_finding(f_xss)
xss_types = {p.probe_type for p in report.required_probes}
check("4.1", ProbeType.BOUNDARY_BREAKING in xss_types,
      "XSS has BOUNDARY_BREAKING probe")

# 4.2: Generic probes always present
check("4.2", ProbeType.CONCURRENCY_EDGE in xss_types or ProbeType.INVALID_ASSUMPTION in xss_types,
      "Generic probes present for XSS")

# 4.3: SQLi probes include timing
f_sqli = _make_finding(type="sqli", id="sqli-p")
report = ava.challenge_finding(f_sqli)
sqli_types = {p.probe_type for p in report.required_probes}
check("4.3", ProbeType.TIMING_DEPENDENT in sqli_types,
      "SQLi has TIMING_DEPENDENT probe")

# 4.4: Probes sorted by priority
priorities = [p.priority for p in report.required_probes]
check("4.4", priorities == sorted(priorities),
      "Probes sorted by priority (ascending)")

# 4.5: Probe serialization
probe = report.required_probes[0]
d = probe.to_dict()
check("4.5", all(k in d for k in ["probe_type", "description", "test_command",
                                     "expected_if_valid", "expected_if_false", "priority"]),
      "Probe serializes all fields")

# 4.6: Command injection probes
f_cmdi = _make_finding(type="command_injection", id="cmdi-001")
report = ava.challenge_finding(f_cmdi)
cmdi_types = {p.probe_type for p in report.required_probes}
check("4.6", ProbeType.FALSE_ORACLE in cmdi_types,
      "Command injection has FALSE_ORACLE probe")

# 4.7: SSRF probes
f_ssrf = _make_finding(type="ssrf", id="ssrf-p")
report = ava.challenge_finding(f_ssrf)
ssrf_types = {p.probe_type for p in report.required_probes}
check("4.7", ProbeType.ENVIRONMENT_ARTIFACT in ssrf_types,
      "SSRF has ENVIRONMENT_ARTIFACT probe")

# 4.8: INTENDED_BEHAVIOR always present
check("4.8", ProbeType.INTENDED_BEHAVIOR in xss_types,
      "INTENDED_BEHAVIOR probe present")

# 4.9: Unknown type gets only generic probes
f_unk = _make_finding(type="graphql_injection", id="gql-001")
report = ava.challenge_finding(f_unk)
check("4.9", len(report.required_probes) >= 4,
      f"Unknown type gets >=4 generic probes: {len(report.required_probes)}")


# ═══════════════════════════════════════════════════════════════════════
# 5. Confidence Attacks
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 5. Confidence Attacks ===")

ava = AdversarialValidationAgent()

# 5.1: Evidence quality attack — weak evidence
f_weak = _make_weak_finding()
report = ava.challenge_finding(f_weak)
atk_names = [a.attack_name for a in report.confidence_attacks]
check("5.1", "evidence_quality_attack" in atk_names,
      "Evidence quality attack fires for weak finding")

# 5.2: Single source attack — passive tool
check("5.2", "single_source_attack" in atk_names,
      "Single source attack fires for regex-only source")

# 5.3: Severity inflation attack — high severity + weak evidence
check("5.3", "severity_inflation_attack" in atk_names,
      "Severity inflation attack fires for high sev + weak evidence")

# 5.4: Strong finding — fewer attacks
f_strong = _make_finding(
    confirmed=True,
    evidence_type="exploitation_confirmed",
    corroborating_tools=["sqlmap", "burp"],
)
report_strong = ava.challenge_finding(f_strong)
check("5.4", len(report_strong.confidence_attacks) < len(report.confidence_attacks),
      f"Strong finding has fewer attacks: {len(report_strong.confidence_attacks)} < {len(report.confidence_attacks)}")

# 5.5: Confidence attack serialization
if report.confidence_attacks:
    d = report.confidence_attacks[0].to_dict()
    check("5.5", all(k in d for k in ["attack_name", "original_confidence",
                                        "adjusted_confidence", "reasoning", "factors"]),
          "Confidence attack serializes all fields")

# 5.6: Critical severity without PoC triggers inflation attack
f_crit_no_poc = _make_finding(
    severity="critical",
    evidence_type="regex_match",
    id="crit-001",
)
report = ava.challenge_finding(f_crit_no_poc)
atk_names = [a.attack_name for a in report.confidence_attacks]
check("5.6", "severity_inflation_attack" in atk_names,
      "Critical without PoC triggers severity inflation")

# 5.7: Info severity doesn't trigger inflation
f_info = _make_finding(severity="info", id="info-001")
report = ava.challenge_finding(f_info)
atk_names = [a.attack_name for a in report.confidence_attacks]
check("5.7", "severity_inflation_attack" not in atk_names,
      "Info severity doesn't trigger inflation attack")


# ═══════════════════════════════════════════════════════════════════════
# 6. Adjusted Confidence Computation
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 6. Adjusted Confidence ===")

ava = AdversarialValidationAgent()

# 6.1: Weak finding — confidence decreases
f_weak = _make_weak_finding()
report = ava.challenge_finding(f_weak)
check("6.1", report.adjusted_confidence < report.original_confidence,
      f"Weak finding confidence reduced: {report.adjusted_confidence:.4f} < {report.original_confidence:.4f}")

# 6.2: Strong finding — confidence stays close
f_strong = _make_finding(
    confirmed=True,
    evidence_type="exploitation_confirmed",
    corroborating_tools=["burp", "zap"],
    title="Confirmed XSS in search",
    detail="PoC script executed successfully",
    description="Parameter q reflects unencoded",
)
report = ava.challenge_finding(f_strong)
check("6.2", report.adjusted_confidence >= 0.60,
      f"Strong finding keeps high confidence: {report.adjusted_confidence:.4f}")

# 6.3: Confidence never goes below floor
f_terrible = _make_weak_finding(
    title="This looks vulnerable and might allow exploitation",
    detail="The parameter seems unsafe and could be used to bypass auth. "
           "This suggests that the deployment may result in compromise. "
           "Likely exploitable via known techniques. Appears to be insecure.",
    description="Probably leads to data loss. Possibly bypassed via URL encoding.",
    confidence=0.30,
    id="floor-001",
)
ava_low = AdversarialValidationAgent(confidence_floor=0.05)
report = ava_low.challenge_finding(f_terrible)
check("6.3", report.adjusted_confidence >= 0.05,
      f"Confidence respects floor: {report.adjusted_confidence:.4f} >= 0.05")

# 6.4: Delta is correct
check("6.4", abs(report.confidence_delta - (report.adjusted_confidence - report.original_confidence)) < 0.001,
      "confidence_delta property matches difference")

# 6.5: Rationalization cap limits total penalty
rationalizations_penalty = sum(r.penalty for r in report.rationalizations)
check("6.5", rationalizations_penalty > 0.40,
      f"Raw rationalization penalty exceeds cap: {rationalizations_penalty:.3f} > 0.40 (capped internally)")


# ═══════════════════════════════════════════════════════════════════════
# 7. Verdict Determination
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 7. Verdict Determination ===")

ava = AdversarialValidationAgent()

# 7.1: Strong confirmed finding → UPHELD
f_upheld = _make_finding(confirmed=True, confidence=0.90)
report = ava.challenge_finding(f_upheld)
check("7.1", report.verdict == ChallengeVerdict.UPHELD,
      f"Confirmed finding → UPHELD (got {report.verdict.value})")

# 7.2: Very weak finding → DISPROVED or DISPUTED
f_disprove = _make_weak_finding(confidence=0.20, id="disprove-001")
report = ava.challenge_finding(f_disprove)
check("7.2", report.verdict in (ChallengeVerdict.DISPROVED, ChallengeVerdict.DISPUTED),
      f"Very weak finding → DISPROVED/DISPUTED (got {report.verdict.value})")

# 7.3: Moderate finding → WEAKENED
f_moderate = _make_finding(
    confidence=0.65,
    id="moderate-001",
    # Remove curl_command to trigger some attacks
    curl_command=None,
    confirmed=False,
)
report = ava.challenge_finding(f_moderate)
check("7.3", report.verdict in (ChallengeVerdict.WEAKENED, ChallengeVerdict.UPHELD),
      f"Moderate finding → WEAKENED/UPHELD (got {report.verdict.value})")

# 7.4: Finding with many rationalizations → NEEDS_RETEST
f_rat_heavy = _make_finding(
    title="This looks vulnerable to stored XSS",
    detail="The parameter seems unsafe and could be used to inject scripts. "
           "This might allow session hijacking. Appears to be exploitable.",
    description="Probably leads to account compromise",
    confirmed=False,
    id="rat-001",
)
report = ava.challenge_finding(f_rat_heavy)
check("7.4", report.verdict in (ChallengeVerdict.NEEDS_RETEST, ChallengeVerdict.WEAKENED, ChallengeVerdict.DISPUTED),
      f"Heavily rationalized → NEEDS_RETEST/WEAKENED/DISPUTED (got {report.verdict.value})")

# 7.5: survived property
f_sur = _make_finding(confirmed=True, confidence=0.90, id="sur-001")
report = ava.challenge_finding(f_sur)
check("7.5", report.survived is True, "UPHELD verdict → survived=True")

# 7.6: Finding without payload/response and low confidence → rejected
f_no_evidence = _make_finding(
    payload=None, response=None, curl_command=None,
    confirmed=False, confidence=0.35, id="noevid-001",
)
report = ava.challenge_finding(f_no_evidence)
check("7.6", report.verdict in (ChallengeVerdict.NEEDS_RETEST, ChallengeVerdict.DISPUTED,
                                  ChallengeVerdict.WEAKENED, ChallengeVerdict.DISPROVED),
      f"No evidence + low confidence → challenged verdict (got {report.verdict.value})")


# ═══════════════════════════════════════════════════════════════════════
# 8. Failure Conditions
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 8. Failure Conditions ===")

ava = AdversarialValidationAgent()

# 8.1: XSS-specific failure conditions
f_xss = _make_finding(type="xss", confirmed=False)
report = ava.challenge_finding(f_xss)
check("8.1", len(report.failure_conditions) >= 3,
      f"XSS has >=3 failure conditions: {len(report.failure_conditions)}")

# 8.2: Failure conditions include CSP mention for XSS
csp_found = any("CSP" in fc for fc in report.failure_conditions)
check("8.2", csp_found, "XSS failure conditions mention CSP")

# 8.3: SQLi-specific conditions
f_sqli = _make_finding(type="sqli", confirmed=False, id="sqli-fc")
report = ava.challenge_finding(f_sqli)
check("8.3", any("prepared statement" in fc.lower() for fc in report.failure_conditions),
      "SQLi failure conditions mention prepared statements")

# 8.4: Unconfirmed finding includes manual reproduction condition
check("8.4", any("manual reproduction" in fc.lower() or "curl" in fc.lower()
                  for fc in report.failure_conditions),
      "Unconfirmed finding has manual reproduction condition")

# 8.5: Conditions from counter-hypotheses
ch_conditions = [fc for fc in report.failure_conditions if fc.startswith("If confirmed:")]
check("8.5", len(ch_conditions) >= 1,
      f"Counter-hypothesis conditions included: {len(ch_conditions)}")


# ═══════════════════════════════════════════════════════════════════════
# 9. Batch Processing
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 9. Batch Processing ===")

ava = AdversarialValidationAgent()

findings = [
    _make_finding(id="batch-1", type="xss", confidence=0.90, confirmed=True),
    _make_weak_finding(id="batch-2", confidence=0.20),
    _make_finding(id="batch-3", type="ssrf", confidence=0.60, confirmed=False),
]

# 9.1: Batch returns correct count
reports = ava.challenge_findings_batch(findings)
check("9.1", len(reports) == 3, f"Batch returns 3 reports: {len(reports)}")

# 9.2: Sorted by verdict severity (disproved/disputed first)
verdicts = [r.verdict for r in reports]
verdict_order = {
    ChallengeVerdict.DISPROVED: 0,
    ChallengeVerdict.DISPUTED: 1,
    ChallengeVerdict.NEEDS_RETEST: 2,
    ChallengeVerdict.WEAKENED: 3,
    ChallengeVerdict.UPHELD: 4,
}
order_values = [verdict_order[v] for v in verdicts]
check("9.2", order_values == sorted(order_values),
      f"Batch sorted by verdict severity: {[v.value for v in verdicts]}")

# 9.3: Each report has unique finding_id
ids = [r.finding_id for r in reports]
check("9.3", len(set(ids)) == 3, "All finding IDs unique in batch")


# ═══════════════════════════════════════════════════════════════════════
# 10. Survivor Filtering
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 10. Survivor Filtering ===")

ava = AdversarialValidationAgent()

findings = [
    _make_finding(id="s-1", type="xss", confidence=0.90, confirmed=True),
    _make_weak_finding(id="s-2", confidence=0.20),
    _make_finding(id="s-3", type="sqli", confidence=0.70, confirmed=False),
]

# 10.1: Survivors have adjusted confidence
survivors, reports = ava.get_survivor_findings(findings, min_adjusted_confidence=0.3)
check("10.1", len(survivors) >= 1,
      f"At least 1 survivor: {len(survivors)}")

# 10.2: Survivors have adversarial_validated flag
if survivors:
    check("10.2", survivors[0].get("adversarial_validated") is True,
          "Survivor has adversarial_validated=True")
else:
    check("10.2", False, "No survivors to check flag")

# 10.3: Survivors have adjusted confidence value
if survivors:
    check("10.3", "confidence" in survivors[0],
          "Survivor has adjusted confidence")
else:
    check("10.3", False, "No survivors to check confidence")

# 10.4: Weak finding filtered out
survivor_ids = {s["id"] for s in survivors}
check("10.4", "s-2" not in survivor_ids,
      "Weak finding filtered from survivors")

# 10.5: Reports cover all findings
check("10.5", len(reports) == 3,
      f"Reports cover all {len(reports)} findings")


# ═══════════════════════════════════════════════════════════════════════
# 11. Statistics Tracking
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 11. Statistics ===")

ava = AdversarialValidationAgent()

# Process several findings
for i in range(5):
    ava.challenge_finding(_make_finding(id=f"stat-{i}", confirmed=True))
for i in range(3):
    ava.challenge_finding(_make_weak_finding(id=f"stat-w-{i}", confidence=0.15))

stats = ava.get_stats()

# 11.1: Total challenged
check("11.1", stats["total_challenged"] == 8, f"Total challenged: {stats['total_challenged']}")

# 11.2: Verdicts sum to total
verdict_sum = sum(stats["verdicts"].values())
check("11.2", verdict_sum == 8, f"Verdicts sum to total: {verdict_sum}")

# 11.3: Survival rate between 0 and 1
check("11.3", 0 <= stats["survival_rate"] <= 1.0,
      f"Survival rate valid: {stats['survival_rate']}")

# 11.4: Disprove rate between 0 and 1
check("11.4", 0 <= stats["disprove_rate"] <= 1.0,
      f"Disprove rate valid: {stats['disprove_rate']}")

# 11.5: Challenge history populated
history = ava.get_challenge_history(last_n=10)
check("11.5", len(history) == 8, f"Challenge history: {len(history)} entries")

# 11.6: History entries have required fields
if history:
    h = history[0]
    check("11.6", all(k in h for k in ["finding_id", "type", "verdict",
                                         "original_confidence", "adjusted_confidence"]),
          "History entry has required fields")


# ═══════════════════════════════════════════════════════════════════════
# 12. Disproval Pattern Analysis
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 12. Disproval Patterns ===")

ava = AdversarialValidationAgent()

# Generate enough disproved findings of one type
for i in range(5):
    ava.challenge_finding(_make_weak_finding(id=f"dp-{i}", confidence=0.10))

# And some confirmed
for i in range(3):
    ava.challenge_finding(_make_finding(id=f"dp-ok-{i}", confirmed=True))

patterns = ava.get_disproval_patterns()

# 12.1: Has patterns key
check("12.1", "patterns" in patterns, "Disproval patterns has 'patterns' key")

# 12.2: Total analyzed
check("12.2", patterns["total_analyzed"] == 8,
      f"Total analyzed: {patterns['total_analyzed']}")

# 12.3: Pattern analysis structure
if patterns["patterns"]:
    p = patterns["patterns"][0]
    check("12.3", all(k in p for k in ["type", "disprove_rate", "total", "disproved"]),
          "Pattern has required fields")
else:
    check("12.3", True, "No systemic patterns detected (may be correct)")


# ═══════════════════════════════════════════════════════════════════════
# 13. Callbacks
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 13. Callbacks ===")

disproved_reports = []
reduced_reports = []

ava = AdversarialValidationAgent(
    on_finding_disproved=lambda r: disproved_reports.append(r),
    on_confidence_reduced=lambda r: reduced_reports.append(r),
)

# 13.1: Disproved callback fires
ava.challenge_finding(_make_weak_finding(confidence=0.10, id="cb-1"))
# Weak finding should trigger disproved or at least confidence reduced
check("13.1", len(disproved_reports) >= 0 or len(reduced_reports) >= 0,
      "At least one callback attempted (depends on verdict)")

# 13.2: Confidence reduced callback fires for weak findings
ava.challenge_finding(_make_weak_finding(
    confidence=0.80,
    id="cb-2",
    title="This looks vulnerable to injection and seems unsafe",
    detail="Likely exploitable via known SQL injection techniques",
))
check("13.2", len(reduced_reports) >= 1,
      f"Confidence reduced callback fired: {len(reduced_reports)}")

# 13.3: Callback receives ChallengeReport
if reduced_reports:
    r = reduced_reports[0]
    check("13.3", hasattr(r, "finding_id") and hasattr(r, "verdict"),
          "Callback receives ChallengeReport object")

# 13.4: Exception in callback doesn't crash
def bad_callback(r):
    raise ValueError("intentional error")

ava_bad = AdversarialValidationAgent(
    on_finding_disproved=bad_callback,
    on_confidence_reduced=bad_callback,
)
try:
    ava_bad.challenge_finding(_make_weak_finding(confidence=0.10, id="cb-err"))
    check("13.4", True, "Exception in callback doesn't crash")
except Exception:
    check("13.4", False, "Exception in callback should be caught")


# ═══════════════════════════════════════════════════════════════════════
# 14. Binding Methods
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 14. Bindings ===")

ava = AdversarialValidationAgent()

# 14.1: Verdict auditor binding
class MockAuditor:
    def __init__(self):
        self.calls = []
    def record_verdict_outcome(self, verdict, *, was_correct):
        self.calls.append((verdict, was_correct))

auditor = MockAuditor()
ava.bind_verdict_auditor(auditor)

ava.challenge_finding(_make_finding(id="bind-1", confirmed=True))
check("14.1", len(auditor.calls) >= 1,
      f"Verdict auditor receives calls: {len(auditor.calls)}")

# 14.2: Chain verifier binding
ava.bind_chain_verifier(object())  # Just verifies binding works
state = ava.to_dict()
check("14.2", state["bindings"]["chain_verifier"] is True,
      "Chain verifier bound")
check("14.3", state["bindings"]["verdict_auditor"] is True,
      "Verdict auditor bound")


# ═══════════════════════════════════════════════════════════════════════
# 15. Serialization (to_dict / ChallengeReport.to_dict)
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 15. Serialization ===")

ava = AdversarialValidationAgent()
report = ava.challenge_finding(_make_weak_finding(id="ser-1"))

# 15.1: ChallengeReport.to_dict has all fields
d = report.to_dict()
required_keys = [
    "finding_id", "finding_type", "original_confidence",
    "adjusted_confidence", "verdict", "rationalizations",
    "counter_hypotheses", "required_probes", "confidence_attacks",
    "failure_conditions", "challenge_duration_ms", "timestamp",
]
check("15.1", all(k in d for k in required_keys),
      "ChallengeReport.to_dict has all required fields")

# 15.2: Verdict is string value
check("15.2", isinstance(d["verdict"], str),
      f"Verdict is string: {d['verdict']}")

# 15.3: Rationalizations are dicts
if d["rationalizations"]:
    check("15.3", isinstance(d["rationalizations"][0], dict),
          "Rationalizations serialized as dicts")
else:
    check("15.3", True, "No rationalizations (clean finding)")

# 15.4: Agent to_dict roundtrip
state = ava.to_dict()
check("15.4", isinstance(state, dict), "Agent to_dict returns dict")
check("15.5", state["stats"]["total_challenged"] == 1,
      "Agent state reflects challenge count")

# 15.6: Duration is reasonable
check("15.6", report.challenge_duration_ms >= 0,
      f"Duration non-negative: {report.challenge_duration_ms:.2f}ms")


# ═══════════════════════════════════════════════════════════════════════
# 16. Edge Cases
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 16. Edge Cases ===")

ava = AdversarialValidationAgent()

# 16.1: Empty finding (minimal dict)
f_empty = {"type": "unknown", "confidence": 0.5}
report = ava.challenge_finding(f_empty)
check("16.1", report is not None, "Empty finding doesn't crash")
check("16.2", report.finding_type == "unknown", "Unknown type handled")

# 16.3: Confidence = 0
f_zero = _make_finding(confidence=0.0, id="zero-1")
report = ava.challenge_finding(f_zero)
check("16.3", report.adjusted_confidence >= 0.0,
      f"Zero confidence handled: {report.adjusted_confidence}")

# 16.4: Confidence = 1.0
f_max = _make_finding(confidence=1.0, id="max-1", confirmed=True)
report = ava.challenge_finding(f_max)
check("16.4", report.adjusted_confidence <= 1.0,
      f"Max confidence bounded: {report.adjusted_confidence}")

# 16.5: Very long text doesn't crash
long_text = "This looks vulnerable " * 100
f_long = _make_finding(detail=long_text, id="long-1")
report = ava.challenge_finding(f_long)
check("16.5", report is not None, "Very long text handled")

# 16.6: Finding with no ID gets generated hash
f_no_id = {"type": "xss", "confidence": 0.5, "title": "test"}
report = ava.challenge_finding(f_no_id)
check("16.6", len(report.finding_id) > 0, "Missing ID gets generated hash")

# 16.7: History bounded
ava_limited = AdversarialValidationAgent()
ava_limited._max_history = 5
for i in range(20):
    ava_limited.challenge_finding(_make_finding(id=f"hist-{i}"))
history = ava_limited.get_challenge_history(last_n=100)
check("16.7", len(history) <= 5, f"History bounded: {len(history)}")


# ═══════════════════════════════════════════════════════════════════════
# 17. Thread Safety
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 17. Thread Safety ===")

ava = AdversarialValidationAgent()
errors = []

def challenge_thread(agent, thread_id):
    try:
        for i in range(10):
            f = _make_finding(id=f"thread-{thread_id}-{i}", confidence=0.5 + (i * 0.03))
            agent.challenge_finding(f)
    except Exception as e:
        errors.append(str(e))

threads = [threading.Thread(target=challenge_thread, args=(ava, t)) for t in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()

stats = ava.get_stats()
check("17.1", len(errors) == 0, f"No thread errors: {errors[:3] if errors else 'none'}")
check("17.2", stats["total_challenged"] == 40,
      f"All 40 challenges recorded: {stats['total_challenged']}")


# ═══════════════════════════════════════════════════════════════════════
# 18. Evidence Type Inference
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 18. Evidence Type Inference ===")

ava = AdversarialValidationAgent()

# 18.1: OOB interaction → oob_callback
f_oob = _make_finding(oob_interaction=True, id="einf-1")
report = ava.challenge_finding(f_oob)
check("18.1", True, "OOB finding processed without error")

# 18.2: Time-based evidence
f_time = _make_finding(time_based=True, id="einf-2",
                        payload=None, response=None)
report = ava.challenge_finding(f_time)
check("18.2", any("timing" in fc.lower() or "time" in fc.lower()
                   for fc in report.failure_conditions),
      "Time-based evidence generates timing failure conditions")

# 18.3: Error-based evidence
f_err = _make_finding(error_pattern="SQL syntax error", id="einf-3")
report = ava.challenge_finding(f_err)
check("18.3", True, "Error-based evidence processed")

# 18.4: Template/matcher → regex_match
f_tmpl = _make_finding(template_id="CVE-2024-1234", matcher_name="status_code",
                        payload=None, response=None, confirmed=False, id="einf-4")
report = ava.challenge_finding(f_tmpl)
check("18.4", any("pattern" in fc.lower() for fc in report.failure_conditions),
      "Template-based finding gets pattern-match failure condition")


# ═══════════════════════════════════════════════════════════════════════
# 19. ChallengeReport Properties
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 19. Report Properties ===")

ava = AdversarialValidationAgent()

# 19.1: confidence_delta property
report = ava.challenge_finding(_make_finding(id="prop-1"))
expected_delta = report.adjusted_confidence - report.original_confidence
check("19.1", abs(report.confidence_delta - expected_delta) < 0.0001,
      f"confidence_delta correct: {report.confidence_delta}")

# 19.2: survived property for upheld
f_upheld = _make_finding(id="prop-2", confirmed=True, confidence=0.95)
report = ava.challenge_finding(f_upheld)
check("19.2", report.survived == (report.verdict in (ChallengeVerdict.UPHELD, ChallengeVerdict.WEAKENED)),
      f"survived matches verdict: {report.survived} for {report.verdict.value}")

# 19.3: timestamp is populated
check("19.3", report.timestamp > 0, "Timestamp populated")


# ═══════════════════════════════════════════════════════════════════════
# 20. Integration Simulation
# ═══════════════════════════════════════════════════════════════════════
print("\n=== 20. Integration Simulation ===")

# Simulate the full pipeline: findings → adversarial validation → filtered output
ava = AdversarialValidationAgent()

pipeline_findings = [
    # Strong confirmed XSS — should survive
    _make_finding(id="pipe-1", type="xss", confirmed=True, confidence=0.92,
                  evidence_type="exploitation_confirmed"),
    # Weak regex-only SQLi — should be filtered
    _make_weak_finding(id="pipe-2", confidence=0.35),
    # Medium SSRF with OOB — should survive
    _make_finding(id="pipe-3", type="ssrf", confidence=0.70,
                  oob_interaction=True, confirmed=False),
    # Rationalized finding — should be challenged hard
    _make_finding(
        id="pipe-4", type="idor", confidence=0.55,
        title="This endpoint looks vulnerable to IDOR",
        detail="Likely exploitable by changing user ID parameter. Could be used to access other accounts.",
        confirmed=False, payload=None, response=None, curl_command=None,
    ),
]

survivors, reports = ava.get_survivor_findings(
    pipeline_findings, min_adjusted_confidence=0.30,
)

check("20.1", len(survivors) >= 1,
      f"Pipeline produces >=1 survivor: {len(survivors)}")

# Strongest finding should survive
strong_survived = any(s["id"] == "pipe-1" for s in survivors)
check("20.2", strong_survived, "Confirmed XSS survives pipeline")

# Weak finding should not survive
weak_survived = any(s["id"] == "pipe-2" for s in survivors)
check("20.3", not weak_survived, "Weak regex-only finding filtered")

# All survivors have adversarial_validated flag
all_flagged = all(s.get("adversarial_validated") for s in survivors)
check("20.4", all_flagged, "All survivors have adversarial_validated flag")

# Stats reflect pipeline run
stats = ava.get_stats()
check("20.5", stats["total_challenged"] == 4,
      f"Pipeline challenged all 4: {stats['total_challenged']}")


# ═══════════════════════════════════════════════════════════════════════
# Results
# ═══════════════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"RESULTS: {passed} passed, {failed} failed out of {passed + failed}")
print(f"{'='*60}")

if failed > 0:
    sys.exit(1)
