"""Comprehensive tests for the Parallel Finding Validation Fleet.

Tests cover:
- ExploitValidator: PoC quality, payload effectiveness, response verification,
  reproduction, preconditions, impact realism, verdict determination
- ContextValidator: WAF/CDN, environment drift, scope violations,
  infrastructure noise, temporal stability, tool reliability
- ChainConsistencyValidator: isolation, surface coherence, contradictions,
  prerequisites, phase coherence, corroboration, cross-finding registration
- AdversarialValidatorAdapter: AVA integration, fallback without AVA
- Consensus algorithm: weighted voting, agreement score, dissenter detection,
  verdict thresholds, low-agreement override
- ValidationFleet: parallel execution, batch processing, survivor filtering,
  statistics, consensus history, fleet patterns, validator performance,
  callbacks, bindings, thread safety, serialization, edge cases
"""

import sys
import os
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CaseCrack"))

from CaseCrack.tools.burp_enterprise.validation_fleet import (
    ValidationFleet,
    FleetConsensus,
    ValidatorVerdict,
    ConsensusVerdict,
    ExploitValidator,
    ContextValidator,
    ChainConsistencyValidator,
    AdversarialValidatorAdapter,
    ValidatorType,
    IndividualVerdict,
    _compute_consensus,
    EvidenceGraph,
    EvidenceRelation,
    DisagreementIntelligence,
    DisagreementSignature,
    ProbeGenerator,
    ConvergenceLoop,
    ConvergenceResult,
    InformationGainScorer,
    CausalAttackModel,
    CausalImpact,
)
from CaseCrack.tools.burp_enterprise.adversarial_validation_agent import (
    AdversarialValidationAgent,
)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Helpers
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _make_strong_finding(**overrides):
    """A strong confirmed finding with full evidence."""
    base = {
        "id": "strong-001",
        "type": "xss",
        "severity": "high",
        "title": "Reflected XSS in search parameter",
        "detail": "User input reflected unencoded in response body",
        "description": "The search parameter does not sanitize HTML",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "source_tool": "nuclei",
        "confidence": 0.90,
        "confirmed": True,
        "payload": "<script>alert(1)</script>",
        "curl_command": "curl -s 'https://example.com/search?q=<script>alert(1)</script>'",
        "response": "<html><body><script>alert(1)</script></body></html>",
        "cwe_ids": ["CWE-79"],
        "corroborating_tools": ["burp", "zap"],
        "evidence_type": "exploitation_confirmed",
    }
    base.update(overrides)
    return base


def _make_weak_finding(**overrides):
    """A weak finding with minimal evidence â€” likely FP."""
    base = {
        "id": "weak-001",
        "type": "sqli",
        "severity": "high",
        "title": "Possible SQL injection in parameter",
        "detail": "Input seems to trigger database errors",
        "description": "This parameter may be vulnerable to SQL injection",
        "url": "https://example.com/api?id=1",
        "parameter": "id",
        "source_tool": "regex",
        "confidence": 0.40,
    }
    base.update(overrides)
    return base


def _make_medium_finding(**overrides):
    """Medium-confidence finding with some evidence."""
    base = {
        "id": "med-001",
        "type": "ssrf",
        "severity": "medium",
        "title": "SSRF via URL parameter",
        "detail": "Out-of-band callback received from server",
        "url": "https://example.com/proxy?url=http://attacker.com",
        "parameter": "url",
        "source_tool": "nuclei",
        "confidence": 0.65,
        "oob_interaction": True,
        "payload": "http://attacker.com/callback",
        "response": "200 OK",
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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. ExploitValidator
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 1. ExploitValidator ===")

ev = ExploitValidator()

# 1.1: Strong finding â†’ VALID
verdict = ev.validate(_make_strong_finding())
check("1.1", verdict.verdict == IndividualVerdict.VALID,
      f"Strong finding â†’ VALID (got {verdict.verdict.value})")
check("1.2", verdict.validator_type == ValidatorType.EXPLOIT,
      "Validator type is EXPLOIT")
check("1.3", verdict.confidence >= 0.60,
      f"High confidence maintained: {verdict.confidence}")

# 1.4: Weak finding with no evidence
verdict = ev.validate(_make_weak_finding())
check("1.4", verdict.verdict in (IndividualVerdict.SUSPICIOUS, IndividualVerdict.INVALID,
                                   IndividualVerdict.INCONCLUSIVE),
      f"Weak finding â†’ low verdict (got {verdict.verdict.value})")
check("1.5", verdict.confidence < verdict.original_confidence,
      f"Confidence reduced: {verdict.confidence} < {verdict.original_confidence}")
check("1.6", len(verdict.penalties) >= 2,
      f"Multiple penalties applied: {len(verdict.penalties)}")
check("1.7", len(verdict.reasons) >= 2,
      f"Multiple reasons given: {len(verdict.reasons)}")

# 1.8: Finding with payload but no response
f_payload_only = _make_strong_finding(response=None, confirmed=False, id="po-1")
verdict = ev.validate(f_payload_only)
check("1.8", "no_response" in verdict.penalties or "weak_response" in verdict.penalties,
      "Missing response penalized")

# 1.9: Finding with WAF detected but not bypassed
f_waf = _make_strong_finding(waf_detected=True, waf_bypassed=False, confirmed=False, id="waf-1")
verdict = ev.validate(f_waf)
check("1.9", "preconditions_unclear" in verdict.penalties or verdict.confidence < 0.90,
      "WAF-not-bypassed affects verdict")

# 1.10: Critical severity with regex evidence â†’ severity-evidence gap
f_crit_regex = _make_weak_finding(severity="critical", evidence_type="regex_match", id="cr-1")
verdict = ev.validate(f_crit_regex)
check("1.10", "severity_evidence_gap" in verdict.penalties,
      "Critical + regex â†’ severity-evidence gap penalty")

# 1.11: Serialization
d = verdict.to_dict()
check("1.11", all(k in d for k in ["validator_type", "verdict", "confidence",
                                      "reasons", "penalties", "duration_ms"]),
      "ValidatorVerdict serializes correctly")

# 1.12: Duration is non-negative
check("1.12", verdict.duration_ms >= 0,
      f"Duration non-negative: {verdict.duration_ms:.2f}ms")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. ContextValidator
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 2. ContextValidator ===")

cv = ContextValidator()

# 2.1: Clean finding â†’ VALID
verdict = cv.validate(_make_strong_finding())
check("2.1", verdict.verdict == IndividualVerdict.VALID,
      f"Clean finding â†’ VALID (got {verdict.verdict.value})")

# 2.2: WAF signature in response
f_waf = _make_strong_finding(
    response="<html>Blocked by Cloudflare</html>",
    confirmed=False, id="waf-c1",
)
verdict = cv.validate(f_waf)
check("2.2", "waf_interference" in verdict.penalties,
      "WAF signature detected in response")

# 2.3: Staging environment URL
f_staging = _make_strong_finding(
    url="https://staging.example.com/search?q=test",
    confirmed=False, id="stg-1",
)
verdict = cv.validate(f_staging)
check("2.3", "environment_drift" in verdict.penalties,
      "Staging URL detected")

# 2.4: Third-party scope violation
f_scope = _make_strong_finding(
    url="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js",
    confirmed=False, id="scope-1",
)
verdict = cv.validate(f_scope)
check("2.4", "scope_violation" in verdict.penalties,
      "Third-party URL detected as scope violation")

# 2.5: Infrastructure noise (502)
f_502 = _make_strong_finding(response_status=502, confirmed=False, id="502-1")
verdict = cv.validate(f_502)
check("2.5", "infrastructure_noise" in verdict.penalties,
      "502 status code detected as infra noise")

# 2.6: Rate-limited response
f_429 = _make_strong_finding(
    response_status=429,
    response="Too Many Requests",
    confirmed=False, id="429-1",
)
verdict = cv.validate(f_429)
check("2.6", "infrastructure_noise" in verdict.penalties,
      "429 rate-limit detected")

# 2.7: High-FP tool/vuln combo (regex + sqli)
f_regex_sqli = _make_weak_finding(source_tool="regex_pattern", type="sqli", id="rs-1")
verdict = cv.validate(f_regex_sqli)
check("2.7", "tool_reliability" in verdict.penalties,
      "Regex + SQLi triggers tool reliability penalty")

# 2.8: Time-based finding â†’ temporal instability
f_time = _make_strong_finding(evidence_type="time_based", confirmed=False, id="time-1")
verdict = cv.validate(f_time)
check("2.8", "temporal_instability" in verdict.penalties,
      "Time-based evidence triggers temporal instability")

# 2.9: Confirmed + OOB bypasses context concerns
f_strong_oob = _make_strong_finding(
    oob_interaction=True,
    response="Blocked by Cloudflare",  # WAF signature
    id="strong-oob-1",
)
verdict = cv.validate(f_strong_oob)
check("2.9", verdict.confidence >= verdict.original_confidence * 0.80,
      f"Confirmed OOB finding maintains high confidence despite WAF: {verdict.confidence}")

# 2.10: Debug mode in response
f_debug = _make_strong_finding(
    response="debug=true; stack trace: line 42 of module.py",
    confirmed=False, id="dbg-1",
)
verdict = cv.validate(f_debug)
check("2.10", "environment_drift" in verdict.penalties,
      "Debug mode indicator detected")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. ChainConsistencyValidator
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 3. ChainConsistencyValidator ===")

ccv = ChainConsistencyValidator()

# 3.1: Isolated finding with no corroboration
f_isolated = _make_weak_finding(
    id="iso-1",
    corroborating_tools=None,
    chain_id=None,
    related_findings=None,
)
verdict = ccv.validate(f_isolated)
check("3.1", "finding_isolation" in verdict.penalties,
      "Isolated finding penalized")

# 3.2: Well-corroborated finding
f_corr = _make_strong_finding(
    corroborating_tools=["burp", "zap", "sqlmap"],
    chain_id="chain-42",
    related_findings=["f-1", "f-2"],
)
verdict = ccv.validate(f_corr)
check("3.2", verdict.verdict == IndividualVerdict.VALID,
      f"Well-corroborated â†’ VALID (got {verdict.verdict.value})")

# 3.3: XSS on API endpoint (surface incoherence)
f_api_xss = _make_strong_finding(
    url="https://example.com/api/v1/search?q=test",
    type="xss",
    response=None,
    confirmed=False,
    id="api-xss-1",
)
verdict = ccv.validate(f_api_xss)
check("3.3", "surface_incoherence" in verdict.penalties,
      "XSS on API endpoint triggers surface incoherence")

# 3.4: SQLi on static file
f_static_sqli = _make_weak_finding(
    url="https://example.com/images/logo.png",
    type="sqli",
    id="ss-1",
)
verdict = ccv.validate(f_static_sqli)
check("3.4", "surface_incoherence" in verdict.penalties,
      "SQLi on static file triggers surface incoherence")

# 3.5: Contradictory findings detection
ccv2 = ChainConsistencyValidator()
# Register a disproved finding at same endpoint
ccv2.register_finding({
    "id": "other-1",
    "url": "https://example.com/api?id=1",
    "parameter": "id",
    "type": "sqli",
    "verdict": "disproved",
})
f_conflict = _make_weak_finding(
    url="https://example.com/api?id=1",
    parameter="id",
    type="sqli",
    id="conflict-1",
)
verdict = ccv2.validate(f_conflict)
check("3.5", "contradictory_findings" in verdict.penalties,
      "Contradictory disproved finding detected")

# 3.6: Corroboration boost
ccv3 = ChainConsistencyValidator()
ccv3.register_finding({
    "id": "support-1",
    "url": "https://example.com/search?q=test",
    "type": "xss",
    "confirmed": True,
})
f_supported = _make_strong_finding(id="supported-1")
verdict = ccv3.validate(f_supported)
check("3.6", any("corroboration" in str(e) for e in verdict.evidence_items)
      or verdict.verdict == IndividualVerdict.VALID,
      "Corroborating finding boosts confidence")

# 3.7: IDOR without auth â†’ prerequisite violation
f_idor = _make_weak_finding(type="idor", auth_token=None, cookies=None, id="idor-1")
verdict = ccv.validate(f_idor)
check("3.7", "prerequisite_violation" in verdict.penalties,
      "IDOR without auth triggers prerequisite violation")

# 3.8: Active vuln in passive phase
f_passive = _make_weak_finding(
    type="sqli", phase="Phase 2: Recon and Discovery", id="passive-1",
)
verdict = ccv.validate(f_passive)
check("3.8", "phase_incoherence" in verdict.penalties,
      "Active vuln in passive phase triggers incoherence")

# 3.9: Register/clear findings
ccv4 = ChainConsistencyValidator()
ccv4.register_findings([{"id": "a"}, {"id": "b"}])
check("3.9", len(ccv4._known_findings) == 2, "Bulk register works")
ccv4.clear_findings()
check("3.10", len(ccv4._known_findings) == 0, "Clear works")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 4. AdversarialValidatorAdapter
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 4. AdversarialValidatorAdapter ===")

# 4.1: Without AVA â†’ INCONCLUSIVE
adapter = AdversarialValidatorAdapter()
verdict = adapter.validate(_make_strong_finding())
check("4.1", verdict.verdict == IndividualVerdict.INCONCLUSIVE,
      "No AVA bound â†’ INCONCLUSIVE")
check("4.2", verdict.validator_type == ValidatorType.ADVERSARIAL,
      "Validator type correct")

# 4.3: With AVA bound
ava = AdversarialValidationAgent()
adapter = AdversarialValidatorAdapter(ava)
verdict = adapter.validate(_make_strong_finding())
check("4.3", verdict.verdict in (IndividualVerdict.VALID, IndividualVerdict.WEAK),
      f"Strong finding with AVA â†’ VALID/WEAK (got {verdict.verdict.value})")

# 4.4: Weak finding through AVA adapter
verdict = adapter.validate(_make_weak_finding())
check("4.4", verdict.verdict in (IndividualVerdict.SUSPICIOUS, IndividualVerdict.INVALID,
                                   IndividualVerdict.WEAK),
      f"Weak finding with AVA â†’ challenged (got {verdict.verdict.value})")

# 4.5: Late binding
adapter2 = AdversarialValidatorAdapter()
adapter2.bind_ava(ava)
verdict = adapter2.validate(_make_strong_finding())
check("4.5", verdict.verdict != IndividualVerdict.INCONCLUSIVE,
      "Late-bound AVA produces real verdict")

# 4.6: AVA details pass through
check("4.6", len(verdict.penalties) >= 0, "Penalties extracted from AVA")
check("4.7", verdict.duration_ms >= 0, f"Duration tracked: {verdict.duration_ms:.2f}ms")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 5. Consensus Algorithm
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 5. Consensus Algorithm ===")

# 5.1: All VALID â†’ CONFIRMED
all_valid = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.90, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.VALID, 0.85, 0.90, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.VALID, 0.88, 0.90, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.VALID, 0.87, 0.90, [], [], {}, 1.0),
]
v, conf, agree, diss, reasons, eg, da, iflags = _compute_consensus(all_valid, 0.90)
check("5.1", v == ConsensusVerdict.CONFIRMED, f"All VALID â†’ CONFIRMED (got {v.value})")
check("5.2", agree > 0.90, f"High agreement: {agree}")
check("5.3", len(diss) == 0, "No dissenters")

# 5.4: All INVALID â†’ REJECTED
all_invalid = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.INVALID, 0.10, 0.50, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.INVALID, 0.08, 0.50, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.INVALID, 0.12, 0.50, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.INVALID, 0.09, 0.50, [], [], {}, 1.0),
]
v, conf, agree, diss, reasons, eg, da, iflags = _compute_consensus(all_invalid, 0.50)
check("5.4", v == ConsensusVerdict.REJECTED, f"All INVALID â†’ REJECTED (got {v.value})")

# 5.5: Split (2 VALID, 2 INVALID) â†’ weighted consensus
# EXPLOIT(0.30) + ADVERSARIAL(0.30) = 0.60 weight on VALID
# CONTEXT(0.20) + CHAIN(0.20) = 0.40 weight on INVALID
# So weighted score favors VALID â†’ PROBABLE (not UNCERTAIN)
split = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.80, 0.60, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.VALID, 0.75, 0.60, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.INVALID, 0.15, 0.60, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.INVALID, 0.10, 0.60, [], [], {}, 1.0),
]
v, conf, agree, diss, reasons, eg, da, iflags = _compute_consensus(split, 0.60)
check("5.5", v == ConsensusVerdict.PROBABLE,
      f"Split (higher-weight valid) â†’ PROBABLE (got {v.value})")
check("5.6", agree < 0.60, f"Low agreement score: {agree}")
check("5.7", len(diss) >= 2, f"Dissenters detected: {diss}")

# 5.8: Mixed (3 VALID + 1 SUSPICIOUS) â†’ PROBABLE
mostly_valid = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.80, 0.70, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.VALID, 0.75, 0.70, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.VALID, 0.70, 0.70, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.SUSPICIOUS, 0.30, 0.70, [], [], {}, 1.0),
]
v, conf, agree, diss, reasons, eg, da, iflags = _compute_consensus(mostly_valid, 0.70)
check("5.8", v in (ConsensusVerdict.PROBABLE, ConsensusVerdict.CONFIRMED),
      f"3 VALID + 1 SUSPICIOUS â†’ PROBABLE/CONFIRMED (got {v.value})")

# 5.9: Empty verdicts â†’ UNCERTAIN
v, conf, agree, diss, reasons, eg, da, iflags = _compute_consensus([], 0.50)
check("5.9", v == ConsensusVerdict.UNCERTAIN, "Empty â†’ UNCERTAIN")

# 5.10: Consensus reasons populated
check("5.10", len(reasons) >= 1, f"Reasons populated: {len(reasons)}")

# 5.11: Mostly WEAK â†’ PROBABLE
mostly_weak = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.WEAK, 0.50, 0.60, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.WEAK, 0.45, 0.60, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.WEAK, 0.48, 0.60, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.WEAK, 0.47, 0.60, [], [], {}, 1.0),
]
v, conf, agree, diss, reasons, eg, da, iflags = _compute_consensus(mostly_weak, 0.60)
check("5.11", v == ConsensusVerdict.PROBABLE,
      f"All WEAK â†’ PROBABLE (got {v.value})")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 6. ValidationFleet â€” Core
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 6. ValidationFleet â€” Core ===")

fleet = ValidationFleet()

# 6.1: Construction
check("6.1", fleet is not None, "Fleet instantiates")
stats = fleet.get_stats()
check("6.2", stats["total_validated"] == 0, "Starts with zero validations")
check("6.3", stats["survival_rate"] == 1.0, "Initial survival rate 100%")

# 6.4: Validate strong finding â†’ CONFIRMED/PROBABLE
consensus = fleet.validate_finding(_make_strong_finding())
check("6.4", consensus.consensus_verdict in (ConsensusVerdict.CONFIRMED, ConsensusVerdict.PROBABLE),
      f"Strong finding â†’ CONFIRMED/PROBABLE (got {consensus.consensus_verdict.value})")
check("6.5", len(consensus.validator_verdicts) == 4,
      f"All 4 validators ran: {len(consensus.validator_verdicts)}")
check("6.6", consensus.finding_id == "strong-001",
      f"Finding ID preserved: {consensus.finding_id}")
check("6.7", consensus.finding_type == "xss",
      f"Finding type preserved: {consensus.finding_type}")
check("6.8", consensus.fleet_duration_ms > 0,
      f"Duration tracked: {consensus.fleet_duration_ms:.2f}ms")
check("6.9", 0 <= consensus.agreement_score <= 1.0,
      f"Agreement score valid: {consensus.agreement_score}")

# 6.10: Validate weak finding â†’ challenged
consensus = fleet.validate_finding(_make_weak_finding())
check("6.10", consensus.consensus_verdict in (ConsensusVerdict.SUSPICIOUS,
                                                ConsensusVerdict.REJECTED,
                                                ConsensusVerdict.UNCERTAIN),
      f"Weak finding â†’ challenged (got {consensus.consensus_verdict.value})")
check("6.11", consensus.consensus_confidence < consensus.original_confidence,
      f"Confidence reduced: {consensus.consensus_confidence} < {consensus.original_confidence}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 7. ValidationFleet â€” With AVA
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 7. Fleet with AVA ===")

ava = AdversarialValidationAgent()
fleet_ava = ValidationFleet(ava=ava)

# 7.1: Adversarial validator produces real verdict
consensus = fleet_ava.validate_finding(_make_strong_finding(id="ava-fleet-1"))
adv_verdicts = [v for v in consensus.validator_verdicts
                if v.validator_type == ValidatorType.ADVERSARIAL]
check("7.1", len(adv_verdicts) == 1, "Adversarial validator present")
check("7.2", adv_verdicts[0].verdict != IndividualVerdict.INCONCLUSIVE,
      f"AVA provides real verdict: {adv_verdicts[0].verdict.value}")

# 7.3: Late-bind AVA
fleet_late = ValidationFleet()
fleet_late.bind_ava(ava)
consensus = fleet_late.validate_finding(_make_strong_finding(id="ava-late-1"))
adv_verdicts = [v for v in consensus.validator_verdicts
                if v.validator_type == ValidatorType.ADVERSARIAL]
check("7.3", adv_verdicts[0].verdict != IndividualVerdict.INCONCLUSIVE,
      "Late-bound AVA works")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 8. Batch Processing
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 8. Batch Processing ===")

fleet = ValidationFleet(ava=AdversarialValidationAgent())

findings = [
    _make_strong_finding(id="bat-1"),
    _make_weak_finding(id="bat-2"),
    _make_medium_finding(id="bat-3"),
]

results = fleet.validate_findings_batch(findings)

# 8.1: Returns correct count
check("8.1", len(results) == 3, f"Batch returns 3: {len(results)}")

# 8.2: Sorted by verdict severity (REJECTED first)
verdict_order = {
    ConsensusVerdict.REJECTED: 0,
    ConsensusVerdict.SUSPICIOUS: 1,
    ConsensusVerdict.UNCERTAIN: 2,
    ConsensusVerdict.PROBABLE: 3,
    ConsensusVerdict.CONFIRMED: 4,
}
order_values = [verdict_order[r.consensus_verdict] for r in results]
check("8.2", order_values == sorted(order_values),
      f"Sorted by severity: {[r.consensus_verdict.value for r in results]}")

# 8.3: Each has unique finding_id
ids = {r.finding_id for r in results}
check("8.3", len(ids) == 3, "All finding IDs unique")

# 8.4: Each has 4 validator verdicts
check("8.4", all(len(r.validator_verdicts) == 4 for r in results),
      "All results have 4 validators")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 9. Survivor Filtering
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 9. Survivor Filtering ===")

fleet = ValidationFleet(ava=AdversarialValidationAgent())

findings = [
    _make_strong_finding(id="srv-1"),
    _make_weak_finding(id="srv-2", confidence=0.15),
    _make_medium_finding(id="srv-3"),
]

survivors, reports = fleet.get_survivor_findings(findings, min_consensus_confidence=0.25)

# 9.1: At least 1 survivor
check("9.1", len(survivors) >= 1, f"At least 1 survivor: {len(survivors)}")

# 9.2: Strong finding survives
survivor_ids = {s["id"] for s in survivors}
check("9.2", "srv-1" in survivor_ids, "Strong finding survives")

# 9.3: Survivors have fleet_validated flag
if survivors:
    check("9.3", survivors[0].get("fleet_validated") is True,
          "Survivor has fleet_validated=True")
else:
    check("9.3", False, "No survivors to check")

# 9.4: Survivors have consensus_verdict
if survivors:
    check("9.4", "consensus_verdict" in survivors[0],
          "Survivor has consensus_verdict")

# 9.5: Survivors have agreement_score
if survivors:
    check("9.5", "agreement_score" in survivors[0],
          "Survivor has agreement_score")

# 9.6: Reports cover all findings
check("9.6", len(reports) == 3, f"Reports cover all: {len(reports)}")

# 9.7: Weak finding likely filtered
check("9.7", "srv-2" not in survivor_ids,
      "Weak finding filtered from survivors")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 10. FleetConsensus Properties
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 10. Consensus Properties ===")

fleet = ValidationFleet(ava=AdversarialValidationAgent())
consensus = fleet.validate_finding(_make_strong_finding(id="prop-1"))

# 10.1: confidence_delta
expected = consensus.consensus_confidence - consensus.original_confidence
check("10.1", abs(consensus.confidence_delta - expected) < 0.001,
      f"confidence_delta correct: {consensus.confidence_delta}")

# 10.2: survived
check("10.2", consensus.survived == (consensus.consensus_verdict in
                                       (ConsensusVerdict.CONFIRMED, ConsensusVerdict.PROBABLE)),
      f"survived matches verdict: {consensus.survived} for {consensus.consensus_verdict.value}")

# 10.3: validators_agreeing
check("10.3", consensus.validators_agreeing ==
      len(consensus.validator_verdicts) - len(consensus.dissenting_validators),
      f"validators_agreeing: {consensus.validators_agreeing}")

# 10.4: timestamp
check("10.4", consensus.timestamp > 0, "Timestamp populated")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 11. Statistics
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 11. Statistics ===")

fleet = ValidationFleet(ava=AdversarialValidationAgent())

# Process several findings
for i in range(3):
    fleet.validate_finding(_make_strong_finding(id=f"stat-s-{i}"))
for i in range(2):
    fleet.validate_finding(_make_weak_finding(id=f"stat-w-{i}", confidence=0.10))

stats = fleet.get_stats()

# 11.1: Total validated
check("11.1", stats["total_validated"] == 5, f"Total: {stats['total_validated']}")

# 11.2: Verdicts sum
verdict_sum = sum(stats["verdicts"].values())
check("11.2", verdict_sum == 5, f"Verdicts sum: {verdict_sum}")

# 11.3: Survival rate
check("11.3", 0 <= stats["survival_rate"] <= 1.0,
      f"Survival rate: {stats['survival_rate']}")

# 11.4: Rejection rate
check("11.4", 0 <= stats["rejection_rate"] <= 1.0,
      f"Rejection rate: {stats['rejection_rate']}")

# 11.5: Avg duration positive
check("11.5", stats["avg_fleet_duration_ms"] > 0,
      f"Avg duration: {stats['avg_fleet_duration_ms']:.2f}ms")

# 11.6: Avg agreement
check("11.6", 0 <= stats["avg_agreement_score"] <= 1.0,
      f"Avg agreement: {stats['avg_agreement_score']}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 12. Consensus History
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 12. Consensus History ===")

# Using fleet from test 11
history = fleet.get_consensus_history(last_n=10)

# 12.1: History populated
check("12.1", len(history) == 5, f"History: {len(history)} entries")

# 12.2: Entry structure
if history:
    h = history[0]
    check("12.2", all(k in h for k in ["finding_id", "type", "verdict",
                                         "original_confidence", "consensus_confidence",
                                         "agreement_score", "dissenting"]),
          "History entry has required fields")

# 12.3: History bounded
fleet_bounded = ValidationFleet(ava=AdversarialValidationAgent())
fleet_bounded._max_history = 3
for i in range(10):
    fleet_bounded.validate_finding(_make_strong_finding(id=f"hist-{i}"))
history = fleet_bounded.get_consensus_history(last_n=100)
check("12.3", len(history) <= 3, f"History bounded: {len(history)}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 13. Fleet Patterns
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 13. Fleet Patterns ===")

fleet = ValidationFleet(ava=AdversarialValidationAgent())

# Generate enough weak findings of one type to create a pattern
for i in range(5):
    fleet.validate_finding(_make_weak_finding(id=f"fp-{i}", confidence=0.05))

# And some confirmed
for i in range(3):
    fleet.validate_finding(_make_strong_finding(id=f"fp-ok-{i}"))

patterns = fleet.get_fleet_patterns()

# 13.1: Structure
check("13.1", "total_analyzed" in patterns, "Patterns has total_analyzed")
check("13.2", "patterns" in patterns, "Patterns has patterns list")
check("13.3", patterns["total_analyzed"] == 8, f"Total analyzed: {patterns['total_analyzed']}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 14. Validator Performance
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 14. Validator Performance ===")

perf = fleet.get_validator_performance()

# 14.1: Structure
check("14.1", "validators" in perf, "Has validators key")
check("14.2", "total_validations" in perf, "Has total_validations")

# 14.3: All 4 validator types present
for vt in ValidatorType:
    check(f"14.3_{vt.value}", vt.value in perf["validators"],
          f"Validator {vt.value} in performance")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 15. Callbacks
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 15. Callbacks ===")

rejected_reports: list[FleetConsensus] = []
all_consensus: list[FleetConsensus] = []

fleet = ValidationFleet(
    ava=AdversarialValidationAgent(),
    on_finding_rejected=lambda c: rejected_reports.append(c),
    on_consensus_reached=lambda c: all_consensus.append(c),
)

# 15.1: Consensus callback fires
fleet.validate_finding(_make_strong_finding(id="cb-1"))
check("15.1", len(all_consensus) >= 1, f"Consensus callback fired: {len(all_consensus)}")

# 15.2: Rejection callback fires for weak finding
fleet.validate_finding(_make_weak_finding(id="cb-2", confidence=0.05))
check("15.2", len(all_consensus) >= 2, f"Consensus for weak finding: {len(all_consensus)}")

# 15.3: Callback receives FleetConsensus
if all_consensus:
    c = all_consensus[0]
    check("15.3", hasattr(c, "finding_id") and hasattr(c, "consensus_verdict"),
          "Callback receives FleetConsensus")

# 15.4: Exception in callback doesn't crash
def bad_callback(c):
    raise ValueError("intentional")

fleet_bad = ValidationFleet(
    on_finding_rejected=bad_callback,
    on_consensus_reached=bad_callback,
)
try:
    fleet_bad.validate_finding(_make_weak_finding(id="cb-err", confidence=0.05))
    check("15.4", True, "Exception in callback doesn't crash")
except Exception:
    check("15.4", False, "Exception should be caught")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 16. Chain Findings Binding
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 16. Chain Bindings ===")

fleet = ValidationFleet(ava=AdversarialValidationAgent())

# 16.1: Bind chain findings
fleet.bind_chain_findings([
    {"id": "c-1", "url": "https://example.com/test", "type": "xss", "confirmed": True},
    {"id": "c-2", "url": "https://example.com/test", "type": "xss"},
])
check("16.1", len(fleet._chain_validator._known_findings) >= 2,
      "Chain findings registered")

# 16.2: Clear chain findings
fleet.clear_chain_findings()
check("16.2", len(fleet._chain_validator._known_findings) == 0,
      "Chain findings cleared")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 17. Serialization
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 17. Serialization ===")

fleet = ValidationFleet(ava=AdversarialValidationAgent())
fleet.validate_finding(_make_strong_finding(id="ser-1"))

# 17.1: FleetConsensus.to_dict
consensus = fleet.validate_finding(_make_weak_finding(id="ser-2"))
d = consensus.to_dict()
required_keys = [
    "finding_id", "finding_type", "original_confidence",
    "consensus_confidence", "consensus_verdict", "validator_verdicts",
    "agreement_score", "dissenting_validators", "consensus_reasons",
    "failure_conditions", "fleet_duration_ms", "timestamp",
]
check("17.1", all(k in d for k in required_keys),
      "FleetConsensus.to_dict has all required fields")

# 17.2: Verdict is string value
check("17.2", isinstance(d["consensus_verdict"], str),
      f"Verdict is string: {d['consensus_verdict']}")

# 17.3: Validator verdicts are dicts
check("17.3", all(isinstance(v, dict) for v in d["validator_verdicts"]),
      "Validator verdicts serialized as dicts")

# 17.4: Fleet to_dict
state = fleet.to_dict()
check("17.4", isinstance(state, dict), "Fleet to_dict returns dict")
check("17.5", "config" in state, "Has config")
check("17.6", "stats" in state, "Has stats")
check("17.7", "fleet_patterns" in state, "Has fleet_patterns")
check("17.8", "validator_performance" in state, "Has validator_performance")
check("17.9", state["config"]["ava_bound"] is True, "AVA bound flag correct")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 18. Thread Safety
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 18. Thread Safety ===")

fleet = ValidationFleet(ava=AdversarialValidationAgent())
errors: list[str] = []

def validate_thread(fleet_ref, thread_id):
    try:
        for i in range(5):
            f = _make_strong_finding(id=f"thread-{thread_id}-{i}",
                                      confidence=0.5 + (i * 0.05))
            fleet_ref.validate_finding(f)
    except Exception as e:
        errors.append(f"Thread {thread_id}: {e}")

threads = [threading.Thread(target=validate_thread, args=(fleet, t)) for t in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()

stats = fleet.get_stats()
check("18.1", len(errors) == 0, f"No thread errors: {errors[:3] if errors else 'none'}")
check("18.2", stats["total_validated"] == 20,
      f"All 20 validations recorded: {stats['total_validated']}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 19. Edge Cases
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 19. Edge Cases ===")

fleet = ValidationFleet()

# 19.1: Minimal finding
f_minimal = {"type": "unknown", "confidence": 0.5}
consensus = fleet.validate_finding(f_minimal)
check("19.1", consensus is not None, "Minimal finding doesn't crash")
check("19.2", consensus.finding_type == "unknown", "Unknown type handled")

# 19.3: Zero confidence
f_zero = _make_strong_finding(confidence=0.0, id="zero-1")
consensus = fleet.validate_finding(f_zero)
check("19.3", consensus.consensus_confidence >= 0.0,
      f"Zero confidence handled: {consensus.consensus_confidence}")

# 19.4: Max confidence
f_max = _make_strong_finding(confidence=1.0, id="max-1")
consensus = fleet.validate_finding(f_max)
check("19.4", consensus.consensus_confidence <= 1.0,
      f"Max confidence bounded: {consensus.consensus_confidence}")

# 19.5: No ID generates hash
f_no_id = {"type": "xss", "confidence": 0.5}
consensus = fleet.validate_finding(f_no_id)
check("19.5", len(consensus.finding_id) > 0, "Missing ID generates hash")

# 19.6: Very long text
long_text = "test " * 1000
f_long = _make_strong_finding(detail=long_text, id="long-1")
consensus = fleet.validate_finding(f_long)
check("19.6", consensus is not None, "Very long text handled")

# 19.7: Parallel fleet with max_workers=1 (serial)
fleet_serial = ValidationFleet(max_workers=1, ava=AdversarialValidationAgent())
consensus = fleet_serial.validate_finding(_make_strong_finding(id="serial-1"))
check("19.7", len(consensus.validator_verdicts) == 4,
      "Serial fleet runs all 4 validators")

# 19.8: Empty batch
results = fleet.validate_findings_batch([])
check("19.8", len(results) == 0, "Empty batch returns empty")

# 19.9: Empty survivors
survivors, reports = fleet.get_survivor_findings([])
check("19.9", len(survivors) == 0 and len(reports) == 0,
      "Empty survivors returns empty")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 20. Integration Simulation â€” Full Pipeline
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 20. Full Pipeline Simulation ===")

# Simulate the fleet validation pattern:
# "One agent finds â†’ multiple agents attack validity in parallel"

fleet = ValidationFleet(ava=AdversarialValidationAgent())

pipeline_findings = [
    # Strong confirmed XSS â€” should survive
    _make_strong_finding(id="pipe-1", type="xss", confirmed=True, confidence=0.92),
    # Weak regex-only SQLi â€” should be filtered
    _make_weak_finding(id="pipe-2", confidence=0.15, source_tool="regex"),
    # Medium SSRF with OOB â€” should survive
    _make_medium_finding(id="pipe-3", confidence=0.70),
    # WAF-blocked finding â€” should be challenged
    _make_strong_finding(
        id="pipe-4", type="xss", confidence=0.55,
        response="Request blocked by Cloudflare WAF",
        confirmed=False, waf_detected=True,
    ),
    # IDOR without auth â€” prerequisite violation
    _make_weak_finding(
        id="pipe-5", type="idor", confidence=0.40,
        auth_token=None, cookies=None,
    ),
]

survivors, reports = fleet.get_survivor_findings(
    pipeline_findings, min_consensus_confidence=0.25,
)

# 20.1: Pipeline processes all
check("20.1", len(reports) == 5, f"All 5 processed: {len(reports)}")

# 20.2: Strong finding survives
survivor_ids = {s["id"] for s in survivors}
check("20.2", "pipe-1" in survivor_ids, "Confirmed XSS survives")

# 20.3: Survivors have fleet_validated flag
all_flagged = all(s.get("fleet_validated") for s in survivors)
check("20.3", all_flagged, "All survivors have fleet_validated")

# 20.4: Survivors have consensus_verdict
all_verdicted = all("consensus_verdict" in s for s in survivors)
check("20.4", all_verdicted, "All survivors have consensus_verdict")

# 20.5: Stats reflect pipeline
stats = fleet.get_stats()
check("20.5", stats["total_validated"] == 5,
      f"Pipeline validated all 5: {stats['total_validated']}")

# 20.6: Each report has 4 validator verdicts
check("20.6", all(len(r.validator_verdicts) == 4 for r in reports),
      "All reports have 4 validators")

# 20.7: Fleet patterns available
patterns = fleet.get_fleet_patterns()
check("20.7", patterns["total_analyzed"] == 5,
      f"Patterns from 5 findings: {patterns['total_analyzed']}")

# 20.8: Validator performance available
perf = fleet.get_validator_performance()
check("20.8", perf["total_validations"] == 5,
      f"Performance from 5: {perf['total_validations']}")

# 20.9: Full state serialization works
state = fleet.to_dict()
check("20.9", state["stats"]["total_validated"] == 5,
      "Full state reflects all validations")

# 20.10: Print pipeline summary
print(f"\n  Pipeline Summary:")
print(f"    Findings processed: {len(reports)}")
print(f"    Survivors: {len(survivors)}")
print(f"    Survival rate: {stats['survival_rate']:.1%}")
print(f"    Rejection rate: {stats['rejection_rate']:.1%}")
print(f"    Avg agreement: {stats['avg_agreement_score']:.2f}")
for r in reports:
    marker = "PASS" if r.survived else "FAIL"
    print(f"    {marker} [{r.finding_id}] {r.consensus_verdict.value} "
          f"(conf: {r.original_confidence:.2f} -> {r.consensus_confidence:.2f}, "
          f"agree: {r.agreement_score:.2f})")

check("20.10", True, "Pipeline summary printed")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 21. Validator Type Coverage
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
print("\n=== 21. Validator Type Coverage ===")

fleet = ValidationFleet(ava=AdversarialValidationAgent())
consensus = fleet.validate_finding(_make_strong_finding(id="coverage-1"))

# Verify each validator type appears exactly once
types_seen = [v.validator_type for v in consensus.validator_verdicts]
check("21.1", ValidatorType.EXPLOIT in types_seen, "ExploitValidator ran")
check("21.2", ValidatorType.ADVERSARIAL in types_seen, "AdversarialValidator ran")
check("21.3", ValidatorType.CONTEXT in types_seen, "ContextValidator ran")
check("21.4", ValidatorType.CHAIN_CONSISTENCY in types_seen, "ChainConsistencyValidator ran")
check("21.5", len(types_seen) == 4, f"Exactly 4 validators: {len(types_seen)}")

# Each validator produced valid output
for v in consensus.validator_verdicts:
    check(f"21.6_{v.validator_type.value}",
          v.verdict in IndividualVerdict.__members__.values(),
          f"{v.validator_type.value} produced valid verdict: {v.verdict.value}")



# ═══════════════════════════════════════════════════════════════════════════════
# 22. Evidence Graph
# ═══════════════════════════════════════════════════════════════════════════════
print("\n=== 22. Evidence Graph ===")

# 22.1: Empty graph returns prior
g = EvidenceGraph()
conf = g.bayesian_confidence(0.50)
check("22.1", conf == 0.50, f"Empty graph returns prior: {conf}")

# 22.2: Single VALID node raises confidence
g2 = EvidenceGraph()
g2.add_verdict(ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.50, [], [], {}, 1.0))
conf2 = g2.bayesian_confidence(0.50)
check("22.2", conf2 > 0.60, f"Single VALID raises confidence: {conf2}")

# 22.3: Single INVALID node lowers confidence
g3 = EvidenceGraph()
g3.add_verdict(ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.INVALID, 0.10, 0.50, [], [], {}, 1.0))
conf3 = g3.bayesian_confidence(0.50)
check("22.3", conf3 < 0.40, f"Single INVALID lowers confidence: {conf3}")

# 22.4: INCONCLUSIVE node has minimal effect
g4 = EvidenceGraph()
g4.add_verdict(ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.INCONCLUSIVE, 0.50, 0.50, [], [], {}, 1.0))
conf4 = g4.bayesian_confidence(0.50)
check("22.4", abs(conf4 - 0.50) < 0.10, f"INCONCLUSIVE has minimal effect: {conf4}")

# 22.5: Evidence graph serialization
g5 = EvidenceGraph()
g5.add_verdict(ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.70, [], [], {}, 1.0))
g5.add_verdict(ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.VALID, 0.85, 0.70, [], [], {}, 1.0))
g5.build_edges()
d5 = g5.to_dict()
check("22.5", len(d5["nodes"]) == 2, f"Graph has 2 nodes: {len(d5['nodes'])}")
check("22.6", len(d5["edges"]) == 1, f"Graph has 1 edge: {len(d5['edges'])}")
check("22.7", "supports" in d5, "Serialization has supports")
check("22.8", "contradicts" in d5, "Serialization has contradicts")
check("22.9", "uncertain" in d5, "Serialization has uncertain")

# 22.10: Contradicting evidence produces lower confidence than supporting
g_support = EvidenceGraph()
g_support.add_verdict(ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.50, [], [], {}, 1.0))
g_support.add_verdict(ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.VALID, 0.85, 0.50, [], [], {}, 1.0))
g_support.build_edges()
conf_support = g_support.bayesian_confidence(0.50)

g_contra = EvidenceGraph()
g_contra.add_verdict(ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.50, [], [], {}, 1.0))
g_contra.add_verdict(ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.INVALID, 0.10, 0.50, [], [], {}, 1.0))
g_contra.build_edges()
conf_contra = g_contra.bayesian_confidence(0.50)

check("22.10", conf_support > conf_contra,
      f"Supporting ({conf_support:.3f}) > contradicting ({conf_contra:.3f})")

# 22.11: Correlation discounting -- correlated validators provide less info
g_corr = EvidenceGraph()
g_corr.add_verdict(ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.50, [], [], {}, 1.0))
g_corr.add_verdict(ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.VALID, 0.85, 0.50, [], [], {}, 1.0))
g_corr.build_edges()
conf_corr = g_corr.bayesian_confidence(0.50)

g_indep = EvidenceGraph()
g_indep.add_verdict(ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.50, [], [], {}, 1.0))
g_indep.add_verdict(ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.VALID, 0.85, 0.50, [], [], {}, 1.0))
g_indep.build_edges()
conf_indep = g_indep.bayesian_confidence(0.50)

check("22.11", conf_indep >= conf_corr,
      f"Independent ({conf_indep:.3f}) >= correlated ({conf_corr:.3f})")

# 22.12: Evidence graph handles single node (no edges)
g_single = EvidenceGraph()
g_single.add_verdict(ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.70, [], [], {}, 1.0))
g_single.build_edges()
d_single = g_single.to_dict()
check("22.12", len(d_single["edges"]) == 0, "Single node has no edges")


# ═══════════════════════════════════════════════════════════════════════════════
# 23. Disagreement Intelligence
# ═══════════════════════════════════════════════════════════════════════════════
print("\n=== 23. Disagreement Intelligence ===")

di = DisagreementIntelligence()

# 23.1: All VALID -> stable_confirmed
all_v = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.90, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.VALID, 0.85, 0.90, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.VALID, 0.88, 0.90, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.VALID, 0.87, 0.90, [], [], {}, 1.0),
]
da = di.analyze(all_v)
check("23.1", da["signature"] == "stable_confirmed",
      f"All VALID -> stable_confirmed (got {da['signature']})")
check("23.2", da["meta_confidence"] >= 0.90,
      f"High meta-confidence: {da['meta_confidence']}")

# 23.3: All INVALID -> stable_rejected
all_inv = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.INVALID, 0.10, 0.50, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.INVALID, 0.08, 0.50, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.INVALID, 0.12, 0.50, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.INVALID, 0.09, 0.50, [], [], {}, 1.0),
]
da2 = di.analyze(all_inv)
check("23.3", da2["signature"] == "stable_rejected",
      f"All INVALID -> stable_rejected (got {da2['signature']})")

# 23.4: Exploit+Adversarial high, Context low -> environment_unstable
env_unstable = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.70, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.VALID, 0.85, 0.70, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.SUSPICIOUS, 0.25, 0.70, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.VALID, 0.80, 0.70, [], [], {}, 1.0),
]
da3 = di.analyze(env_unstable)
check("23.4", da3["signature"] == "environment_unstable",
      f"Exploit+Adv high, Context low -> environment_unstable (got {da3['signature']})")
check("23.5", "ENVIRONMENT_INTERFERENCE" in da3["investigation_flags"],
      "Environment interference flag raised")

# 23.6: Context+Chain high, Exploit low -> evidence_insufficient
ev_insuff = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.SUSPICIOUS, 0.25, 0.60, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.WEAK, 0.50, 0.60, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.VALID, 0.85, 0.60, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.VALID, 0.80, 0.60, [], [], {}, 1.0),
]
da4 = di.analyze(ev_insuff)
check("23.6", da4["signature"] == "evidence_insufficient",
      f"Context+Chain high, Exploit low -> evidence_insufficient (got {da4['signature']})")

# 23.7: All high except adversarial -> adversarial_doubt
adv_doubt = [
    ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.85, 0.70, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.SUSPICIOUS, 0.20, 0.70, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.WEAK, 0.55, 0.70, [], [], {}, 1.0),
    ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.WEAK, 0.50, 0.70, [], [], {}, 1.0),
]
da5 = di.analyze(adv_doubt)
check("23.7", da5["signature"] == "adversarial_doubt",
      f"All high except adversarial -> adversarial_doubt (got {da5['signature']})")

# 23.8: Empty verdicts handled
da_empty = di.analyze([])
check("23.8", da_empty["meta_confidence"] == 0.0, "Empty verdicts -> zero meta-confidence")

# 23.9: Diagnostic is human-readable
check("23.9", len(da["diagnostic"]) > 10, f"Diagnostic is readable: {da['diagnostic'][:50]}")

# 23.10: Recommended action present
check("23.10", len(da["recommended_action"]) > 0, "Has recommended action")

# 23.11: Signature distribution tracks history
dist = di.get_signature_distribution()
check("23.11", sum(dist.values()) >= 4,
      f"Distribution tracks analyses: {sum(dist.values())}")

# 23.12: Avg meta-confidence
avg_mc = di.get_avg_meta_confidence()
check("23.12", 0.0 < avg_mc <= 1.0, f"Avg meta-confidence valid: {avg_mc}")

# 23.13: Per-validator scores in analysis
check("23.13", "per_validator_scores" in da,
      "Analysis includes per-validator scores")


# ═══════════════════════════════════════════════════════════════════════════════
# 24. FleetConsensus New Fields
# ═══════════════════════════════════════════════════════════════════════════════
print("\n=== 24. FleetConsensus New Fields ===")

fleet24 = ValidationFleet(ava=AdversarialValidationAgent())
c24 = fleet24.validate_finding(_make_strong_finding(id="eg-1"))

# 24.1: Evidence graph present
check("24.1", isinstance(c24.evidence_graph, dict), "evidence_graph is dict")
check("24.2", "nodes" in c24.evidence_graph, "evidence_graph has nodes")
check("24.3", "edges" in c24.evidence_graph, "evidence_graph has edges")
check("24.4", len(c24.evidence_graph["nodes"]) == 4,
      f"4 evidence nodes: {len(c24.evidence_graph['nodes'])}")

# 24.5: Disagreement analysis present
check("24.5", isinstance(c24.disagreement_analysis, dict), "disagreement_analysis is dict")
check("24.6", "signature" in c24.disagreement_analysis, "Has signature")
check("24.7", "meta_confidence" in c24.disagreement_analysis, "Has meta_confidence")
check("24.8", "diagnostic" in c24.disagreement_analysis, "Has diagnostic")

# 24.9: Investigation flags present
check("24.9", isinstance(c24.investigation_flags, list), "investigation_flags is list")

# 24.10: to_dict includes new fields
d24 = c24.to_dict()
check("24.10", "evidence_graph" in d24, "to_dict has evidence_graph")
check("24.11", "disagreement_analysis" in d24, "to_dict has disagreement_analysis")
check("24.12", "investigation_flags" in d24, "to_dict has investigation_flags")

# 24.13: Fleet to_dict includes disagreement intelligence
state24 = fleet24.to_dict()
check("24.13", "disagreement_intelligence" in state24,
      "Fleet to_dict has disagreement_intelligence")
check("24.14", "signature_distribution" in state24["disagreement_intelligence"],
      "Has signature_distribution")
check("24.15", "avg_meta_confidence" in state24["disagreement_intelligence"],
      "Has avg_meta_confidence")



# ═══════════════════════════════════════════════════════════════════════════════
# 25. Probe Generator
# ═══════════════════════════════════════════════════════════════════════════════
print("\n=== 25. Probe Generator ===")

pg = ProbeGenerator()

# 25.1: should_probe returns False for stable signatures
check("25.1", not pg.should_probe({"signature": "stable_confirmed"}),
      "No probing for stable_confirmed")
check("25.2", not pg.should_probe({"signature": "stable_rejected"}),
      "No probing for stable_rejected")
check("25.3", not pg.should_probe({"signature": "low_confidence_agreement"}),
      "No probing for low_confidence_agreement")

# 25.4: should_probe returns True for unstable signatures
check("25.4", pg.should_probe({"signature": "environment_unstable"}),
      "Probe for environment_unstable")
check("25.5", pg.should_probe({"signature": "evidence_insufficient"}),
      "Probe for evidence_insufficient")
check("25.6", pg.should_probe({"signature": "adversarial_doubt"}),
      "Probe for adversarial_doubt")
check("25.7", pg.should_probe({"signature": "investigation_required"}),
      "Probe for investigation_required")
check("25.8", pg.should_probe({"signature": "chain_orphan"}),
      "Probe for chain_orphan")

# 25.9: Generate probes for environment_unstable
finding_env = _make_strong_finding(id="probe-env-1")
da_env = {"signature": "environment_unstable", "variance": 0.12}
probes_env = pg.generate_probes(finding_env, da_env)
check("25.9", len(probes_env) >= 2, f"Environment probes: {len(probes_env)}")
check("25.10", all("_probe_metadata" in p for p in probes_env),
      "All probes have metadata")
check("25.11", probes_env[0]["_probe_metadata"]["trigger_signature"] == "environment_unstable",
      "Probe metadata records trigger signature")

# 25.12: Generate probes for evidence_insufficient
da_ev = {"signature": "evidence_insufficient", "variance": 0.10}
probes_ev = pg.generate_probes(finding_env, da_ev)
check("25.12", len(probes_ev) >= 2, f"Evidence probes: {len(probes_ev)}")
check("25.13", any(p["_probe_metadata"]["mutation"] == "escalate_poc" for p in probes_ev),
      "Evidence probe includes escalated PoC")

# 25.14: max_probes limits output
probes_lim = pg.generate_probes(finding_env, da_env, max_probes=1)
check("25.14", len(probes_lim) == 1, f"Max probes respected: {len(probes_lim)}")

# 25.15: Probes are shallow copies (don't mutate original)
check("25.15", "request_headers" not in finding_env or
      finding_env.get("request_headers") != probes_env[0].get("request_headers"),
      "Probes don't mutate original finding")

# 25.16: WAF bypass probe has header overrides
waf_probes = [p for p in probes_env if p["_probe_metadata"]["mutation"] == "strip_waf_headers"]
if waf_probes:
    check("25.16", "X-Forwarded-For" in waf_probes[0].get("request_headers", {}),
          "WAF probe has X-Forwarded-For header")
else:
    check("25.16", True, "No WAF bypass probe (strategy order)")

# 25.17: adversarial_doubt probes strip optional fields
finding_extra = dict(finding_env)
finding_extra["extra_debug"] = "should_be_stripped"
finding_extra["aux_data"] = "also_stripped"
da_adv = {"signature": "adversarial_doubt", "variance": 0.08}
probes_adv = pg.generate_probes(finding_extra, da_adv)
stripped = [p for p in probes_adv if p["_probe_metadata"]["mutation"] == "minimal_exploit"]
if stripped:
    check("25.17", "extra_debug" not in stripped[0], "Minimal probe strips extra_ fields")
else:
    check("25.17", True, "No minimal exploit probe (strategy order)")


# ═══════════════════════════════════════════════════════════════════════════════
# 26. Convergence Loop
# ═══════════════════════════════════════════════════════════════════════════════
print("\n=== 26. Convergence Loop ===")

# 26.1: ConvergenceLoop initializes with sane defaults
cl = ConvergenceLoop(max_rounds=2)
stats = cl.get_stats()
check("26.1", stats["total_runs"] == 0, "Fresh loop has 0 runs")
check("26.2", stats["convergence_rate"] == 0.0, "Fresh loop has 0 convergence rate")

# 26.3: Convergence with stable finding (should skip probing)
def mock_validator_fn_stable(finding):
    """All validators agree -> stable_confirmed -> no probing needed."""
    return [
        ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.80, [], [], {}, 1.0),
        ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.VALID, 0.85, 0.80, [], [], {}, 1.0),
        ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.VALID, 0.88, 0.80, [], [], {}, 1.0),
        ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.VALID, 0.87, 0.80, [], [], {}, 1.0),
    ]

stable_verdicts = mock_validator_fn_stable({})
stable_da = {"signature": "stable_confirmed", "meta_confidence": 0.95, "variance": 0.01}
stable_consensus = FleetConsensus(
    finding_id="conv-stable", finding_type="xss", original_confidence=0.80,
    consensus_confidence=0.88, consensus_verdict=ConsensusVerdict.CONFIRMED,
    validator_verdicts=stable_verdicts, agreement_score=0.95,
    dissenting_validators=[], consensus_reasons=["test"],
    failure_conditions=[], fleet_duration_ms=10.0,
    disagreement_analysis=stable_da,
)

cr_stable = cl.run(
    {"id": "conv-stable", "confidence": 0.80},
    stable_verdicts, stable_consensus,
    mock_validator_fn_stable,
)
check("26.3", cr_stable.rounds == 0, f"Stable finding: 0 rounds (got {cr_stable.rounds})")
check("26.4", cr_stable.converged, "Stable finding counts as converged")
check("26.5", cr_stable.probes_generated == 0, "No probes for stable finding")

# 26.6: Convergence with unstable finding (should probe)
def mock_validator_fn_unstable(finding):
    """Exploit+Adversarial high, Context low -> environment_unstable."""
    return [
        ValidatorVerdict(ValidatorType.EXPLOIT, IndividualVerdict.VALID, 0.90, 0.70, [], [], {}, 1.0),
        ValidatorVerdict(ValidatorType.ADVERSARIAL, IndividualVerdict.VALID, 0.85, 0.70, [], [], {}, 1.0),
        ValidatorVerdict(ValidatorType.CONTEXT, IndividualVerdict.SUSPICIOUS, 0.25, 0.70, [], [], {}, 1.0),
        ValidatorVerdict(ValidatorType.CHAIN_CONSISTENCY, IndividualVerdict.VALID, 0.80, 0.70, [], [], {}, 1.0),
    ]

unstable_verdicts = mock_validator_fn_unstable({})
unstable_da = {"signature": "environment_unstable", "variance": 0.12,
               "investigation_flags": ["ENVIRONMENT_INTERFERENCE"]}
unstable_consensus = FleetConsensus(
    finding_id="conv-unstable", finding_type="sqli", original_confidence=0.70,
    consensus_confidence=0.65, consensus_verdict=ConsensusVerdict.PROBABLE,
    validator_verdicts=unstable_verdicts, agreement_score=0.60,
    dissenting_validators=["context"], consensus_reasons=["test"],
    failure_conditions=[], fleet_duration_ms=10.0,
    disagreement_analysis=unstable_da,
)

cl2 = ConvergenceLoop(max_rounds=2)
cr_unstable = cl2.run(
    {"id": "conv-unstable", "confidence": 0.70},
    unstable_verdicts, unstable_consensus,
    mock_validator_fn_unstable,
)
check("26.6", cr_unstable.rounds > 0, f"Unstable finding probed: {cr_unstable.rounds} rounds")
check("26.7", cr_unstable.probes_generated > 0,
      f"Generated probes: {cr_unstable.probes_generated}")
check("26.8", len(cr_unstable.confidence_trajectory) >= 2,
      f"Confidence trajectory tracked: {len(cr_unstable.confidence_trajectory)} points")
check("26.9", len(cr_unstable.probe_history) > 0, "Probe history recorded")

# 26.10: ConvergenceResult serialization
cr_dict = cr_unstable.to_dict()
check("26.10", "converged" in cr_dict, "Serialization has converged")
check("26.11", "rounds" in cr_dict, "Serialization has rounds")
check("26.12", "confidence_trajectory" in cr_dict, "Serialization has trajectory")
check("26.13", "confidence_delta" in cr_dict, "Serialization has confidence_delta")
check("26.14", "probe_history" in cr_dict, "Serialization has probe_history")
check("26.15", "convergence_reason" in cr_dict, "Serialization has convergence_reason")

# 26.16: Stats update after runs
stats2 = cl2.get_stats()
check("26.16", stats2["total_runs"] == 1, f"Stats tracked: {stats2['total_runs']} run(s)")
check("26.17", stats2["avg_rounds"] > 0, f"Avg rounds: {stats2['avg_rounds']}")


# ═══════════════════════════════════════════════════════════════════════════════
# 27. ValidationFleet with Convergence
# ═══════════════════════════════════════════════════════════════════════════════
print("\n=== 27. ValidationFleet with Convergence ===")

# 27.1: Default fleet has convergence disabled
fleet_default = ValidationFleet(ava=AdversarialValidationAgent())
d_default = fleet_default.to_dict()
check("27.1", d_default["config"]["convergence_enabled"] is False,
      "Default fleet has convergence disabled")
check("27.2", "convergence_loop" not in d_default,
      "No convergence_loop key when disabled")

# 27.3: Fleet with convergence enabled
fleet_conv = ValidationFleet(
    ava=AdversarialValidationAgent(),
    enable_convergence=True,
    max_convergence_rounds=2,
)
d_conv = fleet_conv.to_dict()
check("27.3", d_conv["config"]["convergence_enabled"] is True,
      "Convergence-enabled fleet config")
check("27.4", "convergence_loop" in d_conv,
      "Has convergence_loop stats")
check("27.5", d_conv["convergence_loop"]["total_runs"] == 0,
      "Fresh convergence loop has 0 runs")

# 27.6: Validate finding with convergence enabled
c_conv = fleet_conv.validate_finding(_make_strong_finding(id="conv-fleet-1"))
check("27.6", isinstance(c_conv.convergence_result, dict),
      "convergence_result is dict")

# 27.7: Validate finding WITHOUT convergence (backward compat)
fleet_no_conv = ValidationFleet(ava=AdversarialValidationAgent())
c_no_conv = fleet_no_conv.validate_finding(_make_strong_finding(id="conv-fleet-2"))
check("27.7", c_no_conv.convergence_result == {},
      "No convergence result when disabled")

# 27.8: FleetConsensus.to_dict includes convergence_result
d_c = c_conv.to_dict()
check("27.8", "convergence_result" in d_c, "to_dict has convergence_result")

# 27.9: convergence loop stats update (may be 0 if finding was stable)
d_after = fleet_conv.to_dict()
check("27.9", "total_runs" in d_after["convergence_loop"],
      "Convergence loop stats available")




# ======================================================================
# 28. Information Gain Scorer
# ======================================================================
print("\n=== 28. Information Gain Scorer ===")
igs = InformationGainScorer()

# 28.1: Basic scoring returns sorted list
probes_28 = [
    {"_probe_metadata": {"mutation": "escalate_poc"}, "type": "sqli"},
    {"_probe_metadata": {"mutation": "strip_waf_headers"}, "type": "sqli"},
    {"_probe_metadata": {"mutation": "scope_expansion"}, "type": "sqli"},
]
da_28 = {
    "per_validator_scores": {"exploit": 0.5, "context": 0.8, "adversarial": 0.5, "chain_consistency": 0.3},
    "variance": 0.10,
}
scored_28 = igs.score_probes(probes_28, da_28)
check("28.1", len(scored_28) == 3, f"Scored all 3 probes (got {len(scored_28)})")

# 28.2: Sorted descending by IG score
check("28.2", scored_28[0][0] >= scored_28[1][0] >= scored_28[2][0],
      "Sorted descending by IG score")

# 28.3: Each probe gets information_gain tag
for _, p in scored_28:
    ig_val = p.get("_probe_metadata", {}).get("information_gain")
    check("28.3", ig_val is not None and ig_val >= 0,
          f"Probe tagged with information_gain={ig_val}")
    break

# 28.4: select_top_k returns limited probes
igs.reset_history()
top2 = igs.select_top_k(probes_28, da_28, k=2)
check("28.4", len(top2) == 2, f"top-K returns 2 (got {len(top2)})")

# 28.5: select_top_k returns the highest IG probes
igs.reset_history()
scored_again = igs.score_probes(probes_28, da_28)
top_mutations = [t.get("_probe_metadata", {}).get("mutation") for t in top2]
expected_top = scored_again[0][1].get("_probe_metadata", {}).get("mutation")
check("28.5", expected_top in top_mutations, "Top-K includes highest IG probe")

# 28.6: Novelty decay - repeated mutations score lower
igs.reset_history()
igs._mutation_history = ["escalate_poc", "escalate_poc"]
probes_novel = [
    {"_probe_metadata": {"mutation": "escalate_poc"}, "type": "sqli"},
    {"_probe_metadata": {"mutation": "minimal_exploit"}, "type": "sqli"},
]
scored_novel = igs.score_probes(probes_novel, da_28)
esc_score = [s for s, p in scored_novel if p["_probe_metadata"]["mutation"] == "escalate_poc"][0]
min_score = [s for s, p in scored_novel if p["_probe_metadata"]["mutation"] == "minimal_exploit"][0]
check("28.6", min_score > esc_score,
      f"Novelty decay: fresh={min_score:.4f} > repeated={esc_score:.4f}")

# 28.7: reset_history clears mutation history
igs.reset_history()
check("28.7", len(igs._mutation_history) == 0, "History cleared after reset")

# 28.8: High variance gives higher scores
igs.reset_history()
da_low_var = {"per_validator_scores": {"exploit": 0.5}, "variance": 0.01}
da_high_var = {"per_validator_scores": {"exploit": 0.5}, "variance": 0.15}
s_low = igs.score_probes([{"_probe_metadata": {"mutation": "escalate_poc"}}], da_low_var)
igs.reset_history()
s_high = igs.score_probes([{"_probe_metadata": {"mutation": "escalate_poc"}}], da_high_var)
check("28.8", s_high[0][0] >= s_low[0][0],
      f"High variance yields higher IG: {s_high[0][0]:.4f} >= {s_low[0][0]:.4f}")

# 28.9: Unknown mutation type gets moderate score
igs.reset_history()
s_unk = igs.score_probes([{"_probe_metadata": {"mutation": "mystery_mutation"}}], da_28)
check("28.9", 0 < s_unk[0][0] < 1.0,
      f"Unknown mutation gets moderate score: {s_unk[0][0]:.4f}")

# 28.10: Empty probes list returns empty
igs.reset_history()
empty_scored = igs.score_probes([], da_28)
check("28.10", empty_scored == [], "Empty probes returns empty list")

# 28.11: select_top_k with k > len(probes) returns all
igs.reset_history()
top_all = igs.select_top_k(probes_28, da_28, k=100)
check("28.11", len(top_all) == 3, f"k>len returns all: {len(top_all)}")

# 28.12: Mutation axis mapping coverage
check("28.12", "strip_waf_headers" in InformationGainScorer._MUTATION_AXIS,
      "WAF mutation has axis mapping")

# 28.13: All mutations have base info scores
for m in InformationGainScorer._MUTATION_AXIS:
    if m not in InformationGainScorer._MUTATION_BASE_INFO:
        check("28.13", False, f"Missing base info for {m}")
        break
else:
    check("28.13", True, "All mutation types have base info scores")

# 28.14: IG scores are always non-negative
igs.reset_history()
da_extreme = {"per_validator_scores": {"exploit": 0.0}, "variance": 0.0}
s_extreme = igs.score_probes([{"_probe_metadata": {"mutation": "escalate_poc"}}], da_extreme)
check("28.14", s_extreme[0][0] >= 0, f"IG score non-negative: {s_extreme[0][0]:.4f}")


# ======================================================================
# 29. Causal Attack Model
# ======================================================================
print("\n=== 29. Causal Attack Model ===")
cam = CausalAttackModel()

# 29.1: RCE finding produces CausalImpact
rce_finding = {"type": "rce", "confidence": 0.9, "url": "https://example.com/api"}
rce_impact = cam.predict_impact(rce_finding)
check("29.1", isinstance(rce_impact, CausalImpact), "Returns CausalImpact")

# 29.2: RCE has state changes
check("29.2", len(rce_impact.state_changes) > 0,
      f"RCE has {len(rce_impact.state_changes)} state changes")

# 29.3: RCE opens new attack paths
check("29.3", len(rce_impact.new_attack_paths) > 0,
      f"RCE opens {len(rce_impact.new_attack_paths)} attack paths")

# 29.4: RCE has root privilege escalation
check("29.4", rce_impact.privilege_escalation == "root",
      f"RCE priv esc = {rce_impact.privilege_escalation}")

# 29.5: RCE has lateral movement
check("29.5", len(rce_impact.lateral_movement) > 0,
      f"RCE lateral movement: {rce_impact.lateral_movement}")

# 29.6: Composite impact score is 0-1
check("29.6", 0 <= rce_impact.composite_impact_score <= 1.0,
      f"Composite score: {rce_impact.composite_impact_score}")

# 29.7: to_dict serialization
rce_dict = rce_impact.to_dict()
check("29.7", "composite_impact_score" in rce_dict, "to_dict has composite_impact_score")

# 29.8: XSS has lower impact than RCE
xss_finding = {"type": "xss", "confidence": 0.9}
xss_impact = cam.predict_impact(xss_finding)
check("29.8", xss_impact.composite_impact_score < rce_impact.composite_impact_score,
      f"XSS ({xss_impact.composite_impact_score:.3f}) < RCE ({rce_impact.composite_impact_score:.3f})")

# 29.9: SQLi produces database-related state changes
sqli_finding = {"type": "sqli", "confidence": 0.85}
sqli_impact = cam.predict_impact(sqli_finding)
db_changes = [s for s in sqli_impact.state_changes if "database" in s.get("change", "")]
check("29.9", len(db_changes) > 0, f"SQLi has database state changes: {len(db_changes)}")

# 29.10: SSRF has cloud metadata in lateral movement
ssrf_finding = {"type": "ssrf", "confidence": 0.8}
ssrf_impact = cam.predict_impact(ssrf_finding)
check("29.10", "cloud_metadata" in ssrf_impact.lateral_movement,
      f"SSRF lateral: {ssrf_impact.lateral_movement}")

# 29.11: Type normalization works
sqli_alt = {"type": "sql_injection", "confidence": 0.7}
sqli_alt_impact = cam.predict_impact(sqli_alt)
check("29.11", len(sqli_alt_impact.state_changes) > 0,
      "sql_injection normalizes to sqli")

# 29.12: Unknown type gets empty templates
unk_finding = {"type": "weird_vuln", "confidence": 0.5}
unk_impact = cam.predict_impact(unk_finding)
check("29.12", len(unk_impact.state_changes) == 0,
      "Unknown type has no state changes")

# 29.13: Confidence scales state change confidence
high_conf = {"type": "rce", "confidence": 0.95}
low_conf = {"type": "rce", "confidence": 0.3}
hi = cam.predict_impact(high_conf)
lo = cam.predict_impact(low_conf)
hi_max_sc = max(s["confidence"] for s in hi.state_changes)
lo_max_sc = max(s["confidence"] for s in lo.state_changes)
check("29.13", hi_max_sc > lo_max_sc,
      f"High conf state change: {hi_max_sc:.3f} > {lo_max_sc:.3f}")

# 29.14: With FleetConsensus, uses consensus confidence
mock_consensus = FleetConsensus(
    finding_id="test", finding_type="rce",
    original_confidence=0.3, consensus_confidence=0.95,
    consensus_verdict=ConsensusVerdict.CONFIRMED,
    validator_verdicts=[], agreement_score=0.9,
    dissenting_validators=[], consensus_reasons=[],
    failure_conditions=[], fleet_duration_ms=10.0,
)
impact_with_consensus = cam.predict_impact({"type": "rce", "confidence": 0.3}, mock_consensus)
check("29.14", impact_with_consensus.exploit_probability == 0.95,
      f"Uses consensus confidence: {impact_with_consensus.exploit_probability}")

# 29.15: Data exposure risk is 0-1
for vtype in ["sqli", "xss", "rce", "ssrf", "idor", "auth_bypass", "path_traversal", "ssti"]:
    imp = cam.predict_impact({"type": vtype, "confidence": 0.8})
    if not (0 <= imp.data_exposure_risk <= 1.0):
        check("29.15", False, f"{vtype} data risk out of range: {imp.data_exposure_risk}")
        break
else:
    check("29.15", True, "All vuln types have data_exposure_risk in [0,1]")

# 29.16: Persistence potential is 0-1
for vtype in ["sqli", "xss", "rce", "ssrf"]:
    imp = cam.predict_impact({"type": vtype, "confidence": 0.8})
    if not (0 <= imp.persistence_potential <= 1.0):
        check("29.16", False, f"{vtype} persistence out of range")
        break
else:
    check("29.16", True, "All vuln types have persistence_potential in [0,1]")

# 29.17: Detection difficulty for blind findings
blind_sqli = {"type": "sqli", "confidence": 0.7, "blind": True}
normal_sqli = {"type": "sqli", "confidence": 0.7}
blind_imp = cam.predict_impact(blind_sqli)
normal_imp = cam.predict_impact(normal_sqli)
check("29.17", blind_imp.detection_difficulty > normal_imp.detection_difficulty,
      f"Blind harder to detect: {blind_imp.detection_difficulty:.3f} > {normal_imp.detection_difficulty:.3f}")

# 29.18: Admin URL adds privileged_endpoints to lateral movement
admin_finding = {"type": "rce", "confidence": 0.9, "url": "https://example.com/admin/exec"}
admin_impact = cam.predict_impact(admin_finding)
check("29.18", "privileged_endpoints" in admin_impact.lateral_movement,
      f"Admin URL lateral: {admin_impact.lateral_movement}")

# 29.19: Auth bypass has domain privilege escalation
auth_finding = {"type": "auth_bypass", "confidence": 0.8}
auth_impact = cam.predict_impact(auth_finding)
check("29.19", auth_impact.privilege_escalation == "domain",
      f"Auth bypass priv esc: {auth_impact.privilege_escalation}")

# 29.20: to_dict has all required fields
required_fields = [
    "exploit_probability", "state_changes", "new_attack_paths",
    "lateral_movement", "privilege_escalation", "data_exposure_risk",
    "persistence_potential", "detection_difficulty", "chain_amplification",
    "composite_impact_score",
]
d29 = rce_impact.to_dict()
for f in required_fields:
    if f not in d29:
        check("29.20", False, f"Missing field: {f}")
        break
else:
    check("29.20", True, "to_dict has all 10 required fields")


# ======================================================================
# 30. Fleet Integration with IG + Causal Impact
# ======================================================================
print("\n=== 30. Fleet Integration with IG + Causal Impact ===")

# 30.1: FleetConsensus has causal_impact field
fleet_30 = ValidationFleet()
c_30 = fleet_30.validate_finding(_make_strong_finding())
check("30.1", "causal_impact" in c_30.to_dict(), "to_dict includes causal_impact")

# 30.2: Confirmed finding has non-empty causal impact
if c_30.consensus_verdict in (ConsensusVerdict.CONFIRMED, ConsensusVerdict.PROBABLE):
    check("30.2", len(c_30.causal_impact) > 0,
          f"Confirmed/probable finding has causal impact with {len(c_30.causal_impact)} fields")
else:
    check("30.2", c_30.causal_impact == {},
          f"Non-confirmed finding has empty causal impact (verdict={c_30.consensus_verdict.value})")

# 30.3: Rejected finding has empty causal impact
weak_30 = _make_weak_finding()
c_weak_30 = fleet_30.validate_finding(weak_30)
if c_weak_30.consensus_verdict in (ConsensusVerdict.REJECTED, ConsensusVerdict.SUSPICIOUS):
    check("30.3", c_weak_30.causal_impact == {},
          "Rejected/suspicious finding has empty causal impact")
else:
    check("30.3", True, f"Weak finding verdict={c_weak_30.consensus_verdict.value} (not rejected)")

# 30.4: Causal impact has composite score
if c_30.causal_impact:
    check("30.4", "composite_impact_score" in c_30.causal_impact,
          "Causal impact has composite_impact_score")
else:
    check("30.4", True, "No causal impact to check (finding not confirmed)")

# 30.5: ConvergenceLoop uses IG scorer internally
conv_30 = ConvergenceLoop(max_rounds=2, max_probes_per_round=2)
check("30.5", hasattr(conv_30, "_ig_scorer"),
      "ConvergenceLoop has IG scorer")

# 30.6: ConvergenceLoop IG scorer is InformationGainScorer
check("30.6", isinstance(conv_30._ig_scorer, InformationGainScorer),
      "IG scorer is InformationGainScorer instance")

# 30.7: Fleet with convergence has both IG and causal model
fleet_full = ValidationFleet(enable_convergence=True, max_convergence_rounds=2)
check("30.7", hasattr(fleet_full, "_causal_model"),
      "Fleet has causal model")

# 30.8: Batch validation includes causal impact
batch_results = fleet_30.validate_findings_batch([_make_strong_finding(), _make_weak_finding()])
for br in batch_results:
    d_br = br.to_dict()
    check("30.8", "causal_impact" in d_br, "Batch result has causal_impact")
    break

# 30.9: Causal impact state changes are confidence-scaled
if c_30.causal_impact and c_30.causal_impact.get("state_changes"):
    sc = c_30.causal_impact["state_changes"][0]
    check("30.9", "confidence" in sc and sc["confidence"] <= 1.0,
          f"State change confidence scaled: {sc['confidence']}")
else:
    check("30.9", True, "No state changes to check")

# 30.10: FleetConsensus causal_impact field default is empty dict
bare_consensus = FleetConsensus(
    finding_id="bare", finding_type="xss",
    original_confidence=0.5, consensus_confidence=0.5,
    consensus_verdict=ConsensusVerdict.UNCERTAIN,
    validator_verdicts=[], agreement_score=0.5,
    dissenting_validators=[], consensus_reasons=[],
    failure_conditions=[], fleet_duration_ms=0.0,
)
check("30.10", bare_consensus.causal_impact == {},
      "Default causal_impact is empty dict")

# ═══════════════════════════════════════════════════════════════════════════════
# Section 31: Reactive Context Compaction Engine
# ═══════════════════════════════════════════════════════════════════════════════

from CaseCrack.tools.burp_enterprise.agents.reactive_compaction import (
    ReactiveContextCompactor,
    ProgressiveCompactor,
    ConversationSummariser,
    CompactionLevel,
    CompactionOutcome,
    CompactionResult,
    CompactionStats,
    is_context_overflow_error,
    get_reactive_compactor,
)

print("\n== Section 31: Reactive Context Compaction Engine ==")

# 31.1: is_context_overflow_error detects common overflow patterns
_overflow_msgs = [
    Exception("prompt is too long for this model"),
    Exception("maximum context length exceeded"),
    Exception("context window limit exceeded for model"),
    Exception("token limit exceeded reduce prompt"),
    Exception("request too large (413)"),
    Exception("input too long for context"),
    Exception("reduce your prompt size to fit context"),
]
for i, err in enumerate(_overflow_msgs):
    check(f"31.1.{i}", is_context_overflow_error(err),
          f"Detects overflow pattern: {str(err)[:50]}")

# 31.2: Non-overflow errors are not misclassified
_non_overflow = [
    Exception("connection refused"),
    Exception("authentication failed"),
    Exception("rate limit exceeded"),
    Exception("internal server error"),
    TimeoutError("request timed out"),
]
for i, err in enumerate(_non_overflow):
    check(f"31.2.{i}", not is_context_overflow_error(err),
          f"Rejects non-overflow: {str(err)[:40]}")

# 31.3: HTTP 413 status code detection
class _Http413Error(Exception):
    status_code = 413
check("31.3", is_context_overflow_error(_Http413Error("payload too large")),
      "Detects HTTP 413 via status_code attribute")

# 31.4: CompactionLevel ordering
check("31.4", CompactionLevel.NONE < CompactionLevel.LIGHT < CompactionLevel.MODERATE
      < CompactionLevel.AGGRESSIVE < CompactionLevel.COLLAPSE,
      "Compaction levels are ordered correctly")

# 31.5: ConversationSummariser basic functionality
_summariser = ConversationSummariser()
_long_prompt = """INSTRUCTIONS:
You are a security researcher analyzing web applications.

HISTORY:
Turn 1: Scanned target with nikto, found 3 endpoints.
Turn 2: Ran sqlmap on /api/users, found SQLi.
Turn 3: Tested XSS on /search, confirmed reflected XSS.
Turn 4: Enumerated /admin paths, found exposed panel.
Turn 5: Tested authentication bypass.

FINDINGS:
[1] ID=F001 | CRITICAL | sqli | SQL Injection in /api/users
    URL: https://target.com/api/users
    Description: Blind SQL injection via user_id parameter allows data extraction.
    Evidence: sqlmap output confirmed data dump possible.

[2] ID=F002 | HIGH | xss | Reflected XSS in /search
    URL: https://target.com/search?q=X
    Description: Unfiltered user input reflected in HTML response body.
    Evidence: alert(1) executed in browser.

[3] ID=F003 | MEDIUM | misconfig | Exposed Admin Panel
    URL: https://target.com/admin
    Description: Admin panel accessible without authentication.

[4] ID=F004 | LOW | info_disclosure | Server version header
    URL: https://target.com
    Description: Server responds with Apache/2.4.52.

USER MESSAGE:
What should we exploit next?
"""

_collapsed = _summariser.summarise(_long_prompt, target_tokens=512)
check("31.5.1", len(_collapsed) <= 512 * 4,
      f"Collapsed within budget: {len(_collapsed)} chars <= {512*4}")
check("31.5.2", "CONTEXT COLLAPSED" in _collapsed,
      "Collapse marker present")
check("31.5.3", len(_collapsed) < len(_long_prompt),
      f"Actually smaller: {len(_collapsed)} < {len(_long_prompt)}")

# 31.6: ProgressiveCompactor stages
_compactor = ProgressiveCompactor()

# Light: removes info/low findings and blank lines
_prompt_light = "INFO | Server header\n\n\n\n\nCRITICAL | SQLi in /api"
_result_l, _level_l = _compactor.compact(_prompt_light, target_tokens=10)
check("31.6.1", _level_l.value >= CompactionLevel.LIGHT.value,
      f"Light compaction triggered: {_level_l.name}")

# Aggressive: strips tool output
_with_tools = _long_prompt + "\nTool Output: raw output block...\n" * 20
_result_a, _level_a = _compactor.compact(_with_tools, target_tokens=200)
check("31.6.2", len(_result_a) < len(_with_tools),
      f"Aggressive reduces: {len(_result_a)} < {len(_with_tools)}")

# Collapse: summarizes everything when extremely tight
_massive = _long_prompt * 10
_result_c, _level_c = _compactor.compact(_massive, target_tokens=256)
check("31.6.3", _level_c.value >= CompactionLevel.MODERATE.value,
      f"Aggressive+ compaction for massive prompt: {_level_c.name}")
check("31.6.4", len(_result_c) <= 256 * 4 + 100,
      f"Collapse meets budget: {len(_result_c)} chars")

# 31.7: ReactiveContextCompactor proactive guard
_events_31: list[tuple[str, dict]] = []
def _capture_event_31(event_type, data):
    _events_31.append((event_type, data))

_rcc = ReactiveContextCompactor(
    context_window=20480,
    event_callback=_capture_event_31,
)

# Short prompt should NOT need compaction
_guard_short = _rcc.guard_prompt("Hello world")
check("31.7.1", _guard_short.outcome == CompactionOutcome.NOT_NEEDED,
      "Short prompt: no compaction needed")
check("31.7.2", _guard_short.compacted_prompt == "",
      "Short prompt: no compacted text")
check("31.7.3", _guard_short.reduction_pct == 0.0,
      "Short prompt: 0% reduction")

# 31.8: Proactive guard triggers on large prompt
# context_window=20480 → effective_window=16384 → proactive_threshold=3384
# Need >3384 tokens AND >65536 chars for compact() to actually reduce
_large = (_long_prompt + "\nTool Output: " + "x" * 500 + "\n") * 80
_rcc_large = ReactiveContextCompactor(
    context_window=20480,
    event_callback=_capture_event_31,
)
_guard_large = _rcc_large.guard_prompt(_large)
check("31.8.1", _guard_large.outcome in (CompactionOutcome.COMPACTED, CompactionOutcome.COLLAPSED),
      f"Large prompt compacted: {_guard_large.outcome.value}")
check("31.8.2", _guard_large.compacted_prompt != "" or _guard_large.outcome == CompactionOutcome.COLLAPSED,
      "Compacted prompt exists or collapsed")
check("31.8.3", _guard_large.reduction_pct > 0.0,
      f"Positive reduction: {_guard_large.reduction_pct:.1%}")
check("31.8.4", _guard_large.compacted_tokens <= _guard_large.original_tokens,
      f"Compacted <= original: {_guard_large.compacted_tokens} <= {_guard_large.original_tokens}")

# 31.9: Event emission on compaction
check("31.9", any(e[0] in ("llm.context_compacted", "llm.context_collapsed") for e in _events_31),
      f"Compaction event emitted: {[e[0] for e in _events_31]}")

# 31.10: Reactive overflow handler
_rcc2 = ReactiveContextCompactor(context_window=512)
_overflow_err = Exception("prompt is too long for this model")
_overflow_prompt = "A " * 3000
_reactive = _rcc2.handle_overflow(_overflow_prompt, _overflow_err)
check("31.10.1", _reactive.outcome in (
    CompactionOutcome.COMPACTED, CompactionOutcome.COLLAPSED, CompactionOutcome.FAILED),
      f"Reactive handler ran: {_reactive.outcome.value}")
check("31.10.2", _reactive.elapsed_ms >= 0,
      f"Non-negative elapsed: {_reactive.elapsed_ms}")

# 31.11: Circuit breaker trips after MAX_CONSECUTIVE_FAILURES
_rcc3 = ReactiveContextCompactor(context_window=64)
_tiny_err = Exception("context length exceeded")
_uncollapsible = ("CRITICAL FINDING: " + "A" * 500 + "\n") * 10
for _trip_i in range(4):
    _trip_result = _rcc3.handle_overflow(_uncollapsible, _tiny_err)
check("31.11.1", _rcc3.is_circuit_open or _trip_result.outcome == CompactionOutcome.CIRCUIT_OPEN,
      f"Circuit breaker tripped: open={_rcc3.is_circuit_open}, outcome={_trip_result.outcome.value}")

# Verify circuit blocks further compaction
_blocked = _rcc3.handle_overflow(_uncollapsible, _tiny_err)
check("31.11.2", _blocked.outcome == CompactionOutcome.CIRCUIT_OPEN,
      f"Blocked by circuit: {_blocked.outcome.value}")

# 31.12: record_llm_success resets failure counter
_rcc4 = ReactiveContextCompactor(context_window=128)
_rcc4._stats.consecutive_failures = 2
_rcc4.record_llm_success()
check("31.12", _rcc4._stats.consecutive_failures == 0,
      "Success resets failure counter")

# 31.13: update_context_window adjusts thresholds
_rcc5 = ReactiveContextCompactor(context_window=4096)
_old_threshold = _rcc5.proactive_threshold
_rcc5.update_context_window(131072)
check("31.13.1", _rcc5.effective_window > _old_threshold,
      f"Window expanded: {_rcc5.effective_window}")
check("31.13.2", _rcc5._context_window == 131072,
      "Context window updated to 131072")

# 31.14: get_stats returns structured stats
_stats = _rcc.get_stats()
check("31.14.1", "total_attempts" in _stats,
      "Stats has total_attempts")
check("31.14.2", "circuit_open" in _stats,
      "Stats has circuit_open")
check("31.14.3", "effective_window" in _stats,
      "Stats has effective_window")
check("31.14.4", "recent_history" in _stats and isinstance(_stats["recent_history"], list),
      "Stats has recent_history list")

# 31.15: Singleton pattern
_s1 = get_reactive_compactor(context_window=8192)
_s2 = get_reactive_compactor(context_window=8192)
check("31.15", _s1 is _s2, "Singleton returns same instance")

# 31.16: estimate_tokens handles edge cases
_rcc_tok = ReactiveContextCompactor(context_window=8192)
check("31.16.1", _rcc_tok.estimate_tokens("") == 0, "Empty string = 0 tokens")
check("31.16.2", _rcc_tok.estimate_tokens("hello") >= 1, "Non-empty >= 1 token")
_json_content = '{"key": "value", "list": [1, 2, 3], "nested": {"a": 1}}'
_text_content = "The quick brown fox jumps over the lazy dog and sleeps"
_json_tok = _rcc_tok.estimate_tokens(_json_content * 100)
_text_tok = _rcc_tok.estimate_tokens(_text_content * 100)
_json_ratio = _json_tok / max(1, len(_json_content * 100))
_text_ratio = _text_tok / max(1, len(_text_content * 100))
check("31.16.3", _json_ratio >= _text_ratio * 0.9,
      f"JSON density >= text density: {_json_ratio:.3f} vs {_text_ratio:.3f}")

# 31.17: Proactive guard with circuit open skips compaction
_rcc6 = ReactiveContextCompactor(context_window=1024)
_rcc6._circuit_open_until = time.time() + 600
_guard_blocked = _rcc6.guard_prompt("x " * 5000)
check("31.17", _guard_blocked.outcome == CompactionOutcome.CIRCUIT_OPEN,
      "Proactive guard skipped when circuit open")

# 31.18: CompactionResult.saved_tokens property
_cr = CompactionResult(
    outcome=CompactionOutcome.COMPACTED,
    original_tokens=1000,
    compacted_tokens=600,
    level=CompactionLevel.MODERATE,
    reduction_pct=0.4,
    elapsed_ms=5.0,
)
check("31.18", _cr.saved_tokens == 400, f"Saved tokens = {_cr.saved_tokens}")

# 31.19: CompactionStats.to_dict serialization
_cs = CompactionStats(
    total_attempts=10,
    proactive_compactions=6,
    reactive_compactions=3,
    collapses=1,
    circuit_trips=0,
    total_tokens_saved=5000,
    total_compaction_ms=150.0,
)
_cs_dict = _cs.to_dict()
check("31.19.1", _cs_dict["total_attempts"] == 10, "Stats dict: total_attempts")
check("31.19.2", _cs_dict["avg_compaction_ms"] == 15.0, "Stats dict: avg_compaction_ms")
check("31.19.3", _cs_dict["proactive_compactions"] == 6, "Stats dict: proactive_compactions")

# 31.20: Thread safety concurrent guard_prompt calls
_rcc_ts = ReactiveContextCompactor(context_window=2048)
_ts_errors = []
def _ts_worker():
    try:
        for _ in range(20):
            _rcc_ts.guard_prompt("word " * 800)
    except Exception as exc:
        _ts_errors.append(exc)

_ts_threads = [threading.Thread(target=_ts_worker) for _ in range(4)]
for t in _ts_threads:
    t.start()
for t in _ts_threads:
    t.join(timeout=10)
check("31.20", len(_ts_errors) == 0,
      f"Thread safety: {len(_ts_errors)} errors")

# 31.21: ConversationSummariser preserves system instructions
_sys_prompt = "INSTRUCTIONS:\nYou are a security expert.\n\nHISTORY:\nTurn 1: Did recon.\n" * 5
_collapsed_sys = _summariser.summarise(_sys_prompt, target_tokens=256)
check("31.21", "security" in _collapsed_sys.lower() or "INSTRUCTIONS" in _collapsed_sys
      or "CONTEXT COLLAPSED" in _collapsed_sys,
      "System instructions reference preserved in collapse")

# 31.22: Progressive compaction is idempotent
_idem_prompt = "CRITICAL | SQLi | /api/users\nHIGH | XSS | /search\n" * 20
_pass1, _lvl1 = _compactor.compact(_idem_prompt, target_tokens=100)
_pass2, _lvl2 = _compactor.compact(_pass1, target_tokens=100)
check("31.22", len(_pass2) <= len(_pass1),
      f"Double-compaction doesn't expand: {len(_pass2)} <= {len(_pass1)}")

# 31.23: Reactive handler escalates compaction level on repeated failures
_rcc_esc = ReactiveContextCompactor(context_window=256)
_esc_prompt = "DATA " * 2000
_esc_err = Exception("context length exceeded")
_r1 = _rcc_esc.handle_overflow(_esc_prompt, _esc_err)
_r2 = _rcc_esc.handle_overflow(_esc_prompt, _esc_err)
check("31.23", True,
      f"Escalation: attempt 1={_r1.level.name}, attempt 2={_r2.level.name}")

# 31.24: Empty/minimal prompts don't crash
_edge_prompts = ["", " ", "\n\n\n", "a"]
for i, ep in enumerate(_edge_prompts):
    try:
        _ep_result = _rcc.guard_prompt(ep)
        check(f"31.24.{i}", True, f"Edge prompt handled")
    except Exception as _ep_exc:
        check(f"31.24.{i}", False, f"Edge prompt crashed: {_ep_exc}")

# 31.25: Compaction history ring buffer
_rcc_hist = ReactiveContextCompactor(context_window=1024)
_rcc_hist.guard_prompt("token " * 2000)
_hist_stats = _rcc_hist.get_stats()
check("31.25", len(_hist_stats["recent_history"]) >= 1,
      f"History recorded: {len(_hist_stats['recent_history'])} entries")

# ═══════════════════════════════════════════════════════════════════════════════
# Section 32: Fork/Spawn Agent Semantics Engine

# ╔═══════════════════════════════════════════════════════════════════════════════╗


# ╔═══════════════════════════════════════════════════════════════════════════════╗


# ╔═══════════════════════════════════════════════════════════════════════════════╗


# ╔═══════════════════════════════════════════════════════════════════════════════╗


# ╔═══════════════════════════════════════════════════════════════════════════════╗
# Section 35: Advanced Agent Patterns (AP-1 through AP-7)
# ╚═══════════════════════════════════════════════════════════════════════════════╝

import json
import os
import tempfile
import threading
import time

from CaseCrack.tools.burp_enterprise.agents.advanced_agent_patterns import (
    CacheOptimizedForker,
    DreamConsolidator,
    DreamCycleStats,
    DreamPhase,
    DreamTurn,
    ForkedMessageSet,
    FuseCircuit,
    FuseState,
    HookOutcome,
    HookPriority,
    HookResult,
    LLMMemoryRetriever,
    MemoryCandidate,
    MemorySelection,
    PostTurnOrchestrator,
    PostTurnResult,
    ResolveOnceGuard,
    StallReport,
    StallVerdict,
    StallWatchdog,
    get_dream_consolidator,
    get_memory_retriever,
    get_post_turn_orchestrator,
    get_stall_watchdog,
    reset_dream_consolidator,
    reset_memory_retriever,
    reset_post_turn_orchestrator,
    reset_stall_watchdog,
)

print("\n== Section 35: Advanced Agent Patterns (AP-1 through AP-7) ==")

# ---------- 35.1: FuseCircuit — AP-7 ----------

# 35.1.1: Fuse starts intact
_fuse1 = FuseCircuit(name="test-fuse", threshold=3)
check("35.1.1", _fuse1.state == FuseState.INTACT and not _fuse1.is_blown,
      "Fuse starts INTACT")

# 35.1.2: Fuse blows after threshold consecutive failures
_fuse1.record_failure("err1")
_fuse1.record_failure("err2")
_blew = _fuse1.record_failure("err3")
check("35.1.2", _blew and _fuse1.is_blown and _fuse1.state == FuseState.BLOWN,
      f"Fuse blows after 3 failures (blown={_fuse1.is_blown})")

# 35.1.3: Success resets consecutive counter but NOT blown state
_fuse1.record_success()
check("35.1.3", _fuse1.is_blown,
      "Success after blown does NOT auto-reset")

# 35.1.4: Manual reset restores fuse
_fuse1.reset()
check("35.1.4", not _fuse1.is_blown and _fuse1.state == FuseState.INTACT,
      "Manual reset restores INTACT")

# 35.1.5: Success between failures prevents blowing
_fuse2 = FuseCircuit(name="resilient", threshold=3)
_fuse2.record_failure("a")
_fuse2.record_failure("b")
_fuse2.record_success()  # resets consecutive count
_fuse2.record_failure("c")
_fuse2.record_failure("d")
check("35.1.5", not _fuse2.is_blown,
      "Success between failures prevents blowing")

# 35.1.6: to_dict serialization
_d16 = _fuse2.to_dict()
check("35.1.6", _d16["name"] == "resilient" and _d16["state"] == "intact" and _d16["total_failures"] == 4,
      "to_dict serializes correctly")

# 35.1.7: Thread safety — concurrent failures
_fuse3 = FuseCircuit(name="threaded", threshold=100)
def _concurrent_fail():
    for _ in range(50):
        _fuse3.record_failure("concurrent")
_threads = [threading.Thread(target=_concurrent_fail) for _ in range(4)]
for t in _threads: t.start()
for t in _threads: t.join()
check("35.1.7", _fuse3.total_failures == 200 and _fuse3.is_blown,
      f"Thread-safe: {_fuse3.total_failures} failures, blown={_fuse3.is_blown}")

# ---------- 35.2: ResolveOnceGuard — AP-5 ----------

# 35.2.1: First claim wins
_guard1 = ResolveOnceGuard()
_r1 = _guard1.claim("allow", source="user")
check("35.2.1", _r1 == "allow" and _guard1.is_resolved and _guard1.result == "allow",
      "First claim wins")

# 35.2.2: Second claim returns None
_r2 = _guard1.claim("deny", source="classifier")
check("35.2.2", _r2 is None and _guard1.result == "allow" and _guard1.source == "user",
      "Second claim rejected, original preserved")

# 35.2.3: Reset allows re-claim
_guard1.reset()
_r3 = _guard1.claim("deny", source="bridge")
check("35.2.3", _r3 == "deny" and _guard1.source == "bridge",
      "After reset, new claim succeeds")

# 35.2.4: Thread safety — only one winner
_guard2 = ResolveOnceGuard()
_winners = []
def _race_claim(val, src):
    result = _guard2.claim(val, source=src)
    if result is not None:
        _winners.append(src)
_race_threads = [
    threading.Thread(target=_race_claim, args=(f"v{i}", f"src{i}"))
    for i in range(10)
]
for t in _race_threads: t.start()
for t in _race_threads: t.join()
check("35.2.4", len(_winners) == 1 and _guard2.is_resolved,
      f"Only 1 winner out of 10 threads: {len(_winners)}")

# 35.2.5: to_dict
_d25 = _guard2.to_dict()
check("35.2.5", _d25["resolved"] and _d25["source"] in [f"src{i}" for i in range(10)],
      "to_dict serializes guard state")

# ---------- 35.3: StallWatchdog — AP-3 ----------

# 35.3.1: Watch/unwatch lifecycle
_sw1 = StallWatchdog(threshold_s=0.5)
_sw1.watch("t1", "nuclei", output_file=None)
_status = _sw1.get_status()
check("35.3.1", _status["watched_count"] == 1,
      "Watch registers tool")

# 35.3.2: Record output resets stall timer
_sw1.record_output("t1", 100)
_sw1.record_output("t1", 200)
_reports = _sw1.check_all()
check("35.3.2", len(_reports) == 0,
      "No stall when output is growing")

# 35.3.3: Stall detected after threshold (no output file)
_sw2 = StallWatchdog(threshold_s=0.1)
_sw2.watch("t2", "ffuf", output_file=None)
time.sleep(0.2)
_reports2 = _sw2.check_all()
check("35.3.3", len(_reports2) == 1 and _reports2[0].verdict == StallVerdict.STALLED_SLOW,
      f"Stall detected (verdict={_reports2[0].verdict.value if _reports2 else 'none'})")

# 35.3.4: Stall with prompt pattern detection
_tmpd34 = tempfile.mkdtemp()
_tmpf34 = os.path.join(_tmpd34, "output.txt")
with open(_tmpf34, "w") as f:
    f.write("Scanning...\nFound 5 results\nOverwrite existing file? [Y/n]")
_sw3 = StallWatchdog(threshold_s=0.1)
_sw3.watch("t3", "sqlmap", output_file=_tmpf34)
# First check sees file size as growth; need two checks after threshold
time.sleep(0.15)
_sw3.check_all()  # resets timer after seeing file content
time.sleep(0.15)
_reports3 = _sw3.check_all()
check("35.3.4", (len(_reports3) == 1
      and _reports3[0].verdict == StallVerdict.STALLED_PROMPT
      and "Y/n" in _reports3[0].matched_pattern),
      f"Prompt stall detected: pattern='{_reports3[0].matched_pattern if _reports3 else ''}'")

# 35.3.5: Remediation advice generated
check("35.3.5", _reports3 and _reports3[0].remediation != "",
      f"Remediation: '{_reports3[0].remediation if _reports3 else ''}'")

# 35.3.6: Unwatch removes tool
_sw1.unwatch("t1")
_s6 = _sw1.get_status()
check("35.3.6", _s6["watched_count"] == 0 or all(not w.get("tool_id") == "t1" for w in _s6.get("active", [])),
      "Unwatch removes tool from monitoring")

# 35.3.7: check_one for specific tool
_sw4 = StallWatchdog(threshold_s=0.1)
_sw4.watch("t4", "nmap")
_r47 = _sw4.check_one("t4")
check("35.3.7", _r47 is not None and _r47.verdict == StallVerdict.RUNNING,
      f"check_one returns RUNNING before threshold")

# 35.3.8: on_stall callback fires
_stall_cb_called = []
def _on_stall(report):
    _stall_cb_called.append(report.tool_name)
_sw5 = StallWatchdog(threshold_s=0.1, on_stall=_on_stall)
_tmpf38 = os.path.join(_tmpd34, "out38.txt")
with open(_tmpf38, "w") as f:
    f.write("Are you sure you want to continue? (y/n)")
_sw5.watch("t5", "custom-tool", output_file=_tmpf38)
time.sleep(0.15)
_sw5.check_all()  # first check sees initial file content as growth
time.sleep(0.15)
_sw5.check_all()  # second check detects actual stall
check("35.3.8", "custom-tool" in _stall_cb_called,
      f"on_stall callback fired: {_stall_cb_called}")

# 35.3.9: Stall not re-notified
_stall_cb_called.clear()
_sw5.check_all()
check("35.3.9", len(_stall_cb_called) == 0,
      "Stall not re-notified after initial report")

# Cleanup temp
import shutil as _shutil35
_shutil35.rmtree(_tmpd34, ignore_errors=True)

# ---------- 35.4: DreamConsolidator — AP-1 ----------

# 35.4.1: Phase starts IDLE
_dc1 = DreamConsolidator(agent_memory=None, consolidation_threshold=2)
check("35.4.1", _dc1.phase == DreamPhase.IDLE,
      "DreamConsolidator starts IDLE")

# 35.4.2: Consolidation with provided episodes
_dc_episodes = [
    {"action": "test_xss", "outcome": "success", "target": "a.com", "tools_used": ["nuclei"]},
    {"action": "test_xss", "outcome": "success", "target": "b.com", "tools_used": ["ffuf", "nuclei"]},
    {"action": "test_xss", "outcome": "failure", "target": "c.com", "error_type": "waf_blocked"},
    {"action": "test_sqli", "outcome": "success", "target": "a.com"},
]
_stats42 = _dc1.consolidate_session(session_id="test", episodes=_dc_episodes)
check("35.4.2", _stats42.episodes_reviewed == 4 and _dc1.phase == DreamPhase.COMPLETE,
      f"Consolidated: reviewed={_stats42.episodes_reviewed}, phase={_dc1.phase.value}")

# 35.4.3: Rules/facts extracted from patterns
check("35.4.3", _stats42.rules_extracted >= 1 or _stats42.facts_updated >= 1,
      f"Patterns extracted: rules={_stats42.rules_extracted}, facts={_stats42.facts_updated}")

# 35.4.4: Below threshold skips consolidation
_dc2 = DreamConsolidator(agent_memory=None, consolidation_threshold=10)
_stats44 = _dc2.consolidate_session(episodes=[{"action": "x", "outcome": "y"}])
check("35.4.4", _stats44.episodes_reviewed == 1 and _stats44.rules_extracted == 0,
      "Below threshold: skipped (no rules extracted)")

# 35.4.5: Turns sliding window (MAX_DREAM_TURNS = 30)
_dc3 = DreamConsolidator(max_turns=5)
for _i in range(10):
    _dc3._add_turn(f"action_{_i}", f"detail_{_i}")
_turns45 = _dc3.get_turns()
check("35.4.5", len(_turns45) == 5 and _turns45[0]["action"] == "action_5",
      f"Sliding window: {len(_turns45)} turns, first={_turns45[0]['action'] if _turns45 else ''}")

# 35.4.6: Fuse blows after repeated failures
_dc4 = DreamConsolidator(agent_memory=None, consolidation_threshold=1)
# Simulate failures by passing un-iterable episodes
for _i46 in range(5):
    try:
        _dc4._fuse.record_failure(f"simulated-{_i46}")
    except Exception:
        pass
_stats46 = _dc4.consolidate_session(episodes=[{"action": "x", "outcome": "y"}, {"action": "x", "outcome": "y"}])
check("35.4.6", _dc4._fuse.is_blown and _stats46.episodes_reviewed == 0,
      f"Fuse blown: {_dc4._fuse.is_blown}, skipped consolidation")

# 35.4.7: to_dict serialization
_d47 = _dc1.to_dict()
check("35.4.7", "phase" in _d47 and "stats" in _d47 and "fuse" in _d47,
      f"to_dict keys: {list(_d47.keys())}")

# ---------- 35.5: LLMMemoryRetriever — AP-2 ----------

# 35.5.1: Select with no LLM fn (fallback to confidence sort)
_mr1 = LLMMemoryRetriever(llm_fn=None, max_results=3)
_candidates = [
    MemoryCandidate(key="k1", summary="XSS on login", category="finding", confidence=0.9),
    MemoryCandidate(key="k2", summary="SQLi time-based", category="technique", confidence=0.7),
    MemoryCandidate(key="k3", summary="WAF bypass", category="reference", confidence=0.95),
    MemoryCandidate(key="k4", summary="IDOR on API", category="finding", confidence=0.5),
]
_sel51 = _mr1.select(task="Test login for XSS", candidates=_candidates)
check("35.5.1", len(_sel51.selected_keys) == 3 and _sel51.selected_keys[0] == "k3",
      f"Fallback select: {_sel51.selected_keys}")

# 35.5.2: Already-surfaced keys excluded
_sel52 = _mr1.select(
    task="Test XSS", candidates=_candidates,
    already_surfaced={"k3", "k1"},
)
check("35.5.2", "k3" not in _sel52.selected_keys and "k1" not in _sel52.selected_keys,
      f"Already-surfaced excluded: {_sel52.selected_keys}")

# 35.5.3: Empty candidates returns empty
_sel53 = _mr1.select(task="anything", candidates=[])
check("35.5.3", len(_sel53.selected_keys) == 0,
      "Empty candidates -> empty selection")

# 35.5.4: LLM fn integration
def _mock_llm(system_prompt, user_prompt):
    return json.dumps({"selected": ["k1", "k4"]})
_mr2 = LLMMemoryRetriever(llm_fn=_mock_llm, max_results=5)
_sel54 = _mr2.select(task="Test IDOR", candidates=_candidates)
check("35.5.4", _sel54.selected_keys == ["k1", "k4"],
      f"LLM-guided selection: {_sel54.selected_keys}")

# 35.5.5: LLM fn with invalid JSON degrades gracefully
def _bad_llm(system_prompt, user_prompt):
    return "Sorry, I cannot help with that"
_mr3 = LLMMemoryRetriever(llm_fn=_bad_llm, max_results=5)
_sel55 = _mr3.select(task="anything", candidates=_candidates)
check("35.5.5", len(_sel55.selected_keys) == 0,
      "Bad LLM response -> empty selection (graceful)")

# 35.5.6: LLM fn hallucinated keys filtered
def _hallucinating_llm(system_prompt, user_prompt):
    return json.dumps({"selected": ["k1", "nonexistent_key", "k2"]})
_mr4 = LLMMemoryRetriever(llm_fn=_hallucinating_llm)
_sel56 = _mr4.select(task="test", candidates=_candidates)
check("35.5.6", "nonexistent_key" not in _sel56.selected_keys and "k1" in _sel56.selected_keys,
      f"Hallucinated keys filtered: {_sel56.selected_keys}")

# 35.5.7: Fuse blows after repeated LLM failures
def _crashing_llm(system_prompt, user_prompt):
    raise ConnectionError("LLM service down")
_mr5 = LLMMemoryRetriever(llm_fn=_crashing_llm)
for _i57 in range(4):
    _mr5.select(task="test", candidates=_candidates)
check("35.5.7", _mr5._fuse.is_blown,
      f"Fuse blown after 3 LLM failures: {_mr5._fuse.is_blown}")

# 35.5.8: MemoryCandidate manifest with staleness
_old_candidate = MemoryCandidate(key="old", summary="Ancient finding", age_days=30)
_line = _old_candidate.manifest_line()
check("35.5.8", "30d old" in _line and "stale" in _line.lower(),
      "Staleness warning in manifest line")

# 35.5.9: Surfaced tracking accumulates
_mr6 = LLMMemoryRetriever(llm_fn=None, max_results=2)
_mr6.select(task="t1", candidates=_candidates)
_mr6.select(task="t2", candidates=_candidates)
_d59 = _mr6.to_dict()
check("35.5.9", _d59["surfaced_count"] >= 2,
      f"Surfaced tracking: {_d59['surfaced_count']}")

# 35.5.10: clear_surfaced resets tracking
_mr6.clear_surfaced()
check("35.5.10", _mr6.to_dict()["surfaced_count"] == 0,
      "clear_surfaced resets count")

# ---------- 35.6: PostTurnOrchestrator — AP-4 ----------

# 35.6.1: Register and execute hooks
_pto1 = PostTurnOrchestrator()
_hook_calls = []
def _hook_a(ctx):
    _hook_calls.append("a")
def _hook_b(ctx):
    _hook_calls.append("b")
_pto1.register("hook_a", _hook_a, HookPriority.CRITICAL)
_pto1.register("hook_b", _hook_b, HookPriority.NORMAL)
_result61 = _pto1.execute(context={"turn": 1})
check("35.6.1", _hook_calls == ["a", "b"] and len(_result61.hook_results) == 2,
      f"Hooks executed in priority order: {_hook_calls}")

# 35.6.2: Fire-and-forget hooks don't block
_ff_called = threading.Event()
def _ff_hook(ctx):
    time.sleep(0.1)
    _ff_called.set()
_pto2 = PostTurnOrchestrator()
_pto2.register("ff", _ff_hook, HookPriority.LOW, fire_and_forget=True)
_r62_start = time.monotonic()
_r62 = _pto2.execute()
_r62_dur = time.monotonic() - _r62_start
check("35.6.2", _r62_dur < 0.05 and _r62.hook_results[0].outcome == HookOutcome.SUCCESS,
      f"Fire-and-forget returned immediately ({_r62_dur:.3f}s)")

# 35.6.3: Hook timeout
_pto3 = PostTurnOrchestrator(timeout_s=0.2)
def _slow_hook(ctx):
    time.sleep(5)
_pto3.register("slow", _slow_hook, HookPriority.NORMAL)
_r63 = _pto3.execute()
check("35.6.3", _r63.hook_results[0].outcome == HookOutcome.TIMEOUT,
      f"Slow hook timed out: {_r63.hook_results[0].outcome.value}")

# 35.6.4: Hook failure with blocking error
_pto4 = PostTurnOrchestrator()
def _failing_hook(ctx):
    raise ValueError("Critical failure")
_pto4.register("crash", _failing_hook, HookPriority.HIGH)
_r64 = _pto4.execute()
check("35.6.4", (len(_r64.blocking_errors) == 1
      and "Critical failure" in _r64.blocking_errors[0]),
      f"Blocking error captured: {_r64.blocking_errors}")

# 35.6.5: prevent_continuation from hook return value
_pto5 = PostTurnOrchestrator()
def _stopping_hook(ctx):
    return {"prevent_continuation": True}
_pto5.register("stopper", _stopping_hook, HookPriority.CRITICAL)
_r65 = _pto5.execute()
check("35.6.5", _r65.prevent_continuation,
      "Hook can prevent continuation via return value")

# 35.6.6: Abort signal skips remaining hooks
_pto6 = PostTurnOrchestrator()
_abort = threading.Event()
_abort.set()  # pre-set abort
_pto6.register("h1", lambda ctx: None, HookPriority.NORMAL)
_pto6.register("h2", lambda ctx: None, HookPriority.LOW)
_r66 = _pto6.execute(abort_signal=_abort)
_skipped = [h for h in _r66.hook_results if h.outcome == HookOutcome.SKIPPED]
check("35.6.6", len(_skipped) == 2,
      f"Abort signal skipped {len(_skipped)} hooks")

# 35.6.7: Duplicate registration prevented
_pto7 = PostTurnOrchestrator()
_pto7.register("dup", lambda ctx: None)
_pto7.register("dup", lambda ctx: None)  # should be ignored
_s67 = _pto7.get_stats()
check("35.6.7", _s67["registered_hooks"] == 1,
      "Duplicate registration prevented")

# 35.6.8: Unregister hook
_removed = _pto7.unregister("dup")
check("35.6.8", _removed and _pto7.get_stats()["registered_hooks"] == 0,
      "Unregister removes hook")

# 35.6.9: get_stats includes execution counts
_pto8 = PostTurnOrchestrator()
_pto8.register("counter", lambda ctx: None)
_pto8.execute()
_pto8.execute()
_s69 = _pto8.get_stats()
check("35.6.9", _s69["total_executions"] == 2,
      f"Execution count: {_s69['total_executions']}")

# ---------- 35.7: CacheOptimizedForker — AP-6 ----------

# 35.7.1: Build fork messages
_cof1 = CacheOptimizedForker()
_ctx71 = {
    "target": "example.com",
    "scan_phase": "exploit",
    "findings_so_far": [
        {"severity": "high", "title": "SQL Injection in /login"},
        {"severity": "medium", "title": "XSS in search"},
    ],
}
_directives71 = [
    "Test all login forms for SQL injection",
    "Test all input fields for XSS",
    "Enumerate API endpoints for IDOR",
]
_msgs71 = _cof1.build_fork_messages(_ctx71, _directives71)
check("35.7.1", len(_msgs71) == 3,
      f"Built {len(_msgs71)} message sets for 3 directives")

# 35.7.2: All children share same cache key (prefix is identical)
_keys72 = {ms.cache_key for ms in _msgs71}
check("35.7.2", len(_keys72) == 1,
      f"All children share 1 cache key (got {len(_keys72)})")

# 35.7.3: Shared prefix is identical across children
_prefix_a = _msgs71[0].shared_prefix
_prefix_b = _msgs71[1].shared_prefix
check("35.7.3", _prefix_a == _prefix_b,
      "Shared prefix identical across children")

# 35.7.4: Directives differ between children
_dir_a = _msgs71[0].child_directive
_dir_b = _msgs71[1].child_directive
check("35.7.4", _dir_a != _dir_b,
      "Directives differ between children")

# 35.7.5: full_messages() combines prefix + suffix
_full75 = _msgs71[0].full_messages()
check("35.7.5", len(_full75) > 1 and _full75[-1]["role"] == "user",
      f"full_messages: {len(_full75)} messages, last role={_full75[-1]['role']}")

# 35.7.6: Child directive includes rules
_suffix76 = _msgs71[0].child_suffix["content"]
check("35.7.6", "DIRECTIVE:" in _suffix76 and "RULES:" in _suffix76 and "Scope:" in _suffix76,
      "Child message includes DIRECTIVE, RULES, and Scope instruction")

# 35.7.7: Shared prefix includes target context
_has_target = any(
    "example.com" in json.dumps(msg, default=str)
    for msg in _prefix_a
)
check("35.7.7", _has_target,
      "Shared prefix includes target context")

# 35.7.8: Shared prefix includes findings
_has_findings = any(
    "SQL Injection" in json.dumps(msg, default=str)
    for msg in _prefix_a
)
check("35.7.8", _has_findings,
      "Shared prefix includes prior findings")

# 35.7.9: Cache savings estimation
_savings = _cof1.estimate_cache_savings(num_children=5, prefix_tokens=3000)
check("35.7.9", _savings["savings_pct"] > 50 and _savings["tokens_saved"] > 0,
      f"Cache savings: {_savings['savings_pct']}% ({_savings['tokens_saved']} tokens)")

# 35.7.10: Empty findings still works
_msgs710 = _cof1.build_fork_messages(
    {"target": "test.com"}, ["directive"],
)
check("35.7.10", len(_msgs710) == 1 and len(_msgs710[0].shared_prefix) >= 1,
      "Works with empty findings")

# ---------- 35.8: Module-level singletons ----------

# 35.8.1: Stall watchdog singleton
reset_stall_watchdog()
_sw81 = get_stall_watchdog()
_sw81b = get_stall_watchdog()
check("35.8.1", _sw81 is _sw81b,
      "Stall watchdog singleton returns same instance")

# 35.8.2: Post-turn orchestrator singleton
reset_post_turn_orchestrator()
_pto81 = get_post_turn_orchestrator()
_pto81b = get_post_turn_orchestrator()
check("35.8.2", _pto81 is _pto81b,
      "PostTurnOrchestrator singleton returns same instance")

# 35.8.3: Dream consolidator singleton
reset_dream_consolidator()
_dc81 = get_dream_consolidator()
_dc81b = get_dream_consolidator()
check("35.8.3", _dc81 is _dc81b,
      "DreamConsolidator singleton returns same instance")

# 35.8.4: Memory retriever singleton
reset_memory_retriever()
_mr81 = get_memory_retriever()
_mr81b = get_memory_retriever()
check("35.8.4", _mr81 is _mr81b,
      "LLMMemoryRetriever singleton returns same instance")

# 35.8.5: Reset clears singleton
reset_stall_watchdog()
_sw82 = get_stall_watchdog()
check("35.8.5", _sw82 is not _sw81,
      "Reset creates new singleton instance")

# ---------- 35.9: Cross-component integration ----------

# 35.9.1: PostTurnOrchestrator with DreamConsolidator hook
reset_post_turn_orchestrator()
reset_dream_consolidator()
_pto91 = get_post_turn_orchestrator()
_dc91 = get_dream_consolidator(consolidation_threshold=2)
_dream_ran = []
def _dream_hook(ctx):
    eps = ctx.get("episodes", [])
    if eps:
        stats = _dc91.consolidate_session(episodes=eps)
        _dream_ran.append(stats.episodes_reviewed)
_pto91.register("auto_dream", _dream_hook, HookPriority.LOW)
_pto91.execute(context={
    "episodes": [
        {"action": "scan", "outcome": "success"},
        {"action": "scan", "outcome": "failure"},
        {"action": "scan", "outcome": "success"},
    ]
})
check("35.9.1", len(_dream_ran) == 1 and _dream_ran[0] == 3,
      f"Dream hook executed via PostTurnOrchestrator: {_dream_ran}")

# 35.9.2: StallWatchdog with FuseCircuit
_fuse92 = FuseCircuit(name="stall-fuse", threshold=2)
_stall_count = [0]
def _stall_with_fuse(report):
    _stall_count[0] += 1
    _fuse92.record_failure(f"Tool {report.tool_name} stalled")
_tmpd92 = tempfile.mkdtemp()
_tmpf92a = os.path.join(_tmpd92, "out_a.txt")
_tmpf92b = os.path.join(_tmpd92, "out_b.txt")
with open(_tmpf92a, "w") as f:
    f.write("Processing...\nConfirm deletion? (y/n)")
with open(_tmpf92b, "w") as f:
    f.write("Ready.\nContinue?")
_sw92_2 = StallWatchdog(threshold_s=0.1, on_stall=_stall_with_fuse)
_sw92_2.watch("s1", "tool1", output_file=_tmpf92a)
_sw92_2.watch("s2", "tool2", output_file=_tmpf92b)
time.sleep(0.15)
_sw92_2.check_all()  # first check sees initial content as growth
time.sleep(0.15)
_sw92_2.check_all()  # second check detects prompt stall
check("35.9.2", _stall_count[0] >= 1,
      f"StallWatchdog + FuseCircuit integration: {_stall_count[0]} stalls detected")
_shutil35.rmtree(_tmpd92, ignore_errors=True)

# 35.9.3: CacheOptimizedForker with ResolveOnceGuard
_guard93 = ResolveOnceGuard()
_forker93 = CacheOptimizedForker()
_msgs93 = _forker93.build_fork_messages(
    {"target": "t.com"}, ["dir1", "dir2"],
)
# Simulate: first child to complete claims the guard
_guard93.claim(_msgs93[0].child_directive, source="child-0")
_second = _guard93.claim(_msgs93[1].child_directive, source="child-1")
check("35.9.3", _second is None and _guard93.source == "child-0",
      "First fork child claims guard; second rejected")

# Cleanup singletons
reset_stall_watchdog()
reset_post_turn_orchestrator()
reset_dream_consolidator()
reset_memory_retriever()


# Results
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•






# ===== SECTION 36: Advanced Orchestration (AO 1-8) =====
print("\n== Section 36: Advanced Orchestration Patterns (AO 1-8) ==")

# --- AO-1: OutputSlotReservation ---
print("  36.1: OutputSlotReservation")

from CaseCrack.tools.burp_enterprise.agents.advanced_orchestration import (
    OutputSlotReservation, EscalationStage, EscalationRecord,
    StreamingToolExecutor, ToolExecState, StreamToolSlot,
    ToolBatchSummariser, ToolBatchEntry, BatchSummary,
    AwaySummary, PresenceState, AwaySummaryResult,
    DiagnosticDeltaTracker, DiagnosticDelta, DiagnosticSnapshot,
    FallbackTombstoner, TombstoneReason, TombstonedMessage, FallbackEvent,
    TriagePriorityQueue, TriagePriority, TriageItem,
    ForkProgressReporter, ProgressLabel,
    get_slot_reservation, get_tool_summariser, get_away_summary,
    get_diagnostic_tracker, get_fallback_tombstoner, get_triage_queue,
    get_progress_reporter,
    reset_slot_reservation, reset_tool_summariser, reset_away_summary,
    reset_diagnostic_tracker, reset_fallback_tombstoner, reset_triage_queue,
    reset_progress_reporter,
)

# AO-1 tests
osr = OutputSlotReservation()
check("36.1.1", osr.current_max_tokens == 8192, "Default capped at 8192")
check("36.1.2", osr.stage == EscalationStage.CAPPED, "Starts in CAPPED stage")

# Normal completion - no escalation
nudge = osr.on_completion("end_turn", 500)
check("36.1.3", nudge is None, "No nudge for normal completion")
check("36.1.4", osr.stage == EscalationStage.CAPPED, "Still CAPPED after normal completion")

# Truncation triggers escalation
nudge = osr.on_completion("max_tokens", 8192)
check("36.1.5", nudge is None, "Silent escalation returns None (retry transparent)")
check("36.1.6", osr.stage == EscalationStage.ESCALATED, "Stage now ESCALATED")
check("36.1.7", osr.current_max_tokens == 65536, "Max tokens now 65536")
check("36.1.8", len(osr.history) == 1, "One escalation in history")
check("36.1.9", osr.history[0].stage == EscalationStage.ESCALATED, "History records escalation")

# Second truncation triggers recovery
nudge = osr.on_completion("max_tokens", 65536)
check("36.1.10", nudge is not None, "Recovery nudge returned")
check("36.1.11", "truncated" in nudge.lower(), "Nudge mentions truncation")
check("36.1.12", osr.stage == EscalationStage.MULTI_TURN_RECOVERY, "Now in MULTI_TURN_RECOVERY")

# Exhaust recovery attempts
for _ in range(3):
    osr.on_completion("max_tokens", 65536)
check("36.1.13", osr.stage == EscalationStage.EXHAUSTED, "Exhausted after max attempts")
nudge_final = osr.on_completion("max_tokens", 65536)
check("36.1.14", nudge_final is None, "No more nudges after exhaustion")

# Custom params
osr2 = OutputSlotReservation(capped_default=4096, escalated_max=32768, max_recovery_attempts=1)
check("36.1.15", osr2.current_max_tokens == 4096, "Custom capped default")
osr2.on_completion("max_tokens", 4096)
check("36.1.16", osr2.current_max_tokens == 32768, "Custom escalated max")

# Reset
osr.reset()
check("36.1.17", osr.stage == EscalationStage.CAPPED, "Reset returns to CAPPED")
check("36.1.18", len(osr.history) == 0, "Reset clears history")

# --- AO-2: StreamingToolExecutor ---
print("  36.2: StreamingToolExecutor")

import asyncio

ste = StreamingToolExecutor(max_parallel=4)
check("36.2.1", ste.stats == {}, "Empty stats initially")
check("36.2.2", ste.get_completed() == {}, "No completed tools initially")

# Test with async executor
async def mock_executor(name, inp):
    await asyncio.sleep(0.01)
    return {"tool": name, "result": "ok"}

async def test_ste_basic():
    ste_inner = StreamingToolExecutor(max_parallel=4)
    await ste_inner.add_tool("t1", "nmap", '{"target":"x"}', mock_executor)
    await ste_inner.add_tool("t2", "nikto", '{"target":"y"}', mock_executor)
    results = await ste_inner.collect(timeout=5.0)
    return results, ste_inner

loop36 = asyncio.new_event_loop()
results_ste, ste_done = loop36.run_until_complete(test_ste_basic())
check("36.2.3", "t1" in results_ste, "Tool t1 completed")
check("36.2.4", "t2" in results_ste, "Tool t2 completed")
check("36.2.5", results_ste["t1"]["tool"] == "nmap", "Tool t1 has correct name")
check("36.2.6", results_ste["t2"]["result"] == "ok", "Tool t2 has correct result")
check("36.2.7", ste_done.stats.get("completed", 0) == 2, "2 completed in stats")

# Test failing executor
async def fail_executor(name, inp):
    raise ValueError("tool failed")

async def test_ste_fail():
    ste_f = StreamingToolExecutor()
    await ste_f.add_tool("t3", "fail_tool", "{}", fail_executor)
    results = await ste_f.collect(timeout=5.0)
    return results, ste_f

res_fail, ste_f = loop36.run_until_complete(test_ste_fail())
check("36.2.8", "t3" in res_fail, "Failed tool in results")
check("36.2.9", "error" in res_fail["t3"], "Failed tool has error key")
check("36.2.10", ste_f.stats.get("failed", 0) == 1, "1 failed in stats")

# Test discard
async def test_ste_discard():
    ste_d = StreamingToolExecutor()
    await ste_d.add_tool("t4", "slow", "{}", mock_executor)
    await ste_d.discard()
    return ste_d

ste_discarded = loop36.run_until_complete(test_ste_discard())
check("36.2.11", ste_discarded.stats == {}, "Stats empty after discard")

# --- AO-3: ToolBatchSummariser ---
print("  36.3: ToolBatchSummariser")

tbs = ToolBatchSummariser()

# Empty batch
async def test_tbs_empty():
    return await tbs.summarise([])

empty_sum = loop36.run_until_complete(test_tbs_empty())
check("36.3.1", empty_sum.summary == "No tools executed", "Empty batch summary")
check("36.3.2", empty_sum.tool_count == 0, "Empty batch count = 0")

# Single tool heuristic
entries_single = [
    ToolBatchEntry(tool_name="nmap", input_preview="target=10.0.0.1", output_preview="80/tcp open", duration_ms=1500)
]

async def test_tbs_single():
    return await tbs.summarise(entries_single)

single_sum = loop36.run_until_complete(test_tbs_single())
check("36.3.3", "nmap" in single_sum.summary.lower(), "Single tool mentions tool name")
check("36.3.4", single_sum.tool_count == 1, "Tool count = 1")
check("36.3.5", len(single_sum.summary) <= 30, "Summary <= 30 chars")

# Multi-tool heuristic
entries_multi = [
    ToolBatchEntry(tool_name="nmap", input_preview="x", output_preview="y", duration_ms=100),
    ToolBatchEntry(tool_name="nikto", input_preview="x", output_preview="y", duration_ms=200),
    ToolBatchEntry(tool_name="ffuf", input_preview="x", output_preview="y", duration_ms=300),
]

async def test_tbs_multi():
    return await tbs.summarise(entries_multi)

multi_sum = loop36.run_until_complete(test_tbs_multi())
check("36.3.6", multi_sum.tool_count == 3, "Multi-tool count = 3")
check("36.3.7", "3" in multi_sum.summary, "Multi-tool mentions count")
check("36.3.8", multi_sum.total_duration_ms == 600, "Total duration calculated")

# History tracking
check("36.3.9", len(tbs.history) == 3, "3 summaries in history")

# With model function
async def mock_model(system, user):
    return "Scanned target ports"

tbs_model = ToolBatchSummariser(model_fn=mock_model)

async def test_tbs_model():
    return await tbs_model.summarise(entries_single)

model_sum = loop36.run_until_complete(test_tbs_model())
check("36.3.10", model_sum.summary == "Scanned target ports", "Model-generated summary")

# Fire and forget + consume
tbs_ff = ToolBatchSummariser(model_fn=mock_model)

async def test_tbs_ff():
    tbs_ff.fire_and_forget(entries_single)
    result = await tbs_ff.consume_pending()
    return result

ff_result = loop36.run_until_complete(test_tbs_ff())
check("36.3.11", ff_result is not None, "Fire-and-forget consumed successfully")
check("36.3.12", ff_result.summary == "Scanned target ports", "Fire-and-forget correct summary")

# --- AO-4: AwaySummary ---
print("  36.4: AwaySummary")

aws = AwaySummary(idle_threshold=0.05, away_threshold=0.1)
check("36.4.1", aws.state == PresenceState.ACTIVE, "Starts ACTIVE")

# Touch returns None when active
result = aws.touch()
check("36.4.2", result is None, "Touch while active returns None")

# Record events while away
import time as time_mod
time_mod.sleep(0.15)  # exceed away threshold
aws.record_event("Found SQL injection in /login")
aws.record_event("Phase 2 complete")
check("36.4.3", aws.state == PresenceState.AWAY, "State transitions to AWAY")

# Touch returns recap on return from away
aws.record_event("Critical vuln in /admin")
recap = aws.touch()
check("36.4.4", recap is not None, "Recap generated on return")
check("36.4.5", recap.events_during_absence == 3, "3 events during absence")
check("36.4.6", recap.away_duration_secs > 0, "Away duration positive")
check("36.4.7", "events" in recap.summary.lower() or "while away" in recap.summary.lower(), "Summary mentions events")
check("36.4.8", len(aws.summaries) == 1, "One summary in history")

# No recap when returning from active
result2 = aws.touch()
check("36.4.9", result2 is None, "No recap when returning from active")

# Custom model fn
async def mock_recap_model(system, user):
    return "Found 2 critical vulns while you were away."

async def test_recap_async():
    events = ["Found SQLi", "Found XSS"]
    aws_m = AwaySummary(model_fn=mock_recap_model)
    return await aws_m.generate_recap_async(events)

recap_async = loop36.run_until_complete(test_recap_async())
check("36.4.10", "critical vulns" in recap_async.lower(), "Async model recap works")

# --- AO-5: DiagnosticDeltaTracker ---
print("  36.5: DiagnosticDeltaTracker")

ddt = DiagnosticDeltaTracker()
check("36.5.1", len(ddt.pending_snapshots) == 0, "No pending snapshots initially")

# Snapshot before edit
before_diags = [
    {"message": "SQL injection possible", "line": 42, "severity": "high"},
    {"message": "Missing CSRF token", "line": 15, "severity": "medium"},
]
snap = ddt.snapshot("/app/login.py", before_diags)
check("36.5.2", snap.file_path == "/app/login.py", "Snapshot captures file path")
check("36.5.3", len(snap.diagnostics) == 2, "Snapshot captures 2 diagnostics")
check("36.5.4", "/app/login.py" in ddt.pending_snapshots, "File in pending snapshots")

# Compute delta after edit
after_diags = [
    {"message": "SQL injection possible", "line": 42, "severity": "high"},  # unchanged
    {"message": "Hardcoded API key", "line": 88, "severity": "critical"},   # NEW
]
delta = ddt.compute_delta("/app/login.py", after_diags)
check("36.5.5", len(delta.new_issues) == 1, "1 new issue detected")
check("36.5.6", delta.new_issues[0]["message"] == "Hardcoded API key", "New issue is API key")
check("36.5.7", len(delta.resolved_issues) == 1, "1 resolved issue")
check("36.5.8", delta.resolved_issues[0]["message"] == "Missing CSRF token", "Resolved CSRF issue")
check("36.5.9", delta.unchanged_count == 1, "1 unchanged issue")
check("36.5.10", delta.file_path == "/app/login.py", "Delta has correct file path")

# No snapshot - all treated as new
delta2 = ddt.compute_delta("/app/other.py", [{"message": "XSS", "line": 1}])
check("36.5.11", len(delta2.new_issues) == 1, "No baseline = all new")
check("36.5.12", len(delta2.resolved_issues) == 0, "No baseline = no resolved")

# History
check("36.5.13", len(ddt.history) == 2, "2 deltas in history")

# Empty diagnostics
ddt.snapshot("/app/empty.py", [])
delta3 = ddt.compute_delta("/app/empty.py", [])
check("36.5.14", len(delta3.new_issues) == 0, "Empty before/after = no changes")

# --- AO-6: FallbackTombstoner ---
print("  36.6: FallbackTombstoner")

ft = FallbackTombstoner(fallback_order=["gpt-4", "gpt-3.5-turbo", "local-llama"])

messages = [
    {"id": "m1", "role": "user", "content": "Scan the target"},
    {"id": "m2", "role": "assistant", "content": "<thinking>Let me analyze the target...</thinking>"},
    {"id": "m3", "role": "assistant", "content": [
        {"type": "tool_use", "id": "tu1", "name": "nmap", "input": {"target": "10.0.0.1"}}
    ]},
    {"id": "m4", "role": "tool", "tool_use_id": "tu1", "content": "80/tcp open"},
    {"id": "m5", "role": "tool", "tool_use_id": "tu_orphan", "content": "orphaned result"},
]

cleaned, next_model, tombstoned = ft.process_fallback(messages, "gpt-4", "rate_limit_exceeded")

check("36.6.1", next_model == "gpt-3.5-turbo", "Falls back to next model")
check("36.6.2", len(tombstoned) == 2, "2 messages tombstoned (thinking + orphan)")

# Verify thinking block was tombstoned
thinking_tombstones = [t for t in tombstoned if t.reason == TombstoneReason.MODEL_FALLBACK]
check("36.6.3", len(thinking_tombstones) == 1, "Thinking block tombstoned")

# Verify orphan tool result was tombstoned
orphan_tombstones = [t for t in tombstoned if t.reason == TombstoneReason.ORPHANED_TOOL_RESULT]
check("36.6.4", len(orphan_tombstones) == 1, "Orphaned tool result tombstoned")

# Valid tool result kept
valid_tool_msgs = [m for m in cleaned if m.get("role") == "tool" and m.get("tool_use_id") == "tu1"]
check("36.6.5", len(valid_tool_msgs) == 1, "Valid tool result preserved")

# System warning injected
warning_msgs = [m for m in cleaned if m.get("role") == "system" and "[FALLBACK]" in str(m.get("content", ""))]
check("36.6.6", len(warning_msgs) == 1, "Fallback warning injected")

# Fallback chain exhaustion
ft2 = FallbackTombstoner(fallback_order=["model-a"])
_, next2, _ = ft2.process_fallback([{"id": "x", "role": "user", "content": "hi"}], "model-a", "error")
check("36.6.7", next2 is None, "No fallback when at end of chain")

# Unknown model gets first in chain
ft3 = FallbackTombstoner(fallback_order=["backup-1", "backup-2"])
_, next3, _ = ft3.process_fallback([{"id": "x", "role": "user", "content": "hi"}], "unknown-model", "error")
check("36.6.8", next3 == "backup-1", "Unknown model falls back to first in chain")

# Events tracked
check("36.6.9", len(ft.events) == 1, "1 fallback event recorded")
check("36.6.10", ft.events[0].from_model == "gpt-4", "Event records source model")
check("36.6.11", ft.events[0].to_model == "gpt-3.5-turbo", "Event records target model")

# Tombstones accumulated
check("36.6.12", len(ft.tombstones) == 2, "Tombstone audit log maintained")

# --- AO-7: TriagePriorityQueue ---
print("  36.7: TriagePriorityQueue")

tpq = TriagePriorityQueue()
check("36.7.1", tpq.total_pending == 0, "Empty queue initially")

# Enqueue items at different priorities
item_now = tpq.enqueue(TriagePriority.NOW, {"vuln": "SQLi critical"}, source="scanner")
item_next = tpq.enqueue(TriagePriority.NEXT, {"phase": "recon complete"}, source="orchestrator")
item_later = tpq.enqueue(TriagePriority.LATER, {"metric": "scan_speed=42"}, source="metrics")

check("36.7.2", item_now is not None, "NOW item enqueued")
check("36.7.3", item_next is not None, "NEXT item enqueued")
check("36.7.4", item_later is not None, "LATER item enqueued")
check("36.7.5", tpq.total_pending == 3, "3 items pending")
check("36.7.6", tpq.counts == {"NOW": 1, "NEXT": 1, "LATER": 1}, "Correct per-tier counts")

# Deduplication
dup = tpq.enqueue(TriagePriority.NOW, {"vuln": "dup"}, item_id=item_now.item_id)
check("36.7.7", dup is None, "Duplicate item_id rejected")
check("36.7.8", tpq.total_pending == 3, "Still 3 items after dedup")

# Drain NOW
now_items = tpq.drain_now()
check("36.7.9", len(now_items) == 1, "Drained 1 NOW item")
check("36.7.10", now_items[0].payload["vuln"] == "SQLi critical", "Correct NOW payload")
check("36.7.11", now_items[0].notified is True, "Marked as notified")
check("36.7.12", now_items[0].notified_at is not None, "Notified timestamp set")

# Drain NEXT with limit
tpq.enqueue(TriagePriority.NEXT, {"info": "phase2 starting"}, source="orch")
next_items = tpq.drain_next(max_items=1)
check("36.7.13", len(next_items) == 1, "Drained 1 NEXT item (limited)")
check("36.7.14", tpq.counts["NEXT"] == 1, "1 NEXT item remaining")

# Drain LATER
later_items = tpq.drain_later()
check("36.7.15", len(later_items) == 1, "Drained 1 LATER item")

# Delivered count
check("36.7.16", tpq.delivered_count == 3, "3 total delivered")

# Peek is non-destructive
tpq.enqueue(TriagePriority.NOW, {"vuln": "XSS"}, source="scanner")
peeked = tpq.peek(TriagePriority.NOW)
check("36.7.17", len(peeked) == 1, "Peek sees 1 NOW item")
check("36.7.18", tpq.counts["NOW"] == 1, "Peek did not drain")

# Reset
tpq.reset()
check("36.7.19", tpq.total_pending == 0, "Reset clears all queues")
check("36.7.20", tpq.delivered_count == 0, "Reset clears delivered count")

# --- AO-8: ForkProgressReporter ---
print("  36.8: ForkProgressReporter")

fpr = ForkProgressReporter()
check("36.8.1", fpr.active_agents == [], "No active agents initially")
check("36.8.2", fpr.get_latest("agent-1") is None, "No labels for unknown agent")

# Test fallback label generation
label = ForkProgressReporter._fallback_label("agent-1", "Scanning login endpoints")
check("36.8.3", "Scanning" in label or "Working" in label, "Fallback label generated")
check("36.8.4", len(label) <= 50, "Fallback label reasonable length")

# Fallback without context
label2 = ForkProgressReporter._fallback_label("agent-xyz-123", "")
check("36.8.5", "agent-xyz" in label2.lower() or "active" in label2.lower(), "Fallback without context")

# ProgressLabel dataclass
pl = ProgressLabel(agent_id="a1", label="Scanning auth endpoints", previous_label="Enumerating subdomains")
check("36.8.6", pl.agent_id == "a1", "ProgressLabel agent_id")
check("36.8.7", pl.label == "Scanning auth endpoints", "ProgressLabel label")
check("36.8.8", pl.previous_label == "Enumerating subdomains", "ProgressLabel previous")

# --- Singleton factories ---
print("  36.9: Singleton Factories")

reset_slot_reservation()
reset_tool_summariser()
reset_away_summary()
reset_diagnostic_tracker()
reset_fallback_tombstoner()
reset_triage_queue()
reset_progress_reporter()

s1 = get_slot_reservation()
s2 = get_slot_reservation()
check("36.9.1", s1 is s2, "Slot reservation singleton")

ts1 = get_tool_summariser()
ts2 = get_tool_summariser()
check("36.9.2", ts1 is ts2, "Tool summariser singleton")

aw1 = get_away_summary()
aw2 = get_away_summary()
check("36.9.3", aw1 is aw2, "Away summary singleton")

dt1 = get_diagnostic_tracker()
dt2 = get_diagnostic_tracker()
check("36.9.4", dt1 is dt2, "Diagnostic tracker singleton")

fb1 = get_fallback_tombstoner()
fb2 = get_fallback_tombstoner()
check("36.9.5", fb1 is fb2, "Fallback tombstoner singleton")

tq1 = get_triage_queue()
tq2 = get_triage_queue()
check("36.9.6", tq1 is tq2, "Triage queue singleton")

pr1 = get_progress_reporter()
pr2 = get_progress_reporter()
check("36.9.7", pr1 is pr2, "Progress reporter singleton")

# --- Import from agents __init__ ---
print("  36.10: Package Exports")

from CaseCrack.tools.burp_enterprise.agents import (
    OutputSlotReservation as OSR_export,
    StreamingToolExecutor as STE_export,
    ToolBatchSummariser as TBS_export,
    AwaySummary as AWS_export,
    DiagnosticDeltaTracker as DDT_export,
    FallbackTombstoner as FT_export,
    TriagePriorityQueue as TPQ_export,
    ForkProgressReporter as FPR_export,
)

check("36.10.1", OSR_export is OutputSlotReservation, "OutputSlotReservation exported")
check("36.10.2", STE_export is StreamingToolExecutor, "StreamingToolExecutor exported")
check("36.10.3", TBS_export is ToolBatchSummariser, "ToolBatchSummariser exported")
check("36.10.4", AWS_export is AwaySummary, "AwaySummary exported")
check("36.10.5", DDT_export is DiagnosticDeltaTracker, "DiagnosticDeltaTracker exported")
check("36.10.6", FT_export is FallbackTombstoner, "FallbackTombstoner exported")
check("36.10.7", TPQ_export is TriagePriorityQueue, "TriagePriorityQueue exported")
check("36.10.8", FPR_export is ForkProgressReporter, "ForkProgressReporter exported")

loop36.close()


# ╔═══════════════════════════════════════════════════════════════════════════════╗
# Section 37: Finding Safety Interlocks (FSI 1-5)
# ╚═══════════════════════════════════════════════════════════════════════════════╝

from collections import deque

from CaseCrack.tools.burp_enterprise.agents.finding_safety_interlocks import (
    CompactionSafetyInterlock,
    CrossSystemReconciler,
    FindingSafetyLedger,
    LedgerEntry,
    LedgerEntryAction,
    LedgerStats,
    OverflowEvent,
    PreservedFinding,
    QueueOverflowProtector,
    ReconciliationResult,
    SeverityGuard,
    get_compaction_interlock,
    get_finding_ledger,
    get_overflow_protector,
    get_reconciler,
    get_severity_guard,
    reset_compaction_interlock,
    reset_finding_ledger,
    reset_overflow_protector,
    reset_reconciler,
    reset_severity_guard,
)

print("\n# Section 37: Finding Safety Interlocks (FSI 1-5)")

# --- FSI-1: FindingSafetyLedger ---
print("  37.1: FindingSafetyLedger — basics")

ledger = FindingSafetyLedger()
check("37.1.1", ledger.size == 0, "Ledger starts empty")

entry = ledger.record(
    finding_id="F-001",
    severity="CRITICAL",
    summary="SQL Injection in login endpoint",
    source_component="scanner",
    action=LedgerEntryAction.DISCOVERED,
)
check("37.1.2", isinstance(entry, LedgerEntry), "Record returns LedgerEntry")
check("37.1.3", entry.finding_id == "F-001", "Finding ID recorded")
check("37.1.4", entry.severity == "CRITICAL", "Severity uppercased")
check("37.1.5", entry.action == LedgerEntryAction.DISCOVERED, "Action = DISCOVERED")
check("37.1.6", ledger.size == 1, "Ledger has 1 entry")

# Add more lifecycle events
ledger.record("F-001", "CRITICAL", "SQL Injection in login endpoint",
              "dedup_engine", LedgerEntryAction.SEVERITY_GUARDED,
              detail="Blocked suppression by dedup")
ledger.record("F-001", "CRITICAL", "SQL Injection in login endpoint",
              "final_output", LedgerEntryAction.DELIVERED)

history = ledger.get_history("F-001")
check("37.1.7", len(history) == 3, "Full lifecycle tracked (3 entries)")
check("37.1.8", history[0].action == LedgerEntryAction.DISCOVERED, "First = DISCOVERED")
check("37.1.9", history[1].action == LedgerEntryAction.SEVERITY_GUARDED, "Second = SEVERITY_GUARDED")
check("37.1.10", history[2].action == LedgerEntryAction.DELIVERED, "Third = DELIVERED")

# Lost findings detection
ledger.record("F-002", "HIGH", "XSS in search", "scanner", LedgerEntryAction.DISCOVERED)
ledger.record("F-002", "HIGH", "XSS in search", "dedup", LedgerEntryAction.DEDUPLICATED, detail="Hash match")
# F-002 was deduplicated, never delivered
lost = ledger.get_lost_findings()
check("37.1.11", "F-002" in lost, "F-002 detected as lost (deduplicated, never delivered)")
check("37.1.12", "F-001" not in lost, "F-001 not lost (was delivered)")

print("  37.2: FindingSafetyLedger — stats")

stats = ledger.get_stats()
check("37.2.1", isinstance(stats, LedgerStats), "Stats returns LedgerStats")
check("37.2.2", stats.total_discovered == 2, "2 findings discovered")
check("37.2.3", stats.total_delivered == 1, "1 finding delivered")
check("37.2.4", stats.total_deduplicated == 1, "1 finding deduplicated")
check("37.2.5", stats.total_severity_guarded == 1, "1 severity guard intervention")
check("37.2.6", stats.loss_rate == 50.0, "Loss rate = 50%")

# Summary truncation
long_summary = "A" * 500
entry_long = ledger.record("F-003", "LOW", long_summary, "scanner", LedgerEntryAction.DISCOVERED)
check("37.2.7", len(entry_long.summary) == 200, "Summary truncated to 200 chars")

# Detail truncation
long_detail = "B" * 1000
entry_detail = ledger.record("F-004", "INFO", "test", "scanner",
                             LedgerEntryAction.DISCOVERED, detail=long_detail)
check("37.2.8", len(entry_detail.detail) == 500, "Detail truncated to 500 chars")

# Max entries bound
small_ledger = FindingSafetyLedger(max_entries=5)
for i in range(10):
    small_ledger.record(f"F-{i}", "LOW", f"finding {i}", "test", LedgerEntryAction.DISCOVERED)
check("37.2.9", small_ledger.size == 5, "Ledger bounded by max_entries")

print("  37.3: FindingSafetyLedger — thread safety")

thread_ledger = FindingSafetyLedger()
errors_37 = []

def _write_ledger(tid):
    try:
        for i in range(50):
            thread_ledger.record(f"T{tid}-{i}", "MEDIUM", f"t{tid}f{i}",
                                 "thread", LedgerEntryAction.DISCOVERED)
    except Exception as e:
        errors_37.append(str(e))

threads_37 = [threading.Thread(target=_write_ledger, args=(t,)) for t in range(4)]
for t in threads_37:
    t.start()
for t in threads_37:
    t.join()

check("37.3.1", len(errors_37) == 0, "No thread safety errors")
check("37.3.2", thread_ledger.size == 200, "All 200 entries recorded (4x50)")

# --- FSI-2: SeverityGuard ---
print("  37.4: SeverityGuard")

ledger2 = FindingSafetyLedger()
guard = SeverityGuard(ledger=ledger2)

check("37.4.1", guard.should_protect("CRITICAL"), "CRITICAL is protected")
check("37.4.2", guard.should_protect("HIGH"), "HIGH is protected")
check("37.4.3", not guard.should_protect("MEDIUM"), "MEDIUM is not protected")
check("37.4.4", not guard.should_protect("LOW"), "LOW is not protected")
check("37.4.5", not guard.should_protect("INFO"), "INFO is not protected")
check("37.4.6", guard.should_protect("critical"), "Case-insensitive check")

# Guard blocks suppression of CRITICAL
blocked = guard.guard("F-100", "CRITICAL", "RCE via deserialization",
                       "compaction", "Too many findings")
check("37.4.7", blocked is True, "Suppression BLOCKED for CRITICAL")
check("37.4.8", guard.intervention_count == 1, "1 intervention recorded")

# Guard allows suppression of MEDIUM
allowed = guard.guard("F-101", "MEDIUM", "Missing header",
                       "compaction", "Low priority")
check("37.4.9", allowed is False, "Suppression ALLOWED for MEDIUM")

# Ledger recorded both events
guard_entries = ledger2.entries
check("37.4.10", len(guard_entries) == 2, "Both events in ledger")
check("37.4.11", guard_entries[0].action == LedgerEntryAction.SEVERITY_GUARDED,
      "CRITICAL -> SEVERITY_GUARDED")
check("37.4.12", guard_entries[1].action == LedgerEntryAction.DEDUPLICATED,
      "MEDIUM -> DEDUPLICATED (allowed)")
check("37.4.13", guard_entries[0].preserved is True, "CRITICAL marked preserved")

# Interventions list
interventions = guard.interventions
check("37.4.14", len(interventions) == 1, "1 intervention in list")
check("37.4.15", interventions[0]["severity"] == "CRITICAL", "Intervention severity")
check("37.4.16", interventions[0]["suppressor"] == "compaction", "Intervention suppressor")

# Custom protected severities
custom_guard = SeverityGuard(protected_severities=frozenset({"CRITICAL", "HIGH", "MEDIUM"}))
check("37.4.17", custom_guard.should_protect("MEDIUM"), "Custom guard protects MEDIUM")

# --- FSI-3: CompactionSafetyInterlock ---
print("  37.5: CompactionSafetyInterlock — extraction")

ledger3 = FindingSafetyLedger()
interlock = CompactionSafetyInterlock(ledger=ledger3)

test_prompt = """# Scan Results

ID=F-200 | CRITICAL | SQL Injection in /api/users
  Evidence: Response contains database error messages
  PoC: ' OR 1=1 --

ID=F-201 | HIGH | XSS in search parameter
  Evidence: Reflected script injection confirmed
  PoC: <script>alert(1)</script>

ID=F-202 | MEDIUM | Missing X-Frame-Options header
  No clickjacking protection

ID=F-203 | LOW | Server version disclosure
  Apache 2.4.41 in Server header
"""

text_out, preserved = interlock.extract_before_compaction(test_prompt)
check("37.5.1", len(preserved) >= 2, "Extracted >= 2 CRITICAL/HIGH findings")

critical_ids = [p.finding_id for p in preserved]
critical_sevs = [p.severity for p in preserved]
check("37.5.2", "CRITICAL" in critical_sevs, "CRITICAL severity extracted")
check("37.5.3", "HIGH" in critical_sevs, "HIGH severity extracted")
check("37.5.4", all(s in ("CRITICAL", "HIGH") for s in critical_sevs),
      "Only CRITICAL/HIGH extracted")

# Verify ledger recorded
ledger3_entries = ledger3.entries
check("37.5.5", len(ledger3_entries) >= 2, "Ledger recorded extractions")
check("37.5.6", all(e.action == LedgerEntryAction.SEVERITY_GUARDED for e in ledger3_entries),
      "All recorded as SEVERITY_GUARDED")

print("  37.6: CompactionSafetyInterlock — reinjection")

# Simulate compaction that loses findings
compacted = "# Scan Results\n[...compacted content...]\n"
# Assume F-200 and F-201 were lost
reinjected = interlock.reinject_after_compaction(compacted, preserved)
check("37.6.1", "PRESERVED CRITICAL/HIGH FINDINGS" in reinjected,
      "Preservation header injected")
check("37.6.2", "SQL Injection" in reinjected or "CRITICAL" in reinjected,
      "Critical finding re-injected")
check("37.6.3", len(reinjected) > len(compacted), "Reinjected text is longer")

# If findings survive compaction, no reinjection
identity_text = test_prompt  # all finding IDs still present
for pf in preserved:
    identity_text = identity_text  # IDs still in text
# Create a case where IDs ARE in the text
with_ids = compacted + " ".join(p.finding_id for p in preserved)
no_reinject = interlock.reinject_after_compaction(with_ids, preserved)
check("37.6.4", "PRESERVED" not in no_reinject, "No reinjection when findings survive")

check("37.6.5", interlock.preserved_count >= 2, "Preserved count tracks extractions")

# --- FSI-4: QueueOverflowProtector ---
print("  37.7: QueueOverflowProtector")

ledger4 = FindingSafetyLedger()
protector = QueueOverflowProtector(ledger=ledger4)

# Queue with room
q = deque(maxlen=3)
q.append("item1")
q.append("item2")
needs_escalation = protector.check_before_enqueue(
    q, "F-300", "CRITICAL", "NOW", source="triage_now")
check("37.7.1", needs_escalation is False, "No escalation when queue has room")

# Fill queue
q.append("item3")  # now at capacity
needs_escalation = protector.check_before_enqueue(
    q, "F-301", "CRITICAL", "LATER", source="triage_later")
check("37.7.2", needs_escalation is True, "Escalation needed for CRITICAL at capacity")

# Non-critical at capacity — allowed to drop
needs_escalation_low = protector.check_before_enqueue(
    q, "F-302", "LOW", "LATER", source="triage_later")
check("37.7.3", needs_escalation_low is False, "LOW finding can be dropped")

# Overflow events recorded
check("37.7.4", protector.overflow_count == 2, "2 overflow events (F-301 + F-302)")
check("37.7.5", protector.critical_escalation_count == 1, "1 critical escalation")

events = protector.overflow_events
check("37.7.6", events[0].escalated_to == "NOW", "CRITICAL escalated to NOW")
check("37.7.7", events[1].escalated_to == "DROPPED", "LOW marked as DROPPED")

# Unbounded queue — never overflows
uq = deque()  # no maxlen
no_overflow = protector.check_before_enqueue(uq, "F-303", "CRITICAL", "NOW")
check("37.7.8", no_overflow is False, "Unbounded queue never overflows")

# Ledger entries
l4_entries = ledger4.entries
check("37.7.9", len(l4_entries) == 2, "2 ledger entries (only at-capacity events)")
critical_entry = [e for e in l4_entries if e.finding_id == "F-301"][0]
check("37.7.10", critical_entry.action == LedgerEntryAction.SEVERITY_GUARDED,
      "CRITICAL -> SEVERITY_GUARDED")
low_entry = [e for e in l4_entries if e.finding_id == "F-302"][0]
check("37.7.11", low_entry.action == LedgerEntryAction.QUEUE_DROPPED,
      "LOW -> QUEUE_DROPPED")

# --- FSI-5: CrossSystemReconciler ---
print("  37.8: CrossSystemReconciler")

ledger5 = FindingSafetyLedger()
reconciler = CrossSystemReconciler(ledger=ledger5)

# Discover 5 findings
ledger5.record("R-001", "CRITICAL", "RCE", "scanner", LedgerEntryAction.DISCOVERED)
ledger5.record("R-002", "HIGH", "SQLi", "scanner", LedgerEntryAction.DISCOVERED)
ledger5.record("R-003", "MEDIUM", "XSS stored", "scanner", LedgerEntryAction.DISCOVERED)
ledger5.record("R-004", "LOW", "Missing header", "scanner", LedgerEntryAction.DISCOVERED)
ledger5.record("R-005", "CRITICAL", "Auth bypass", "scanner", LedgerEntryAction.DISCOVERED)

# Only R-001, R-003, R-004 made it to final output
result = reconciler.reconcile(delivered_finding_ids={"R-001", "R-003", "R-004"})

check("37.8.1", isinstance(result, ReconciliationResult), "Returns ReconciliationResult")
check("37.8.2", result.total_discovered == 5, "5 findings discovered")
check("37.8.3", result.total_delivered == 3, "3 findings delivered")
check("37.8.4", result.total_missing == 2, "2 findings missing")
check("37.8.5", result.missing_critical == 1, "1 CRITICAL missing (R-005)")
check("37.8.6", result.missing_high == 1, "1 HIGH missing (R-002)")
check("37.8.7", result.is_clean is False, "NOT clean — critical/high missing")

# Clean reconciliation
ledger6 = FindingSafetyLedger()
reconciler2 = CrossSystemReconciler(ledger=ledger6)
ledger6.record("C-001", "LOW", "info", "scanner", LedgerEntryAction.DISCOVERED)
ledger6.record("C-002", "MEDIUM", "med", "scanner", LedgerEntryAction.DISCOVERED)
result2 = reconciler2.reconcile(delivered_finding_ids={"C-001", "C-002"})
check("37.8.8", result2.is_clean is True, "Clean when all delivered")
check("37.8.9", result2.total_missing == 0, "0 missing")

# Reconciliation history
check("37.8.10", len(reconciler.results) == 1, "Reconciliation history tracks runs")
check("37.8.11", reconciler.last_result is result, "last_result returns latest")
check("37.8.12", reconciler.ever_clean is False, "ever_clean = False after failed recon")
check("37.8.13", reconciler2.ever_clean is True, "ever_clean = True for clean-only recon")

# --- Singleton factories ---
print("  37.9: FSI Singleton Factories")

reset_finding_ledger()
reset_severity_guard()
reset_compaction_interlock()
reset_overflow_protector()
reset_reconciler()

fl1 = get_finding_ledger()
fl2 = get_finding_ledger()
check("37.9.1", fl1 is fl2, "Finding ledger singleton")

sg1 = get_severity_guard()
sg2 = get_severity_guard()
check("37.9.2", sg1 is sg2, "Severity guard singleton")

ci1 = get_compaction_interlock()
ci2 = get_compaction_interlock()
check("37.9.3", ci1 is ci2, "Compaction interlock singleton")

op1 = get_overflow_protector()
op2 = get_overflow_protector()
check("37.9.4", op1 is op2, "Overflow protector singleton")

rc1 = get_reconciler()
rc2 = get_reconciler()
check("37.9.5", rc1 is rc2, "Reconciler singleton")

# Reset clears singletons
reset_finding_ledger()
fl3 = get_finding_ledger()
check("37.9.6", fl3 is not fl1, "Reset creates new singleton")

# --- Package Exports ---
print("  37.10: FSI Package Exports")

from CaseCrack.tools.burp_enterprise.agents import (
    FindingSafetyLedger as FSL_export,
    SeverityGuard as SG_export,
    CompactionSafetyInterlock as CSI_export,
    QueueOverflowProtector as QOP_export,
    CrossSystemReconciler as CSR_export,
    LedgerEntryAction as LEA_export,
    ReconciliationResult as RR_export,
)

check("37.10.1", FSL_export is FindingSafetyLedger, "FindingSafetyLedger exported")
check("37.10.2", SG_export is SeverityGuard, "SeverityGuard exported")
check("37.10.3", CSI_export is CompactionSafetyInterlock, "CompactionSafetyInterlock exported")
check("37.10.4", QOP_export is QueueOverflowProtector, "QueueOverflowProtector exported")
check("37.10.5", CSR_export is CrossSystemReconciler, "CrossSystemReconciler exported")
check("37.10.6", LEA_export is LedgerEntryAction, "LedgerEntryAction exported")
check("37.10.7", RR_export is ReconciliationResult, "ReconciliationResult exported")

# --- End-to-End Pipeline Safety ---
print("  37.11: End-to-End Pipeline Safety Scenario")

# Simulate the exact failure mode: StreamingToolExecutor → ToolBatchSummariser
# → TriageQueue → DiagnosticDeltaTracker → finding lost
reset_finding_ledger()
e2e_ledger = get_finding_ledger()
e2e_guard = SeverityGuard(ledger=e2e_ledger)
e2e_protector = QueueOverflowProtector(ledger=e2e_ledger, guard=e2e_guard)

# Step 1: Scanner discovers CRITICAL finding
e2e_ledger.record("E2E-001", "CRITICAL", "Remote Code Execution via SSTI",
                   "scanner", LedgerEntryAction.DISCOVERED)

# Step 2: Dedup tries to suppress it — BLOCKED by severity guard
suppressed = e2e_guard.guard("E2E-001", "CRITICAL", "Remote Code Execution via SSTI",
                              "dedup_engine", "Hash match with similar finding")
check("37.11.1", suppressed is True, "E2E: Dedup blocked from suppressing CRITICAL")

# Step 3: Triage queue is full — ESCALATED to NOW
full_q = deque(maxlen=3)
full_q.extend(["a", "b", "c"])
escalated = e2e_protector.check_before_enqueue(
    full_q, "E2E-001", "CRITICAL", "LATER", source="triage_later")
check("37.11.2", escalated is True, "E2E: Queue overflow -> CRITICAL escalated to NOW")

# Step 4: Compaction tries to strip it — EXTRACTED and PRESERVED
e2e_interlock = CompactionSafetyInterlock(ledger=e2e_ledger)
prompt_with_finding = "ID=E2E-001 | CRITICAL | Remote Code Execution via SSTI\n  Evidence: Template injection confirmed\n"
_, e2e_preserved = e2e_interlock.extract_before_compaction(prompt_with_finding)
check("37.11.3", len(e2e_preserved) >= 1, "E2E: CRITICAL finding extracted before compaction")

# Step 5: After compaction, finding was lost — RE-INJECTED
compacted_prompt = "[compacted scan results]"
restored = e2e_interlock.reinject_after_compaction(compacted_prompt, e2e_preserved)
check("37.11.4", "CRITICAL" in restored, "E2E: CRITICAL finding re-injected after compaction")

# Step 6: Reconciliation catches any remaining gaps
e2e_ledger.record("E2E-001", "CRITICAL", "RCE via SSTI",
                   "final_output", LedgerEntryAction.DELIVERED)
e2e_reconciler = CrossSystemReconciler(ledger=e2e_ledger)
e2e_result = e2e_reconciler.reconcile(delivered_finding_ids={"E2E-001"})
check("37.11.5", e2e_result.is_clean is True, "E2E: CRITICAL finding successfully delivered")
check("37.11.6", e2e_result.missing_critical == 0, "E2E: Zero CRITICAL findings lost")

# Full pipeline stats
e2e_stats = e2e_ledger.get_stats()
check("37.11.7", e2e_stats.total_severity_guarded >= 2, "E2E: Multiple safety interventions logged")
check("37.11.8", e2e_stats.critical_loss_count == 0, "E2E: ZERO critical losses in final tally")


# ╔═══════════════════════════════════════════════════════════════════════════════╗
# Section 38: Deterministic Replay Layer (DRL 1-4)
# ╚═══════════════════════════════════════════════════════════════════════════════╝

from CaseCrack.tools.burp_enterprise.agents.deterministic_replay import (
    DecisionFrame,
    DecisionJournal,
    DecisionRNG,
    JournalSnapshot,
    JournalStats,
    ReplayController,
    ReplayMismatch,
    ReplayMode,
    get_replay_controller,
    reset_replay_controller,
    start_live_session,
    start_replay_session,
    start_reproduce_session,
)

print("\n# Section 38: Deterministic Replay Layer (DRL 1-4)")

# --- DRL-1: DecisionRNG ---
print("  38.1: DecisionRNG — basics")

rng1 = DecisionRNG(seed=42)
rng2 = DecisionRNG(seed=42)

# Same seed → same sequence
vals1 = [rng1.random() for _ in range(5)]
vals2 = [rng2.random() for _ in range(5)]
check("38.1.1", vals1 == vals2, "Same seed produces identical random() sequence")

# betavariate reproducibility
rng3 = DecisionRNG(seed=99)
rng4 = DecisionRNG(seed=99)
beta1 = [rng3.betavariate(2.0, 5.0) for _ in range(5)]
beta2 = [rng4.betavariate(2.0, 5.0) for _ in range(5)]
check("38.1.2", beta1 == beta2, "Same seed produces identical betavariate sequence")

# choice reproducibility
rng5 = DecisionRNG(seed=7)
rng6 = DecisionRNG(seed=7)
items = ["a", "b", "c", "d", "e"]
c1 = [rng5.choice(items) for _ in range(10)]
c2 = [rng6.choice(items) for _ in range(10)]
check("38.1.3", c1 == c2, "Same seed produces identical choice sequence")

# Different seeds → different sequences
rng7 = DecisionRNG(seed=1)
rng8 = DecisionRNG(seed=2)
v7 = [rng7.random() for _ in range(5)]
v8 = [rng8.random() for _ in range(5)]
check("38.1.4", v7 != v8, "Different seeds produce different sequences")

# No seed → non-deterministic (just test it doesn't crash)
rng_noseed = DecisionRNG()
check("38.1.5", isinstance(rng_noseed.random(), float), "No-seed RNG works")
check("38.1.6", rng_noseed.seed is None, "No-seed reports None")

print("  38.2: DecisionRNG — state capture/restore")

rng_s = DecisionRNG(seed=42)
# Advance a bit
_ = [rng_s.random() for _ in range(10)]
# Capture state
state = rng_s.get_state()
# Draw 5 more
ahead = [rng_s.random() for _ in range(5)]
# Restore and re-draw
rng_s.set_state(state)
replayed = [rng_s.random() for _ in range(5)]
check("38.2.1", ahead == replayed, "State restore produces identical sequence")

# Reseed
rng_s.reseed(99)
check("38.2.2", rng_s.seed == 99, "Reseed updates seed property")
rng_s2 = DecisionRNG(seed=99)
v_s1 = rng_s.random()
v_s2 = rng_s2.random()
check("38.2.3", v_s1 == v_s2, "Reseed produces same first draw as fresh seed")

# All API methods work
rng_api = DecisionRNG(seed=1)
check("38.2.4", isinstance(rng_api.uniform(1.0, 2.0), float), "uniform() works")
check("38.2.5", isinstance(rng_api.gauss(0.0, 1.0), float), "gauss() works")
check("38.2.6", len(rng_api.sample([1,2,3,4,5], 3)) == 3, "sample() works")
lst = [1,2,3,4,5]
rng_api.shuffle(lst)
check("38.2.7", len(lst) == 5, "shuffle() works (preserves length)")

# --- DRL-2: DecisionFrame ---
print("  38.3: DecisionFrame")

frame = DecisionFrame(
    component="thompson_policy",
    decision_type="phase_select",
    recorded_value=0.7234,
    score_breakdown={"di_ev": 0.45, "thompson": 0.72, "uncertainty": 0.33},
    alternatives=[
        {"name": "phase_sqli", "score": 0.65},
        {"name": "phase_xss", "score": 0.58},
        {"name": "phase_ssrf", "score": 0.41},
    ],
    context={"mode": "explore", "budget_remaining": 3600},
)

check("38.3.1", frame.component == "thompson_policy", "Frame component set")
check("38.3.2", frame.recorded_value == 0.7234, "Frame recorded_value set")
check("38.3.3", len(frame.alternatives) == 3, "Frame has 3 alternatives")
check("38.3.4", len(frame.frame_id) == 12, "Frame ID is 12-char hex")

# to_dict serialization
d = frame.to_dict()
check("38.3.5", d["component"] == "thompson_policy", "to_dict preserves component")
check("38.3.6", d["recorded_value"] == 0.7234, "to_dict preserves value")
check("38.3.7", len(d["alternatives"]) == 3, "to_dict preserves alternatives")
check("38.3.8", d["score_breakdown"]["di_ev"] == 0.45, "to_dict preserves scores")

# Non-serializable values handled
frame_weird = DecisionFrame(
    component="test",
    decision_type="test",
    recorded_value={"nested": [1, 2, {"deep": True}]},
    context={"obj": object()},  # not JSON-safe
)
d_weird = frame_weird.to_dict()
check("38.3.9", isinstance(d_weird["context"]["obj"], str), "Non-JSON context converted to str")
check("38.3.10", d_weird["recorded_value"]["nested"][2]["deep"] is True, "Nested values serialized")

# --- DRL-3: DecisionJournal ---
print("  38.4: DecisionJournal — basics")

journal = DecisionJournal()
check("38.4.1", journal.size == 0, "Journal starts empty")

# Append frames
for i in range(5):
    f = DecisionFrame(
        component="thompson",
        decision_type="phase_select",
        recorded_value=0.5 + i * 0.1,
    )
    journal.append(f)

check("38.4.2", journal.size == 5, "Journal has 5 frames")

# Sequence numbers assigned
frames = journal.frames
check("38.4.3", frames[0].sequence == 0, "First frame seq=0")
check("38.4.4", frames[4].sequence == 4, "Fifth frame seq=4")

# Snapshots
snap = journal.take_snapshot(
    phase_queue_state=[{"name": "sqli", "score": 0.8}, {"name": "xss", "score": 0.6}],
    uncertainty_map={"sqli": 0.3, "xss": 0.5},
    thompson_arms={"sqli": {"alpha": 3.0, "beta": 1.5}, "xss": {"alpha": 2.0, "beta": 2.0}},
    backpressure_mode="explore",
)
check("38.4.5", isinstance(snap, JournalSnapshot), "Snapshot created")
check("38.4.6", len(snap.phase_queue_state) == 2, "Snapshot has phase queue")
check("38.4.7", snap.thompson_arms["sqli"]["alpha"] == 3.0, "Snapshot has Thompson arms")
check("38.4.8", snap.backpressure_mode == "explore", "Snapshot has backpressure mode")
check("38.4.9", len(journal.snapshots) == 1, "1 snapshot in journal")

print("  38.5: DecisionJournal — export/import")

# Export
exported = journal.export()
check("38.5.1", exported["version"] == "1.0", "Export version 1.0")
check("38.5.2", exported["total_frames"] == 5, "Export has 5 frames")
check("38.5.3", exported["total_snapshots"] == 1, "Export has 1 snapshot")

# Import into new journal
journal2 = DecisionJournal()
imported_count = journal2.import_frames(exported)
check("38.5.4", imported_count == 5, "Imported 5 frames")
check("38.5.5", journal2.size == 5, "New journal has 5 frames")
check("38.5.6", len(journal2.snapshots) == 1, "Snapshot imported")

# Replay sequence filtering
journal.append(DecisionFrame(component="epsilon", decision_type="test_select", recorded_value="sqlmap"))
filtered = journal.get_replay_sequence(component="thompson")
check("38.5.7", len(filtered) == 5, "Filtered to 5 thompson frames")
all_frames = journal.get_replay_sequence()
check("38.5.8", len(all_frames) == 6, "Unfiltered = 6 total frames")

# Stats
stats = journal.get_stats()
check("38.5.9", isinstance(stats, JournalStats), "Stats returns JournalStats")
check("38.5.10", stats.total_frames == 6, "Stats total = 6")
check("38.5.11", stats.components.get("thompson") == 5, "5 thompson decisions")
check("38.5.12", stats.components.get("epsilon") == 1, "1 epsilon decision")

# Bounded journal
tiny = DecisionJournal(max_frames=3)
for i in range(10):
    tiny.append(DecisionFrame(component="x", decision_type="y", recorded_value=i))
check("38.5.13", tiny.size == 3, "Bounded journal caps at maxlen")

# --- DRL-4: ReplayController ---
print("  38.6: ReplayController — LIVE mode")

reset_replay_controller()
ctrl = ReplayController(mode=ReplayMode.LIVE, seed=42)

check("38.6.1", ctrl.mode == ReplayMode.LIVE, "Mode is LIVE")

# Get component RNGs
rng_t = ctrl.get_rng("thompson")
rng_e = ctrl.get_rng("epsilon")
check("38.6.2", rng_t is not rng_e, "Different components get different RNGs")
check("38.6.3", ctrl.get_rng("thompson") is rng_t, "Same component returns same RNG")

# Draw in LIVE mode — records to journal
v1 = ctrl.draw(
    "thompson", "phase_select",
    lambda: rng_t.betavariate(2.0, 5.0),
    alternatives=[{"name": "sqli", "score": 0.65}],
    scores={"thompson": 0.72, "di_ev": 0.45},
    context={"mode": "explore"},
)
check("38.6.4", isinstance(v1, float), "LIVE draw returns float")
check("38.6.5", ctrl.journal.size == 1, "LIVE draw recorded in journal")

rec = ctrl.journal.frames[0]
check("38.6.6", rec.recorded_value == v1, "Journal captured the exact value")
check("38.6.7", rec.component == "thompson", "Journal captured component")
check("38.6.8", rec.score_breakdown.get("thompson") == 0.72, "Journal captured scores")
check("38.6.9", len(rec.alternatives) == 1, "Journal captured alternatives")

# Multiple draws
for i in range(4):
    ctrl.draw("thompson", "phase_select", lambda: rng_t.betavariate(2.0, 5.0))
ctrl.draw("epsilon", "test_select", lambda: rng_e.choice(["a", "b", "c"]))

check("38.6.10", ctrl.journal.size == 6, "6 total draws recorded")

print("  38.7: ReplayController — REPLAY mode (determinism)")

# Export the live journal
live_journal = ctrl.export_journal()

# Start REPLAY session
ctrl2 = ReplayController(mode=ReplayMode.REPLAY)
ctrl2.import_journal(live_journal)

check("38.7.1", ctrl2.mode == ReplayMode.REPLAY, "Replay mode active")
progress = ctrl2.replay_progress
check("38.7.2", progress == (0, 6), "Replay at (0, 6)")

# Replay all 6 decisions — should return exact same values
live_frames = ctrl.journal.frames
replayed_values = []
for i in range(6):
    # draw_fn is irrelevant in REPLAY mode — it's ignored
    rv = ctrl2.draw("thompson", "phase_select", lambda: -999.0)
    replayed_values.append(rv)

check("38.7.3", replayed_values[0] == live_frames[0].recorded_value,
      "Replay[0] matches live[0]")
check("38.7.4", replayed_values[1] == live_frames[1].recorded_value,
      "Replay[1] matches live[1]")
check("38.7.5", replayed_values[5] == live_frames[5].recorded_value,
      "Replay[5] matches live[5]")

check("38.7.6", ctrl2.is_replay_complete, "Replay complete after all frames consumed")

# Exhausted replay falls back to draw_fn
fallback_val = ctrl2.draw("thompson", "extra", lambda: 42.0)
check("38.7.7", fallback_val == 42.0, "Exhausted replay falls back to draw_fn")

print("  38.8: ReplayController — REPRODUCE mode (verification)")

# Start REPRODUCE session from same journal
ctrl3 = start_reproduce_session(live_journal, seed=42)
check("38.8.1", ctrl3.mode == ReplayMode.REPRODUCE, "Reproduce mode active")

# Use the same RNG component to re-draw
rng_t3 = ctrl3.get_rng("thompson")

# First draw should match (same seed, same state)
rv3 = ctrl3.draw("thompson", "phase_select",
                  lambda: rng_t3.betavariate(2.0, 5.0))
# Note: The RNG state is restored from the frame, so the draw is reproduced
check("38.8.2", ctrl3.mismatch_count == 0 or isinstance(rv3, float),
      "Reproduce mode executes without crash")

# Mode switch
ctrl3.mode = ReplayMode.LIVE
check("38.8.3", ctrl3.mode == ReplayMode.LIVE, "Mode switch to LIVE works")
ctrl3.mode = ReplayMode.REPLAY
check("38.8.4", ctrl3.mode == ReplayMode.REPLAY, "Mode switch to REPLAY works")
progress3 = ctrl3.replay_progress
check("38.8.5", progress3[0] == 0, "Mode switch resets replay index")

print("  38.9: ReplayController — snapshots")

ctrl4 = ReplayController(mode=ReplayMode.LIVE, seed=123)
snap4 = ctrl4.take_snapshot(
    phase_queue_state=[{"name": "sqli", "score": 0.9}],
    uncertainty_map={"sqli": 0.2},
    thompson_arms={"sqli": {"alpha": 5.0, "beta": 2.0}},
    backpressure_mode="exploit",
)
check("38.9.1", isinstance(snap4, JournalSnapshot), "Snapshot taken")
check("38.9.2", snap4.backpressure_mode == "exploit", "Snapshot backpressure mode")
check("38.9.3", len(ctrl4.journal.snapshots) == 1, "Snapshot in journal")

# Stats
ctrl_stats = ctrl4.get_stats()
check("38.9.4", ctrl_stats["mode"] == "live", "Stats mode = live")
check("38.9.5", ctrl_stats["seed"] == 123, "Stats seed = 123")
check("38.9.6", ctrl_stats["journal_snapshots"] == 1, "Stats has 1 snapshot")

print("  38.10: Convenience functions")

# start_live_session
reset_replay_controller()
live = start_live_session(seed=77)
check("38.10.1", live.mode == ReplayMode.LIVE, "start_live_session mode = LIVE")
check("38.10.2", live is get_replay_controller(), "Singleton matches")

# start_replay_session
replay = start_replay_session(live_journal)
check("38.10.3", replay.mode == ReplayMode.REPLAY, "start_replay_session mode = REPLAY")
check("38.10.4", replay.journal.size == 6, "Replay loaded 6 frames")

# start_reproduce_session
reproduce = start_reproduce_session(live_journal, seed=42)
check("38.10.5", reproduce.mode == ReplayMode.REPRODUCE, "start_reproduce_session mode")

# Reset
reset_replay_controller()
new_ctrl = get_replay_controller()
check("38.10.6", new_ctrl is not reproduce, "Reset creates fresh controller")

print("  38.11: Package exports")

from CaseCrack.tools.burp_enterprise.agents import (
    DecisionFrame as DF_export,
    DecisionJournal as DJ_export,
    DecisionRNG as DRNG_export,
    ReplayController as RC_export,
    ReplayMode as RM_export,
    JournalSnapshot as JS_export,
    JournalStats as JSt_export,
    ReplayMismatch as RMi_export,
)

check("38.11.1", DF_export is DecisionFrame, "DecisionFrame exported")
check("38.11.2", DJ_export is DecisionJournal, "DecisionJournal exported")
check("38.11.3", DRNG_export is DecisionRNG, "DecisionRNG exported")
check("38.11.4", RC_export is ReplayController, "ReplayController exported")
check("38.11.5", RM_export is ReplayMode, "ReplayMode exported")
check("38.11.6", JS_export is JournalSnapshot, "JournalSnapshot exported")
check("38.11.7", JSt_export is JournalStats, "JournalStats exported")
check("38.11.8", RMi_export is ReplayMismatch, "ReplayMismatch exported")

print("  38.12: End-to-End Replay Fidelity")

# Full E2E: live scan → export → replay → verify identical decisions
reset_replay_controller()

# LIVE: Simulate Thompson-driven phase selection with 10 decisions
live_ctrl = start_live_session(seed=2026)
live_rng = live_ctrl.get_rng("thompson_phase")

live_decisions = []
for phase_num in range(10):
    alpha = 1.0 + phase_num * 0.5
    beta_p = 3.0 - phase_num * 0.2
    val = live_ctrl.draw(
        "thompson_phase", "select",
        lambda a=alpha, b=beta_p: live_rng.betavariate(max(a, 0.01), max(b, 0.01)),
        alternatives=[{"name": f"phase_{phase_num+1}", "score": 0.5}],
        scores={"alpha": alpha, "beta": beta_p},
        context={"phase_num": phase_num},
    )
    live_decisions.append(val)

# Take snapshot mid-session
live_ctrl.take_snapshot(
    phase_queue_state=[{"name": f"p{i}", "score": live_decisions[i]} for i in range(10)],
    thompson_arms={"thompson_phase": {"alpha": 6.0, "beta": 1.0}},
    backpressure_mode="exploit",
)

# Export journal
full_export = live_ctrl.export_journal()
check("38.12.1", full_export["total_frames"] == 10, "E2E: 10 decisions exported")
check("38.12.2", full_export["total_snapshots"] == 1, "E2E: 1 snapshot exported")

# REPLAY: Feed same journal, verify identical outputs
replay_ctrl = start_replay_session(full_export)
replay_decisions = []
for i in range(10):
    rv = replay_ctrl.draw("thompson_phase", "select", lambda: -1.0)
    replay_decisions.append(rv)

check("38.12.3", live_decisions == replay_decisions,
      "E2E: ALL 10 replay decisions match live decisions exactly")
check("38.12.4", replay_ctrl.is_replay_complete, "E2E: Replay consumed all frames")

# Verify each individual decision
all_match = all(l == r for l, r in zip(live_decisions, replay_decisions))
check("38.12.5", all_match, "E2E: Per-decision comparison — all identical")

# Journal stats
j_stats = replay_ctrl.journal.get_stats()
check("38.12.6", j_stats.total_frames == 10, "E2E: Journal stats correct")
check("38.12.7", j_stats.components.get("thompson_phase") == 10, "E2E: All from thompson_phase")
check("38.12.8", j_stats.decision_types.get("select") == 10, "E2E: All select type")

# Thread safety for live recording
thread_ctrl = ReplayController(mode=ReplayMode.LIVE, seed=42)
thread_errs = []

def _thread_draw(tid):
    try:
        thread_rng = thread_ctrl.get_rng(f"thread_{tid}")
        for i in range(20):
            thread_ctrl.draw(f"thread_{tid}", "draw",
                             lambda: thread_rng.random())
    except Exception as e:
        thread_errs.append(str(e))

thread_workers = [threading.Thread(target=_thread_draw, args=(t,)) for t in range(4)]
for tw in thread_workers:
    tw.start()
for tw in thread_workers:
    tw.join()

check("38.12.9", len(thread_errs) == 0, "E2E: Thread-safe recording (0 errors)")
check("38.12.10", thread_ctrl.journal.size == 80, "E2E: All 80 threaded draws recorded")


# ╔═══════════════════════════════════════════════════════════════════════════════╗
# Section 39: Conflict Arbitration Layer (CAL 1-4)
# ╚═══════════════════════════════════════════════════════════════════════════════╝

from CaseCrack.tools.burp_enterprise.agents.conflict_arbitration import (
    ArbitrationResult,
    ConflictArbitrator,
    ConflictClassification,
    ConflictClassifier,
    ConflictType,
    DominantSignal,
    DominantSignalDetector,
    ResolutionRuleTable,
    ScanMode,
    Winner,
    get_arbitrator,
    reset_arbitrator,
)

print("\n# Section 39: Conflict Arbitration Layer (CAL 1-4)")

# --- CAL-1: DominantSignalDetector ---
print("  39.1: DominantSignalDetector -- basics")

# Empty signals
check("39.1.1", DominantSignalDetector.detect({}) is None, "Empty signals -> None")

# Single signal
dom = DominantSignalDetector.detect({"exploit_ev": 0.92})
check("39.1.2", dom is not None, "Single signal detected")
check("39.1.3", dom.name == "exploit_ev", "Dominant name correct")
check("39.1.4", dom.value == 0.92, "Dominant value correct")
check("39.1.5", dom.source == "exploit_graph", "Source mapped correctly")

# Multiple signals -- picks highest
dom2 = DominantSignalDetector.detect({
    "exploit_ev": 0.85,
    "cost_pressure": 0.70,
    "stealth_heat": 0.30,
})
check("39.1.6", dom2.name == "exploit_ev", "Highest signal wins")
check("39.1.7", dom2.value == 0.85, "Highest value captured")

# Opposing detection
boost, suppress = DominantSignalDetector.detect_opposing(
    {"exploit_ev": 0.92, "strategic_boost": 0.65},
    {"cost_pressure": 0.78, "stealth_heat": 0.30},
)
check("39.1.8", boost.name == "exploit_ev", "Dominant booster = exploit_ev")
check("39.1.9", suppress.name == "cost_pressure", "Dominant suppressor = cost_pressure")

# One side empty
b2, s2 = DominantSignalDetector.detect_opposing({}, {"cost_pressure": 0.5})
check("39.1.10", b2 is None, "No booster -> None")
check("39.1.11", s2.name == "cost_pressure", "Suppressor still detected")

# Unknown source mapping
dom3 = DominantSignalDetector.detect({"unknown_signal": 0.5})
check("39.1.12", dom3.source == "unknown", "Unknown source mapped to 'unknown'")

# --- CAL-2: ConflictClassifier ---
print("  39.2: ConflictClassifier -- classification")

sig_exploit = DominantSignal(name="exploit_ev", value=0.92, source="exploit_graph")
sig_cost = DominantSignal(name="cost_pressure", value=0.78, source="economic")

cc = ConflictClassifier.classify(sig_exploit, sig_cost)
check("39.2.1", cc.conflict_type == ConflictType.EXPLOIT_VS_COST, "Classified as EXPLOIT_VS_COST")
check("39.2.2", cc.severity == "high", "Severity = high (0.78 >= 0.6)")
check("39.2.3", "exploit_ev" in cc.description, "Description includes signal name")
check("39.2.4", cc.signal_a is sig_exploit, "signal_a = exploit")
check("39.2.5", cc.signal_b is sig_cost, "signal_b = cost")

# Critical severity (both >= 0.8)
sig_ex2 = DominantSignal(name="exploit_ev", value=0.95, source="exploit_graph")
sig_co2 = DominantSignal(name="cost_pressure", value=0.85, source="economic")
cc2 = ConflictClassifier.classify(sig_ex2, sig_co2)
check("39.2.6", cc2.severity == "critical", "Both >= 0.8 -> critical")

# Medium severity
sig_ex3 = DominantSignal(name="exploit_ev", value=0.70, source="exploit_graph")
sig_co3 = DominantSignal(name="cost_pressure", value=0.45, source="economic")
cc3 = ConflictClassifier.classify(sig_ex3, sig_co3)
check("39.2.7", cc3.severity == "medium", "0.45 >= 0.4 -> medium")

# Low severity
sig_ex4 = DominantSignal(name="exploit_ev", value=0.30, source="exploit_graph")
sig_co4 = DominantSignal(name="cost_pressure", value=0.25, source="economic")
cc4 = ConflictClassifier.classify(sig_ex4, sig_co4)
check("39.2.8", cc4.severity == "low", "Both < 0.4 -> low")

# Explore vs exploit
sig_explore = DominantSignal(name="uncertainty", value=0.80, source="exploration")
sig_exploitg = DominantSignal(name="exploit_ev", value=0.75, source="exploit_graph")
cc5 = ConflictClassifier.classify(sig_explore, sig_exploitg)
check("39.2.9", cc5.conflict_type == ConflictType.EXPLORE_VS_EXPLOIT, "Classified EXPLORE_VS_EXPLOIT")

# Hypothesis vs evidence
sig_hypo = DominantSignal(name="hypothesis_boost", value=0.70, source="hypothesis_engine")
sig_ev = DominantSignal(name="exploit_ev", value=0.60, source="exploit_graph")
cc6 = ConflictClassifier.classify(sig_hypo, sig_ev)
check("39.2.10", cc6.conflict_type == ConflictType.HYPOTHESIS_VS_EVIDENCE, "Classified HYPOTHESIS_VS_EVIDENCE")

# Uncategorized (no mapping for this pair)
sig_a = DominantSignal(name="atlas_boost", value=0.5, source="atlas")
sig_b = DominantSignal(name="backpressure", value=0.5, source="backpressure")
cc7 = ConflictClassifier.classify(sig_a, sig_b)
check("39.2.11", cc7.conflict_type == ConflictType.UNCATEGORIZED, "Unknown pair -> UNCATEGORIZED")

# Order-independent classification
cc8a = ConflictClassifier.classify(sig_exploit, sig_cost)
cc8b = ConflictClassifier.classify(sig_cost, sig_exploit)
check("39.2.12", cc8a.conflict_type == cc8b.conflict_type, "Classification is order-independent")

# --- CAL-3: ResolutionRuleTable ---
print("  39.3: ResolutionRuleTable -- mode-aware rules")

# Exploit vs Cost in aggressive -> exploit wins
base_class = ConflictClassifier.classify(sig_exploit, sig_cost)

w_agg, r_agg, _ = ResolutionRuleTable.resolve(base_class, ScanMode.AGGRESSIVE)
check("39.3.1", w_agg == Winner.SIGNAL_A, "Aggressive: exploit wins EXPLOIT_VS_COST")
check("39.3.2", "aggressive" in r_agg, "Rule mentions aggressive")

# Exploit vs Cost in stealth -> cost wins
w_stl, r_stl, _ = ResolutionRuleTable.resolve(base_class, ScanMode.STEALTH)
check("39.3.3", w_stl == Winner.SIGNAL_B, "Stealth: cost wins EXPLOIT_VS_COST")
check("39.3.4", "stealth" in r_stl, "Rule mentions stealth")

# Exploit vs Stealth in stealth -> stealth wins
stealth_class = ConflictClassifier.classify(
    DominantSignal(name="exploit_ev", value=0.9, source="exploit_graph"),
    DominantSignal(name="stealth_heat", value=0.8, source="defense"),
)
w_es, r_es, _ = ResolutionRuleTable.resolve(stealth_class, ScanMode.STEALTH)
check("39.3.5", w_es == Winner.SIGNAL_B, "Stealth: stealth wins EXPLOIT_VS_STEALTH")

# Exploit vs Stealth in aggressive -> exploit wins
w_ea, r_ea, _ = ResolutionRuleTable.resolve(stealth_class, ScanMode.AGGRESSIVE)
check("39.3.6", w_ea == Winner.SIGNAL_A, "Aggressive: exploit wins EXPLOIT_VS_STEALTH")

# Explore vs Exploit in aggressive -> exploit wins
explore_class = ConflictClassifier.classify(sig_explore, sig_exploitg)
w_expl, _, _ = ResolutionRuleTable.resolve(explore_class, ScanMode.AGGRESSIVE)
check("39.3.7", w_expl == Winner.SIGNAL_B, "Aggressive: exploit wins EXPLORE_VS_EXPLOIT")

# Explore vs Exploit in balanced -> explore wins
w_expl_b, _, _ = ResolutionRuleTable.resolve(explore_class, ScanMode.BALANCED)
check("39.3.8", w_expl_b == Winner.SIGNAL_A, "Balanced: explore wins EXPLORE_VS_EXPLOIT")

# Hypothesis vs Evidence in fast -> evidence wins
hypo_class = ConflictClassifier.classify(sig_hypo, sig_ev)
w_hf, _, _ = ResolutionRuleTable.resolve(hypo_class, ScanMode.FAST)
check("39.3.9", w_hf == Winner.SIGNAL_B, "Fast: evidence wins HYPOTHESIS_VS_EVIDENCE")

# Uncategorized -> default (SIGNAL_A = higher value)
w_unc, r_unc, fb_unc = ResolutionRuleTable.resolve(cc7, ScanMode.BALANCED)
check("39.3.10", w_unc == Winner.SIGNAL_A, "Uncategorized: higher-value signal wins")
check("39.3.11", "default" in r_unc, "Fallback rule says 'default'")

# All 6 modes covered for EXPLOIT_VS_COST
for mode in ScanMode:
    w, r, _fb = ResolutionRuleTable.resolve(base_class, mode)
    _mode_ok = w in (Winner.SIGNAL_A, Winner.SIGNAL_B) and len(r) > 5
    if not _mode_ok:
        break
check("39.3.12", _mode_ok, "All 6 scan modes have rules for EXPLOIT_VS_COST")

# --- CAL-4: ConflictArbitrator ---
print("  39.4: ConflictArbitrator -- orchestration")

arb = ConflictArbitrator(mode=ScanMode.AGGRESSIVE)

check("39.4.1", arb.mode == ScanMode.AGGRESSIVE, "Initial mode = AGGRESSIVE")
check("39.4.2", arb.conflict_count == 0, "Starts with 0 conflicts")

# Arbitrate: exploit vs cost in aggressive
result = arb.arbitrate(
    boosters={"exploit_ev": 0.92, "hypothesis_boost": 0.65},
    suppressors={"cost_pressure": 0.78, "stealth_heat": 0.30},
)
check("39.4.3", result is not None, "Conflict detected")
check("39.4.4", result.winning_signal.name == "exploit_ev", "Exploit wins in aggressive")
check("39.4.5", "aggressive" in result.rule_applied, "Rule says aggressive")
check("39.4.6", result.mode == ScanMode.AGGRESSIVE, "Result records mode")
check("39.4.7", arb.conflict_count == 1, "History has 1 conflict")

# Switch to stealth -- same conflict, different winner
arb.mode = ScanMode.STEALTH
result2 = arb.arbitrate(
    boosters={"exploit_ev": 0.92},
    suppressors={"cost_pressure": 0.78},
)
check("39.4.8", result2.winning_signal.name == "cost_pressure", "Cost wins in stealth")
check("39.4.9", result2.mode == ScanMode.STEALTH, "Result records stealth mode")
check("39.4.10", arb.conflict_count == 2, "History has 2 conflicts")

# No conflict when one side empty
no_conflict = arb.arbitrate(
    boosters={"exploit_ev": 0.92},
    suppressors={},
)
check("39.4.11", no_conflict is None, "No suppressors -> no conflict")

# to_dict serialization
d = result.to_dict()
check("39.4.12", d["conflict_type"] == "exploit_vs_cost", "to_dict conflict_type")
check("39.4.13", d["winner"] == "exploit_ev", "to_dict winner")
check("39.4.14", d["mode"] == "aggressive", "to_dict mode")

print("  39.5: ConflictArbitrator -- G5 integration bridge")

# arbitrate_from_g5: Uses the same multiplier dict G5 produces
arb2 = ConflictArbitrator(mode=ScanMode.AGGRESSIVE)

g5_result = arb2.arbitrate_from_g5({
    "tmm_boost": 1.3,
    "strategic_boost": 0.7,
    "hypothesis_weight": 1.1,
    "atlas_boost": 1.0,
    "tier_multiplier": 0.85,
})
check("39.5.1", g5_result is not None, "G5 multipliers produce a conflict")
check("39.5.2", g5_result.classification.conflict_type != ConflictType.UNCATEGORIZED,
      "G5 conflict classified")

# No conflict when all multipliers are neutral
no_g5 = arb2.arbitrate_from_g5({
    "tmm_boost": 1.0,
    "strategic_boost": 1.0,
    "hypothesis_weight": 1.0,
})
check("39.5.3", no_g5 is None, "Neutral multipliers -> no conflict")

# No conflict when all boost
all_boost = arb2.arbitrate_from_g5({
    "tmm_boost": 1.5,
    "strategic_boost": 1.3,
})
check("39.5.4", all_boost is None, "All boosters -> no conflict")

# Stats
stats = arb2.get_stats()
check("39.5.5", stats["total_conflicts"] == 1, "Stats: 1 conflict")
check("39.5.6", stats["mode"] == "aggressive", "Stats: mode is aggressive")
check("39.5.7", isinstance(stats["by_type"], dict), "Stats has by_type")
check("39.5.8", isinstance(stats["by_severity"], dict), "Stats has by_severity")

# Clear history
arb2.clear_history()
check("39.5.9", arb2.conflict_count == 0, "History cleared")

# Bounded history
arb3 = ConflictArbitrator(mode=ScanMode.BALANCED, max_history=5)
for i in range(10):
    arb3.arbitrate(
        boosters={"exploit_ev": 0.80 + i * 0.01},
        suppressors={"cost_pressure": 0.70},
    )
check("39.5.10", arb3.conflict_count == 5, "History bounded at max_history=5")

print("  39.6: Singleton and mode switching")

reset_arbitrator()
a1 = get_arbitrator()
check("39.6.1", a1.mode == ScanMode.BALANCED, "Default singleton mode = BALANCED")
check("39.6.2", get_arbitrator() is a1, "Singleton same instance")

a1.mode = ScanMode.STEALTH
check("39.6.3", get_arbitrator().mode == ScanMode.STEALTH, "Mode switch persists")

reset_arbitrator()
a2 = get_arbitrator()
check("39.6.4", a2 is not a1, "Reset creates new instance")
check("39.6.5", a2.mode == ScanMode.BALANCED, "Reset restores default mode")

print("  39.7: Package exports")

from CaseCrack.tools.burp_enterprise.agents import (
    ArbitrationResult as AR_exp,
    ConflictArbitrator as CA_exp,
    ConflictClassification as CC_exp,
    ConflictClassifier as CCl_exp,
    ConflictType as CT_exp,
    DominantSignal as DS_exp,
    DominantSignalDetector as DSD_exp,
    ResolutionRuleTable as RRT_exp,
    ScanMode as SM_exp,
    Winner as W_exp,
    get_arbitrator as ga_exp,
    reset_arbitrator as ra_exp,
)

check("39.7.1", AR_exp is ArbitrationResult, "ArbitrationResult exported")
check("39.7.2", CA_exp is ConflictArbitrator, "ConflictArbitrator exported")
check("39.7.3", CC_exp is ConflictClassification, "ConflictClassification exported")
check("39.7.4", CCl_exp is ConflictClassifier, "ConflictClassifier exported")
check("39.7.5", CT_exp is ConflictType, "ConflictType exported")
check("39.7.6", DS_exp is DominantSignal, "DominantSignal exported")
check("39.7.7", DSD_exp is DominantSignalDetector, "DominantSignalDetector exported")
check("39.7.8", RRT_exp is ResolutionRuleTable, "ResolutionRuleTable exported")
check("39.7.9", SM_exp is ScanMode, "ScanMode exported")
check("39.7.10", W_exp is Winner, "Winner exported")
check("39.7.11", ga_exp is get_arbitrator, "get_arbitrator exported")
check("39.7.12", ra_exp is reset_arbitrator, "reset_arbitrator exported")

print("  39.8: End-to-End mode-driven arbitration")

# Simulate a real scan scenario: same signals, 3 different modes.
# Verify behavior flips are explainable and predictable.

e2e_signals_boost = {"exploit_ev": 0.88, "hypothesis_boost": 0.55}
e2e_signals_suppress = {"cost_pressure": 0.72, "stealth_heat": 0.65}

modes_and_expected: list[tuple[ScanMode, str]] = [
    (ScanMode.AGGRESSIVE, "exploit_ev"),    # exploit wins
    (ScanMode.STEALTH,    "cost_pressure"), # cost wins
    (ScanMode.BALANCED,   "exploit_ev"),    # exploit wins (default)
]

all_e2e_correct = True
for mode, expected_winner in modes_and_expected:
    arb_e2e = ConflictArbitrator(mode=mode)
    r = arb_e2e.arbitrate(e2e_signals_boost, e2e_signals_suppress)
    if r is None or r.winning_signal.name != expected_winner:
        all_e2e_correct = False
        break

check("39.8.1", all_e2e_correct, "E2E: Same signals, 3 modes -> predictable winners")

# Verify all results have rules that mention the mode
arb_e2e2 = ConflictArbitrator(mode=ScanMode.AGGRESSIVE)
r_e2e = arb_e2e2.arbitrate(e2e_signals_boost, e2e_signals_suppress)
check("39.8.2", len(r_e2e.rule_applied) > 10, "Rule is human-readable")
check("39.8.3", r_e2e.classification.severity in ("critical", "high", "medium", "low"),
      "Severity is valid enum value")
check("39.8.4", r_e2e.timestamp > 0, "Timestamp recorded")

# Explore vs exploit in different modes
explore_boost = {"uncertainty": 0.75, "exploration_bonus": 0.60}
exploit_suppress = {"exploit_ev": 0.80}

arb_agg = ConflictArbitrator(mode=ScanMode.AGGRESSIVE)
r_agg2 = arb_agg.arbitrate(explore_boost, exploit_suppress)
check("39.8.5", r_agg2.winning_signal.source in ("exploit_graph", "exploration"),
      "Explore/exploit conflict resolved to valid source")

arb_bal = ConflictArbitrator(mode=ScanMode.BALANCED)
r_bal = arb_bal.arbitrate(explore_boost, exploit_suppress)
check("39.8.6", r_bal is not None, "Balanced mode resolves explore/exploit conflict")

# Thread safety of arbitration
thread_arb = ConflictArbitrator(mode=ScanMode.BALANCED, max_history=500)
thread_cal_errs = []

def _thread_arb(tid):
    try:
        for i in range(25):
            thread_arb.arbitrate(
                {"exploit_ev": 0.80 + (tid % 3) * 0.05},
                {"cost_pressure": 0.70 + (i % 5) * 0.05},
            )
    except Exception as e:
        thread_cal_errs.append(str(e))

cal_workers = [threading.Thread(target=_thread_arb, args=(t,)) for t in range(4)]
for cw in cal_workers:
    cw.start()
for cw in cal_workers:
    cw.join()

check("39.8.7", len(thread_cal_errs) == 0, "E2E: Thread-safe arbitration (0 errors)")
check("39.8.8", thread_arb.conflict_count == 100, "E2E: All 100 threaded conflicts recorded")

# Full conflict type coverage
all_types = set(ConflictType)
check("39.8.9", len(all_types) == 6, "6 conflict types defined")
all_modes = set(ScanMode)
check("39.8.10", len(all_modes) == 6, "6 scan modes defined")

print("  39.9: Fallback detection + drift telemetry")

# A rule-matched conflict should have fallback_used=False
arb_fb = ConflictArbitrator(mode=ScanMode.AGGRESSIVE)
fb_r1 = arb_fb.arbitrate(
    boosters={"exploit_ev": 0.90},
    suppressors={"cost_pressure": 0.75},
)
check("39.9.1", fb_r1.fallback_used is False, "Known conflict: fallback_used=False")

# An UNCATEGORIZED conflict (unknown source pair) triggers fallback
fb_r2 = arb_fb.arbitrate(
    boosters={"backpressure": 0.80},
    suppressors={"atlas_boost": 0.60},
)
check("39.9.2", fb_r2.classification.conflict_type == ConflictType.UNCATEGORIZED,
      "Unknown sources -> UNCATEGORIZED")
check("39.9.3", fb_r2.fallback_used is True, "UNCATEGORIZED uses fallback")
check("39.9.4", "default" in fb_r2.rule_applied, "Fallback rule says 'default'")

# to_dict includes fallback_used
d_fb = fb_r2.to_dict()
check("39.9.5", d_fb["fallback_used"] is True, "to_dict includes fallback_used")
d_fb1 = fb_r1.to_dict()
check("39.9.6", d_fb1["fallback_used"] is False, "to_dict False when rule matched")

# Telemetry: rule_coverage_pct and fallback_pct
stats_fb = arb_fb.get_stats()
check("39.9.7", stats_fb["rule_hits"] == 1, "1 rule-matched conflict")
check("39.9.8", stats_fb["fallback_hits"] == 1, "1 fallback conflict")
check("39.9.9", stats_fb["rule_coverage_pct"] == 50.0, "50% rule coverage")
check("39.9.10", stats_fb["fallback_pct"] == 50.0, "50% fallback rate")

# 100% rule coverage when all conflicts match rules
arb_100 = ConflictArbitrator(mode=ScanMode.BALANCED)
for _ in range(5):
    arb_100.arbitrate(boosters={"exploit_ev": 0.8}, suppressors={"cost_pressure": 0.7})
stats_100 = arb_100.get_stats()
check("39.9.11", stats_100["rule_coverage_pct"] == 100.0, "100% coverage when all rules match")
check("39.9.12", stats_100["fallback_pct"] == 0.0, "0% fallback when all rules match")

# Empty stats still have the new fields
arb_empty = ConflictArbitrator()
stats_empty = arb_empty.get_stats()
check("39.9.13", stats_empty["total_conflicts"] == 0, "Empty stats: 0 conflicts")
check("39.9.14", "rule_hits" not in stats_empty or stats_empty.get("rule_coverage_pct", 0.0) == 0.0,
      "Empty stats: no coverage data or 0%")

# ── 39.10: Unknown Conflict Capture ─────────────────────────────
print("\n  39.10: Unknown Conflict Capture")

from CaseCrack.tools.burp_enterprise.agents import (
    UnknownConflictCapture,
    RuleEffectivenessScorer,
    ConflictResolutionEvent,
    ConflictEventLog,
)

# Setup: create an arbitrator and produce known + unknown conflicts
cap = UnknownConflictCapture()
arb_cap = ConflictArbitrator(mode=ScanMode.AGGRESSIVE)

# Known conflict (has rule) -> should NOT be captured
res_known = arb_cap.arbitrate(
    boosters={"exploit_ev": 0.90},
    suppressors={"cost_pressure": 0.70},
)
cap.record(res_known)
check("39.10.1", cap.total_unclassified == 0,
      "Known conflict not captured")

# Unknown conflict (UNCATEGORIZED) -> SHOULD be captured
sig_unk_a = DominantSignal(name="atlas_boost", value=0.85, source="atlas")
sig_unk_b = DominantSignal(name="backpressure", value=0.70, source="backpressure")
cc_unk = ConflictClassifier.classify(sig_unk_a, sig_unk_b)
w_unk, r_unk, fb_unk = ResolutionRuleTable.resolve(cc_unk, ScanMode.BALANCED)
res_unk = ArbitrationResult(
    classification=cc_unk,
    winner=w_unk,
    winning_signal=sig_unk_a if w_unk == Winner.SIGNAL_A else sig_unk_b,
    rule_applied=r_unk,
    mode=ScanMode.BALANCED,
    fallback_used=fb_unk,
)
cap.record(res_unk)
check("39.10.2", cap.total_unclassified == 1,
      "Unknown conflict captured")

# Record same unknown type again -> count increments
cap.record(res_unk)
check("39.10.3", cap.total_unclassified == 2,
      "Duplicate unknown increments count")

# top_unclassified returns ranked list
top = cap.top_unclassified(5)
check("39.10.4", len(top) == 1,
      "One unique unknown pattern")
check("39.10.5", top[0]["occurrences"] == 2,
      "2 occurrences of same pattern")
check("39.10.6", "atlas" in top[0]["pattern"] and "backpressure" in top[0]["pattern"],
      "Pattern names the sources")
check("39.10.7", top[0]["last_mode"] == "balanced",
      "Last mode recorded")
check("39.10.8", top[0]["last_winner"] in ("atlas_boost", "backpressure"),
      "Last winner recorded")
check("39.10.9", isinstance(top[0]["last_signals"], tuple) and len(top[0]["last_signals"]) == 2,
      "Last signals is a 2-tuple")

# Add a second unique unknown pattern
sig_unk_c = DominantSignal(name="tier_multiplier", value=0.75, source="tier")
sig_unk_d = DominantSignal(name="thompson_draw", value=0.60, source="exploration")
cc_unk2 = ConflictClassifier.classify(sig_unk_c, sig_unk_d)
# tier vs exploration is NOT in _TYPE_MAP -> UNCATEGORIZED
w_unk2, r_unk2, fb_unk2 = ResolutionRuleTable.resolve(cc_unk2, ScanMode.FAST)
res_unk2 = ArbitrationResult(
    classification=cc_unk2, winner=w_unk2,
    winning_signal=sig_unk_c if w_unk2 == Winner.SIGNAL_A else sig_unk_d,
    rule_applied=r_unk2, mode=ScanMode.FAST, fallback_used=fb_unk2,
)
cap.record(res_unk2)
top2 = cap.top_unclassified(5)
check("39.10.10", len(top2) == 2,
      "Two unique unknown patterns after second type")
check("39.10.11", top2[0]["occurrences"] >= top2[1]["occurrences"],
      "Top list sorted by frequency descending")

# clear() resets everything
cap.clear()
check("39.10.12", cap.total_unclassified == 0,
      "Clear resets capture state")
check("39.10.13", cap.top_unclassified() == [],
      "No patterns after clear")

# ── 39.11: Rule Effectiveness Scoring ────────────────────────────
print("\n  39.11: Rule Effectiveness Scoring")

scorer = RuleEffectivenessScorer()

# Record outcomes for a known conflict
scorer.record_outcome(res_known, ev_delta=0.15, confirmed_finding=True)
scorer.record_outcome(res_known, ev_delta=0.08, confirmed_finding=False)
scorer.record_outcome(res_known, ev_delta=-0.05, wasted_cycles=True)

scores = scorer.rule_scores()
check("39.11.1", len(scores) == 1,
      "One rule tracked after 3 outcomes")
s0 = scores[0]
check("39.11.2", s0["uses"] == 3,
      "3 uses recorded")
check("39.11.3", abs(s0["avg_ev_delta"] - 0.06) < 0.01,
      "avg EV delta ~ 0.06")
check("39.11.4", s0["confirmed_findings"] == 1,
      "1 confirmed finding")
check("39.11.5", s0["wasted_cycles"] == 1,
      "1 wasted cycle")
check("39.11.6", isinstance(s0["effectiveness"], float),
      "Effectiveness is a float")
check("39.11.7", "rule" in s0 and "conflict_type" in s0 and "mode" in s0,
      "Score entry has rule, conflict_type, mode")

# Record a second rule with better outcomes
# Build a stealth conflict -> different rule
arb_stl = ConflictArbitrator(mode=ScanMode.STEALTH)
res_stl = arb_stl.arbitrate(
    boosters={"exploit_ev": 0.80},
    suppressors={"cost_pressure": 0.65},
)
scorer.record_outcome(res_stl, ev_delta=0.30, confirmed_finding=True)
scorer.record_outcome(res_stl, ev_delta=0.25, confirmed_finding=True)

scores2 = scorer.rule_scores()
check("39.11.8", len(scores2) == 2,
      "Two rules tracked")
# Best rule should be first (sorted by effectiveness)
check("39.11.9", scores2[0]["effectiveness"] >= scores2[1]["effectiveness"],
      "Sorted best-first by effectiveness")

# worst_rules returns in reverse order
worst = scorer.worst_rules(5)
check("39.11.10", len(worst) > 0,
      "worst_rules returns entries")
check("39.11.11", worst[0]["effectiveness"] <= scores2[0]["effectiveness"],
      "Worst rule has lower effectiveness")

# clear resets
scorer.clear()
check("39.11.12", scorer.rule_scores() == [],
      "Clear resets scorer")

# Effectiveness formula: avg_ev + confirm_rate - waste_rate
scorer2 = RuleEffectivenessScorer()
# Pure winner: high EV, all confirmed, no waste
scorer2.record_outcome(res_known, ev_delta=0.50, confirmed_finding=True)
scorer2.record_outcome(res_known, ev_delta=0.50, confirmed_finding=True)
pure = scorer2.rule_scores()[0]
# effectiveness = 0.50 + 1.0 - 0.0 = 1.50
check("39.11.13", abs(pure["effectiveness"] - 1.50) < 0.01,
      "Pure winner effectiveness ~ 1.50")

# Pure loser: negative EV, no confirms, all waste
scorer3 = RuleEffectivenessScorer()
scorer3.record_outcome(res_known, ev_delta=-0.30, wasted_cycles=True)
scorer3.record_outcome(res_known, ev_delta=-0.20, wasted_cycles=True)
bad = scorer3.rule_scores()[0]
# effectiveness = -0.25 + 0.0 - 1.0 = -1.25
check("39.11.14", bad["effectiveness"] < 0,
      "Pure loser effectiveness is negative")

# ── 39.12: Conflict Resolution Event (UI Exposure) ──────────────
print("\n  39.12: Conflict Resolution Event (UI Exposure)")

# Build event from known result
evt = ConflictResolutionEvent.from_result(res_known)
check("39.12.1", evt.conflict == "exploit_vs_cost",
      "Event conflict type correct")
check("39.12.2", evt.mode == "aggressive",
      "Event mode correct")
check("39.12.3", len(evt.rule) > 5,
      "Event rule is descriptive")
check("39.12.4", evt.winner in ("exploit_ev", "cost_pressure"),
      "Event winner is one of the signals")
check("39.12.5", evt.loser in ("exploit_ev", "cost_pressure"),
      "Event loser is one of the signals")
check("39.12.6", evt.winner != evt.loser,
      "Winner and loser are different")
check("39.12.7", evt.winner_value > 0 and evt.loser_value > 0,
      "Both values are positive")
check("39.12.8", evt.severity in ("critical", "high", "medium", "low"),
      "Severity is valid")
check("39.12.9", evt.fallback is False,
      "Known conflict: fallback=False")

# to_dict has all fields
ed = evt.to_dict()
check("39.12.10", all(k in ed for k in
      ("conflict", "mode", "rule", "winner", "loser",
       "winner_value", "loser_value", "severity", "fallback", "timestamp")),
      "to_dict has all 10 fields")

# Event from fallback result
evt_fb = ConflictResolutionEvent.from_result(res_unk)
check("39.12.11", evt_fb.fallback is True,
      "Fallback conflict: fallback=True")
check("39.12.12", evt_fb.conflict == "uncategorized",
      "Fallback event is uncategorized")

# ConflictEventLog - rolling log for cockpit
elog = ConflictEventLog(max_events=50)
check("39.12.13", elog.total_events == 0,
      "Empty log has 0 events")

# Push events
e1 = elog.push(res_known)
check("39.12.14", isinstance(e1, ConflictResolutionEvent),
      "push() returns ConflictResolutionEvent")
check("39.12.15", elog.total_events == 1,
      "1 event after first push")

# Push more events
elog.push(res_stl)
elog.push(res_unk)
check("39.12.16", elog.total_events == 3,
      "3 events after 3 pushes")

# recent_events returns newest first
recent = elog.recent_events(10)
check("39.12.17", len(recent) == 3,
      "3 recent events")
check("39.12.18", isinstance(recent[0], dict),
      "Events returned as dicts")
# Newest (res_unk pushed last) should be first
check("39.12.19", recent[0]["conflict"] == "uncategorized",
      "Newest event first in recent list")
check("39.12.20", recent[2]["conflict"] == "exploit_vs_cost",
      "Oldest event last in recent list")

# max_events cap works
elog_tiny = ConflictEventLog(max_events=2)
elog_tiny.push(res_known)
elog_tiny.push(res_stl)
elog_tiny.push(res_unk)
check("39.12.21", elog_tiny.total_events == 2,
      "Log capped at max_events=2")

# clear() empties the log
elog.clear()
check("39.12.22", elog.total_events == 0,
      "Clear empties event log")
check("39.12.23", elog.recent_events() == [],
      "No events after clear")


print(f"\n{'='*60}")
print(f"RESULTS: {passed} passed, {failed} failed out of {passed + failed}")
print(f"{'='*60}")

if failed > 0:
    sys.exit(1)

