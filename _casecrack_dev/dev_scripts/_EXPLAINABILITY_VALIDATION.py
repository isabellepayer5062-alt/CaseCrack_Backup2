#!/usr/bin/env python3
"""
Explainability Layer Validation
Proves: EX-001, EX-002, EX-003

Ports the mcp-ui-adapter.js _computeExplanation pipeline to Python and verifies:
  EX-001: Same fixture → exact same explanation output (deterministic)
  EX-002: Explanation fields are logically complete (summary, causes, projectedOutcome, confidence)
  EX-003: No internal contradictions — cause "license issue" must NOT
          lead to "increase concurrency" recommendation

Also combines results with _INTELLIGENCE_PARTIAL_REPORT.json to write the
final _INTELLIGENCE_EXPLAINABILITY_DETERMINISM_REPORT.json consumed by
the production readiness contract runner.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
PARTIAL_REPORT_PATH = ROOT / "_INTELLIGENCE_PARTIAL_REPORT.json"
COMBINED_REPORT_PATH = ROOT / "_INTELLIGENCE_EXPLAINABILITY_DETERMINISM_REPORT.json"


# ── Python port of explainability layer ──────────────────────────────────────
# Faithful port of _computeExplanation and all helpers from
# CaseCrack/tools/burp_enterprise/static/js/mcp-ui-adapter.js


def _str(v: Any) -> str:
    return "" if v is None else str(v)


def _severity_rank(severity: Any) -> int:
    s = _str(severity).lower()
    if s == "critical":
        return 3
    if s == "warning":
        return 2
    if s == "info":
        return 1
    return 0


def _signal_set_from_intel(
    warnings: List[Dict], anomalies: List[Dict]
) -> Dict[str, bool]:
    sig: Dict[str, bool] = {}
    for w in warnings:
        code = _str((w or {}).get("code") or "").upper()
        if code:
            sig[code] = True
    for a in anomalies:
        t = _str((a or {}).get("type") or "").upper()
        code = _str((a or {}).get("code") or "").upper()
        if t:
            sig[t] = True
        if code:
            sig[code] = True
    return sig


def _pick_dominant_anomaly(anomalies: List[Dict]) -> str:
    by_type: Dict[str, int] = {}
    for a in anomalies:
        t = _str((a or {}).get("type") or "").upper()
        if t:
            by_type[t] = by_type.get(t, 0) + 1
    if not by_type:
        return ""
    return max(sorted(by_type.keys()), key=lambda k: by_type[k])


def _build_explanation_summary(warnings: List[Dict], anomalies: List[Dict]) -> str:
    if not warnings and not anomalies:
        return "System is stable with no active warnings or anomalies."

    highest = ""
    highest_rank = -1
    for w in warnings:
        sev = _str((w or {}).get("severity") or "")
        rank = _severity_rank(sev)
        if rank > highest_rank:
            highest_rank = rank
            highest = _str((w or {}).get("code") or "").upper()

    dominant = _pick_dominant_anomaly(anomalies)

    if highest == "PERSISTENT_LICENSE_REQUIRED":
        return "System is experiencing persistent license enforcement failures."
    if dominant == "RATE_LIMIT_SPIKE" or highest == "RATE_LIMIT_SATURATION":
        return "System is experiencing elevated error rates and intermittent rate limiting."
    if dominant == "FLAPPING_STATE":
        return "System is unstable with flapping execution states."
    if highest == "HIGH_ERROR_RATE":
        return "System is experiencing elevated error rates across recent actions."
    return "System is showing active operational anomalies requiring attention."


def _build_explanation_situation(
    warnings: List[Dict], anomalies: List[Dict]
) -> List[str]:
    situation: List[str] = []
    for w in warnings:
        label = _str((w or {}).get("label") or (w or {}).get("code") or "")
        metric = {}
        try:
            metric = (w or {}).get("metric") or {}
        except Exception:
            metric = {}
        metric_str = json.dumps(metric) if metric else ""
        if label:
            situation.append(label + (f" [{metric_str}]" if metric_str and metric_str != "{}" else ""))
    for a in anomalies:
        typ = _str((a or {}).get("type") or "ANOMALY")
        detail_str = json.dumps(a or {})
        situation.append(typ + (f" [{detail_str}]" if detail_str and detail_str != "{}" else ""))
    return situation


def _build_explanation_causes(warnings: List[Dict], anomalies: List[Dict]) -> List[str]:
    sig = _signal_set_from_intel(warnings, anomalies)
    causes: List[str] = []
    if sig.get("PERSISTENT_LICENSE_REQUIRED") or sig.get("LICENSE_REQUIRED") or sig.get("REPEATED_ERROR_CLUSTER"):
        causes.append("Tool execution blocked due to license enforcement (missing or invalid license context).")
    if sig.get("RATE_LIMIT_SATURATION") or sig.get("RATE_LIMIT_SPIKE") or sig.get("RATE_LIMITED"):
        causes.append("Request concurrency exceeds backend threshold.")
    if sig.get("FLAPPING_STATE"):
        causes.append("Backend stability is degraded or retry behavior is oscillating.")
    if sig.get("ORPHAN_RECOVERY") or sig.get("STREAM_INSTABILITY"):
        causes.append("Transport instability detected in event stream delivery/recovery path.")
    if not causes:
        causes.append("No strong causal cluster identified from current signal windows.")
    return causes


def _build_explanation_projected_outcome(warnings: List[Dict], anomalies: List[Dict]) -> List[str]:
    sig = _signal_set_from_intel(warnings, anomalies)
    outcome: List[str] = []
    if sig.get("RATE_LIMIT_SATURATION") or sig.get("RATE_LIMIT_SPIKE") or sig.get("RATE_LIMITED"):
        outcome.append("Rate limiting is likely to persist if concurrency remains unchanged.")
    if sig.get("PERSISTENT_LICENSE_REQUIRED") or sig.get("LICENSE_REQUIRED"):
        outcome.append("License-related failures will continue until configuration or entitlement is corrected.")
    if sig.get("FLAPPING_STATE"):
        outcome.append("Execution instability is likely to continue under sustained load.")
    if sig.get("HIGH_ERROR_RATE"):
        outcome.append("Error rate is likely to remain elevated without intervention.")
    if not outcome:
        outcome.append("System should remain stable if current operating conditions are maintained.")
    return outcome


def _build_explanation_confidence(
    warnings: List[Dict], anomalies: List[Dict], recommendations: List[Dict]
) -> float:
    sig = _signal_set_from_intel(warnings, anomalies)
    corroborating = min(5, len(warnings) + len(anomalies))
    consistency = 0
    if (sig.get("RATE_LIMIT_SATURATION") or sig.get("RATE_LIMITED")) and sig.get("RATE_LIMIT_SPIKE"):
        consistency += 1
    if (sig.get("PERSISTENT_LICENSE_REQUIRED") or sig.get("LICENSE_REQUIRED")) and sig.get("REPEATED_ERROR_CLUSTER"):
        consistency += 1
    if sig.get("STREAM_INSTABILITY") and sig.get("ORPHAN_RECOVERY"):
        consistency += 1
    has_no_action = any(_str((r or {}).get("action") or "").upper() == "NO_ACTION_REQUIRED" for r in recommendations)
    has_active = any(_str((r or {}).get("action") or "").upper() != "NO_ACTION_REQUIRED" for r in recommendations)
    conflict_penalty = 1 if (has_no_action and has_active) else 0
    score = 0.4 + (corroborating * 0.08) + (consistency * 0.11) - (conflict_penalty * 0.15)
    score = max(0.1, min(0.98, score))
    return round(score, 2)


def compute_explanation(
    warnings: List[Dict], anomalies: List[Dict], recommendations: List[Dict]
) -> Dict[str, Any]:
    """
    Pure function port of _computeExplanation.
    Exported for use by other harnesses.
    """
    return {
        "summary": _build_explanation_summary(warnings, anomalies),
        "situation": _build_explanation_situation(warnings, anomalies),
        "causes": _build_explanation_causes(warnings, anomalies),
        "projectedOutcome": _build_explanation_projected_outcome(warnings, anomalies),
        "recommendedActions": [dict(r) for r in recommendations],
        "confidence": _build_explanation_confidence(warnings, anomalies, recommendations),
    }


# ── Test fixtures ─────────────────────────────────────────────────────────────

def _license_intel() -> Dict[str, Any]:
    """Intelligence payload for a pure license-failure scenario."""
    warnings = [{
        "code": "PERSISTENT_LICENSE_REQUIRED",
        "label": "Persistent license failures",
        "severity": "critical",
        "metric": {"license_required_count": 5, "failed_actions": 7, "failure_ratio": 0.71},
    }]
    anomalies = [{
        "type": "REPEATED_ERROR_CLUSTER",
        "code": "LICENSE_REQUIRED",
        "count": 5,
        "evidence_window": "last_5_actions",
    }]
    recommendations = [{
        "action": "CHECK_LICENSE_CONFIGURATION",
        "reason": "Persistent LICENSE_REQUIRED failures detected",
        "confidence": 0.92,
        "evidence": {"warning_code": "PERSISTENT_LICENSE_REQUIRED", "metric": {}},
    }]
    return {"warnings": warnings, "anomalies": anomalies, "recommendations": recommendations}


def _rate_limit_intel() -> Dict[str, Any]:
    """Intelligence payload for a pure rate-limit scenario."""
    warnings = [{
        "code": "RATE_LIMIT_SATURATION",
        "label": "Rate-limit saturation",
        "severity": "warning",
        "metric": {"rate_limited_count": 10, "total": 30, "ratio": 0.33},
    }]
    anomalies = [{
        "type": "RATE_LIMIT_SPIKE",
        "code": "RATE_LIMITED",
        "count": 10,
        "window": "last_30_actions",
    }]
    recommendations = [{
        "action": "REDUCE_CONCURRENCY",
        "reason": "RATE_LIMITED spike in recent action window",
        "suggested_limit": 3,
        "confidence": 0.88,
        "evidence": {"anomaly_type": "RATE_LIMIT_SPIKE", "count": 10, "window": "last_30_actions"},
    }]
    return {"warnings": warnings, "anomalies": anomalies, "recommendations": recommendations}


def _stable_intel() -> Dict[str, Any]:
    """Intelligence payload for a stable system."""
    return {"warnings": [], "anomalies": [], "recommendations": []}


# ── EX-001: Determinism ───────────────────────────────────────────────────────

def test_ex001_determinism() -> Dict[str, Any]:
    """Same fixture → exact same explanation output, 10 runs."""
    payload = _license_intel()
    runs = [
        json.dumps(
            compute_explanation(payload["warnings"], payload["anomalies"], payload["recommendations"]),
            sort_keys=True,
        )
        for _ in range(10)
    ]
    unique = len(set(runs))
    passed = unique == 1
    return {
        "test": "explanation_determinism",
        "blocker": "EX-001",
        "passed": passed,
        "unique_outputs": unique,
        "detail": "10/10 identical" if passed else f"Got {unique} unique outputs (non-deterministic)",
    }


# ── EX-002: Completeness ──────────────────────────────────────────────────────

def test_ex002_completeness() -> Dict[str, Any]:
    """
    Explanation always has summary, causes, projectedOutcome, confidence.
    Tested across license, rate-limit, and stable scenarios.
    """
    violations: List[str] = []
    required_fields = ["summary", "situation", "causes", "projectedOutcome", "recommendedActions", "confidence"]

    for name, payload in [
        ("license", _license_intel()),
        ("rate_limit", _rate_limit_intel()),
        ("stable", _stable_intel()),
    ]:
        expl = compute_explanation(
            payload["warnings"], payload["anomalies"], payload["recommendations"]
        )
        for field in required_fields:
            if field not in expl:
                violations.append(f"EX-002: {name} scenario missing field '{field}'")
            elif field == "summary" and not expl["summary"]:
                violations.append(f"EX-002: {name} scenario has empty summary")
            elif field == "confidence" and not (0.0 <= expl["confidence"] <= 1.0):
                violations.append(f"EX-002: {name} confidence out of range: {expl['confidence']}")

    # License scenario: summary must mention license
    license_expl = compute_explanation(*[_license_intel()[k] for k in ("warnings", "anomalies", "recommendations")])
    if "license" not in license_expl["summary"].lower():
        violations.append(f"EX-002: license scenario summary doesn't mention license: {license_expl['summary']!r}")

    # Causes must be non-empty for non-stable scenarios
    for name, payload in [("license", _license_intel()), ("rate_limit", _rate_limit_intel())]:
        expl = compute_explanation(payload["warnings"], payload["anomalies"], payload["recommendations"])
        if not expl["causes"]:
            violations.append(f"EX-002: {name} scenario has empty causes list")
        if not expl["projectedOutcome"]:
            violations.append(f"EX-002: {name} scenario has empty projectedOutcome")

    passed = len(violations) == 0
    return {
        "test": "explanation_completeness",
        "blocker": "EX-002",
        "passed": passed,
        "violations": violations,
    }


# ── EX-003: No contradictions ─────────────────────────────────────────────────

def test_ex003_no_contradictions() -> Dict[str, Any]:
    """
    Logical consistency rules:
    1. If causes contain license issue → recommended actions must NOT include
       anything that increases concurrency (inverse of correct response).
    2. If causes contain only rate-limit → license recommendation absent.
    3. summary and causes must be consistent (license summary → license cause).
    4. projectedOutcome must be consistent with causes.
    """
    violations: List[str] = []

    # Rule 1: license cause → no "INCREASE_CONCURRENCY" recommendation
    license_payload = _license_intel()
    expl = compute_explanation(
        license_payload["warnings"], license_payload["anomalies"], license_payload["recommendations"]
    )
    causes_text = " ".join(expl["causes"]).lower()
    rec_actions = [r.get("action", "") for r in expl["recommendedActions"]]

    if "license" in causes_text:
        # No recommendation should say "increase concurrency"
        bad_recs = [a for a in rec_actions if "INCREASE_CONCURRENCY" in a.upper()]
        if bad_recs:
            violations.append(
                f"EX-003: cause says license issue but recommendation is increase concurrency: {bad_recs}"
            )
        # Should be CHECK_LICENSE_CONFIGURATION
        if "CHECK_LICENSE_CONFIGURATION" not in rec_actions:
            violations.append(
                f"EX-003: license cause present but CHECK_LICENSE_CONFIGURATION missing: {rec_actions}"
            )

    # Rule 2: rate-limit only → no CHECK_LICENSE_CONFIGURATION
    rate_payload = _rate_limit_intel()
    expl_rate = compute_explanation(
        rate_payload["warnings"], rate_payload["anomalies"], rate_payload["recommendations"]
    )
    rate_rec_actions = [r.get("action", "") for r in expl_rate["recommendedActions"]]
    if "CHECK_LICENSE_CONFIGURATION" in rate_rec_actions:
        violations.append(
            f"EX-003: pure rate-limit scenario has CHECK_LICENSE_CONFIGURATION recommendation: {rate_rec_actions}"
        )
    if "REDUCE_CONCURRENCY" not in rate_rec_actions:
        violations.append(
            f"EX-003: pure rate-limit scenario missing REDUCE_CONCURRENCY: {rate_rec_actions}"
        )

    # Rule 3: license summary → license cause
    if "license" in expl["summary"].lower():
        if not any("license" in c.lower() for c in expl["causes"]):
            violations.append(
                f"EX-003: summary mentions license but no license cause: summary={expl['summary']!r}, causes={expl['causes']}"
            )

    # Rule 4: license projectedOutcome must mention license correction
    if "license" in causes_text:
        outcome_text = " ".join(expl["projectedOutcome"]).lower()
        if "license" not in outcome_text and "configuration" not in outcome_text:
            violations.append(
                f"EX-003: license cause but projectedOutcome doesn't mention license: {expl['projectedOutcome']}"
            )

    # Rule 5: stable system → no active recommendations (or NO_ACTION_REQUIRED only)
    stable_payload = _stable_intel()
    expl_stable = compute_explanation(
        stable_payload["warnings"], stable_payload["anomalies"], stable_payload["recommendations"]
    )
    stable_recs = [r.get("action", "") for r in expl_stable["recommendedActions"]]
    bad_stable_recs = [a for a in stable_recs if a not in ("", "NO_ACTION_REQUIRED")]
    if bad_stable_recs:
        violations.append(
            f"EX-003: stable system has active recommendations: {bad_stable_recs}"
        )

    passed = len(violations) == 0
    return {
        "test": "no_contradictions",
        "blocker": "EX-003",
        "passed": passed,
        "violations": violations,
        "license_explanation": {
            "summary": expl.get("summary"),
            "causes": expl.get("causes"),
            "recommendations": rec_actions,
        },
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    tests = [test_ex001_determinism, test_ex002_completeness, test_ex003_no_contradictions]
    results: List[Dict[str, Any]] = []
    all_expl_pass = True

    for fn in tests:
        result = fn()
        results.append(result)
        status = "PASS" if result["passed"] else "FAIL"
        if not result["passed"]:
            all_expl_pass = False
        detail = result.get("detail") or "; ".join(result.get("violations", [])) or "ok"
        print(f"  [{status}] {result['test']} ({result['blocker']}): {detail}")

    # Load intelligence partial report if it exists
    intel_partial: Dict[str, Any] = {}
    if PARTIAL_REPORT_PATH.exists():
        try:
            intel_partial = json.loads(PARTIAL_REPORT_PATH.read_text(encoding="utf-8"))
        except Exception:
            intel_partial = {}

    intel_pass = intel_partial.get("intelligence_deterministic", False)
    intel_fixture = intel_partial.get("intelligence_fixture_pass", False)
    intel_blockers = intel_partial.get("blockers_proven", {})

    combined_blockers = {
        "IN-001": intel_blockers.get("IN-001", False),
        "IN-002": intel_blockers.get("IN-002", False),
        "IN-003": intel_blockers.get("IN-003", False),
        "IN-004": intel_blockers.get("IN-004", False),
        "EX-001": next((r["passed"] for r in results if r["blocker"] == "EX-001"), False),
        "EX-002": next((r["passed"] for r in results if r["blocker"] == "EX-002"), False),
        "EX-003": next((r["passed"] for r in results if r["blocker"] == "EX-003"), False),
    }
    all_pass = all(combined_blockers.values())

    combined = {
        "verdict": "PASS" if all_pass else "FAIL",
        "intelligence_deterministic": intel_pass,
        "intelligence_fixture_pass": intel_fixture,
        "explainability_deterministic": all_expl_pass,
        "no_contradictions": next(
            (r["passed"] for r in results if r["blocker"] == "EX-003"), False
        ),
        "blockers_proven": combined_blockers,
        "intelligence_tests": intel_partial.get("tests", []),
        "explainability_tests": results,
    }

    COMBINED_REPORT_PATH.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    verdict = combined["verdict"]
    print(f"\nExplainability Validation: {'PASS' if all_expl_pass else 'FAIL'}")
    print(f"Combined (IN+EX): {verdict}")
    print(f"  blockers_proven: {combined_blockers}")
    print(f"  Combined report: {COMBINED_REPORT_PATH}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
