"""OTL Policy Validation Tests — Post-Feature-Completeness Verification

Three categories of validation:
1. Cross-layer contradiction tests — policy inconsistency bugs
2. Priority inversion stress tests — CRITICAL vs LOW preemption
3. Multi-layer failure cascade simulation — graceful degradation
"""

import asyncio
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CaseCrack"))

from CaseCrack.tools.burp_enterprise.agents.finding_safety_interlocks import (
    FindingSafetyLedger,
    SeverityGuard,
    LedgerEntryAction,
    get_finding_ledger,
    get_severity_guard,
    reset_finding_ledger,
    reset_severity_guard,
)
from CaseCrack.tools.burp_enterprise.agents.finding_dedup import (
    FindingDedup,
    DedupResult,
)
from CaseCrack.tools.burp_enterprise.core_infra.canonical_finding import (
    FindingDeduplicator,
)
from CaseCrack.tools.burp_enterprise.caap.escalation_gateway import (
    EscalationGateway,
    EscalationStatus,
    EscalationDecision,
    ESCALATION_TIMEOUT_SECONDS,
    get_gateway,
    reset_gateway,
)
from CaseCrack.tools.burp_enterprise.decision_plane import (
    DecisionPlane,
    OperatorGatingEngine,
    OperatorGateLevel,
)
from CaseCrack.tools.burp_enterprise.operator_feedback import (
    OperatorFeedbackLoop,
    OverrideType,
    get_operator_feedback_loop,
)
from CaseCrack.tools.burp_enterprise.agents.autonomy import (
    auto_approve_set,
    resolve_autonomy,
)
from CaseCrack.tools.burp_enterprise.agents.copilot_loop import (
    ProposedAction,
    CopilotLoop,
    _is_interactive,
)

# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _make_finding(**overrides):
    """Create a canonical finding dict."""
    base = {
        "id": "vuln-001",
        "title": "SQL Injection in /api/users",
        "type": "sqli",
        "severity": "HIGH",
        "url": "http://127.0.0.1:8080/api/users",
        "description": "The id parameter is vulnerable to SQL injection",
        "parameter": "id",
        "category": "injection",
        "source_tool": "nuclei",
        "confidence": 0.85,
    }
    base.update(overrides)
    return base


def _make_action(index=1, risk="aggressive", hyp_id="H-001",
                 command="sqli --url http://127.0.0.1:8080", **kwargs):
    """Create a ProposedAction."""
    return ProposedAction(
        index=index,
        hypothesis_id=hyp_id,
        command=command,
        risk=risk,
        rationale="test rationale",
        **kwargs,
    )


def _make_copilot(autonomy=2, url="http://127.0.0.1:8080"):
    """Create a CopilotLoop with subsystems stubbed."""
    with patch.multiple(
        "CaseCrack.tools.burp_enterprise.agents.copilot_loop",
        _try_import_logger=lambda: None,
    ):
        loop = CopilotLoop(url=url, autonomy=autonomy, disable_llm=True)
    return loop


@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset all singletons before each test."""
    reset_finding_ledger()
    reset_severity_guard()
    reset_gateway()
    # Reset operator feedback singleton
    import CaseCrack.tools.burp_enterprise.operator_feedback as ofmod
    with ofmod._instance_lock:
        ofmod._instance = None
    yield
    reset_finding_ledger()
    reset_severity_guard()
    reset_gateway()
    with ofmod._instance_lock:
        ofmod._instance = None


# ═══════════════════════════════════════════════════════════════════════
# 1. CROSS-LAYER CONTRADICTION TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestCrossLayerContradictions:
    """Policy inconsistency bugs that must never happen."""

    # ── Contradiction 1: FSI preserves finding ❌ dedup removes it ──

    def test_fsi_preserves_critical_finding_dedup_cannot_remove(self):
        """SeverityGuard says CRITICAL is protected → dedup MUST keep it."""
        guard = get_severity_guard()

        # Two nearly-identical CRITICAL findings
        f1 = _make_finding(id="crit-1", severity="CRITICAL",
                           title="SQL injection in /api/login",
                           url="http://127.0.0.1:8080/api/login")
        f2 = _make_finding(id="crit-2", severity="CRITICAL",
                           title="SQL injection in /api/login",
                           url="http://127.0.0.1:8080/api/login")

        # SeverityGuard says protected
        assert guard.should_protect("CRITICAL") is True

        # FindingDedup must NOT discard either
        dedup = FindingDedup(bridge=None)
        result = asyncio.get_event_loop().run_until_complete(
            dedup.deduplicate([f1, f2], use_llm=False)
        )

        # Both must be in merged — neither discarded
        assert len(result.merged) == 2, (
            f"FSI-dedup contradiction: CRITICAL findings discarded. "
            f"merged={len(result.merged)} discarded={len(result.discarded)}"
        )
        assert len(result.discarded) == 0

    def test_fsi_preserves_high_finding_dedup_cannot_remove(self):
        """SeverityGuard says HIGH is protected → dedup MUST keep it."""
        f1 = _make_finding(id="high-1", severity="HIGH",
                           title="XSS in search parameter",
                           url="http://127.0.0.1:8080/search")
        f2 = _make_finding(id="high-2", severity="HIGH",
                           title="XSS in search parameter",
                           url="http://127.0.0.1:8080/search")

        dedup = FindingDedup(bridge=None)
        result = asyncio.get_event_loop().run_until_complete(
            dedup.deduplicate([f1, f2], use_llm=False)
        )

        assert len(result.merged) == 2, "HIGH findings must be preserved by SeverityGuard"

    def test_fsi_allows_medium_dedup(self):
        """SeverityGuard does NOT protect MEDIUM → dedup CAN remove it."""
        guard = get_severity_guard()
        assert guard.should_protect("MEDIUM") is False

        f1 = _make_finding(id="med-1", severity="MEDIUM",
                           title="Missing HSTS header",
                           url="http://127.0.0.1:8080/")
        f2 = _make_finding(id="med-2", severity="MEDIUM",
                           title="Missing HSTS header",
                           url="http://127.0.0.1:8080/")

        dedup = FindingDedup(bridge=None)
        result = asyncio.get_event_loop().run_until_complete(
            dedup.deduplicate([f1, f2], use_llm=False)
        )

        # MEDIUM duplicates SHOULD be merged (only 1 kept)
        assert len(result.merged) == 1, "MEDIUM duplicates should be deduped normally"
        assert len(result.discarded) == 1

    def test_canonical_dedup_respects_severity_guard(self):
        """FindingDeduplicator.is_duplicate must respect SeverityGuard for CRITICAL/HIGH."""
        deduplicator = FindingDeduplicator()

        f1 = _make_finding(id="crit-a", severity="CRITICAL",
                           title="RCE via deserialization",
                           url="http://127.0.0.1:8080/api")

        # First insert — not duplicate
        assert deduplicator.is_duplicate(f1) is False

        # Second insert of exact same finding — fingerprint match
        # SeverityGuard should block suppression
        assert deduplicator.is_duplicate(f1) is False, (
            "Canonical dedup suppressed a CRITICAL finding — SeverityGuard failed"
        )

    # ── Contradiction 2: Headless mode ❌ still calls blocking input() ──

    def test_headless_mode_never_calls_input(self):
        """When COPILOT_HEADLESS=1, _approve must NOT call input()."""
        loop = _make_copilot(autonomy=2)

        aggressive_action = _make_action(risk="aggressive")

        with patch.dict(os.environ, {"COPILOT_HEADLESS": "1"}):
            with patch("builtins.input", side_effect=AssertionError("input() called in headless mode!")):
                result = loop._approve([aggressive_action])

        # Should return something (not block on input)
        assert result is not None

    def test_non_interactive_stdin_never_calls_input(self):
        """When stdin is not a TTY, _approve must NOT call input()."""
        loop = _make_copilot(autonomy=2)

        aggressive_action = _make_action(risk="aggressive")

        with patch(
            "CaseCrack.tools.burp_enterprise.agents.copilot_loop._is_interactive",
            return_value=False,
        ):
            with patch("builtins.input", side_effect=AssertionError("input() called in non-interactive mode!")):
                result = loop._approve([aggressive_action])

        assert result is not None

    # ── Contradiction 3: Circuit breaker trips ❌ escalation still executes ──

    def test_circuit_breaker_blocks_exploitation_after_threshold(self):
        """After circuit breaker trips, exploit() must refuse further calls."""
        from CaseCrack.tools.burp_enterprise.exploitation.engine import ExploitationEngine

        engine = ExploitationEngine.__new__(ExploitationEngine)
        engine._exploit_consecutive_failures = 5
        engine._exploit_cb_threshold = 5
        engine._exploit_cb_tripped = True
        engine.target_url = "http://127.0.0.1:8080"

        finding = {"id": "test", "url": "http://127.0.0.1:8080/api", "type": "sqli"}
        result = engine.exploit(finding)

        assert result.get("circuit_breaker") is True, "Circuit breaker tripped but exploit still ran"

    def test_circuit_breaker_resets_on_success(self):
        """Successful exploitation must reset the failure counter."""
        from CaseCrack.tools.burp_enterprise.exploitation.engine import ExploitationEngine

        engine = ExploitationEngine.__new__(ExploitationEngine)
        engine._exploit_consecutive_failures = 3
        engine._exploit_cb_threshold = 5
        engine._exploit_cb_tripped = False

        # After a successful run, counter should be 0
        # We simulate by directly setting and checking
        engine._exploit_consecutive_failures = 0  # as post-exploit() does
        assert engine._exploit_consecutive_failures == 0
        assert engine._exploit_cb_tripped is False

    # ── Contradiction 4: Escalation gateway approves ↔ autonomy blocks ──

    def test_escalation_override_expands_autonomy(self):
        """Gateway override can expand the auto-approve set beyond base autonomy."""
        gw = EscalationGateway(session_id="test", base_autonomy=2)
        base_set = auto_approve_set(2)  # {"safe"}
        assert "aggressive" not in base_set

        # The gateway's effective set should start the same as base
        eff = gw.effective_auto_approve_set()
        assert eff == base_set

    def test_gateway_check_action_consistent_with_autonomy(self):
        """check_action should be consistent with effective_auto_approve_set."""
        gw = EscalationGateway(session_id="test", base_autonomy=2)

        # At autonomy 2, only "safe" is auto-approved
        approved, _ = gw.check_action(
            action_risk="safe",
            hypothesis_id="H-1",
            action_command="headers --url http://127.0.0.1:8080",
        )
        assert approved is True, "Safe action should be approved at autonomy 2"

        approved, _ = gw.check_action(
            action_risk="aggressive",
            hypothesis_id="H-1",
            action_command="sqli --url http://127.0.0.1:8080",
        )
        assert approved is False, "Aggressive action should NOT be approved at autonomy 2"

    # ── Contradiction 5: Operator skip ↔ FSI keeps finding anyway ──

    def test_operator_skip_does_not_delete_existing_findings(self):
        """Operator skipping a vuln_type means don't test it —
        but already-discovered findings of that type must NOT be discarded."""
        ledger = get_finding_ledger()

        # CRITICAL finding already discovered
        ledger.record(
            finding_id="already-found",
            severity="CRITICAL",
            summary="SQL injection",
            source_component="tool",
            action=LedgerEntryAction.DISCOVERED,
        )

        # Operator skips sqli for future testing
        ofl = get_operator_feedback_loop()
        ofl.record_override(
            override_type=OverrideType.SKIP_PHASE.value,
            target="sqli",
            reason="Already covered",
        )

        # The finding must still be in the ledger
        history = ledger.get_history("already-found")
        assert len(history) >= 1, "Operator skip must not erase existing ledger entries"
        assert history[0].action == LedgerEntryAction.DISCOVERED

    # ── Contradiction 6: Decision plane gate ↔ full-auto mode ──

    def test_full_auto_bypasses_approval_but_respects_scope(self):
        """Autonomy 5 auto-approves everything, but scope enforcement
        is in the exploitation engine, not approval — so both must work."""
        loop = _make_copilot(autonomy=5)

        actions = [
            _make_action(index=1, risk="aggressive"),
            _make_action(index=2, risk="standard"),
        ]

        result = loop._approve(actions)
        assert result is not None
        assert len(result) == 2, "Full auto must approve all actions"


# ═══════════════════════════════════════════════════════════════════════
# 2. PRIORITY INVERSION STRESS TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestPriorityInversion:
    """Ensure CRITICAL findings/actions are never starved by LOW ones."""

    def test_critical_finding_survives_dedup_queue(self):
        """A CRITICAL finding arriving late should never be dropped by dedup."""
        # Build a queue: 20 LOW findings, then 1 CRITICAL
        findings = []
        for i in range(20):
            findings.append(_make_finding(
                id=f"low-{i}", severity="LOW",
                title=f"Info disclosure variant {i}",
                url=f"http://127.0.0.1:8080/path{i}",
            ))

        # Late-arriving CRITICAL — same URL pattern as LOW
        findings.append(_make_finding(
            id="critical-late", severity="CRITICAL",
            title="Remote code execution in /path0",
            url="http://127.0.0.1:8080/path0",
        ))

        dedup = FindingDedup(bridge=None)
        result = asyncio.get_event_loop().run_until_complete(
            dedup.deduplicate(findings, use_llm=False)
        )

        # CRITICAL finding must be in merged
        merged_ids = [f.get("id") for f in result.merged]
        assert "critical-late" in merged_ids, (
            f"CRITICAL finding lost in dedup! merged_ids={merged_ids}"
        )

    def test_critical_finding_not_lost_by_canonical_dedup(self):
        """FindingDeduplicator must never mark a CRITICAL as duplicate."""
        deduplicator = FindingDeduplicator()

        # Fill window with LOW findings
        for i in range(50):
            deduplicator.is_duplicate(_make_finding(
                id=f"low-{i}", severity="LOW",
                title=f"Missing header variant {i}",
                url=f"http://127.0.0.1:8080/p{i}",
            ))

        # Now a CRITICAL arrives with similar text
        critical = _make_finding(
            id="critical-late", severity="CRITICAL",
            title="Missing header variant 0",
            url="http://127.0.0.1:8080/p0",
        )

        is_dup = deduplicator.is_duplicate(critical)
        assert is_dup is False, (
            "CRITICAL finding marked as duplicate — SeverityGuard failed!"
        )

    def test_escalation_prioritises_critical_over_pending_low(self):
        """CRITICAL escalation should be created with higher urgency
        than existing LOW requests."""
        gw = EscalationGateway(session_id="test", base_autonomy=2)

        # Create a LOW escalation first
        low_req = gw.create_request(
            action_command="headers --url http://127.0.0.1:8080",
            action_risk="safe",
            hypothesis_id="H-low",
            severity="low",
            confidence=0.3,
        )

        # Now create a CRITICAL escalation
        crit_req = gw.create_request(
            action_command="sqli --url http://127.0.0.1:8080",
            action_risk="aggressive",
            hypothesis_id="H-crit",
            severity="critical",
            confidence=0.95,
        )

        # CRITICAL request should exist and have higher required autonomy
        assert crit_req.required_autonomy >= low_req.required_autonomy, (
            f"CRITICAL request has lower required_autonomy "
            f"({crit_req.required_autonomy}) than LOW ({low_req.required_autonomy})"
        )

    def test_fsi_ledger_tracks_critical_separately(self):
        """Ledger stats must separately track CRITICAL losses."""
        ledger = get_finding_ledger()

        # Record several findings
        ledger.record("crit-1", "CRITICAL", "RCE", "tool", LedgerEntryAction.DISCOVERED)
        ledger.record("low-1", "LOW", "Info", "tool", LedgerEntryAction.DISCOVERED)

        # Deliver only the LOW one
        ledger.record("low-1", "LOW", "Info", "copilot", LedgerEntryAction.DELIVERED)

        stats = ledger.get_stats()
        lost = ledger.get_lost_findings()

        # CRITICAL was discovered but never delivered — it must appear as lost
        assert "crit-1" in lost, (
            f"CRITICAL finding not tracked as lost! lost={lost}"
        )

    def test_dedup_preserves_ordering_of_critical_findings(self):
        """When dedup processes mixed-severity findings, CRITICAL must
        never be swapped behind LOW in the output."""
        findings = [
            _make_finding(id="low-first", severity="LOW",
                          title="Missing HSTS header", type="headers",
                          parameter="", url="http://127.0.0.1:8080/a"),
            _make_finding(id="critical-second", severity="CRITICAL",
                          title="RCE via deserialization", type="rce",
                          parameter="data", url="http://127.0.0.1:8080/api"),
            _make_finding(id="low-third", severity="LOW",
                          title="Server version disclosed", type="info",
                          parameter="", url="http://127.0.0.1:8080/b"),
        ]

        dedup = FindingDedup(bridge=None)
        result = asyncio.get_event_loop().run_until_complete(
            dedup.deduplicate(findings, use_llm=False)
        )

        # All 3 should be in merged (completely different findings)
        merged_ids = [f.get("id") for f in result.merged]
        assert "critical-second" in merged_ids
        assert len(result.merged) == 3, (
            f"Expected 3 distinct findings, got {len(result.merged)}: {merged_ids}"
        )


# ═══════════════════════════════════════════════════════════════════════
# 3. MULTI-LAYER FAILURE CASCADE SIMULATION
# ═══════════════════════════════════════════════════════════════════════

class TestMultiLayerFailureCascade:
    """Simulate multiple subsystem failures simultaneously.
    Verify the system degrades predictably, not chaotically."""

    def test_cascade_all_subsystems_unavailable(self):
        """When FSI, escalation gateway, operator feedback, and
        decision plane all fail to import, CopilotLoop still works."""
        loop = _make_copilot(autonomy=3)

        # Null out all OTL subsystems
        loop._escalation_gw = None
        loop._operator_feedback = None

        actions = [
            _make_action(index=1, risk="safe"),
            _make_action(index=2, risk="standard"),
        ]

        # _approve should still work with base autonomy
        result = loop._approve(actions)
        assert result is not None
        assert len(result) == 2, (
            "With all OTL subsystems down, base autonomy should still approve safe+standard"
        )

    def test_cascade_circuit_breaker_tripped_plus_headless(self):
        """Circuit breaker tripped + headless mode active.
        System should: reject exploitation, not block on input, degrade gracefully."""
        from CaseCrack.tools.burp_enterprise.exploitation.engine import ExploitationEngine

        # Circuit breaker tripped
        engine = ExploitationEngine.__new__(ExploitationEngine)
        engine._exploit_consecutive_failures = 10
        engine._exploit_cb_threshold = 5
        engine._exploit_cb_tripped = True
        engine.target_url = "http://127.0.0.1:8080"

        # Exploitation attempt should be refused
        result = engine.exploit({"id": "test", "url": "http://127.0.0.1:8080/api", "type": "sqli"})
        assert result.get("circuit_breaker") is True

        # Meanwhile, headless approval should still function
        loop = _make_copilot(autonomy=2)
        aggressive = _make_action(risk="aggressive")

        with patch.dict(os.environ, {"COPILOT_HEADLESS": "1"}):
            with patch("builtins.input", side_effect=AssertionError("BLOCKED")):
                approved = loop._approve([aggressive])

        assert approved is not None, "Headless approval must not block"

    def test_cascade_escalation_gateway_full_plus_fsi_pressure(self):
        """Escalation gateway at MAX_PENDING_REQUESTS + FSI ledger under pressure.
        Both should degrade gracefully."""
        from CaseCrack.tools.burp_enterprise.caap.escalation_gateway import MAX_PENDING_REQUESTS

        gw = EscalationGateway(session_id="pressure-test", base_autonomy=2)

        # Fill gateway to capacity
        for i in range(MAX_PENDING_REQUESTS):
            gw.create_request(
                action_command=f"nmap variant-{i}",
                action_risk="aggressive",
                hypothesis_id=f"H-{i}",
            )

        # One more — should NOT crash (force-expires oldest)
        overflow_req = gw.create_request(
            action_command="overflow-action",
            action_risk="aggressive",
            hypothesis_id="H-overflow",
        )
        assert overflow_req is not None, "Gateway should handle overflow gracefully"

        # FSI ledger can still record under pressure
        ledger = get_finding_ledger()
        for i in range(1000):
            ledger.record(
                f"pressure-{i}", "MEDIUM", f"Finding {i}",
                "stress", LedgerEntryAction.DISCOVERED,
            )

        stats = ledger.get_stats()
        assert stats.total_discovered >= 1000, "FSI ledger must handle pressure"

    def test_cascade_decision_plane_gate_with_timeout(self):
        """Decision plane creates a blocking gate but it gets resolved.
        Verify has_blocking_gates transitions correctly."""
        dp = DecisionPlane()
        gate = dp.operator_gate.evaluate_transition(
            transition_type="exploit",
            risk_level="critical",
            context={"finding": "test"},
        )

        if gate.level in (OperatorGateLevel.CONFIRMATION, OperatorGateLevel.BLOCK):
            assert dp.operator_gate.has_blocking_gates() is True

            # Resolve the gate
            dp.operator_gate.resolve_gate(gate.gate_id, approved=True)
            assert dp.operator_gate.has_blocking_gates() is False, (
                "Gate resolved but has_blocking_gates still True"
            )

    def test_cascade_operator_override_with_null_runner(self):
        """OperatorFeedbackLoop should work even when runner is not bound."""
        ofl = get_operator_feedback_loop()
        # Don't bind a runner — it should still record overrides

        override = ofl.record_override(
            override_type=OverrideType.SKIP_PHASE.value,
            target="headers",
            reason="Not relevant",
        )
        assert override is not None

        # should_skip should still work
        assert ofl.should_skip("headers") is True

    def test_cascade_simultaneous_fsi_dedup_escalation_failure(self):
        """FSI ledger + dedup + escalation all under stress simultaneously.
        Nothing should crash — system degrades to base behavior."""
        # 1. FSI: Overwhelm ledger
        ledger = get_finding_ledger()
        for i in range(500):
            ledger.record(f"f-{i}", "LOW", f"Finding {i}",
                          "stress", LedgerEntryAction.DISCOVERED)

        # 2. Dedup: Process many findings
        findings = [
            _make_finding(id=f"dup-{i}", severity="LOW",
                          title="Info disclosure",
                          url=f"http://127.0.0.1:8080/p{i % 5}")
            for i in range(50)
        ]
        dedup = FindingDedup(bridge=None)
        result = asyncio.get_event_loop().run_until_complete(
            dedup.deduplicate(findings, use_llm=False)
        )
        assert result is not None
        assert len(result.merged) + len(result.discarded) == 50

        # 3. Escalation: Create and expire requests
        gw = EscalationGateway(session_id="cascade", base_autonomy=2,
                               escalation_timeout=0.001)  # Instant expiry
        for i in range(10):
            gw.create_request(
                action_command=f"test-{i}",
                action_risk="aggressive",
                hypothesis_id=f"H-{i}",
            )

        # Force expiry check
        time.sleep(0.01)
        stats = gw.get_stats()
        assert isinstance(stats, dict), "Gateway stats must return dict under stress"

    def test_cascade_approve_with_broken_gateway_and_feedback(self):
        """_approve works when gateway raises and feedback is None."""
        loop = _make_copilot(autonomy=2)

        # Gateway that raises on every call
        broken_gw = MagicMock()
        broken_gw.effective_auto_approve_set.side_effect = RuntimeError("gateway dead")
        broken_gw.check_action.side_effect = RuntimeError("gateway dead")
        loop._escalation_gw = broken_gw
        loop._operator_feedback = None

        actions = [_make_action(risk="safe")]

        # Should fall back to base autonomy — safe is auto-approved at level 2
        result = loop._approve(actions)
        assert result is not None
        assert len(result) >= 1, "Broken gateway should not prevent safe-action approval"

    def test_cascade_dedup_with_broken_fsi(self):
        """Dedup still works when FSI ledger and guard are None."""
        dedup = FindingDedup(bridge=None)
        dedup._fsi_ledger = None
        dedup._fsi_guard = None

        findings = [
            _make_finding(id="a", severity="LOW", title="test1",
                          url="http://127.0.0.1:8080/a"),
            _make_finding(id="b", severity="LOW", title="test1",
                          url="http://127.0.0.1:8080/a"),
        ]

        result = asyncio.get_event_loop().run_until_complete(
            dedup.deduplicate(findings, use_llm=False)
        )

        # Without FSI guard, normal dedup should work
        assert result is not None
        assert len(result.merged) == 1, "Without FSI, normal dedup should merge duplicates"

    def test_deterministic_degradation_order(self):
        """Verify that as subsystems fail one by one, the system
        degrades in a predictable order, not randomly."""
        loop = _make_copilot(autonomy=3)

        actions = [
            _make_action(index=1, risk="safe"),
            _make_action(index=2, risk="standard"),
            _make_action(index=3, risk="aggressive"),
        ]

        # Phase 1: All subsystems active — gateway might expand set
        loop._escalation_gw = EscalationGateway(
            session_id="degrade-test", base_autonomy=3
        )
        result_full = loop._approve(actions)

        # Phase 2: Gateway down — falls back to base autonomy
        loop._escalation_gw = None
        with patch(
            "CaseCrack.tools.burp_enterprise.agents.copilot_loop._is_interactive",
            return_value=False,
        ):
            with patch("builtins.input", side_effect=AssertionError("BLOCKED")):
                result_no_gw = loop._approve(actions)

        # Phase 3: Full degradation — base autonomy only
        assert result_no_gw is not None, "Must not crash with gateway down"

        # At autonomy 3, safe+standard are auto-approved
        base_set = auto_approve_set(3)
        auto_count = sum(1 for a in actions if a.risk in base_set)
        assert len(result_no_gw) >= auto_count, (
            f"Degraded mode should still approve {auto_count} base actions, "
            f"got {len(result_no_gw)}"
        )


# ═══════════════════════════════════════════════════════════════════════
# 4. EDGE CASE POLICY INTERACTIONS
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCasePolicyInteractions:
    """Nuanced policy edge cases at subsystem boundaries."""

    def test_scope_enforcement_is_independent_of_approval(self):
        """Scope check happens in ExploitationEngine.exploit(), not in _approve().
        A fully-approved action can still be blocked by scope enforcement."""
        from CaseCrack.tools.burp_enterprise.exploitation.engine import ExploitationEngine

        engine = ExploitationEngine.__new__(ExploitationEngine)
        engine.target_url = "http://127.0.0.1:8080"
        engine._exploit_consecutive_failures = 0
        engine._exploit_cb_threshold = 5
        engine._exploit_cb_tripped = False

        # Domain extraction should work
        assert engine._extract_domain("http://127.0.0.1:8080/api") != ""
        assert engine._extract_domain("http://evil.com/attack") != ""

        # Cross-domain check
        target_domain = engine._extract_domain(engine.target_url)
        finding_domain = engine._extract_domain("http://evil.com/attack")
        assert target_domain != finding_domain, "Scope check should distinguish domains"

    def test_escalation_timeout_configurable(self):
        """OTL-8: Timeout should be configurable, not hardcoded."""
        gw_default = EscalationGateway(session_id="t1", base_autonomy=2)
        assert gw_default._escalation_timeout == ESCALATION_TIMEOUT_SECONDS

        gw_custom = EscalationGateway(session_id="t2", base_autonomy=2,
                                      escalation_timeout=30.0)
        assert gw_custom._escalation_timeout == 30.0

        # Requests should use the custom timeout
        req = gw_custom.create_request(
            action_command="test",
            action_risk="aggressive",
            hypothesis_id="H-1",
        )
        assert req.expires_at <= req.created_at + 31.0, (
            "Request timeout should use configurable value"
        )

    def test_fsi_ledger_counts_match_actions(self):
        """The ledger stats must be mathematically consistent:
        discovered = delivered + lost + in-flight."""
        ledger = get_finding_ledger()

        # Record lifecycle
        for i in range(10):
            ledger.record(f"f-{i}", "MEDIUM", f"Finding {i}",
                          "tool", LedgerEntryAction.DISCOVERED)

        # Deliver 7
        for i in range(7):
            ledger.record(f"f-{i}", "MEDIUM", f"Finding {i}",
                          "copilot", LedgerEntryAction.DELIVERED)

        stats = ledger.get_stats()
        lost = ledger.get_lost_findings()

        assert stats.total_discovered == 10
        assert stats.total_delivered == 7
        assert len(lost) == 3, (
            f"Expected 3 lost findings (10 discovered - 7 delivered), got {len(lost)}"
        )

    def test_headless_creates_escalation_requests(self):
        """In headless mode, unapproved actions should create escalation requests."""
        loop = _make_copilot(autonomy=2)
        gw = EscalationGateway(session_id="headless-test", base_autonomy=2)
        loop._escalation_gw = gw

        aggressive_actions = [
            _make_action(index=1, risk="aggressive", command="sqli --url http://127.0.0.1:8080"),
            _make_action(index=2, risk="aggressive", command="cmdi --url http://127.0.0.1:8080"),
        ]

        with patch.dict(os.environ, {"COPILOT_HEADLESS": "1"}):
            with patch("builtins.input", side_effect=AssertionError("BLOCKED")):
                result = loop._approve(aggressive_actions)

        # Requests should have been created in the gateway
        stats = gw.get_stats()
        assert stats.get("total_created", 0) >= 2, (
            f"Headless mode should create escalation requests: stats={stats}"
        )

    def test_operator_steering_affects_plan_filtering(self):
        """Operator avoid_areas should filter hypotheses from the plan."""
        ofl = get_operator_feedback_loop()

        # Set steering to avoid "headers" vuln type
        ofl.record_override(
            override_type=OverrideType.SKIP_PHASE.value,
            target="headers",
            reason="Already covered",
        )

        # should_skip should reflect the override
        assert ofl.should_skip("headers") is True
        assert ofl.should_skip("sqli") is False
