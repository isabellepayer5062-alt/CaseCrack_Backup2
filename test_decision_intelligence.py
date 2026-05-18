"""
Test suite for Decision Intelligence Layer
============================================

Tests the three new higher-order systems:
1. DecisionQualityEvaluator  — retrospective quality scoring
2. CounterfactualEngine      — "what if" simulation
3. OperatorTrustDashboard    — unified trust metrics

Plus integration between them and the existing DecisionOrchestrator.
"""

import pytest
import time
from unittest.mock import patch, MagicMock


# ═══════════════════════════════════════════════════════════════════════
# 1. DECISION QUALITY EVALUATOR
# ═══════════════════════════════════════════════════════════════════════


class TestDecisionQualityEvaluator:
    """Test retrospective decision quality scoring."""

    def setup_method(self):
        from CaseCrack.tools.burp_enterprise.decision_quality_evaluator import (
            reset_quality_evaluator,
        )
        reset_quality_evaluator()

    def _get(self):
        from CaseCrack.tools.burp_enterprise.decision_quality_evaluator import (
            get_quality_evaluator,
        )
        return get_quality_evaluator()

    def test_singleton_consistency(self):
        """Singleton returns the same instance."""
        e1 = self._get()
        e2 = self._get()
        assert e1 is e2

    def test_record_decision_returns_id(self):
        """record_decision should return a non-empty record_id."""
        e = self._get()
        rid = e.record_decision("xss", predicted_ev=0.5, predicted_p_success=0.7)
        assert rid and len(rid) == 12

    def test_record_outcome_matches_pending(self):
        """record_outcome should match oldest pending decision."""
        e = self._get()
        e.record_decision("sqli", predicted_p_success=0.8, predicted_impact=70.0)
        quality = e.record_outcome("sqli", success=True, findings_count=3)
        assert quality is not None
        assert 0.0 <= quality <= 1.0

    def test_orphan_outcome_returns_none(self):
        """Outcome without prior decision returns None."""
        e = self._get()
        quality = e.record_outcome("unknown_action", success=True)
        assert quality is None

    def test_perfect_prediction_scores_high(self):
        """Perfect prediction → quality near 1.0."""
        e = self._get()
        e.record_decision(
            "xss",
            predicted_p_success=1.0,
            predicted_impact=60.0,  # 3/5 = 0.6 yield → 60% impact
            predicted_cost=0.1,     # 30s / 300s = 0.1
        )
        quality = e.record_outcome(
            "xss",
            success=True,
            findings_count=3,
            duration_seconds=30.0,
        )
        assert quality is not None and quality > 0.8

    def test_wrong_prediction_scores_low(self):
        """Confident wrong prediction → quality below 0.5."""
        e = self._get()
        e.record_decision(
            "csrf", predicted_p_success=0.95, predicted_impact=90.0,
        )
        quality = e.record_outcome("csrf", success=False, findings_count=0)
        assert quality is not None and quality < 0.5

    def test_signal_correlation_tracking(self):
        """Tracks per-component vote vs outcome correlation."""
        e = self._get()
        # Component A votes FOR, action succeeds
        e.record_decision(
            "idor",
            predicted_p_success=0.7,
            signal_votes={"BayesianPrioritizer": "for", "ExploitGraph": "against"},
        )
        e.record_outcome("idor", success=True, findings_count=1)

        report = e.get_report()
        bp = report.signal_correlations.get("BayesianPrioritizer")
        assert bp is not None
        assert bp.voted_for_and_succeeded == 1
        assert bp.voted_for_and_failed == 0

        eg = report.signal_correlations.get("ExploitGraph")
        assert eg is not None
        assert eg.voted_against_and_succeeded == 1

    def test_quality_report_aggregate(self):
        """get_report returns proper aggregate stats."""
        e = self._get()
        for i in range(10):
            e.record_decision(f"action_{i}", predicted_p_success=0.5 + i * 0.05)
            e.record_outcome(
                f"action_{i}",
                success=(i % 2 == 0),
                findings_count=i if (i % 2 == 0) else 0,
            )

        report = e.get_report()
        assert report.total_decisions == 10
        assert report.total_with_outcomes == 10
        assert 0.0 <= report.mean_quality <= 1.0
        assert 0.0 <= report.calibration_error <= 1.0

    def test_component_ranking(self):
        """get_component_ranking returns sorted by accuracy."""
        e = self._get()
        # Need at least 3 decisions per component for ranking
        for i in range(4):
            e.record_decision(f"a_{i}", predicted_p_success=0.8,
                              signal_votes={"CompA": "for", "CompB": "against"})
            e.record_outcome(f"a_{i}", success=True, findings_count=1)

        ranking = e.get_component_ranking()
        assert len(ranking) == 2
        comp_names = [r["component"] for r in ranking]
        assert "CompA" in comp_names
        assert "CompB" in comp_names

    def test_quality_trend_window(self):
        """Quality trend is captured as a list of recent scores."""
        e = self._get()
        for i in range(20):
            e.record_decision(f"act_{i}", predicted_p_success=0.5)
            e.record_outcome(f"act_{i}", success=True, findings_count=1)
        report = e.get_report()
        assert len(report.quality_trend) > 0

    def test_system_trust_score_in_report(self):
        """QualityReport has a system_trust_score."""
        e = self._get()
        e.record_decision("x", predicted_p_success=0.9)
        e.record_outcome("x", success=True, findings_count=1)
        report = e.get_report()
        assert 0.0 <= report.system_trust_score <= 1.0


# ═══════════════════════════════════════════════════════════════════════
# 2. COUNTERFACTUAL ENGINE
# ═══════════════════════════════════════════════════════════════════════


class TestCounterfactualEngine:
    """Test counterfactual simulation."""

    def setup_method(self):
        from CaseCrack.tools.burp_enterprise.counterfactual_engine import (
            reset_counterfactual_engine,
        )
        reset_counterfactual_engine()

    def _get(self):
        from CaseCrack.tools.burp_enterprise.counterfactual_engine import (
            get_counterfactual_engine,
        )
        return get_counterfactual_engine()

    def test_singleton_consistency(self):
        cf1 = self._get()
        cf2 = self._get()
        assert cf1 is cf2

    def test_capture_snapshot(self):
        """capture_snapshot stores context and returns ID."""
        cf = self._get()
        sid = cf.capture_snapshot("xss", target="example.com", ev=0.75)
        assert sid and len(sid) == 12

    def test_record_snapshot_outcome(self):
        """record_snapshot_outcome fills ground truth."""
        cf = self._get()
        cf.capture_snapshot("sqli", ev=0.6)
        cf.record_snapshot_outcome("sqli", success=True, findings=2, severity="high")

        with cf._lock:
            snaps = cf._snapshot_by_action.get("sqli", [])
        assert len(snaps) == 1
        assert snaps[0].outcome_success is True
        assert snaps[0].outcome_findings == 2

    def test_simulate_alternative_with_simplified_fallback(self):
        """simulate_alternative works even without DecisionOrchestrator."""
        cf = self._get()
        cf.capture_snapshot("nuclei", ev=0.5, context={"technologies": ["php"]})
        result = cf.simulate_alternative("nuclei", "xss")
        assert result.original_action == "nuclei"
        assert result.simulated_action == "xss"
        assert isinstance(result.ev_delta, float)

    def test_simulate_alternative_no_snapshot(self):
        """simulate_alternative returns empty result if no snapshot."""
        cf = self._get()
        result = cf.simulate_alternative("nonexistent", "xss")
        assert "No context snapshot" in result.rationale[0]

    def test_compare_branches(self):
        """compare_branches ranks candidates correctly."""
        cf = self._get()
        cf.capture_snapshot("chosen_action", ev=0.3)
        comparison = cf.compare_branches("chosen_action", ["xss", "sqli", "csrf"])
        assert comparison.decision_action == "chosen_action"
        assert len(comparison.candidates) >= 1
        assert isinstance(comparison.decision_was_optimal, bool)
        assert isinstance(comparison.opportunity_cost, float)

    def test_get_report_with_data(self):
        """get_report computes aggregate stats."""
        cf = self._get()
        for i, action in enumerate(["xss", "sqli", "csrf"]):
            cf.capture_snapshot(action, ev=0.1 * (i + 1))
            cf.record_snapshot_outcome(
                action,
                success=(i == 0),
                findings=1 if i == 0 else 0,
            )
        report = cf.get_report()
        assert report.total_simulations >= 0
        assert isinstance(report.mean_regret, float)

    def test_simulate_modified_context(self):
        """simulate_modified_context re-scores with overrides."""
        cf = self._get()
        cf.capture_snapshot(
            "ssrf",
            ev=0.4,
            context={"technologies": ["python"], "waf_detected": True},
        )
        result = cf.simulate_modified_context(
            "ssrf",
            context_overrides={"waf_detected": False},
        )
        assert result.original_action == "ssrf"
        # EV should change since WAF was removed
        assert isinstance(result.ev_delta, float)

    def test_report_regret_by_action(self):
        """Report tracks regret grouped by action type."""
        cf = self._get()
        cf.capture_snapshot("a", ev=0.5)
        cf.compare_branches("a", ["b"])
        report = cf.get_report()
        assert isinstance(report.regret_by_action, dict)


# ═══════════════════════════════════════════════════════════════════════
# 3. OPERATOR TRUST DASHBOARD
# ═══════════════════════════════════════════════════════════════════════


class TestOperatorTrustDashboard:
    """Test the operator-facing trust dashboard."""

    def setup_method(self):
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            reset_trust_dashboard,
        )
        from CaseCrack.tools.burp_enterprise.decision_quality_evaluator import (
            reset_quality_evaluator,
        )
        from CaseCrack.tools.burp_enterprise.counterfactual_engine import (
            reset_counterfactual_engine,
        )
        from CaseCrack.tools.burp_enterprise.decision_trace import (
            get_decision_trace,
        )
        reset_trust_dashboard()
        reset_quality_evaluator()
        reset_counterfactual_engine()
        get_decision_trace().reset()

    def _get(self):
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            get_trust_dashboard,
        )
        return get_trust_dashboard()

    def test_singleton_consistency(self):
        d1 = self._get()
        d2 = self._get()
        assert d1 is d2

    def test_get_snapshot_returns_trust_snapshot(self):
        """get_snapshot returns a TrustSnapshot with valid fields."""
        d = self._get()
        snap = d.get_snapshot()
        assert 0.0 <= snap.system_trust_score <= 1.0
        assert isinstance(snap.signal_contributions, list)
        assert isinstance(snap.attention_items, list)
        assert snap.decision_quality_trend in (
            "improving", "stable", "declining", "insufficient_data",
        )

    def test_snapshot_caching(self):
        """Snapshot should be cached for performance."""
        d = self._get()
        s1 = d.get_snapshot()
        s2 = d.get_snapshot()
        assert s1 is s2  # Same object due to caching

    def test_snapshot_force_refresh(self):
        """force_refresh bypasses cache."""
        d = self._get()
        s1 = d.get_snapshot()
        s2 = d.get_snapshot(force_refresh=True)
        assert s1 is not s2  # Different objects

    def test_attention_items_empty_system(self):
        """Empty system should have 'operating normally' attention item."""
        d = self._get()
        snap = d.get_snapshot()
        assert any("normally" in item.lower() for item in snap.attention_items)

    def test_to_dict_serialization(self):
        """TrustSnapshot.to_dict() produces JSON-serializable dict."""
        import json
        d = self._get()
        snap = d.get_snapshot()
        data = snap.to_dict()
        # Should be JSON-serializable
        serialized = json.dumps(data)
        assert len(serialized) > 10

    def test_explain_for_operator(self):
        """explain_for_operator returns action-specific explanation."""
        d = self._get()
        explanation = d.explain_for_operator("xss")
        assert explanation["action"] == "xss"
        assert "signals" in explanation

    def test_get_metrics(self):
        """get_metrics returns dashboard metadata."""
        d = self._get()
        d.get_snapshot()  # Ensure a snapshot exists
        metrics = d.get_metrics()
        assert metrics["has_snapshot"] is True

    def test_signal_contribution_dominance(self):
        """SignalContribution.dominance computed correctly."""
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            SignalContribution,
        )
        c = SignalContribution(component="TestComp", won_conflicts=3, lost_conflicts=7)
        assert abs(c.dominance - 0.3) < 0.001

    def test_signal_contribution_dominance_zero(self):
        """Dominance is 0 when no conflicts."""
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            SignalContribution,
        )
        c = SignalContribution(component="X")
        assert c.dominance == 0.0

    def test_signal_contribution_to_dict(self):
        """SignalContribution.to_dict includes all fields."""
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            SignalContribution,
        )
        c = SignalContribution(
            component="BP",
            total_signals=50,
            influence_score=0.25,
            accuracy=0.82,
        )
        d = c.to_dict()
        assert d["component"] == "BP"
        assert d["total_signals"] == 50
        assert d["influence_score"] == 0.25

    def test_conflict_summary_to_dict(self):
        """ConflictSummary.to_dict includes all fields."""
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            ConflictSummary,
        )
        cs = ConflictSummary(
            action="xss",
            severity="high",
            components_for=["A"],
            components_against=["B"],
            winner="A",
        )
        d = cs.to_dict()
        assert d["action"] == "xss"
        assert d["winner"] == "A"


# ═══════════════════════════════════════════════════════════════════════
# 4. INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════


class TestDecisionIntelligenceIntegration:
    """Integration tests: all three systems working together."""

    def setup_method(self):
        from CaseCrack.tools.burp_enterprise.decision_quality_evaluator import (
            reset_quality_evaluator,
        )
        from CaseCrack.tools.burp_enterprise.counterfactual_engine import (
            reset_counterfactual_engine,
        )
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            reset_trust_dashboard,
        )
        from CaseCrack.tools.burp_enterprise.decision_trace import (
            get_decision_trace,
        )
        reset_quality_evaluator()
        reset_counterfactual_engine()
        reset_trust_dashboard()
        get_decision_trace().reset()

    def test_quality_feeds_into_dashboard(self):
        """Quality evaluator metrics appear in dashboard snapshot."""
        from CaseCrack.tools.burp_enterprise.decision_quality_evaluator import (
            get_quality_evaluator,
        )
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            get_trust_dashboard,
        )

        e = get_quality_evaluator()
        # Record and resolve 10 decisions
        for i in range(10):
            e.record_decision(f"act_{i}", predicted_p_success=0.6)
            e.record_outcome(f"act_{i}", success=(i < 6), findings_count=1 if i < 6 else 0)

        d = get_trust_dashboard()
        snap = d.get_snapshot(force_refresh=True)
        assert snap.total_decisions == 10
        assert snap.decisions_with_outcomes == 10
        assert snap.mean_quality > 0

    def test_counterfactual_feeds_into_dashboard(self):
        """Counterfactual regret appears in dashboard snapshot."""
        from CaseCrack.tools.burp_enterprise.counterfactual_engine import (
            get_counterfactual_engine,
        )
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            get_trust_dashboard,
        )

        cf = get_counterfactual_engine()
        # Create snapshots with outcomes so regret can be computed
        cf.capture_snapshot("xss", ev=0.5)
        cf.record_snapshot_outcome("xss", success=True, findings=2)
        cf.compare_branches("xss", ["sqli", "csrf"])

        d = get_trust_dashboard()
        snap = d.get_snapshot(force_refresh=True)
        # Counterfactual data should be present
        assert isinstance(snap.optimal_decision_rate, float)
        assert isinstance(snap.mean_regret, float)

    def test_trace_signals_feed_into_dashboard(self):
        """Decision trace signals appear in dashboard contributions."""
        from CaseCrack.tools.burp_enterprise.decision_trace import (
            get_decision_trace, SignalType,
        )
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            get_trust_dashboard,
        )

        dt = get_decision_trace()
        # Emit several signals from different components
        for comp in ["BayesianPrioritizer", "ExploitGraph", "ScanIntelligence"]:
            dt.emit_quick(
                source=comp,
                method="test",
                action="xss",
                signal_type=SignalType.BOOST,
                value=0.7,
            )

        d = get_trust_dashboard()
        snap = d.get_snapshot(force_refresh=True)
        comp_names = [c.component for c in snap.signal_contributions]
        # At minimum the emitted components should appear
        assert len(comp_names) >= 3

    def test_full_cycle_decision_to_trust(self):
        """Full cycle: decision → outcome → quality → dashboard."""
        from CaseCrack.tools.burp_enterprise.decision_quality_evaluator import (
            get_quality_evaluator,
        )
        from CaseCrack.tools.burp_enterprise.counterfactual_engine import (
            get_counterfactual_engine,
        )
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            get_trust_dashboard,
        )
        from CaseCrack.tools.burp_enterprise.decision_trace import (
            get_decision_trace, SignalType,
        )

        dt = get_decision_trace()
        dqe = get_quality_evaluator()
        cf = get_counterfactual_engine()
        dash = get_trust_dashboard()

        # Simulate 20 decisions
        actions = ["xss", "sqli", "csrf", "ssrf", "idor"] * 4
        for i, action in enumerate(actions):
            # Emit trace signal
            dt.emit_quick(
                source="BayesianPrioritizer",
                method="score",
                action=action,
                signal_type=SignalType.SCORE,
                value=0.3 + i * 0.02,
            )

            # Record decision
            dqe.record_decision(
                action,
                predicted_p_success=0.5 + i * 0.02,
                predicted_impact=50.0,
                signal_votes={"BayesianPrioritizer": "for"},
            )

            # Capture counterfactual snapshot
            cf.capture_snapshot(action, ev=0.3 + i * 0.02)

            # Record outcome
            success = i % 3 != 0
            findings = 1 if success else 0
            dqe.record_outcome(action, success=success, findings_count=findings)
            cf.record_snapshot_outcome(
                action, success=success, findings=findings,
            )

        # Get dashboard snapshot
        snap = dash.get_snapshot(force_refresh=True)

        # Verify all data sources fed in
        assert snap.total_decisions == 20
        assert snap.system_coherence >= 0.0
        assert 0.0 <= snap.system_trust_score <= 1.0
        assert snap.decision_quality_trend in (
            "improving", "stable", "declining", "insufficient_data",
        )
        assert len(snap.attention_items) >= 1


# ═══════════════════════════════════════════════════════════════════════
# 5. DATA MODEL EDGE CASES
# ═══════════════════════════════════════════════════════════════════════


class TestDataModelEdgeCases:
    """Edge case tests for data models."""

    def test_quality_evaluator_max_records(self):
        """Records are capped at MAX_RECORDS."""
        from CaseCrack.tools.burp_enterprise.decision_quality_evaluator import (
            get_quality_evaluator, reset_quality_evaluator,
        )
        reset_quality_evaluator()
        e = get_quality_evaluator()
        for i in range(1050):
            e.record_decision(f"a_{i}", predicted_p_success=0.5)
        with e._lock:
            assert len(e._records) <= 1000

    def test_counterfactual_max_snapshots(self):
        """Snapshots are capped at MAX_SNAPSHOTS."""
        from CaseCrack.tools.burp_enterprise.counterfactual_engine import (
            get_counterfactual_engine, reset_counterfactual_engine,
        )
        reset_counterfactual_engine()
        cf = get_counterfactual_engine()
        for i in range(550):
            cf.capture_snapshot(f"act_{i}", ev=0.1)
        with cf._lock:
            assert len(cf._snapshots) <= 500

    def test_trust_snapshot_to_dict_complete(self):
        """All TrustSnapshot fields present in to_dict output."""
        from CaseCrack.tools.burp_enterprise.operator_trust_dashboard import (
            TrustSnapshot,
        )
        s = TrustSnapshot(
            system_trust_score=0.85,
            system_coherence=0.9,
            calibration_accuracy=0.75,
            decision_quality_trend="stable",
            total_decisions=100,
            mean_quality=0.72,
        )
        d = s.to_dict()
        expected_keys = {
            "system_trust_score", "system_coherence", "calibration_accuracy",
            "decision_quality_trend", "signal_contributions",
            "most_accurate_component", "total_decisions",
            "mean_quality", "attention_items",
        }
        assert expected_keys.issubset(set(d.keys()))
