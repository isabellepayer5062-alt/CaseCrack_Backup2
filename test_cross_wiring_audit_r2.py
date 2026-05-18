"""
Cross-Module Wiring Audit Round 2 — Verifies fixes L2, L3, M2, N3, O1, O2.

Tests that previously disconnected modules are now properly wired:
  L2: chain_executor → DecisionOrchestrator outcome feedback
  L3: exploit_persistence_engine → exploit_graph push on success
  M2: unified_arbitration debate verdict → DO record_outcome
  N3: reasoning_engine ↔ agent_memory episodic recall in hypothesize()
  O1: correlation engine wired into full_scan_orchestrator post-scan
  O2: notification dispatch wired to scan completion events
"""

from __future__ import annotations

import os
import sys
import textwrap
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CaseCrack"))

BE = "CaseCrack.tools.burp_enterprise"


# ═══════════════════════════════════════════════════════════════════════
# L2: chain_executor._record_chain_outcome() feeds DecisionOrchestrator
# ═══════════════════════════════════════════════════════════════════════

class TestL2_ChainExecutorDOFeedback:
    """Verify chain_executor pushes outcomes to DecisionOrchestrator."""

    def test_record_chain_outcome_method_exists(self):
        """_record_chain_outcome must exist on ChainVerifier."""
        from CaseCrack.tools.burp_enterprise.exploit_chains.chain_executor import (
            ChainVerifier,
        )
        assert hasattr(ChainVerifier, "_record_chain_outcome"), (
            "ChainVerifier missing _record_chain_outcome method"
        )

    def test_record_chain_outcome_calls_do(self):
        """_record_chain_outcome should call decision_orchestrator.record_outcome."""
        from CaseCrack.tools.burp_enterprise.exploit_chains.chain_executor import (
            ChainVerifier,
        )

        mock_do = MagicMock()
        mock_do.record_outcome = MagicMock()

        result = SimpleNamespace(
            title="XSS chain",
            severity="high",
            status=SimpleNamespace(value="confirmed"),
            max_severity="high",
            duration_ms=1500,
        )

        # The method does `from ..decision_orchestrator import get_decision_orchestrator`
        # which resolves to the top-level module function.
        import CaseCrack.tools.burp_enterprise.decision_orchestrator as do_mod
        with patch.object(
            do_mod, "get_decision_orchestrator",
            return_value=mock_do,
        ):
            ce = ChainVerifier.__new__(ChainVerifier)
            ce._record_chain_outcome(result, confirmed=2, total=3)

        mock_do.record_outcome.assert_called_once()
        kwargs = mock_do.record_outcome.call_args
        assert "chain:" in str(kwargs)


# ═══════════════════════════════════════════════════════════════════════
# L3: exploit_persistence_engine → exploit_graph push on success
# ═══════════════════════════════════════════════════════════════════════

class TestL3_ExploitPersistenceGraphPush:
    """Verify exploit persistence results feed exploit_graph on success."""

    def test_push_to_exploit_graph_method_exists(self):
        """_push_to_exploit_graph must exist on ExploitPersistenceEngine."""
        from CaseCrack.tools.burp_enterprise.recon_dashboard.exploit_persistence_engine import (
            ExploitPersistenceEngine,
        )
        assert hasattr(ExploitPersistenceEngine, "_push_to_exploit_graph"), (
            "ExploitPersistenceEngine missing _push_to_exploit_graph"
        )

    def test_push_calls_exploit_graph_engine(self):
        """Success results should be forwarded to exploit_graph.process_finding."""
        from CaseCrack.tools.burp_enterprise.recon_dashboard.exploit_persistence_engine import (
            ExploitPersistenceEngine,
        )

        mock_graph = MagicMock()
        mock_graph.process_finding = MagicMock(return_value=[])

        result = SimpleNamespace(
            final_outcome=SimpleNamespace(value="success"),
            evidence=["proof1"],
        )

        with patch(
            f"{BE}.exploit_chains.exploit_graph.get_exploit_graph_engine",
            return_value=mock_graph,
        ):
            epe = ExploitPersistenceEngine.__new__(ExploitPersistenceEngine)
            epe._push_to_exploit_graph(result, vuln_type="sqli", endpoint="/login")

        mock_graph.process_finding.assert_called_once()
        finding_arg = mock_graph.process_finding.call_args[0][0]
        assert isinstance(finding_arg, dict)
        assert finding_arg["finding_type"] == "sqli"


# ═══════════════════════════════════════════════════════════════════════
# M2: unified_arbitration debate verdict → DO outcome
# ═══════════════════════════════════════════════════════════════════════

class TestM2_DebateVerdictDOFeedback:
    """Verify debate verdicts in unified_arbitration feed DO."""

    def test_debate_outcome_block_in_source(self):
        """The M2 fix code should be present in unified_arbitration.py."""
        import inspect
        from CaseCrack.tools.burp_enterprise.agents import unified_arbitration

        src = inspect.getsource(unified_arbitration)
        assert "M2-FIX" in src, "M2 fix marker not found in unified_arbitration"
        assert "record_outcome" in src, "record_outcome call not found"
        assert "debate:" in src, "debate: action prefix not found"


# ═══════════════════════════════════════════════════════════════════════
# N3: reasoning_engine ↔ agent_memory episodic recall
# ═══════════════════════════════════════════════════════════════════════

class TestN3_ReasoningMemoryIntegration:
    """Verify reasoning engine queries agent memory during hypothesize()."""

    def test_set_agent_memory_wires_memory(self):
        """set_agent_memory should store the memory reference."""
        from CaseCrack.tools.burp_enterprise.agents.reasoning_engine import (
            ReasoningEngine,
        )

        re = ReasoningEngine.__new__(ReasoningEngine)
        re._agent_memory = None
        mock_mem = MagicMock()
        re.set_agent_memory(mock_mem)
        assert re._agent_memory is mock_mem

    def test_hypothesize_queries_memory_when_set(self):
        """hypothesize() should call recall_similar when memory is available."""
        from CaseCrack.tools.burp_enterprise.agents.reasoning_engine import (
            ReasoningEngine,
        )

        mock_mem = MagicMock()
        mock_mem.recall_similar = MagicMock(return_value=[])

        mock_hyp_engine = MagicMock()
        mock_hyp_engine.generate_hypotheses = MagicMock(return_value=[])

        re = ReasoningEngine.__new__(ReasoningEngine)
        re._agent_memory = mock_mem
        re.hypothesis_engine = mock_hyp_engine
        re._exploit_graph_context = None
        re._llm_bridge = None
        re._llm_available = False

        re.hypothesize(
            target="https://example.com",
            technologies=["Django", "PostgreSQL"],
            previous_findings=[],
        )

        mock_mem.recall_similar.assert_called_once()
        mock_hyp_engine.generate_hypotheses.assert_called_once()

    def test_agent_loop_binds_memory_to_reasoning(self):
        """Agent loop should call set_agent_memory on ReasoningEngine."""
        import inspect
        from CaseCrack.tools.burp_enterprise.agents import agent_loop

        src = inspect.getsource(agent_loop)
        assert "set_agent_memory" in src, (
            "agent_loop does not call set_agent_memory on ReasoningEngine"
        )
        assert "N3-FIX" in src, "N3 fix marker not found in agent_loop"


# ═══════════════════════════════════════════════════════════════════════
# O1: Correlation engine wired into full_scan_orchestrator
# ═══════════════════════════════════════════════════════════════════════

class TestO1_CorrelationEngineWiring:
    """Verify correlation engine runs as a post-scan phase."""

    def test_run_correlation_engine_method_exists(self):
        """_run_correlation_engine must exist on FullScanOrchestrator."""
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator,
        )
        assert hasattr(FullScanOrchestrator, "_run_correlation_engine"), (
            "FullScanOrchestrator missing _run_correlation_engine"
        )

    def test_correlation_engine_called_in_pipeline(self):
        """_run_correlation_engine should appear in the scan pipeline source."""
        import inspect
        from CaseCrack.tools.burp_enterprise.pipeline import full_scan_orchestrator

        src = inspect.getsource(full_scan_orchestrator)
        assert "_run_correlation_engine" in src
        assert "O1-FIX" in src, "O1 fix marker not found"

    def test_correlation_engine_processes_findings(self):
        """_run_correlation_engine should call correlate_findings."""
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator,
            OrchestratorConfig,
            OrchestratorResult,
            ModuleResult,
            ScanPhase,
        )

        result = OrchestratorResult(
            module_results=[
                ModuleResult(
                    module_name="test_scanner",
                    phase=ScanPhase.ACTIVE,
                    findings=[
                        {"title": "XSS", "severity": "high"},
                        {"title": "SQLi", "severity": "critical"},
                    ],
                )
            ]
        )

        mock_report = SimpleNamespace(
            attack_chains=[{"chain": "test"}],
            correlation_links=[{"link": "test"}],
        )

        with patch(
            f"{BE}.output.correlation_engine.correlate_findings",
            return_value=mock_report,
        ) as mock_correlate:
            orch = FullScanOrchestrator.__new__(FullScanOrchestrator)
            orch.config = OrchestratorConfig(target_url="https://example.com")
            orch._run_correlation_engine(result)

        mock_correlate.assert_called_once()
        assert hasattr(result, "correlation_report")
        assert result.correlation_report is mock_report


# ═══════════════════════════════════════════════════════════════════════
# O2: Notification dispatch on scan completion
# ═══════════════════════════════════════════════════════════════════════

class TestO2_NotificationWiring:
    """Verify notification dispatch is wired to scan completion."""

    def test_send_scan_notifications_method_exists(self):
        """_send_scan_notifications must exist on FullScanOrchestrator."""
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator,
        )
        assert hasattr(FullScanOrchestrator, "_send_scan_notifications"), (
            "FullScanOrchestrator missing _send_scan_notifications"
        )

    def test_notification_source_markers(self):
        """O2 fix markers should be present in orchestrator source."""
        import inspect
        from CaseCrack.tools.burp_enterprise.pipeline import full_scan_orchestrator

        src = inspect.getsource(full_scan_orchestrator)
        assert "O2-FIX" in src, "O2 fix marker not found"
        assert "_send_scan_notifications" in src

    def test_slack_notification_dispatched(self):
        """When VENATOR_SLACK_WEBHOOK is set, Slack notifier should fire."""
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator,
            OrchestratorConfig,
            OrchestratorResult,
            ModuleResult,
            ScanPhase,
        )

        result = OrchestratorResult(
            module_results=[
                ModuleResult(
                    module_name="test",
                    phase=ScanPhase.ACTIVE,
                    findings=[{"title": "XSS", "severity": "high"}],
                )
            ]
        )

        mock_notifier = MagicMock()
        mock_notifier.notify_scan_complete = MagicMock(return_value=True)

        env_patch = {"VENATOR_SLACK_WEBHOOK": "https://hooks.slack.com/test"}
        with patch.dict(os.environ, env_patch, clear=False):
            with patch(
                f"{BE}.notifications.slack.SlackNotifier",
                return_value=mock_notifier,
            ):
                orch = FullScanOrchestrator.__new__(FullScanOrchestrator)
                orch.config = OrchestratorConfig(target_url="https://example.com")
                orch._send_scan_notifications(result)

        mock_notifier.notify_scan_complete.assert_called_once()
        summary = mock_notifier.notify_scan_complete.call_args[0][0]
        assert summary["target"] == "https://example.com"
        assert summary["total_findings"] == 1

    def test_no_notifications_when_no_env_vars(self):
        """No notifications should fire when no env vars are configured."""
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator,
            OrchestratorConfig,
            OrchestratorResult,
        )

        result = OrchestratorResult()

        # Clear all notification env vars
        env_clear = {
            k: "" for k in [
                "VENATOR_SLACK_WEBHOOK", "VENATOR_TEAMS_WEBHOOK",
                "VENATOR_WEBHOOK_URL", "VENATOR_DISCORD_WEBHOOK",
                "VENATOR_NTFY_TOPIC", "VENATOR_EMAIL_SMTP_HOST",
            ]
        }
        with patch.dict(os.environ, env_clear, clear=False):
            orch = FullScanOrchestrator.__new__(FullScanOrchestrator)
            orch.config = OrchestratorConfig(target_url="https://example.com")
            # Should not raise
            orch._send_scan_notifications(result)
