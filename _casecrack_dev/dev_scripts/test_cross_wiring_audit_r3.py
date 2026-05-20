"""
Cross-Module Wiring Audit Round 3 — Verifies fixes F1, F3, F6, F7, F8.

  F1: pipeline/worker.py broken sibling imports fixed
      (.tool_wrappers._scan_runner → ..tool_wrappers._scan_runner,
       .data.postgres → ..data.postgres)
  F3: Atlas gets scan-completion episodes recorded via
      FullScanOrchestrator._record_atlas_episode()
  F6: OrchestratorResult.summary() now emits a "findings" key with
      serialized finding dicts.
  F7: VENATOR_AUTO_REPORT env var triggers post-scan report generation
      via FullScanOrchestrator._maybe_auto_report()
  F8: learning_loop_engine subscribes to "domain_vertical_detected"
      (previously orphan publish).
"""

from __future__ import annotations

import inspect
import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CaseCrack"))

BE = "CaseCrack.tools.burp_enterprise"


# ═══════════════════════════════════════════════════════════════════════
# F1: pipeline/worker.py imports resolve
# ═══════════════════════════════════════════════════════════════════════
class TestF1_WorkerImports:
    def test_worker_module_imports_cleanly(self):
        import importlib
        mod = importlib.import_module(f"{BE}.pipeline.worker")
        assert mod is not None

    def test_scan_runner_import_is_two_dots(self):
        """Verify worker.py uses `..tool_wrappers._scan_runner` (parent package)."""
        from CaseCrack.tools.burp_enterprise.pipeline import worker
        src = inspect.getsource(worker)
        assert "from ..tool_wrappers._scan_runner import run_scan" in src, \
            "F1-FIX: scan_runner import must use .. (parent) not . (sibling)"

    def test_postgres_import_is_two_dots(self):
        from CaseCrack.tools.burp_enterprise.pipeline import worker
        src = inspect.getsource(worker)
        assert "from ..data.postgres import get_store" in src, \
            "F1-FIX: postgres import must use .. (parent) not . (sibling)"

    def test_scan_runner_actually_resolves(self):
        """Confirm the imported target actually exists and is callable."""
        from CaseCrack.tools.burp_enterprise.tool_wrappers._scan_runner import run_scan
        assert callable(run_scan)

    def test_postgres_get_store_resolves(self):
        from CaseCrack.tools.burp_enterprise.data.postgres import get_store
        assert callable(get_store)


# ═══════════════════════════════════════════════════════════════════════
# F6: OrchestratorResult.summary() includes findings key
# ═══════════════════════════════════════════════════════════════════════
class TestF6_SummaryIncludesFindings:
    def _make_result(self):
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            OrchestratorResult, ModuleResult, ScanPhase,
        )
        mr = ModuleResult(
            module_name="fake_scanner",
            phase=ScanPhase.ACTIVE,
            success=True,
            elapsed_seconds=1.0,
            findings=[
                {"type": "xss", "severity": "high", "url": "https://t/a"},
                {"type": "sqli", "severity": "critical", "url": "https://t/b"},
            ],
        )
        return OrchestratorResult(
            start_time=0.0,
            end_time=1.0,
            module_results=[mr],
        )

    def test_summary_has_findings_key(self):
        result = self._make_result()
        s = result.summary()
        assert "findings" in s, "F6-FIX: summary() must include 'findings' key"

    def test_summary_findings_are_serialized(self):
        result = self._make_result()
        s = result.summary()
        assert isinstance(s["findings"], list)
        assert len(s["findings"]) == 2
        assert all(isinstance(f, dict) for f in s["findings"])
        assert {f["type"] for f in s["findings"]} == {"xss", "sqli"}

    def test_summary_handles_object_findings(self):
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            OrchestratorResult, ModuleResult, ScanPhase,
        )
        class Finding:
            def __init__(self, t, sev):
                self.t = t
                self.sev = sev
            def to_dict(self):
                return {"type": self.t, "severity": self.sev}
        mr = ModuleResult(
            module_name="x", phase=ScanPhase.ACTIVE,
            success=True, elapsed_seconds=0.5,
            findings=[Finding("idor", "medium")],
        )
        result = OrchestratorResult(
            start_time=0.0, end_time=1.0,
            module_results=[mr],
        )
        s = result.summary()
        assert s["findings"][0]["type"] == "idor"


# ═══════════════════════════════════════════════════════════════════════
# F3: Atlas episode recorded on scan completion
# ═══════════════════════════════════════════════════════════════════════
class TestF3_AtlasRecordEpisode:
    def test_record_atlas_episode_method_exists(self):
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator,
        )
        assert hasattr(FullScanOrchestrator, "_record_atlas_episode")

    def test_run_inner_calls_record_atlas_episode(self):
        """_run_inner must call _record_atlas_episode."""
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator,
        )
        src = inspect.getsource(FullScanOrchestrator._run_inner)
        assert "_record_atlas_episode" in src

    def test_atlas_episode_submits_observation_per_finding(self):
        """When called, it must call atlas.submit_observation_raw per finding."""
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator, OrchestratorResult, ModuleResult, ScanPhase,
            OrchestratorConfig,
        )

        mr = ModuleResult(
            module_name="xss_scanner", phase=ScanPhase.ACTIVE,
            success=True, elapsed_seconds=1.0,
            findings=[
                {"type": "xss", "severity": "high"},
                {"type": "csrf", "severity": "medium"},
            ],
        )
        result = OrchestratorResult(
            start_time=0.0, end_time=1.0,
            module_results=[mr],
        )

        # Build orchestrator with a minimal config
        cfg = OrchestratorConfig(target_url="https://t")
        orch = FullScanOrchestrator.__new__(FullScanOrchestrator)
        orch.config = cfg

        fake_atlas = MagicMock()
        fake_atlas.submit_observation_raw.return_value = True

        import CaseCrack.tools.burp_enterprise.atlas as atlas_pkg
        with patch.object(atlas_pkg, "get_atlas", return_value=fake_atlas):
            orch._record_atlas_episode(result)

        assert fake_atlas.submit_observation_raw.call_count == 2
        call_kwargs = [c.kwargs for c in fake_atlas.submit_observation_raw.call_args_list]
        assert {kw["step_name"] for kw in call_kwargs} == {"xss", "csrf"}


# ═══════════════════════════════════════════════════════════════════════
# F7: VENATOR_AUTO_REPORT triggers report emission
# ═══════════════════════════════════════════════════════════════════════
class TestF7_AutoReport:
    def test_maybe_auto_report_method_exists(self):
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator,
        )
        assert hasattr(FullScanOrchestrator, "_maybe_auto_report")

    def test_run_inner_calls_maybe_auto_report(self):
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator,
        )
        src = inspect.getsource(FullScanOrchestrator._run_inner)
        assert "_maybe_auto_report" in src

    def test_no_op_when_env_unset(self, monkeypatch, tmp_path):
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator, OrchestratorResult, OrchestratorConfig,
        )
        monkeypatch.delenv("VENATOR_AUTO_REPORT", raising=False)
        orch = FullScanOrchestrator.__new__(FullScanOrchestrator)
        orch.config = OrchestratorConfig(target_url="https://t")
        result = OrchestratorResult(
            start_time=0.0, end_time=1.0,
            module_results=[],
        )
        # Must not raise and must not create any file
        orch._maybe_auto_report(result)
        assert not any(tmp_path.iterdir())

    def test_sarif_emission_on_env_set(self, monkeypatch, tmp_path):
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator, OrchestratorResult, OrchestratorConfig,
            ModuleResult, ScanPhase,
        )
        monkeypatch.setenv("VENATOR_AUTO_REPORT", "sarif")
        monkeypatch.setenv("VENATOR_AUTO_REPORT_DIR", str(tmp_path))

        mr = ModuleResult(
            module_name="s", phase=ScanPhase.ACTIVE,
            success=True, elapsed_seconds=1.0,
            findings=[{"type": "xss", "severity": "high", "url": "https://t/x"}],
        )
        result = OrchestratorResult(
            start_time=0.0, end_time=1.0,
            module_results=[mr],
        )
        orch = FullScanOrchestrator.__new__(FullScanOrchestrator)
        orch.config = OrchestratorConfig(target_url="https://t")
        orch._maybe_auto_report(result)

        out_files = list(tmp_path.glob("*.sarif"))
        assert len(out_files) == 1
        doc = json.loads(out_files[0].read_text())
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"][0]["ruleId"] == "xss"

    def test_json_emission_on_env_set(self, monkeypatch, tmp_path):
        from CaseCrack.tools.burp_enterprise.pipeline.full_scan_orchestrator import (
            FullScanOrchestrator, OrchestratorResult, OrchestratorConfig,
            ModuleResult, ScanPhase,
        )
        monkeypatch.setenv("VENATOR_AUTO_REPORT", "json")
        monkeypatch.setenv("VENATOR_AUTO_REPORT_DIR", str(tmp_path))

        mr = ModuleResult(
            module_name="s", phase=ScanPhase.ACTIVE,
            success=True, elapsed_seconds=1.0,
            findings=[{"type": "sqli", "severity": "critical"}],
        )
        result = OrchestratorResult(
            start_time=0.0, end_time=1.0,
            module_results=[mr],
        )
        orch = FullScanOrchestrator.__new__(FullScanOrchestrator)
        orch.config = OrchestratorConfig(target_url="https://t")
        orch._maybe_auto_report(result)

        out_files = list(tmp_path.glob("*.json"))
        assert len(out_files) == 1
        data = json.loads(out_files[0].read_text())
        assert data["total_findings"] == 1
        assert "findings" in data  # F6 wiring


# ═══════════════════════════════════════════════════════════════════════
# F8: learning_loop_engine subscribes to domain_vertical_detected
# ═══════════════════════════════════════════════════════════════════════
class TestF8_DomainVerticalSubscribed:
    def test_handler_method_exists(self):
        from CaseCrack.tools.burp_enterprise.learning_loop_engine import (
            LearningLoopEngine,
        )
        assert hasattr(LearningLoopEngine, "_on_domain_vertical_detected")

    def test_bind_event_bus_subscribes_domain_vertical(self):
        from CaseCrack.tools.burp_enterprise.learning_loop_engine import (
            LearningLoopEngine,
        )
        src = inspect.getsource(LearningLoopEngine.bind_event_bus)
        assert "domain_vertical_detected" in src, \
            "F8-FIX: bind_event_bus must subscribe to domain_vertical_detected"

    def test_handler_updates_context_with_vertical(self):
        from CaseCrack.tools.burp_enterprise.learning_loop_engine import (
            LearningLoopEngine,
        )
        engine = LearningLoopEngine.__new__(LearningLoopEngine)
        engine.update_context = MagicMock()
        event = SimpleNamespace(data={"vertical": "ecommerce"})
        engine._on_domain_vertical_detected(event)
        engine.update_context.assert_called_once()
        kw = engine.update_context.call_args.kwargs
        assert "vertical:ecommerce" in kw.get("technologies", [])
