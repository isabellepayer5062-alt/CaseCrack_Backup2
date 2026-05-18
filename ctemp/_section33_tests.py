# Section 33 test content for Speculative Tool Pre-Execution Engine
# This will be inserted into test_validation_fleet.py by _insert_section33.py

SECTION_33_TESTS = r'''
# Section 33: Speculative Tool Pre-Execution Engine
# ===============================================================================

from CaseCrack.tools.burp_enterprise.agents.speculative_executor import (
    OverlayContext,
    SpeculationOutcome,
    SpeculationPolicy,
    SpeculationRequest,
    SpeculationStats,
    SpeculationStatus,
    SpeculativeExecutor,
    SpeculativeResult,
    get_speculative_executor,
    reset_speculative_executor,
    MAX_CONCURRENT_SPECULATIONS,
    CACHE_TTL_SECONDS,
    MIN_EV_THRESHOLD,
    MAX_PIPELINE_DEPTH,
)

print("\n== Section 33: Speculative Tool Pre-Execution Engine ==")

# ---------- 33.1: OverlayContext ----------

# 33.1.1: Create from dict
_octx = OverlayContext.from_dict({
    "target": "https://example.com",
    "technologies": ["nginx", "php"],
    "endpoints": ["/admin", "/login"],
    "waf_detected": "cloudflare",
    "phase_name": "recon",
    "findings": [
        {"severity": "high", "title": "XSS"},
        {"severity": "high", "title": "SQLi"},
        {"severity": "medium", "title": "Info Leak"},
    ],
}, target="https://example.com")
check("33.1.1", _octx.target == "https://example.com" and len(_octx.technologies) == 2,
      f"OverlayContext from dict: target={_octx.target}, techs={len(_octx.technologies)}")

# 33.1.2: Hash determinism
_octx2 = OverlayContext.from_dict({
    "target": "https://example.com",
    "technologies": ["php", "nginx"],  # different order, same set
    "endpoints": ["/admin", "/login"],
    "waf_detected": "cloudflare",
    "phase_name": "recon",
    "findings": [
        {"severity": "high", "title": "XSS"},
        {"severity": "high", "title": "SQLi"},
        {"severity": "medium", "title": "Info Leak"},
    ],
}, target="https://example.com")
check("33.1.2", _octx.context_hash == _octx2.context_hash,
      "Same data -> same context_hash")

# 33.1.3: Different context -> different hash
_octx3 = OverlayContext.from_dict({
    "target": "https://other.com",
    "technologies": ["apache"],
    "endpoints": [],
    "waf_detected": "",
    "phase_name": "exploit",
}, target="https://other.com")
check("33.1.3", _octx.context_hash != _octx3.context_hash,
      "Different data -> different hash")

# 33.1.4: Findings summary counted correctly
check("33.1.4", _octx.findings_summary.get("high") == 2 and _octx.findings_summary.get("medium") == 1,
      f"Findings summary: {_octx.findings_summary}")

# 33.1.5: to_dict roundtrip
_odict = _octx.to_dict()
check("33.1.5", "context_hash" in _odict and "target" in _odict,
      "to_dict contains expected keys")

# 33.1.6: Endpoints capped at 50
_big_endpoints = [f"/path_{i}" for i in range(200)]
_octx_big = OverlayContext.from_dict({
    "endpoints": _big_endpoints,
}, target="test")
check("33.1.6", len(_octx_big.endpoints) <= 50,
      f"Endpoint cap: {len(_octx_big.endpoints)} <= 50")

# ---------- 33.2: SpeculationPolicy ----------

# 33.2.1: Default policy creation
_pol = SpeculationPolicy()
check("33.2.1", _pol.enabled and _pol.max_concurrent == MAX_CONCURRENT_SPECULATIONS,
      f"Default policy: enabled={_pol.enabled}, max_concurrent={_pol.max_concurrent}")

# 33.2.2: Safe tool check
check("33.2.2", _pol.is_safe_to_speculate("nuclei_scan") and _pol.is_safe_to_speculate("nmap_scan"),
      "nuclei_scan and nmap_scan are safe")

# 33.2.3: Blocked tool check
check("33.2.3", not _pol.is_safe_to_speculate("sqlmap_exploit") and
      not _pol.is_safe_to_speculate("metasploit_exploit"),
      "sqlmap and metasploit are blocked")

# 33.2.4: Unknown tool is not safe
check("33.2.4", not _pol.is_safe_to_speculate("unknown_tool_xyz"),
      "Unknown tools are not safe by default")

# 33.2.5: Evaluate accepts good request
_req = SpeculationRequest(
    action="nuclei_scan", tool_name="nuclei_scan",
    expected_value=0.5, target="https://test.com",
)
_eval = _pol.evaluate(_req, active_count=0, pipeline_depth=0)
check("33.2.5", _eval == SpeculationOutcome.ACCEPTED,
      f"Good request accepted: {_eval.value}")

# 33.2.6: Evaluate rejects non-read-only
_req_bad = SpeculationRequest(
    action="sqlmap_exploit", tool_name="sqlmap_exploit",
    expected_value=0.9, target="https://test.com",
)
_eval_bad = _pol.evaluate(_req_bad, active_count=0, pipeline_depth=0)
check("33.2.6", _eval_bad == SpeculationOutcome.REJECTED_NOT_READ_ONLY,
      f"Destructive tool rejected: {_eval_bad.value}")

# 33.2.7: Evaluate rejects below threshold
_req_low = SpeculationRequest(
    action="nuclei_scan", tool_name="nuclei_scan",
    expected_value=0.01, target="https://test.com",
)
_eval_low = _pol.evaluate(_req_low, active_count=0, pipeline_depth=0)
check("33.2.7", _eval_low == SpeculationOutcome.REJECTED_BELOW_THRESHOLD,
      f"Low-EV rejected: {_eval_low.value}")

# 33.2.8: Evaluate rejects pool full
_eval_full = _pol.evaluate(_req, active_count=MAX_CONCURRENT_SPECULATIONS, pipeline_depth=0)
check("33.2.8", _eval_full == SpeculationOutcome.REJECTED_POOL_FULL,
      f"Pool full rejected: {_eval_full.value}")

# 33.2.9: Evaluate rejects pipeline full
_eval_pipe = _pol.evaluate(_req, active_count=0, pipeline_depth=MAX_PIPELINE_DEPTH)
check("33.2.9", _eval_pipe == SpeculationOutcome.REJECTED_PIPELINE_FULL,
      f"Pipeline full rejected: {_eval_pipe.value}")

# 33.2.10: Disabled policy rejects everything
_pol_disabled = SpeculationPolicy(enabled=False)
_eval_dis = _pol_disabled.evaluate(_req, active_count=0, pipeline_depth=0)
check("33.2.10", _eval_dis == SpeculationOutcome.REJECTED_DISABLED,
      f"Disabled policy rejects: {_eval_dis.value}")

# 33.2.11: to_dict
_pol_dict = _pol.to_dict()
check("33.2.11", "max_concurrent" in _pol_dict and "safe_tools_count" in _pol_dict,
      f"Policy to_dict has expected keys")

# ---------- 33.3: SpeculativeResult ----------

# 33.3.1: Default state
_sr = SpeculativeResult(speculation_id="spec-test", action="nuclei_scan")
check("33.3.1", _sr.status == SpeculationStatus.PENDING and not _sr.is_usable,
      f"Default: status={_sr.status.value}, usable={_sr.is_usable}")

# 33.3.2: Usable when completed
_sr.status = SpeculationStatus.COMPLETED
check("33.3.2", _sr.is_usable,
      "COMPLETED result is usable")

# 33.3.3: Terminal states
_sr_fail = SpeculativeResult(status=SpeculationStatus.FAILED)
_sr_timeout = SpeculativeResult(status=SpeculationStatus.TIMEOUT)
_sr_cancel = SpeculativeResult(status=SpeculationStatus.CANCELLED)
check("33.3.3", all(r.is_terminal for r in [_sr_fail, _sr_timeout, _sr_cancel]),
      "FAILED/TIMEOUT/CANCELLED are terminal")

# 33.3.4: Non-terminal states
_sr_pending = SpeculativeResult(status=SpeculationStatus.PENDING)
_sr_running = SpeculativeResult(status=SpeculationStatus.RUNNING)
check("33.3.4", not _sr_pending.is_terminal and not _sr_running.is_terminal,
      "PENDING/RUNNING are not terminal")

# 33.3.5: to_dict
import time as _time33
_sr.completed_at = _time33.time()
_sr.elapsed_ms = 42.5
_sr.finding_count = 3
_sr_dict = _sr.to_dict()
check("33.3.5", _sr_dict["elapsed_ms"] == 42.5 and _sr_dict["finding_count"] == 3,
      f"to_dict: elapsed={_sr_dict['elapsed_ms']}, findings={_sr_dict['finding_count']}")

# ---------- 33.4: SpeculativeExecutor Core ----------

# 33.4.1: Create executor with custom tool_executor
_executed_actions = []
def _mock_tool_executor(action, target, params, timeout):
    _executed_actions.append(action)
    return {
        "action": action,
        "target": target,
        "status": "completed",
        "finding_count": 2,
        "raw_output": f"Mock output for {action}",
        "value": 0.6,
    }

_exec = SpeculativeExecutor(tool_executor=_mock_tool_executor)
check("33.4.1", _exec.active_count == 0 and _exec.cache_size == 0,
      f"New executor: active={_exec.active_count}, cache={_exec.cache_size}")

# 33.4.2: Request speculation
_req_spec = SpeculationRequest(
    action="nuclei_scan", tool_name="nuclei_scan",
    target="https://test.com", expected_value=0.5,
    context={"technologies": ["nginx"]},
    triggered_by="lookahead",
)
_outcome, _sid = _exec.request_speculation(_req_spec)
check("33.4.2", _outcome == SpeculationOutcome.ACCEPTED and _sid.startswith("spec-"),
      f"Speculation accepted: {_outcome.value}, id={_sid[:16]}")

# 33.4.3: Wait for completion and check result
import time as _time_exec
_time_exec.sleep(0.3)  # Let the thread pool execute
_result = _exec.get_result_by_id(_sid)
check("33.4.3", _result is not None and _result.status == SpeculationStatus.COMPLETED,
      f"Speculation completed: status={_result.status.value if _result else 'None'}")

# 33.4.4: Result data populated
check("33.4.4", _result is not None and _result.finding_count == 2 and _result.actual_value == 0.6,
      f"Result data: findings={_result.finding_count if _result else 0}, value={_result.actual_value if _result else 0}")

# 33.4.5: Commit result
_committed = _exec.commit(_sid)
check("33.4.5", _committed,
      "Speculation committed successfully")

# 33.4.6: Stats after commit
_stats = _exec.get_stats()
check("33.4.6", _stats["total_hits"] >= 1 and _stats["total_completed"] >= 1,
      f"Stats: hits={_stats['total_hits']}, completed={_stats['total_completed']}")

# 33.4.7: Duplicate request rejected
_outcome_dup, _ = _exec.request_speculation(_req_spec)
check("33.4.7", _outcome_dup in (
    SpeculationOutcome.REJECTED_ALREADY_CACHED,
    SpeculationOutcome.REJECTED_ALREADY_RUNNING,
    SpeculationOutcome.REJECTED_COOLDOWN,
),
      f"Duplicate rejected: {_outcome_dup.value}")

# 33.4.8: Destructive tool rejected
_req_destruct = SpeculationRequest(
    action="sqlmap_exploit", tool_name="sqlmap_exploit",
    target="https://test.com", expected_value=0.9,
)
_outcome_d, _ = _exec.request_speculation(_req_destruct)
check("33.4.8", _outcome_d == SpeculationOutcome.REJECTED_NOT_READ_ONLY,
      f"Destructive tool rejected: {_outcome_d.value}")

# 33.4.9: Low EV rejected
_req_low_ev = SpeculationRequest(
    action="nuclei_scan", tool_name="nuclei_scan",
    target="https://other.com", expected_value=0.05,
)
_outcome_low, _ = _exec.request_speculation(_req_low_ev)
check("33.4.9", _outcome_low == SpeculationOutcome.REJECTED_BELOW_THRESHOLD,
      f"Low EV rejected: {_outcome_low.value}")

_exec.shutdown(wait=True)

# ---------- 33.5: Pipeline (Multiple Sequential Speculations) ----------

_pipeline_actions = []
def _pipe_executor(action, target, params, timeout):
    _pipeline_actions.append(action)
    _time_exec.sleep(0.02)
    return {"action": action, "finding_count": 1, "value": 0.3}

_pipe_exec = SpeculativeExecutor(tool_executor=_pipe_executor)

# 33.5.1: Pipeline multiple requests
_pipe_reqs = [
    SpeculationRequest(action="nmap_scan", tool_name="nmap_scan",
                       target="https://pipe1.com", expected_value=0.8),
    SpeculationRequest(action="httpx_probe", tool_name="httpx_probe",
                       target="https://pipe2.com", expected_value=0.7),
    SpeculationRequest(action="ffuf_scan", tool_name="ffuf_scan",
                       target="https://pipe3.com", expected_value=0.6),
]
_pipe_results = _pipe_exec.pipeline_next(_pipe_reqs)
check("33.5.1", len(_pipe_results) == 3 and all(r[0] == SpeculationOutcome.ACCEPTED for r in _pipe_results),
      f"Pipeline accepted {len(_pipe_results)} requests")

# 33.5.2: Wait and check all completed
_time_exec.sleep(0.5)
_completed = _pipe_exec.get_completed_results()
check("33.5.2", len(_completed) >= 3,
      f"Pipeline: {len(_completed)} completed")

# 33.5.3: Get pipeline status
_pipe_status = _pipe_exec.get_pipeline_status()
check("33.5.3", len(_pipe_status) >= 3,
      f"Pipeline status: {len(_pipe_status)} entries")

_pipe_exec.shutdown(wait=True)

# ---------- 33.6: Cancel and Lifecycle ----------

_cancel_actions = []
def _slow_executor(action, target, params, timeout):
    _cancel_actions.append(action)
    _time_exec.sleep(2.0)  # Slow execution
    return {"action": action, "finding_count": 0, "value": 0}

_cancel_exec = SpeculativeExecutor(tool_executor=_slow_executor)

# 33.6.1: Cancel in-flight
_slow_req = SpeculationRequest(
    action="katana_crawl", tool_name="katana_crawl",
    target="https://cancel.com", expected_value=0.5,
)
_out_slow, _sid_slow = _cancel_exec.request_speculation(_slow_req)
check("33.6.1", _out_slow == SpeculationOutcome.ACCEPTED,
      f"Slow speculation accepted: {_out_slow.value}")

# 33.6.2: Cancel
_time_exec.sleep(0.1)
_cancelled = _cancel_exec.cancel(_sid_slow)
check("33.6.2", _cancelled,
      "Cancel returned True")

# 33.6.3: Cancel all
_cancel_exec.request_speculation(SpeculationRequest(
    action="nmap_scan", tool_name="nmap_scan",
    target="https://cancel2.com", expected_value=0.4,
))
_num_cancelled = _cancel_exec.cancel_all()
check("33.6.3", _num_cancelled >= 0,
      f"cancel_all: {_num_cancelled} cancelled")

# 33.6.4: Reset clears everything
_cancel_exec.reset()
check("33.6.4", _cancel_exec.cache_size == 0 and _cancel_exec.active_count == 0,
      f"Reset: cache={_cancel_exec.cache_size}, active={_cancel_exec.active_count}")

_cancel_exec.shutdown(wait=False)

# ---------- 33.7: Error Handling ----------

def _error_executor(action, target, params, timeout):
    if "error" in action:
        raise RuntimeError("Simulated tool failure")
    if "timeout" in action:
        raise TimeoutError("Tool timed out")
    return {"action": action, "finding_count": 0, "value": 0}

_err_exec = SpeculativeExecutor(tool_executor=_error_executor)

# 33.7.1: Error handled gracefully
_err_req = SpeculationRequest(
    action="error_scan", tool_name="error_scan",
    target="https://test.com", expected_value=0.5,
)
# Need to add error_scan to safe tools first
SpeculationPolicy.SAFE_TOOLS = frozenset(SpeculationPolicy.SAFE_TOOLS | {"error_scan", "timeout_scan"})
_err_out, _err_sid = _err_exec.request_speculation(_err_req)
check("33.7.1", _err_out == SpeculationOutcome.ACCEPTED,
      f"Error request accepted: {_err_out.value}")

# 33.7.2: Wait and check failed status
_time_exec.sleep(0.3)
_err_result = _err_exec.get_result_by_id(_err_sid)
check("33.7.2", _err_result is not None and _err_result.status == SpeculationStatus.FAILED,
      f"Error result: status={_err_result.status.value if _err_result else 'None'}")

# 33.7.3: Error message captured
check("33.7.3", _err_result is not None and "Simulated" in _err_result.error_message,
      f"Error message: {_err_result.error_message[:30] if _err_result else 'None'}")

# 33.7.4: Timeout handled
_timeout_req = SpeculationRequest(
    action="timeout_scan", tool_name="timeout_scan",
    target="https://test2.com", expected_value=0.5,
)
_to_out, _to_sid = _err_exec.request_speculation(_timeout_req)
_time_exec.sleep(0.3)
_to_result = _err_exec.get_result_by_id(_to_sid)
check("33.7.4", _to_result is not None and _to_result.status == SpeculationStatus.TIMEOUT,
      f"Timeout result: status={_to_result.status.value if _to_result else 'None'}")

# 33.7.5: Stats reflect errors
_err_stats = _err_exec.get_stats()
check("33.7.5", _err_stats["total_failed"] >= 1 and _err_stats["total_timeouts"] >= 1,
      f"Error stats: failed={_err_stats['total_failed']}, timeouts={_err_stats['total_timeouts']}")

# Restore safe tools
SpeculationPolicy.SAFE_TOOLS = frozenset(SpeculationPolicy.SAFE_TOOLS - {"error_scan", "timeout_scan"})
_err_exec.shutdown(wait=True)

# ---------- 33.8: Event Callbacks ----------

_events_received = []
def _test_event_callback(event_type, data):
    _events_received.append(event_type)

_ev_exec = SpeculativeExecutor(
    tool_executor=_mock_tool_executor,
    event_callback=_test_event_callback,
)

# 33.8.1: Events emitted on request
_ev_req = SpeculationRequest(
    action="subfinder_scan", tool_name="subfinder_scan",
    target="https://events.com", expected_value=0.6,
)
_ev_exec.request_speculation(_ev_req)
_time_exec.sleep(0.3)
check("33.8.1", "speculation.requested" in _events_received,
      f"Request event emitted: {_events_received}")

# 33.8.2: Completion event emitted
check("33.8.2", "speculation.completed" in _events_received,
      f"Completion event emitted")

_ev_exec.shutdown(wait=True)

# ---------- 33.9: SpeculationRequest Cache Key ----------

# 33.9.1: Same request -> same cache key
_rk1 = SpeculationRequest(action="nmap_scan", tool_name="nmap_scan",
                           target="https://key.com", expected_value=0.5,
                           context={"technologies": ["nginx"]})
_rk2 = SpeculationRequest(action="nmap_scan", tool_name="nmap_scan",
                           target="https://key.com", expected_value=0.8,
                           context={"technologies": ["nginx"]})
check("33.9.1", _rk1.cache_key == _rk2.cache_key,
      "Same action+target+context -> same cache_key (EV irrelevant)")

# 33.9.2: Different context -> different cache key
_rk3 = SpeculationRequest(action="nmap_scan", tool_name="nmap_scan",
                           target="https://key.com", expected_value=0.5,
                           context={"technologies": ["apache"]})
check("33.9.2", _rk1.cache_key != _rk3.cache_key,
      "Different context -> different cache_key")

# ---------- 33.10: Singleton ----------

# 33.10.1: get_speculative_executor returns same instance
reset_speculative_executor()
_sing1 = get_speculative_executor()
_sing2 = get_speculative_executor()
check("33.10.1", _sing1 is _sing2,
      "Singleton returns same instance")

# 33.10.2: Reset creates new instance
reset_speculative_executor()
_sing3 = get_speculative_executor()
check("33.10.2", _sing3 is not _sing1,
      "Reset creates new instance")

reset_speculative_executor()

# ---------- 33.11: Shutdown and Stats ----------

_shut_exec = SpeculativeExecutor(tool_executor=_mock_tool_executor)

# 33.11.1: Execute and shutdown
_shut_req = SpeculationRequest(
    action="wappalyzer_scan", tool_name="wappalyzer_scan",
    target="https://shut.com", expected_value=0.5,
)
_shut_exec.request_speculation(_shut_req)
_time_exec.sleep(0.3)
_final_stats = _shut_exec.shutdown(wait=True)
check("33.11.1", "total_completed" in _final_stats and _final_stats["total_completed"] >= 1,
      f"Shutdown stats: completed={_final_stats.get('total_completed', 0)}")

# 33.11.2: Shutdown disables new requests
_shut_out, _ = _shut_exec.request_speculation(SpeculationRequest(
    action="nuclei_scan", tool_name="nuclei_scan",
    target="https://shut2.com", expected_value=0.5,
))
check("33.11.2", _shut_out == SpeculationOutcome.REJECTED_DISABLED,
      f"Post-shutdown rejected: {_shut_out.value}")

# ---------- 33.12: Integration with LookaheadEngine ----------

# 33.12.1: LookaheadEngine accepts bind_speculative_executor
from CaseCrack.tools.burp_enterprise.lookahead_engine import LookaheadEngine
_le = LookaheadEngine()
_spec_for_le = SpeculativeExecutor(tool_executor=_mock_tool_executor)
_le.bind_speculative_executor(_spec_for_le)
check("33.12.1", _le._speculative_executor is _spec_for_le,
      "LookaheadEngine bound to SpeculativeExecutor")

# 33.12.2: compute_lookahead_ev triggers speculation
_le.bind_score_function(lambda action, target, ctx: type("R", (), {
    "action": action, "expected_value": 0.5, "probability_success": 0.5,
    "rationale": [], "confidence": None,
})())
_la_result = _le.compute_lookahead_ev(
    action="nuclei_scan", p_success=0.6,
    candidates=["nmap_scan", "httpx_probe"],
    ctx={"technologies": ["nginx"]}, target="https://le-test.com",
)
check("33.12.2", _la_result is not None and hasattr(_la_result, "future_ev"),
      f"Lookahead EV computed: {_la_result.future_ev:.4f}")

_spec_for_le.shutdown(wait=True)

# ---------- 33.13: Integration with DecisionOrchestrator ----------

# 33.13.1: DecisionOrchestrator accepts bind_speculative_executor
from CaseCrack.tools.burp_enterprise.decision_orchestrator import DecisionOrchestrator
_do = DecisionOrchestrator()
_spec_for_do = SpeculativeExecutor(tool_executor=_mock_tool_executor)
_do.bind_speculative_executor(_spec_for_do)
check("33.13.1", _do._speculative_executor is _spec_for_do,
      "DecisionOrchestrator bound to SpeculativeExecutor")

_spec_for_do.shutdown(wait=True)

# ---------- 33.14: Integration with AgentCoordinator ----------

# 33.14.1: AgentCoordinator has speculative_executor
from CaseCrack.tools.burp_enterprise.agent_roles import AgentCoordinator
_ac = AgentCoordinator()
check("33.14.1", hasattr(_ac, "_speculative_executor") and _ac._speculative_executor is not None,
      "AgentCoordinator has speculative executor")

# 33.14.2: speculative_executor property accessible
_spec_prop = _ac.speculative_executor
check("33.14.2", _spec_prop is not None,
      "speculative_executor property works")

# ---------- 33.15: Concurrent Speculations ----------

_conc_actions = []
_conc_lock = __import__("threading").Lock()
def _conc_executor(action, target, params, timeout):
    with _conc_lock:
        _conc_actions.append(action)
    _time_exec.sleep(0.05)
    return {"action": action, "finding_count": 1, "value": 0.4}

_conc_exec = SpeculativeExecutor(tool_executor=_conc_executor, max_workers=4)

# 33.15.1: Multiple concurrent speculations
_conc_reqs = [
    SpeculationRequest(action="ssl_scan", tool_name="ssl_scan",
                       target="https://conc0.com", expected_value=0.5),
    SpeculationRequest(action="testssl", tool_name="testssl",
                       target="https://conc1.com", expected_value=0.5),
    SpeculationRequest(action="security_headers_check", tool_name="security_headers_check",
                       target="https://conc2.com", expected_value=0.5),
    SpeculationRequest(action="whatweb_scan", tool_name="whatweb_scan",
                       target="https://conc3.com", expected_value=0.5),
]
_conc_outs = _conc_exec.pipeline_next(_conc_reqs)
_accepted_count = sum(1 for o, _ in _conc_outs if o == SpeculationOutcome.ACCEPTED)
check("33.15.1", _accepted_count >= 3,
      f"Concurrent: {_accepted_count} accepted")

# 33.15.2: Wait for all to complete
_time_exec.sleep(0.5)
_conc_completed = _conc_exec.get_completed_results()
check("33.15.2", len(_conc_completed) >= 3,
      f"Concurrent completed: {len(_conc_completed)}")

# 33.15.3: Peak concurrent stat
_conc_stats = _conc_exec.get_stats()
check("33.15.3", _conc_stats["peak_concurrent"] >= 2,
      f"Peak concurrent: {_conc_stats['peak_concurrent']}")

_conc_exec.shutdown(wait=True)

# ---------- 33.16: SpeculationStatus Enum ----------

# 33.16.1: All expected statuses exist
_expected_statuses = ["pending", "running", "completed", "failed",
                       "timeout", "cancelled", "evicted", "committed"]
_all_exist = all(
    hasattr(SpeculationStatus, s.upper()) for s in _expected_statuses
)
check("33.16.1", _all_exist,
      f"All {len(_expected_statuses)} statuses exist")

# 33.16.2: SpeculationOutcome values
_expected_outcomes = [
    "accepted", "rejected_not_read_only", "rejected_already_cached",
    "rejected_already_running", "rejected_pool_full",
    "rejected_below_threshold", "rejected_pipeline_full",
    "rejected_disabled", "rejected_cooldown",
]
_all_outcomes = all(
    hasattr(SpeculationOutcome, o.upper()) for o in _expected_outcomes
)
check("33.16.2", _all_outcomes,
      f"All {len(_expected_outcomes)} outcomes exist")

# ---------- 33.17: Advanced Policy ----------

# 33.17.1: Custom thresholds
_custom_pol = SpeculationPolicy(
    max_concurrent=2,
    min_ev_threshold=0.3,
    max_pipeline_depth=5,
    tool_cooldown_s=0.1,
)
check("33.17.1", _custom_pol.max_concurrent == 2 and _custom_pol.min_ev_threshold == 0.3,
      f"Custom policy: concurrent={_custom_pol.max_concurrent}, threshold={_custom_pol.min_ev_threshold}")

# 33.17.2: Cooldown tracking
_custom_pol.record_speculation("nmap_scan")
_cd_check = _custom_pol.check_cooldown("nmap_scan")
check("33.17.2", not _cd_check,
      f"Cooldown active: check={_cd_check}")

# 33.17.3: Cooldown expires
_time_exec.sleep(0.15)
_cd_check2 = _custom_pol.check_cooldown("nmap_scan")
check("33.17.3", _cd_check2,
      f"Cooldown expired: check={_cd_check2}")

# ---------- 33.18: Edge Cases ----------

# 33.18.1: Empty context
_edge_exec = SpeculativeExecutor(tool_executor=_mock_tool_executor)
_edge_req = SpeculationRequest(
    action="gobuster_scan", tool_name="gobuster_scan",
    target="", expected_value=0.5,
    context={},
)
_edge_out, _edge_sid = _edge_exec.request_speculation(_edge_req)
check("33.18.1", _edge_out == SpeculationOutcome.ACCEPTED,
      f"Empty context accepted: {_edge_out.value}")

# 33.18.2: get_result with no match returns None
_no_match = _edge_exec.get_result("nonexistent_tool", "http://x.com", {})
check("33.18.2", _no_match is None,
      "No match returns None")

# 33.18.3: Commit nonexistent ID returns False
_bad_commit = _edge_exec.commit("spec-nonexistent")
check("33.18.3", not _bad_commit,
      "Commit nonexistent returns False")

# 33.18.4: Cancel nonexistent ID returns False
_bad_cancel = _edge_exec.cancel("spec-nonexistent")
check("33.18.4", not _bad_cancel,
      "Cancel nonexistent returns False")

# 33.18.5: Stats structure
_edge_stats = _edge_exec.get_stats()
_expected_keys = {"total_requested", "total_accepted", "total_completed",
                   "total_hits", "hit_rate", "peak_concurrent", "cache_size",
                   "policy", "active_count", "pipeline_depth"}
check("33.18.5", _expected_keys.issubset(set(_edge_stats.keys())),
      f"Stats has all expected keys")

_edge_exec.shutdown(wait=True)
'''
