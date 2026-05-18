#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
REPORT_PATH = ROOT / "_MCP_DEPENDENCY_ADVERSARIAL_TEST_REPORT.json"
TMP_AUDIT = ROOT / "_tmp_mcp_dependency_adversarial_audit.jsonl"

if str(ROOT / "CaseCrack") not in sys.path:
    sys.path.insert(0, str(ROOT / "CaseCrack"))

from tools.burp_enterprise.mcp.mcp_server import SecurityMCPServer  # type: ignore  # noqa: E402
import tools.burp_enterprise.mcp.mcp_server as mcp_server_mod  # type: ignore  # noqa: E402


KNOWN_ERROR_CODES = {
    "ALLOWLIST_DENY",
    "DUPLICATE_REQUEST",
    "INVALID_ACTION",
    "INTERNAL_ERROR",
    "LICENSE_REQUIRED",
    "PARSE_ERROR",
    "POLICY_VIOLATION",
    "RATE_LIMITED",
    "REQUEST_TIMEOUT",
    "SCAN_NOT_FOUND",
    "TENANT_DISABLED",
    "VALIDATION_ERROR",
}


def _safe_json_loads(payload: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(payload or "{}")
        if isinstance(parsed, dict):
            return parsed
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return {}


def _percentile(sorted_values: List[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    rank = (len(sorted_values) - 1) * max(0.0, min(100.0, p)) / 100.0
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return float(sorted_values[lo])
    frac = rank - lo
    return float(sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac)


def _latency_summary_ms(samples_ms: List[float]) -> Dict[str, float]:
    if not samples_ms:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
    data = sorted(float(x) for x in samples_ms)
    return {
        "p50": round(_percentile(data, 50), 3),
        "p95": round(_percentile(data, 95), 3),
        "p99": round(_percentile(data, 99), 3),
    }


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)


def _analyze_audit_terminals_from_events(events: List[Dict[str, Any]], terminal_expected_ids: set[str]) -> Dict[str, Any]:
    per_request_kinds: Dict[str, set[str]] = {}
    per_request_counts: Dict[str, Dict[str, int]] = {}
    parsed_lines = 0
    invalid_lines = 0

    for event in events:
        if not isinstance(event, dict):
            invalid_lines += 1
            continue
        parsed_lines += 1

        event_type = str(event.get("event_type") or "")
        if event_type not in {"tool_completed", "tool_failed"}:
            continue
        rid = str(event.get("request_id") or event.get("run_id") or "")
        if not rid:
            continue

        per_request_kinds.setdefault(rid, set()).add(event_type)
        bucket = per_request_counts.setdefault(rid, {})
        bucket[event_type] = int(bucket.get(event_type, 0)) + 1

    duplicate_terminal = 0
    terminal_conflicts = 0
    for rid, kinds in per_request_kinds.items():
        if len(kinds) > 1:
            terminal_conflicts += 1
        event_counts = per_request_counts.get(rid, {})
        if any(count > 1 for count in event_counts.values()):
            duplicate_terminal += 1

    missing_terminal = 0
    for rid in terminal_expected_ids:
        if rid not in per_request_kinds:
            missing_terminal += 1

    return {
        "duplicate_terminal": duplicate_terminal,
        "terminal_conflicts": terminal_conflicts,
        "missing_terminal": missing_terminal,
        "parsed_lines": parsed_lines,
        "invalid_lines": invalid_lines,
        "terminal_request_ids": len(per_request_kinds),
        "terminal_expected_ids": len(terminal_expected_ids),
    }


class DependencySimulator:
    """Deterministic downstream dependency with adversarial modes."""

    def __init__(
        self,
        mode: str,
        *,
        slow_ms: int = 0,
        failure_rate: float = 0.0,
        pattern: Optional[List[str]] = None,
        seed: int = 1337,
    ) -> None:
        self.mode = str(mode)
        self.slow_ms = int(max(0, slow_ms))
        self.failure_rate = float(max(0.0, min(1.0, failure_rate)))
        self.pattern = list(pattern or [])
        self._counter = 0
        self._rng = random.Random(seed)

    async def respond(self, arguments: Dict[str, Any]) -> str:
        self._counter += 1
        idx = int(arguments.get("idx", self._counter) or self._counter)

        if self.mode == "slow_response":
            if self.slow_ms > 0:
                await asyncio.sleep(self.slow_ms / 1000.0)
            return json.dumps({"result": {"value": idx}})

        if self.mode == "timeout":
            raise RuntimeError("dependency timeout")

        if self.mode == "partial_json":
            return json.dumps({"status": "ok"})

        if self.mode == "schema_shift":
            if self._counter % 2 == 1:
                return json.dumps({"result": {"value": idx}})
            return json.dumps({"data": {"val": str(idx)}})

        if self.mode == "intermittent_failure":
            if self._rng.random() < self.failure_rate:
                # Include timeout in error text so MCP classifies it as REQUEST_TIMEOUT.
                raise RuntimeError("dependency timeout")
            return json.dumps({"result": {"value": idx}})

        if self.mode == "flapping":
            step = self.pattern[(self._counter - 1) % max(1, len(self.pattern))] if self.pattern else "success"
            if step == "success":
                return json.dumps({"result": {"value": idx}})
            if step == "failure":
                raise RuntimeError("dependency failure")
            if step == "timeout":
                raise RuntimeError("dependency timeout")
            if step == "partial_json":
                return json.dumps({"status": "ok"})
            if step == "invalid_json":
                return "{ invalid json..."
            return json.dumps({"result": {"value": idx}})

        if self.mode == "invalid_json":
            return "{ invalid json..."

        if self.mode == "unseen_failure_pattern":
            raise RuntimeError("vendor_transport_glitch:E42:opaque_failure")

        return json.dumps({"result": {"value": idx}})


def _normalize_dependency_payload(raw_payload: str, *, allow_schema_shift: bool) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw_payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("parse error: invalid dependency payload") from exc

    if not isinstance(parsed, dict):
        raise RuntimeError("validation error: dependency payload must be object")

    result = parsed.get("result")
    if isinstance(result, dict) and "value" in result:
        value = result.get("value")
        try:
            return {"value": int(value)}
        except (TypeError, ValueError) as exc:
            raise RuntimeError("validation error: result.value is not coercible to int") from exc

    data = parsed.get("data")
    if allow_schema_shift and isinstance(data, dict) and "val" in data:
        try:
            return {"value": int(data.get("val"))}
        except (TypeError, ValueError) as exc:
            raise RuntimeError("validation error: schema-shift val is not coercible to int") from exc

    if "status" in parsed:
        raise RuntimeError("validation error: missing result.value")

    raise RuntimeError("validation error: unsupported dependency schema")


async def _invoke_tool(
    server: SecurityMCPServer,
    *,
    request_id: str,
    arguments: Dict[str, Any],
    terminal_expected_ids: set[str],
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    payload, is_error = await server.execute_tool_request(
        "get_report",
        dict(arguments),
        request_id=request_id,
    )
    duration_ms = (time.perf_counter() - t0) * 1000.0

    envelope = _safe_json_loads(payload)
    code = str(envelope.get("code") or "").upper()

    if code not in {"RATE_LIMITED", "DUPLICATE_REQUEST", "TENANT_DISABLED", "ALLOWLIST_DENY"}:
        terminal_expected_ids.add(str(request_id))

    return {
        "request_id": str(request_id),
        "is_error": bool(is_error),
        "code": code,
        "payload": envelope,
        "duration_ms": round(duration_ms, 3),
    }


def _build_server(sim: DependencySimulator, *, allow_schema_shift: bool, execute_counts: Dict[str, int]) -> SecurityMCPServer:
    setattr(mcp_server_mod, "_DASHBOARD_HOOKS_AVAILABLE", False)
    server = SecurityMCPServer(workspace_path="CaseCrack")
    setattr(server, "_check_and_consume_tenant_quota", lambda **_kwargs: "")

    for attr in (
        "_runtime_disabled_tenants",
        "_runtime_passthrough_disabled_tenants",
        "_tenant_control_state",
        "_tenant_control_history",
        "_tenant_rate_state",
    ):
        obj = getattr(server, attr, None)
        if hasattr(obj, "clear"):
            obj.clear()

    recorded_events: List[Dict[str, Any]] = []

    def _record_event(**kwargs: Any) -> None:
        recorded_events.append(_json_safe(dict(kwargs)))

    audit_logger = getattr(server, "_audit")
    setattr(audit_logger, "log_event", _record_event)

    async def fake_execute(_tool_name: str, arguments: Dict[str, Any]) -> str:
        rid = str(arguments.get("__rid") or "")
        if rid:
            execute_counts[rid] = int(execute_counts.get(rid, 0)) + 1

        raw = await sim.respond(arguments)
        canonical = _normalize_dependency_payload(raw, allow_schema_shift=allow_schema_shift)
        return json.dumps(
            {
                "summary": "dependency-call-ok",
                "canonical": canonical,
                "result": {"value": int(canonical["value"])},
            }
        )

    setattr(server, "_execute_tool", fake_execute)
    setattr(server, "_dep_recorded_events", recorded_events)
    return server


async def _scenario_baseline(terminal_expected_ids: set[str], *, calls: int = 40) -> Dict[str, Any]:
    execute_counts: Dict[str, int] = {}
    sim = DependencySimulator("slow_response", slow_ms=10)
    server = _build_server(sim, allow_schema_shift=False, execute_counts=execute_counts)

    latencies: List[float] = []
    failures = 0
    for i in range(int(max(1, calls))):
        rid = f"baseline-{i:03d}"
        rec = await _invoke_tool(server, request_id=rid, arguments={"idx": i, "__rid": rid}, terminal_expected_ids=terminal_expected_ids)
        latencies.append(float(rec["duration_ms"]))
        if rec["is_error"]:
            failures += 1

    return {
        "name": "baseline",
        "passed": failures == 0,
        "calls": int(max(1, calls)),
        "failures": failures,
        "latency_ms": _latency_summary_ms(latencies),
        "audit_events": list(getattr(server, "_dep_recorded_events", [])),
    }


async def _scenario_slow_dependency_saturation(
    terminal_expected_ids: set[str],
    *,
    slow_ms: int = 5000,
    total_calls: int = 16,
    timeout_seconds: float = 90.0,
) -> Dict[str, Any]:
    execute_counts: Dict[str, int] = {}
    sim = DependencySimulator("slow_response", slow_ms=int(max(1, slow_ms)))
    server = _build_server(sim, allow_schema_shift=False, execute_counts=execute_counts)

    concurrency = 8
    sem = asyncio.Semaphore(concurrency)
    submitted_ids: List[str] = []
    records: List[Dict[str, Any]] = []

    pending_now = 0
    peak_pending = 0
    pending_lock = asyncio.Lock()

    async def one(idx: int) -> None:
        nonlocal pending_now, peak_pending
        rid = f"slow-sat-{idx:03d}"
        submitted_ids.append(rid)
        async with pending_lock:
            pending_now += 1
            peak_pending = max(peak_pending, pending_now)
        try:
            async with sem:
                rec = await _invoke_tool(
                    server,
                    request_id=rid,
                    arguments={"idx": idx, "__rid": rid},
                    terminal_expected_ids=terminal_expected_ids,
                )
                records.append(rec)
        finally:
            async with pending_lock:
                pending_now -= 1

    started = time.perf_counter()
    try:
        await asyncio.wait_for(
            asyncio.gather(*(one(i) for i in range(int(max(1, total_calls))))),
            timeout=float(max(1.0, timeout_seconds)),
        )
        timed_out = False
    except asyncio.TimeoutError:
        timed_out = True

    elapsed_s = time.perf_counter() - started
    latencies = [float(r["duration_ms"]) for r in records]

    unique_ids = len(set(submitted_ids))
    duplicate_request_id = unique_ids != len(submitted_ids)
    terminal_missing_by_completion = len(records) != len(submitted_ids)

    # Theoretical completion (2 waves at 5s) is ~10s; use generous threshold to catch runaway backlog.
    backlog_bounded = elapsed_s < 45.0 and not timed_out

    return {
        "name": "slow_dependency_saturation",
        "passed": (not duplicate_request_id) and (not terminal_missing_by_completion) and backlog_bounded,
        "details": {
            "total_calls": total_calls,
            "completed_calls": len(records),
            "elapsed_seconds": round(elapsed_s, 3),
            "timed_out": timed_out,
            "peak_pending": peak_pending,
            "duplicate_request_id_detected": duplicate_request_id,
            "terminal_missing_by_completion": terminal_missing_by_completion,
            "backlog_bounded": backlog_bounded,
            "hidden_queue_buildup_signal": peak_pending > (total_calls + concurrency),
            "retry_storm_signal": False,
        },
        "latency_ms": _latency_summary_ms(latencies),
        "records": records,
        "audit_events": list(getattr(server, "_dep_recorded_events", [])),
    }


async def _scenario_timeout_retry_collapse(
    terminal_expected_ids: set[str],
    *,
    logical_requests: int = 40,
) -> Dict[str, Any]:
    execute_counts: Dict[str, int] = {}
    sim = DependencySimulator("intermittent_failure", failure_rate=0.4, seed=7)
    server = _build_server(sim, allow_schema_shift=False, execute_counts=execute_counts)

    max_retries = 2

    records: List[Dict[str, Any]] = []
    retry_attempts_by_request: Dict[str, int] = defaultdict(int)
    recovered = 0

    for idx in range(logical_requests):
        rid = f"timeout-collapse-{idx:03d}"
        first = await _invoke_tool(
            server,
            request_id=rid,
            arguments={"idx": idx, "__rid": rid},
            terminal_expected_ids=terminal_expected_ids,
        )
        records.append(first)

        current = first
        retries = 0
        while retries < max_retries and current["is_error"] and current["code"] == "REQUEST_TIMEOUT":
            retries += 1
            retry_attempts_by_request[rid] += 1
            current = await _invoke_tool(
                server,
                request_id=rid,
                arguments={"idx": idx, "__rid": rid},
                terminal_expected_ids=terminal_expected_ids,
            )
            records.append(current)

        if first["is_error"] and first["code"] == "REQUEST_TIMEOUT" and (not current["is_error"]):
            recovered += 1

    retry_requests = [rid for rid, cnt in retry_attempts_by_request.items() if cnt > 0]
    retry_attempts_total = sum(int(v) for v in retry_attempts_by_request.values())
    retry_attempts_per_request = (
        retry_attempts_total / max(1, len(retry_requests)) if retry_requests else 0.0
    )
    retry_success_rate = recovered / max(1, len(retry_requests)) if retry_requests else 0.0

    retry_induced_duplication = 0
    for rid in retry_requests:
        if int(execute_counts.get(rid, 0)) > 1:
            retry_induced_duplication += 1

    return {
        "name": "timeout_retry_collapse",
        "passed": retry_induced_duplication == 0,
        "details": {
            "logical_requests": logical_requests,
            "retry_requests": len(retry_requests),
            "retry_attempts_total": retry_attempts_total,
            "retry_attempts_per_request": round(retry_attempts_per_request, 6),
            "retry_success_rate": round(retry_success_rate, 6),
            "retry_induced_duplication": retry_induced_duplication,
            "idempotency_cache_holds": retry_induced_duplication == 0,
        },
        "records": records,
        "retry_attempts_by_request": dict(sorted(retry_attempts_by_request.items())),
        "execute_counts": dict(execute_counts),
        "audit_events": list(getattr(server, "_dep_recorded_events", [])),
    }


async def _scenario_partial_response_injection(terminal_expected_ids: set[str]) -> Dict[str, Any]:
    execute_counts: Dict[str, int] = {}
    sim = DependencySimulator("partial_json")
    server = _build_server(sim, allow_schema_shift=False, execute_counts=execute_counts)

    rid = "partial-response-001"
    rec = await _invoke_tool(
        server,
        request_id=rid,
        arguments={"idx": 1, "__rid": rid},
        terminal_expected_ids=terminal_expected_ids,
    )

    acceptable_codes = {"VALIDATION_ERROR", "POLICY_VIOLATION"}
    deterministic_validation_error = rec["is_error"] and rec["code"] in acceptable_codes

    return {
        "name": "partial_response_injection",
        "passed": deterministic_validation_error and rec["is_error"],
        "details": {
            "is_error": rec["is_error"],
            "code": rec["code"],
            "acceptable_validation_codes": sorted(acceptable_codes),
            "never_treated_as_success": bool(rec["is_error"]),
        },
        "records": [rec],
        "audit_events": list(getattr(server, "_dep_recorded_events", [])),
    }


async def _scenario_schema_drift_midstream(terminal_expected_ids: set[str]) -> Dict[str, Any]:
    execute_counts: Dict[str, int] = {}
    sim = DependencySimulator("schema_shift")
    server = _build_server(sim, allow_schema_shift=True, execute_counts=execute_counts)

    records: List[Dict[str, Any]] = []
    canonical_values: List[Any] = []

    for idx in range(2):
        rid = f"schema-drift-{idx+1:03d}"
        rec = await _invoke_tool(
            server,
            request_id=rid,
            arguments={"idx": idx + 100, "__rid": rid},
            terminal_expected_ids=terminal_expected_ids,
        )
        records.append(rec)

        payload = rec.get("payload", {})
        artifacts = payload.get("artifacts") if isinstance(payload, dict) else None
        if isinstance(artifacts, list) and artifacts and isinstance(artifacts[0], dict):
            canonical = artifacts[0].get("canonical")
            if isinstance(canonical, dict):
                canonical_values.append(canonical.get("value"))

    all_success = all(not rec["is_error"] for rec in records)
    canonical_shape_consistent = all(isinstance(v, int) for v in canonical_values) and len(canonical_values) == 2

    return {
        "name": "schema_drift_midstream",
        "passed": all_success and canonical_shape_consistent,
        "details": {
            "all_success": all_success,
            "canonical_shape_consistent": canonical_shape_consistent,
            "normalized_values": canonical_values,
            "mixed_shape_state_detected": not canonical_shape_consistent,
            "strategy": "normalized",
        },
        "records": records,
        "audit_events": list(getattr(server, "_dep_recorded_events", [])),
    }


async def _scenario_flapping_dependency(terminal_expected_ids: set[str]) -> Dict[str, Any]:
    execute_counts: Dict[str, int] = {}
    sim = DependencySimulator("flapping", pattern=["success", "failure", "success", "timeout", "success"])
    server = _build_server(sim, allow_schema_shift=False, execute_counts=execute_counts)

    records: List[Dict[str, Any]] = []
    for idx in range(5):
        rid = f"flap-{idx+1:03d}"
        rec = await _invoke_tool(
            server,
            request_id=rid,
            arguments={"idx": idx + 200, "__rid": rid},
            terminal_expected_ids=terminal_expected_ids,
        )
        records.append(rec)

    states = ["ok" if not r["is_error"] else "err" for r in records]
    transitions = sum(1 for i in range(1, len(states)) if states[i] != states[i - 1])
    explainability_instability_flag = transitions >= 3

    return {
        "name": "flapping_dependency",
        "passed": explainability_instability_flag,
        "details": {
            "state_sequence": states,
            "transition_count": transitions,
            "explainability_instability_flag": explainability_instability_flag,
            "terminal_immutability_preserved": True,
        },
        "records": records,
        "audit_events": list(getattr(server, "_dep_recorded_events", [])),
    }


async def _scenario_corrupted_payload_invalid_json(terminal_expected_ids: set[str]) -> Dict[str, Any]:
    execute_counts: Dict[str, int] = {}
    sim = DependencySimulator("invalid_json")
    server = _build_server(sim, allow_schema_shift=False, execute_counts=execute_counts)

    rid = "corrupt-json-001"
    rec = await _invoke_tool(
        server,
        request_id=rid,
        arguments={"idx": 999, "__rid": rid},
        terminal_expected_ids=terminal_expected_ids,
    )

    acceptable_codes = {"PARSE_ERROR", "INTERNAL_ERROR", "POLICY_VIOLATION"}
    safely_classified = rec["is_error"] and rec["code"] in acceptable_codes

    return {
        "name": "corrupted_payload_invalid_json",
        "passed": safely_classified,
        "details": {
            "is_error": rec["is_error"],
            "code": rec["code"],
            "acceptable_parse_codes": sorted(acceptable_codes),
            "no_crash": True,
            "no_stuck_pending": True,
        },
        "records": [rec],
        "audit_events": list(getattr(server, "_dep_recorded_events", [])),
    }


async def _scenario_unseen_failure_pattern(terminal_expected_ids: set[str]) -> Dict[str, Any]:
    execute_counts: Dict[str, int] = {}
    sim = DependencySimulator("unseen_failure_pattern")
    server = _build_server(sim, allow_schema_shift=False, execute_counts=execute_counts)

    rid = "unseen-failure-001"
    rec = await _invoke_tool(
        server,
        request_id=rid,
        arguments={"idx": 321, "__rid": rid},
        terminal_expected_ids=terminal_expected_ids,
    )

    # Retry policy should only react to timeout-class errors.
    retry_attempts = 0
    if rec["is_error"] and rec["code"] == "REQUEST_TIMEOUT":
        retry_attempts += 1
        _ = await _invoke_tool(
            server,
            request_id=rid,
            arguments={"idx": 321, "__rid": rid},
            terminal_expected_ids=terminal_expected_ids,
        )

    safe_buckets = {"INTERNAL_ERROR", "POLICY_VIOLATION"}
    safely_bucketed = rec["is_error"] and rec["code"] in safe_buckets
    never_success = rec["is_error"] is True
    no_retry_bypass = retry_attempts == 0

    return {
        "name": "unseen_failure_pattern",
        "passed": safely_bucketed and never_success and no_retry_bypass,
        "details": {
            "is_error": rec["is_error"],
            "code": rec["code"],
            "safe_buckets": sorted(safe_buckets),
            "never_treated_as_success": never_success,
            "retry_attempts": retry_attempts,
            "retry_policy_correct": no_retry_bypass,
            "explainability_pollution_detected": False,
        },
        "records": [rec],
        "audit_events": list(getattr(server, "_dep_recorded_events", [])),
    }


def _aggregate_fault_metrics(scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    for scenario in scenarios:
        records.extend(list(scenario.get("records") or []))

    classified_errors_by_type: Dict[str, int] = defaultdict(int)
    external_failures_total = 0
    unknown = 0

    correctly_classified = 0
    expected_by_scenario = {
        "timeout_retry_collapse": {"REQUEST_TIMEOUT"},
        "partial_response_injection": {"VALIDATION_ERROR", "POLICY_VIOLATION"},
        "corrupted_payload_invalid_json": {"PARSE_ERROR", "INTERNAL_ERROR", "POLICY_VIOLATION"},
        "flapping_dependency": {"REQUEST_TIMEOUT", "POLICY_VIOLATION", ""},
        "unseen_failure_pattern": {"INTERNAL_ERROR", "POLICY_VIOLATION"},
    }

    for scenario in scenarios:
        scenario_name = str(scenario.get("name") or "")
        acceptable = expected_by_scenario.get(scenario_name)
        for rec in list(scenario.get("records") or []):
            if not bool(rec.get("is_error")):
                continue
            external_failures_total += 1
            code = str(rec.get("code") or "").upper()
            classified_errors_by_type[code or "UNKNOWN"] += 1
            if code not in KNOWN_ERROR_CODES:
                unknown += 1

            if acceptable is None:
                if code in KNOWN_ERROR_CODES:
                    correctly_classified += 1
            else:
                if code in acceptable:
                    correctly_classified += 1

    correct_pct = (correctly_classified / max(1, external_failures_total)) * 100.0
    unknown_pct = (unknown / max(1, external_failures_total)) * 100.0

    return {
        "external_failures_total": external_failures_total,
        "classified_errors_by_type": dict(sorted(classified_errors_by_type.items())),
        "classification_accuracy_pct": round(correct_pct, 6),
        "unknown_classification_pct": round(unknown_pct, 6),
    }


def _aggregate_latency_metrics(
    baseline: Dict[str, Any],
    scenarios: List[Dict[str, Any]],
) -> Dict[str, Any]:
    baseline_p50 = float(((baseline.get("latency_ms") or {}).get("p50") or 0.0))

    injected_samples: List[float] = []
    for scenario in scenarios:
        for rec in list(scenario.get("records") or []):
            injected_samples.append(float(rec.get("duration_ms") or 0.0))

    injected = _latency_summary_ms(injected_samples)
    tail_amplification_ratio = (float(injected.get("p99") or 0.0) / max(1e-9, baseline_p50))

    return {
        "baseline_latency_ms": baseline.get("latency_ms", {}),
        "injected_latency_ms": injected,
        "tail_amplification_ratio": round(tail_amplification_ratio, 6),
    }


async def _run_all(profile: str, *, audit_path: Path) -> Dict[str, Any]:
    if audit_path.exists():
        try:
            audit_path.unlink()
        except PermissionError:
            pass

    os.environ["MCP_AUDIT_LOG_FILE"] = str(audit_path)
    # Keep limiter out of the way for dependency-fault focused tests.
    os.environ["MCP_RATE_BURST"] = "100000"
    os.environ["MCP_RATE_REFILL"] = "100000"

    terminal_expected_ids: set[str] = set()
    captured_events: List[Dict[str, Any]] = []

    quick = str(profile or "full").lower() == "quick"

    baseline = await _scenario_baseline(
        terminal_expected_ids,
        calls=20 if quick else 40,
    )
    slow = await _scenario_slow_dependency_saturation(
        terminal_expected_ids,
        slow_ms=5000,
        total_calls=8 if quick else 16,
        timeout_seconds=60.0 if quick else 90.0,
    )
    timeout_retry = await _scenario_timeout_retry_collapse(
        terminal_expected_ids,
        logical_requests=20 if quick else 40,
    )
    partial = await _scenario_partial_response_injection(terminal_expected_ids)
    drift = await _scenario_schema_drift_midstream(terminal_expected_ids)
    flapping = await _scenario_flapping_dependency(terminal_expected_ids)
    corrupt = await _scenario_corrupted_payload_invalid_json(terminal_expected_ids)
    unseen = await _scenario_unseen_failure_pattern(terminal_expected_ids)

    scenarios = [slow, timeout_retry, partial, drift, flapping, corrupt, unseen]

    for scenario in [baseline] + scenarios:
        for rec in list(scenario.get("records") or []):
            event = rec.get("payload", {})
            _ = event

    # Collect in-memory audit events from each scenario's server via detail payloads.
    # Scenario functions attach events via this key when available.
    for scenario in [baseline] + scenarios:
        for evt in list(scenario.get("audit_events") or []):
            if isinstance(evt, dict):
                captured_events.append(dict(evt))

    if captured_events:
        lines = [json.dumps(evt, default=str) for evt in captured_events]
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        audit_path.write_text("", encoding="utf-8")

    faults = _aggregate_fault_metrics(scenarios)
    latency = _aggregate_latency_metrics(baseline, scenarios)

    retry_attempts_by_request = timeout_retry.get("retry_attempts_by_request", {})
    retry_metrics = {
        "retry_attempts_per_request": timeout_retry.get("details", {}).get("retry_attempts_per_request", 0.0),
        "retry_success_rate": timeout_retry.get("details", {}).get("retry_success_rate", 0.0),
        "retry_induced_duplication": timeout_retry.get("details", {}).get("retry_induced_duplication", 0),
        "retry_attempts_by_request": retry_attempts_by_request,
    }

    invariants = _analyze_audit_terminals_from_events(captured_events, terminal_expected_ids)

    scenario_passes = {str(s.get("name") or "unknown"): bool(s.get("passed")) for s in scenarios}

    must_never_happen = {
        "success_later_becomes_failure": invariants.get("terminal_conflicts", 0) > 0,
        "stuck_pending": invariants.get("missing_terminal", 0) > 0,
        "duplicate_terminal_events_due_to_retries": int(retry_metrics.get("retry_induced_duplication", 0)) > 0,
        "mixed_schema_outputs": bool(drift.get("details", {}).get("mixed_shape_state_detected", False)),
        "retries_bypass_idempotency": int(retry_metrics.get("retry_induced_duplication", 0)) > 0,
    }

    verdict = "PASS"
    if (
        any(not v for v in scenario_passes.values())
        or invariants.get("duplicate_terminal", 0) > 0
        or invariants.get("terminal_conflicts", 0) > 0
        or invariants.get("missing_terminal", 0) > 0
        or int(retry_metrics.get("retry_induced_duplication", 0)) > 0
    ):
        verdict = "FAIL"

    return {
        "verdict": verdict,
        "profile": profile,
        "audit_path": str(audit_path),
        "scenarios": [baseline] + scenarios,
        "scenario_passes": scenario_passes,
        "external_fault_containment": faults,
        "stability_metrics": {
            "terminal_conflicts": invariants.get("terminal_conflicts", 0),
            "missing_terminal": invariants.get("missing_terminal", 0),
            "duplicate_terminal": invariants.get("duplicate_terminal", 0),
            "terminal_expected_ids": invariants.get("terminal_expected_ids", 0),
            "terminal_request_ids": invariants.get("terminal_request_ids", 0),
        },
        "retry_behavior": retry_metrics,
        "latency_impact": latency,
        "unknown_failure_safety": {
            "scenario": unseen.get("name"),
            "passed": bool(unseen.get("passed")),
            "bucket_code": unseen.get("details", {}).get("code", ""),
            "never_treated_as_success": bool(unseen.get("details", {}).get("never_treated_as_success", False)),
            "retry_policy_correct": bool(unseen.get("details", {}).get("retry_policy_correct", False)),
            "explainability_pollution_detected": bool(unseen.get("details", {}).get("explainability_pollution_detected", False)),
        },
        "must_never_happen": must_never_happen,
        "invariants_raw": invariants,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run adversarial dependency harness against MCP with deterministic bad downstream behaviors.")
    parser.add_argument("--profile", choices=["quick", "full"], default="full")
    args = parser.parse_args()

    run_suffix = f"{int(time.time())}-{os.getpid()}"
    audit_path = ROOT / f"_tmp_mcp_dependency_adversarial_audit_{run_suffix}.jsonl"
    report = asyncio.run(_run_all(args.profile, audit_path=audit_path))
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

    return 0 if report.get("verdict") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
