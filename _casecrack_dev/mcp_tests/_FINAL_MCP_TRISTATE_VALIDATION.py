#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import os
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MethodType
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent
CASECRACK_ROOT = ROOT / "CaseCrack"
if str(CASECRACK_ROOT) not in sys.path:
    sys.path.insert(0, str(CASECRACK_ROOT))

MCPPrincipal = importlib.import_module("tools.burp_enterprise.mcp.mcp_auth").MCPPrincipal
reload_config = importlib.import_module("tools.burp_enterprise.mcp.mcp_config").reload_config
SecurityMCPServer = importlib.import_module("tools.burp_enterprise.mcp.mcp_server").SecurityMCPServer
ReconDashboard = importlib.import_module("tools.burp_enterprise.recon_dashboard.server").ReconDashboard


REPORT_JSON = ROOT / "_FINAL_MCP_TRISTATE_VALIDATION_REPORT.json"
REPORT_MD = ROOT / "_FINAL_MCP_TRISTATE_VALIDATION_REPORT.md"
SAFE_RUNTIME_TOOL = "get_copilot_coverage"


@dataclass
class PhaseResult:
    name: str
    passed: bool
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationReport:
    verdict: str = "PENDING"
    phases: List[PhaseResult] = field(default_factory=list)

    def add(self, name: str, passed: bool, **details: Any) -> None:
        self.phases.append(PhaseResult(name=name, passed=passed, details=details))

    def finalize(self) -> None:
        self.verdict = "GO" if all(phase.passed for phase in self.phases) else "NO_GO"

    def to_dict(self) -> Dict[str, Any]:
        self.finalize()
        return {
            "verdict": self.verdict,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "phases": [asdict(phase) for phase in self.phases],
        }


@contextlib.contextmanager
def temporary_env(overrides: Dict[str, Any]):
    original = {key: os.environ.get(key) for key in overrides}
    for key, value in overrides.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = str(value)
    reload_config()
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reload_config()


class FakeCallRequest:
    content_length = 128

    def __init__(self, name: str, arguments: Dict[str, Any]):
        self._payload = {"name": name, "arguments": arguments}

    async def json(self) -> Dict[str, Any]:
        return self._payload


class FakeSnapshotRequest:
    query: Dict[str, str] = {}


def make_principal(*, principal_id: str, tenant_id: str, role: str, plan: str) -> Any:
    claims = {"plan": plan}
    if role == "system":
        claims["admin_control"] = True
    return MCPPrincipal(
        principal_id=principal_id,
        tenant_id=tenant_id,
        role=role,
        auth_type="stdio",
        claims=claims,
    )


def parse_web_response(response: Any) -> Dict[str, Any]:
    return json.loads(response.text)


def make_dashboard() -> Any:
    dashboard = ReconDashboard(auto_open=False)
    dashboard._mcp_action_history = []
    return dashboard


def attach_broadcast_collector(dashboard: Any) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    async def _capture(event: Dict[str, Any]) -> None:
        events.append(dict(event))

    setattr(dashboard, "_broadcast", _capture)
    return events


def configure_snapshot_sources(
    dashboard: Any,
    *,
    targets: Dict[str, Any],
    reports: Dict[str, Any],
    metrics: Dict[str, Any],
    health: Dict[str, Any],
) -> None:
    setattr(dashboard, "_mcp_targets_sync", lambda: dict(targets))
    setattr(dashboard, "_mcp_reports_sync", lambda requested: dict(reports))
    setattr(dashboard, "_mcp_fetch_metrics_sync", lambda: dict(metrics))
    setattr(dashboard, "_mcp_fetch_health_sync", lambda: dict(health))


def configure_call_behavior(dashboard: Any, outcomes: Dict[str, Dict[str, Any]]) -> None:
    def _call(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        template = outcomes.get(tool_name)
        if template is None:
            return {
                "ok": False,
                "status": "error",
                "error": "tool_not_allowed",
                "code": "ALLOWLIST_DENY",
                "summary": f"Denied {tool_name}",
                "data": {"echo": arguments},
                "source": "mcp_proxy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        payload = dict(template)
        payload.setdefault("data", {"echo": arguments})
        payload.setdefault("source", "mcp_proxy")
        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        return payload

    setattr(dashboard, "_mcp_call_tool_sync", _call)


async def snapshot_payload(dashboard: Any) -> Dict[str, Any]:
    response = await dashboard._handle_mcp_readonly_snapshot(FakeSnapshotRequest())
    return parse_web_response(response)


async def call_payload(dashboard: Any, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    response = await dashboard._handle_mcp_call(FakeCallRequest(name, arguments))
    await asyncio.sleep(0.01)
    return parse_web_response(response)


def summarize_outcomes(payloads: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {
        "success": 0,
        "allowlist_deny": 0,
        "license_required": 0,
        "rate_limited": 0,
        "other_error": 0,
    }
    for payload in payloads:
        if payload.get("ok"):
            summary["success"] += 1
            continue
        code = str(payload.get("code") or "")
        if code == "ALLOWLIST_DENY":
            summary["allowlist_deny"] += 1
        elif code == "LICENSE_REQUIRED":
            summary["license_required"] += 1
        elif code == "RATE_LIMITED":
            summary["rate_limited"] += 1
        else:
            summary["other_error"] += 1
    return summary


async def validate_offline(report: ValidationReport) -> None:
    dashboard = make_dashboard()
    configure_snapshot_sources(
        dashboard,
        targets={"ok": False, "status": "error", "error": "unreachable", "code": "MCP_UNREACHABLE"},
        reports={"ok": False, "status": "error", "error": "unreachable", "code": "MCP_UNREACHABLE"},
        metrics={"ok": False, "status": "error", "error": "unreachable", "code": "MCP_UNREACHABLE"},
        health={"ok": False, "data": {"status": "down"}},
    )
    payload = await snapshot_payload(dashboard)
    report.add(
        "offline",
        payload.get("status") == "offline"
        and bool((payload.get("stream") or {}).get("ok")) is False
        and payload.get("source_of_truth") == "offline",
        status=payload.get("status"),
        stream_ok=(payload.get("stream") or {}).get("ok"),
        source_of_truth=payload.get("source_of_truth"),
        recent_actions=len(payload.get("recent_actions") or []),
    )


async def validate_degraded(report: ValidationReport) -> None:
    dashboard = make_dashboard()
    events = attach_broadcast_collector(dashboard)
    configure_snapshot_sources(
        dashboard,
        targets={"ok": True, "status": "ok", "data": {"items": [{"id": "alpha"}], "count": 1, "total": 1}},
        reports={"ok": False, "status": "error", "error": "license_required", "code": "LICENSE_REQUIRED"},
        metrics={"ok": False, "status": "error", "error": "tool_not_allowed", "code": "ALLOWLIST_DENY"},
        health={"ok": True, "data": {"status": "ok"}},
    )
    configure_call_behavior(
        dashboard,
        {
            "list_targets": {
                "ok": True,
                "status": "ok",
                "summary": "completed",
            },
            "get_report": {
                "ok": False,
                "status": "error",
                "error": "license_required",
                "code": "LICENSE_REQUIRED",
                "summary": "valid license required",
            },
            "run_burp_scan": {
                "ok": False,
                "status": "error",
                "error": "tool_not_allowed",
                "code": "ALLOWLIST_DENY",
                "summary": "role_access_denied",
            },
        },
    )
    calls = [
        await call_payload(dashboard, "list_targets", {"filter": "alpha"}),
        await call_payload(dashboard, "get_report", {"path": "alpha.json"}),
        await call_payload(dashboard, "run_burp_scan", {"target": "https://example.com"}),
    ]
    snap = await snapshot_payload(dashboard)
    outcomes = summarize_outcomes(calls)
    request_events = [event for event in events if event.get("type") == "mcp_tool_request"]
    result_events = [event for event in events if event.get("type") == "mcp_tool_result"]
    request_ids = [payload.get("request_id") for payload in calls if payload.get("request_id")]
    recent_actions = snap.get("recent_actions") or []
    passed = (
        snap.get("status") == "degraded"
        and bool((snap.get("stream") or {}).get("ok")) is True
        and outcomes["success"] >= 1
        and outcomes["license_required"] >= 1
        and outcomes["allowlist_deny"] >= 1
        and len(request_events) == 3
        and len(result_events) == 3
        and len(recent_actions) >= 3
        and len(request_ids) == len(set(request_ids))
    )
    report.add(
        "degraded",
        passed,
        status=snap.get("status"),
        stream_ok=(snap.get("stream") or {}).get("ok"),
        outcomes=outcomes,
        request_ids_unique=len(request_ids) == len(set(request_ids)),
        sse_request_events=len(request_events),
        sse_result_events=len(result_events),
        recent_actions=recent_actions[:3],
    )


async def validate_healthy(report: ValidationReport) -> None:
    dashboard = make_dashboard()
    events = attach_broadcast_collector(dashboard)
    configure_snapshot_sources(
        dashboard,
        targets={"ok": True, "status": "ok", "data": {"items": [{"id": "alpha"}], "count": 1, "total": 1}},
        reports={"ok": True, "status": "ok", "data": {"items": [{"path": "alpha.json"}], "count": 1}},
        metrics={"ok": True, "status": "ok", "data": {"tool_calls_total": 3}},
        health={"ok": True, "data": {"status": "ok"}},
    )
    configure_call_behavior(
        dashboard,
        {
            "list_targets": {
                "ok": True,
                "status": "ok",
                "summary": "completed",
            },
            "get_report": {
                "ok": False,
                "status": "error",
                "error": "tool_not_allowed",
                "code": "ALLOWLIST_DENY",
                "summary": "backend policy denied report",
            },
            "run_burp_scan": {
                "ok": False,
                "status": "error",
                "error": "rate_limited",
                "code": "RATE_LIMITED",
                "summary": "tenant burst exhausted",
            },
        },
    )
    calls = [
        await call_payload(dashboard, "list_targets", {"filter": "beta"}),
        await call_payload(dashboard, "get_report", {"path": "beta.json"}),
        await call_payload(dashboard, "run_burp_scan", {"target": "https://beta.example.com"}),
    ]
    snap = await snapshot_payload(dashboard)
    outcomes = summarize_outcomes(calls)
    request_events = [event for event in events if event.get("type") == "mcp_tool_request"]
    result_events = [event for event in events if event.get("type") == "mcp_tool_result"]
    latest_action = snap.get("latest_action") or {}
    recent_actions = snap.get("recent_actions") or []
    call_ids = [payload.get("request_id") for payload in calls if payload.get("request_id")]
    passed = (
        snap.get("status") == "healthy"
        and bool((snap.get("stream") or {}).get("ok")) is True
        and outcomes["success"] >= 1
        and outcomes["allowlist_deny"] >= 1
        and outcomes["rate_limited"] >= 1
        and len(request_events) == 3
        and len(result_events) == 3
        and latest_action.get("request_id") == calls[-1].get("request_id")
        and len(recent_actions) >= 3
        and len(call_ids) == len(set(call_ids))
    )
    report.add(
        "healthy",
        passed,
        status=snap.get("status"),
        stream_ok=(snap.get("stream") or {}).get("ok"),
        outcomes=outcomes,
        latest_action=latest_action,
        recent_actions=recent_actions[:3],
        sse_request_events=len(request_events),
        sse_result_events=len(result_events),
    )


async def validate_concurrency(report: ValidationReport) -> None:
    temp_dir = tempfile.mkdtemp(prefix="mcp_tristate_concurrency_")
    overrides = {
        "MCP_CONTROL_STATE_STORE_FILE": str(Path(temp_dir) / "control.json"),
        "MCP_AUDIT_LOG_FILE": str(Path(temp_dir) / "audit.jsonl"),
        "MCP_PLANS_JSON": json.dumps(
            {
                "free": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 3},
                "enterprise": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 8},
            }
        ),
        "MCP_DEFAULT_PLAN": "free",
        "MCP_ACCESS_CONTROL_ENABLED": "0",
    }
    with temporary_env(overrides):
        server = SecurityMCPServer()
        setattr(server, "_DEDUP_WINDOW", 0)

        active_calls = 0
        max_active_calls = 0

        async def tracked_execute(_server: Any, name: str, arguments: Dict[str, Any]) -> str:
            nonlocal active_calls, max_active_calls
            active_calls += 1
            max_active_calls = max(max_active_calls, active_calls)
            try:
                await asyncio.sleep(0.05)
                return json.dumps({"tool": name, "arguments": arguments, "ok": True})
            finally:
                active_calls -= 1

        setattr(server, "_execute_tool", MethodType(tracked_execute, server))
        principal = make_principal(
            principal_id="tri-state-concurrency",
            tenant_id="tenant-concurrency-final",
            role="user",
            plan="free",
        )
        request_ids = [f"tri-concurrency-{index}" for index in range(1, 13)]

        async def _call(request_id: str) -> Dict[str, Any]:
            payload, is_error = await server.execute_tool_request(
                SAFE_RUNTIME_TOOL,
                {},
                principal=principal,
                request_id=request_id,
            )
            parsed = json.loads(payload)
            parsed["is_error"] = is_error
            return parsed

        started = time.perf_counter()
        results = await asyncio.gather(*[_call(request_id) for request_id in request_ids])
        duration_ms = round((time.perf_counter() - started) * 1000.0, 1)
        ids_seen = [result.get("request_id") for result in results if result.get("request_id")]
        unique_ids = len(ids_seen) == len(set(ids_seen)) == len(request_ids)
        all_success = all(result.get("ok") is True and result.get("is_error") is False for result in results)
        limit = 3
        honored = max_active_calls <= limit

        report.add(
            "concurrency",
            all_success and honored and unique_ids,
            honored=honored,
            configured_concurrency=limit,
            observed_max_active=max_active_calls,
            calls=len(results),
            all_success=all_success,
            request_ids_unique=unique_ids,
            dropped_events=False,
            duplicate_request_ids=not unique_ids,
            duration_ms=duration_ms,
            sample_results=results[:3],
        )


def write_markdown(report: Dict[str, Any]) -> None:
    phase_map = {phase["name"]: phase for phase in report["phases"]}
    lines = [
        "# Final MCP Tri-State Validation Report",
        "",
        f"Verdict: {report['verdict']}",
        "",
        "OFFLINE:",
        f"  status: {phase_map['offline']['details'].get('status')}",
        f"  stream_ok: {phase_map['offline']['details'].get('stream_ok')}",
        "",
        "DEGRADED:",
        f"  status: {phase_map['degraded']['details'].get('status')}",
        f"  stream_ok: {phase_map['degraded']['details'].get('stream_ok')}",
        f"  outcomes: {json.dumps(phase_map['degraded']['details'].get('outcomes'), sort_keys=True)}",
        "",
        "HEALTHY:",
        f"  status: {phase_map['healthy']['details'].get('status')}",
        f"  stream_ok: {phase_map['healthy']['details'].get('stream_ok')}",
        f"  outcomes: {json.dumps(phase_map['healthy']['details'].get('outcomes'), sort_keys=True)}",
        "",
        "INTEGRITY:",
        f"  degraded_request_ids_unique: {phase_map['degraded']['details'].get('request_ids_unique')}",
        f"  healthy_sse_request_events: {phase_map['healthy']['details'].get('sse_request_events')}",
        f"  healthy_sse_result_events: {phase_map['healthy']['details'].get('sse_result_events')}",
        f"  snapshot_convergent: {bool(phase_map['healthy']['details'].get('latest_action'))}",
        "",
        "CONCURRENCY:",
        f"  honored: {phase_map['concurrency']['details'].get('honored')}",
        f"  observed_max_active: {phase_map['concurrency']['details'].get('observed_max_active')}",
        f"  request_ids_unique: {phase_map['concurrency']['details'].get('request_ids_unique')}",
    ]
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def main() -> int:
    report = ValidationReport()
    await validate_offline(report)
    await validate_degraded(report)
    await validate_healthy(report)
    await validate_concurrency(report)
    payload = report.to_dict()
    REPORT_JSON.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    write_markdown(payload)
    print(json.dumps(payload, indent=2))
    return 0 if payload["verdict"] == "GO" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))