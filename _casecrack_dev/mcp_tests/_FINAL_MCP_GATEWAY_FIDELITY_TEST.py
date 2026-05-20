#!/usr/bin/env python3
"""Gateway fidelity validation for MCP facade endpoints.

Compares direct MCP backend tool execution with dashboard gateway responses.
Ensures pass-through fidelity for status/code/request_id/payload structure.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent
CASECRACK_ROOT = ROOT / "CaseCrack"
if str(CASECRACK_ROOT) not in sys.path:
    sys.path.insert(0, str(CASECRACK_ROOT))

SecurityMCPServer = importlib.import_module("tools.burp_enterprise.mcp.mcp_server").SecurityMCPServer
MCPPrincipal = importlib.import_module("tools.burp_enterprise.mcp.mcp_auth").MCPPrincipal
ReconDashboard = importlib.import_module("tools.burp_enterprise.recon_dashboard.server").ReconDashboard


@dataclass
class Check:
    name: str
    passed: bool
    details: Dict[str, Any]


class FakeCallRequest:
    content_length = 128

    def __init__(self, name: str, arguments: Dict[str, Any]):
        self._payload = {"name": name, "arguments": arguments}

    async def json(self) -> Dict[str, Any]:
        return self._payload


class FakeQueryRequest:
    def __init__(self, query: Dict[str, str]):
        self.query = query


def parse_web_response(response: Any) -> Dict[str, Any]:
    try:
        return json.loads(response.text)
    except Exception:
        return {"ok": False, "error": "invalid_gateway_json", "raw": getattr(response, "text", "")}


def normalized_status(payload: Dict[str, Any]) -> str:
    status = str(payload.get("status") or "").strip().lower()
    if status:
        return status
    return "ok" if payload.get("ok") else "error"


def payload_shape(payload: Dict[str, Any]) -> Dict[str, str]:
    return {k: type(v).__name__ for k, v in sorted(payload.items())}


def core_shape(payload: Dict[str, Any]) -> Dict[str, str]:
    keys = ("ok", "error", "code", "request_id", "summary", "tool")
    return {k: type(payload.get(k)).__name__ for k in keys if k in payload}


async def compare_tool(
    dashboard: Any,
    backend: Any,
    principal: Any,
    name: str,
    arguments: Dict[str, Any],
) -> Check:
    direct_raw_text, direct_is_error = await backend.execute_tool_request(
        name,
        arguments,
        principal=principal,
        request_id=f"direct-{name}-fid",
    )
    direct_payload = json.loads(direct_raw_text)

    gateway_response = await dashboard._handle_mcp_call(FakeCallRequest(name, arguments))
    gateway_payload = parse_web_response(gateway_response)

    direct_core = core_shape(direct_payload)
    gateway_core = core_shape(gateway_payload)

    passed = (
        normalized_status(gateway_payload) == normalized_status(direct_payload)
        and str(gateway_payload.get("code") or "") == str(direct_payload.get("code") or "")
        and bool(str(gateway_payload.get("request_id") or ""))
        and bool(str(direct_payload.get("request_id") or ""))
        and direct_core == gateway_core
    )

    return Check(
        name=f"tool_fidelity::{name}",
        passed=passed,
        details={
            "direct_is_error": direct_is_error,
            "gateway_http_status": getattr(gateway_response, "status", None),
            "direct_status": normalized_status(direct_payload),
            "gateway_status": normalized_status(gateway_payload),
            "direct_code": direct_payload.get("code"),
            "gateway_code": gateway_payload.get("code"),
            "direct_request_id": direct_payload.get("request_id"),
            "gateway_request_id": gateway_payload.get("request_id"),
            "shape_match": direct_core == gateway_core,
            "direct_shape": payload_shape(direct_payload),
            "gateway_shape": payload_shape(gateway_payload),
            "direct_core_shape": direct_core,
            "gateway_core_shape": gateway_core,
        },
    )


async def check_snapshot_history_request_id(dashboard: Any) -> Check:
    call_response = await dashboard._handle_mcp_call(FakeCallRequest("list_targets", {"limit": 3}))
    call_payload = parse_web_response(call_response)
    request_id = str(call_payload.get("request_id") or "")

    snapshot_response = await dashboard._handle_mcp_readonly_snapshot(FakeQueryRequest({}))
    snapshot_payload = parse_web_response(snapshot_response)
    latest_action = snapshot_payload.get("latest_action") or {}
    recent_actions = snapshot_payload.get("recent_actions") or []

    in_recent = any(str(item.get("request_id") or "") == request_id for item in recent_actions)
    passed = bool(request_id) and str(latest_action.get("request_id") or "") == request_id and in_recent

    return Check(
        name="snapshot_history_request_id",
        passed=passed,
        details={
            "request_id": request_id,
            "latest_action_request_id": latest_action.get("request_id"),
            "recent_action_count": len(recent_actions),
            "request_id_in_recent_actions": in_recent,
            "snapshot_status": snapshot_payload.get("status"),
        },
    )


async def check_gateway_surface(dashboard: Any) -> Check:
    targets_response = await dashboard._handle_mcp_targets(FakeQueryRequest({"page": "1", "page_size": "5"}))
    report_response = await dashboard._handle_mcp_report(FakeQueryRequest({"path": "nonexistent-report.json"}))
    snapshot_response = await dashboard._handle_mcp_readonly_snapshot(FakeQueryRequest({}))

    targets_payload = parse_web_response(targets_response)
    report_payload = parse_web_response(report_response)
    snapshot_payload = parse_web_response(snapshot_response)

    passed = (
        isinstance(targets_payload, dict)
        and isinstance(report_payload, dict)
        and isinstance(snapshot_payload, dict)
        and str(snapshot_payload.get("status") or "") in {"offline", "degraded", "healthy"}
    )

    return Check(
        name="gateway_surface_contract",
        passed=passed,
        details={
            "targets_status": getattr(targets_response, "status", None),
            "report_status": getattr(report_response, "status", None),
            "snapshot_status": snapshot_payload.get("status"),
            "snapshot_source_of_truth": snapshot_payload.get("source_of_truth"),
        },
    )


async def main() -> int:
    backend = SecurityMCPServer()
    dashboard = ReconDashboard(auto_open=False)

    principal = MCPPrincipal(
        principal_id="gateway-fidelity",
        tenant_id="control-plane",
        role="system",
        auth_type="test",
        claims={"plan": "enterprise", "admin_control": True},
    )

    checks: List[Check] = []
    checks.append(await compare_tool(dashboard, backend, principal, "list_targets", {"limit": 5, "include_sessions": True}))
    checks.append(await compare_tool(dashboard, backend, principal, "get_report", {"path": "nonexistent-report.json"}))
    checks.append(await compare_tool(dashboard, backend, principal, "run_burp_scan", {"target": "https://example.com"}))
    checks.append(await check_snapshot_history_request_id(dashboard))
    checks.append(await check_gateway_surface(dashboard))

    blocking = [c for c in checks if not c.passed]
    report = {
        "verdict": "GO" if not blocking else "NO_GO",
        "checks": [asdict(c) for c in checks],
        "failures": [asdict(c) for c in blocking],
    }

    out_path = ROOT / "_FINAL_MCP_GATEWAY_FIDELITY_REPORT.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

    return 0 if not blocking else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
