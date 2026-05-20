#!/usr/bin/env python3
"""Strict live-runtime frontend integration gate for the MCP backend.

This verifier checks the real Burp Enterprise MCP runtime under
CaseCrack/tools/burp_enterprise/mcp/, not the root-level Phase 1 prototypes.

It is intentionally strict:
- Missing Phase 1 tools are a hard blocker.
- Missing golden dataset artifacts are a hard blocker.
- Control-plane persistence and recovery semantics must be executable.
- Metrics, audit, and SSE payloads are checked against the live server.

The script writes a JSON report to _FINAL_FRONTEND_INTEGRATION_GATE_REPORT.json
and exits non-zero whenever any blocking check fails.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import MethodType
from typing import Any, Dict, Iterable, List


ROOT = Path(__file__).resolve().parent
CASECRACK_ROOT = ROOT / "CaseCrack"
if str(CASECRACK_ROOT) not in sys.path:
    sys.path.insert(0, str(CASECRACK_ROOT))

MCPPrincipal = importlib.import_module("tools.burp_enterprise.mcp.mcp_auth").MCPPrincipal
reload_config = importlib.import_module("tools.burp_enterprise.mcp.mcp_config").reload_config
MCPHTTPTransport = importlib.import_module("tools.burp_enterprise.mcp.mcp_http_server").MCPHTTPTransport
SecurityMCPServer = importlib.import_module("tools.burp_enterprise.mcp.mcp_server").SecurityMCPServer
ReconDashboard = importlib.import_module("tools.burp_enterprise.recon_dashboard.server").ReconDashboard


REQUIRED_PHASE1_TOOLS = {"run_burp_scan", "list_targets", "get_report"}
REQUIRED_METRICS = {
    "tenant_requests_total",
    "tenant_rate_limited_total",
    "passthrough_calls_total",
    "tenant_control_actions_total",
    "tenant_control_state",
}
SAFE_RUNTIME_TOOL = "get_copilot_coverage"
GOLDEN_DATASET = ROOT / "_PHASE1_GOLDEN_DATASET.json"
REPORT_PATH = ROOT / "_FINAL_FRONTEND_INTEGRATION_GATE_REPORT.json"
FRONTEND_JS_ROOT = CASECRACK_ROOT / "tools" / "burp_enterprise" / "static" / "js"


@dataclass
class CheckResult:
    name: str
    blocking: bool
    passed: bool
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationReport:
    verdict: str = "PENDING"
    checks: List[CheckResult] = field(default_factory=list)

    def add(self, name: str, blocking: bool, passed: bool, **details: Any) -> None:
        self.checks.append(
            CheckResult(
                name=name,
                blocking=blocking,
                passed=passed,
                details=details,
            )
        )

    def finalize(self) -> None:
        blocking_failures = [check for check in self.checks if check.blocking and not check.passed]
        self.verdict = "GO" if not blocking_failures else "NO_GO"

    def to_dict(self) -> Dict[str, Any]:
        self.finalize()
        return {
            "verdict": self.verdict,
            "blocking_failures": [
                {
                    "name": check.name,
                    "details": check.details,
                }
                for check in self.checks
                if check.blocking and not check.passed
            ],
            "checks": [asdict(check) for check in self.checks],
        }


@contextlib.contextmanager
def temporary_env(overrides: Dict[str, Any]) -> Iterable[None]:
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


def parse_payload(payload: str) -> Dict[str, Any]:
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {"raw": payload}


def make_principal(
    *,
    principal_id: str,
    tenant_id: str,
    role: str,
    plan: str,
    auth_type: str = "stdio",
) -> Any:
    claims = {"plan": plan}
    if role == "system":
        claims["admin_control"] = True
    return MCPPrincipal(
        principal_id=principal_id,
        tenant_id=tenant_id,
        role=role,
        auth_type=auth_type,
        claims=claims,
    )


async def call_tool(
    server: Any,
    name: str,
    arguments: Dict[str, Any],
    *,
    principal: MCPPrincipal,
    request_id: str,
) -> tuple[Dict[str, Any], bool]:
    payload, is_error = await server.execute_tool_request(
        name,
        arguments,
        principal=principal,
        request_id=request_id,
    )
    return parse_payload(payload), is_error


def live_server() -> Any:
    return SecurityMCPServer()


async def check_required_tool_surface(report: VerificationReport) -> None:
    server = live_server()
    names = {tool["name"] for tool in server.get_tool_schemas()}
    missing = sorted(REQUIRED_PHASE1_TOOLS - names)
    report.add(
        "phase1_tool_surface_present",
        True,
        not missing,
        required=sorted(REQUIRED_PHASE1_TOOLS),
        present=sorted(REQUIRED_PHASE1_TOOLS & names),
        missing=missing,
        tool_count=len(names),
    )


async def check_golden_dataset(report: VerificationReport) -> None:
    report.add(
        "golden_dataset_present",
        True,
        GOLDEN_DATASET.exists(),
        path=str(GOLDEN_DATASET),
        exists=GOLDEN_DATASET.exists(),
    )


async def check_generic_enforcement(report: VerificationReport) -> None:
    temp_dir = tempfile.mkdtemp(prefix="frontend_gate_enforcement_")
    if temp_dir:
        overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(temp_dir) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(Path(temp_dir) / "audit.jsonl"),
            "MCP_PLANS_JSON": json.dumps(
                {
                    "free": {"burst": 1.0, "refill": 0.0, "daily": 1, "concurrency": 1},
                    "enterprise": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 8},
                }
            ),
            "MCP_DEFAULT_PLAN": "free",
        }
        with temporary_env(overrides):
            server = live_server()
            setattr(server, "_DEDUP_WINDOW", 0)

            admin = make_principal(
                principal_id="gate-admin",
                tenant_id="control-plane",
                role="system",
                plan="enterprise",
            )
            user = make_principal(
                principal_id="gate-user",
                tenant_id="tenant-enforcement",
                role="user",
                plan="free",
            )

            invalid_payload, invalid_error = await call_tool(
                server,
                "manage_tenant_controls",
                {"action": "disable", "reason": "missing tenant id", "reason_code": "INVALID"},
                principal=admin,
                request_id="invalid-params",
            )
            invalid_rejected = invalid_error and "tenant_id" in json.dumps(invalid_payload).lower()

            async def fake_execute(_server: Any, name: str, arguments: Dict[str, Any]) -> str:
                await asyncio.sleep(0.03)
                return json.dumps({"tool": name, "arguments": arguments, "ok": True})

            setattr(server, "_execute_tool", MethodType(fake_execute, server))

            first_payload, first_error = await call_tool(
                server,
                SAFE_RUNTIME_TOOL,
                {},
                principal=user,
                request_id="quota-1",
            )
            second_payload, second_error = await call_tool(
                server,
                SAFE_RUNTIME_TOOL,
                {},
                principal=user,
                request_id="quota-2",
            )
            quota_enforced = (not first_error) and second_error and "rate" in json.dumps(second_payload).lower()

            active_calls = 0
            max_active_calls = 0

            async def tracked_execute(_server: Any, name: str, _arguments: Dict[str, Any]) -> str:
                nonlocal active_calls, max_active_calls
                active_calls += 1
                max_active_calls = max(max_active_calls, active_calls)
                try:
                    await asyncio.sleep(0.05)
                    return json.dumps({"tool": name, "ok": True})
                finally:
                    active_calls -= 1

            setattr(server, "_execute_tool", MethodType(tracked_execute, server))
            tenant = "tenant-concurrency"
            concurrency_principal = make_principal(
                principal_id="gate-concurrency",
                tenant_id=tenant,
                role="user",
                plan="free",
            )
            server_config = getattr(server, "_config")
            base_limits = server_config.plans.resolve_limits(tenant, "free")
            limit = int(base_limits.get("concurrency", 1) or 1)
            results = await asyncio.gather(
                *[
                    call_tool(
                        server,
                        SAFE_RUNTIME_TOOL,
                        {},
                        principal=concurrency_principal,
                        request_id=f"concurrency-{index}",
                    )
                    for index in range(5)
                ]
            )
            concurrency_honored = all(not is_error for _payload, is_error in results) and max_active_calls <= limit

            report.add(
                "generic_enforcement_wrapper_smoke",
                False,
                invalid_rejected and quota_enforced and concurrency_honored,
                invalid_params_rejected=invalid_rejected,
                invalid_params_payload=invalid_payload,
                quota_enforced=quota_enforced,
                first_quota_payload=first_payload,
                second_quota_payload=second_payload,
                concurrency_honored=concurrency_honored,
                observed_max_active=max_active_calls,
                configured_concurrency_limit=limit,
            )


async def check_control_plane_integrity(report: VerificationReport) -> None:
    temp_dir = tempfile.mkdtemp(prefix="frontend_gate_control_")
    if temp_dir:
        store_path = Path(temp_dir) / "control.json"
        audit_path = Path(temp_dir) / "audit.jsonl"
        overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(store_path),
            "MCP_AUDIT_LOG_FILE": str(audit_path),
            "MCP_RECOVERY_THROTTLE_SECONDS": "120",
            "MCP_THROTTLED_CONCURRENCY_CAP": "1",
            "MCP_ADMIN_REASON_REQUIRED": "1",
        }
        with temporary_env(overrides):
            admin = make_principal(
                principal_id="gate-admin",
                tenant_id="control-plane",
                role="system",
                plan="enterprise",
            )
            user = make_principal(
                principal_id="gate-user",
                tenant_id="tenant-control",
                role="user",
                plan="free",
                auth_type="api_key",
            )

            server = live_server()
            target_tenant = "tenant-control"
            user_status_payload, user_status_error = await call_tool(
                server,
                "manage_tenant_controls",
                {"action": "status", "tenant_id": target_tenant},
                principal=user,
                request_id="status-user",
            )
            admin_only = user_status_error

            disable_payload, disable_error = await call_tool(
                server,
                "manage_tenant_controls",
                {
                    "action": "disable",
                    "tenant_id": target_tenant,
                    "reason": "frontend gate disable test",
                    "reason_code": "MANUAL_GATE_DISABLE",
                    "duration_seconds": 180,
                },
                principal=admin,
                request_id="disable-admin",
            )
            status_after_disable = getattr(server, "_tenant_status_payload")(target_tenant)
            disabled_persisted_before_restart = (not disable_error) and status_after_disable.get("level") == "disabled"

            restarted_server = live_server()
            status_after_restart = getattr(restarted_server, "_tenant_status_payload")(target_tenant)
            restart_persistence = status_after_restart.get("level") == "disabled"

            enable_payload, enable_error = await call_tool(
                restarted_server,
                "manage_tenant_controls",
                {
                    "action": "enable",
                    "tenant_id": target_tenant,
                    "reason": "frontend gate enable test",
                    "reason_code": "MANUAL_GATE_ENABLE",
                },
                principal=admin,
                request_id="enable-admin",
            )
            status_after_enable = getattr(restarted_server, "_tenant_status_payload")(target_tenant)
            restarted_config = getattr(restarted_server, "_config")
            base_limits = restarted_config.plans.resolve_limits(target_tenant, "free")
            effective_limits = getattr(restarted_server, "_effective_limits_for_tenant")(target_tenant, base_limits)
            expected_cap = min(
                int(base_limits.get("concurrency", restarted_config.tool.max_concurrent) or restarted_config.tool.max_concurrent),
                int(restarted_config.tool.throttled_concurrency_cap or 1),
            )
            recovery_window = (not enable_error) and status_after_enable.get("level") == "recovery"
            reduced_limits = int(effective_limits.get("concurrency", 0) or 0) <= expected_cap

            report.add(
                "control_plane_integrity",
                True,
                admin_only and disabled_persisted_before_restart and restart_persistence and recovery_window and reduced_limits,
                admin_only=admin_only,
                user_status_payload=user_status_payload,
                disable_payload=disable_payload,
                disable_error=disable_error,
                status_after_disable=status_after_disable,
                status_after_restart=status_after_restart,
                enable_payload=enable_payload,
                enable_error=enable_error,
                status_after_enable=status_after_enable,
                effective_limits=effective_limits,
                expected_recovery_concurrency_cap=expected_cap,
            )


async def check_observability(report: VerificationReport) -> None:
    temp_dir = tempfile.mkdtemp(prefix="frontend_gate_observability_")
    if temp_dir:
        audit_path = Path(temp_dir) / "audit.jsonl"
        overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(temp_dir) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(audit_path),
        }
        with temporary_env(overrides):
            server = live_server()
            admin = make_principal(
                principal_id="gate-admin",
                tenant_id="control-plane",
                role="system",
                plan="enterprise",
            )

            await call_tool(
                server,
                "manage_tenant_controls",
                {
                    "action": "status",
                    "tenant_id": "tenant-observability",
                    "reason": "probe",
                    "reason_code": "OBS_CHECK",
                },
                principal=admin,
                request_id="observability-status",
            )

            metrics_text = server.render_metrics()
            missing_metrics = sorted(metric for metric in REQUIRED_METRICS if metric not in metrics_text)

            audit_records: List[Dict[str, Any]] = []
            if audit_path.exists():
                audit_records = [
                    json.loads(line)
                    for line in audit_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            latest = audit_records[-1] if audit_records else {}
            principal_payload = latest.get("principal") or {}
            audit_fields_ok = bool(
                latest.get("request_id")
                and latest.get("tool") == "manage_tenant_controls"
                and isinstance(latest.get("arguments"), dict)
                and principal_payload.get("principal_id")
                and principal_payload.get("tenant_id")
            )

            report.add(
                "observability_signals_present",
                True,
                (not missing_metrics) and audit_fields_ok,
                missing_metrics=missing_metrics,
                audit_record_count=len(audit_records),
                latest_audit_record=latest,
            )


async def check_sse_contract(report: VerificationReport) -> None:
    temp_dir = tempfile.mkdtemp(prefix="frontend_gate_sse_")
    if temp_dir:
        overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(temp_dir) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(Path(temp_dir) / "audit.jsonl"),
        }
        with temporary_env(overrides):
            server = live_server()

            async def fake_execute(_server: Any, name: str, _arguments: Dict[str, Any]) -> str:
                return json.dumps({"tool": name, "ok": True})

            setattr(server, "_execute_tool", MethodType(fake_execute, server))
            transport = MCPHTTPTransport(server)
            principal = make_principal(
                principal_id="gate-sse",
                tenant_id="tenant-sse",
                role="system",
                plan="enterprise",
            )
            captured_events: List[Dict[str, Any]] = []

            async def capture(event: Dict[str, Any]) -> None:
                captured_events.append(event)

            setattr(transport, "_broadcast", capture)
            setattr(transport, "_authenticate", lambda _request, **_kwargs: principal)

            class FakeRequest:
                headers: Dict[str, str] = {}
                content_length = 128

                async def json(self) -> Dict[str, Any]:
                    return {"name": SAFE_RUNTIME_TOOL, "arguments": {}}

            await asyncio.gather(*[transport.handle_call_tool(FakeRequest()) for _ in range(5)])

            request_events = [event for event in captured_events if event.get("type") == "tool_request"]
            request_ids = [event.get("request_id") for event in request_events if event.get("request_id")]
            duplicated_request_ids = len(request_ids) != len(set(request_ids))
            expected_event_count = 10
            dropped_events = len(captured_events) != expected_event_count
            missing_top_level_fields = [
                {
                    "type": event.get("type"),
                    "missing": [field for field in ("request_id", "tenant_id", "status") if field not in event],
                }
                for event in captured_events
                if any(field not in event for field in ("request_id", "tenant_id", "status"))
            ]

            report.add(
                "sse_event_contract",
                True,
                (not duplicated_request_ids) and (not dropped_events) and (not missing_top_level_fields),
                captured_event_count=len(captured_events),
                expected_event_count=expected_event_count,
                duplicated_request_ids=duplicated_request_ids,
                dropped_events=dropped_events,
                missing_top_level_fields=missing_top_level_fields,
                sample_events=captured_events[:4],
            )


async def check_error_taxonomy(report: VerificationReport) -> None:
    deny_tmp = tempfile.mkdtemp(prefix="frontend_gate_errors_deny_")
    rate_tmp = tempfile.mkdtemp(prefix="frontend_gate_errors_rate_")
    license_tmp = tempfile.mkdtemp(prefix="frontend_gate_errors_license_")
    if deny_tmp and rate_tmp and license_tmp:
        deny_overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(deny_tmp) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(Path(deny_tmp) / "audit.jsonl"),
            "MCP_ACCESS_CONTROL_ENABLED": "1",
            "MCP_ROLE_ALLOWED_CATEGORIES_JSON": json.dumps({"user": []}),
            "MCP_ROLE_DENIED_TOOLS_JSON": json.dumps({"user": []}),
            "MCP_PLANS_JSON": json.dumps(
                {
                    "free": {"burst": 1.0, "refill": 0.0, "daily": 1, "concurrency": 1},
                    "enterprise": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 8},
                }
            ),
            "MCP_DEFAULT_PLAN": "free",
        }
        with temporary_env(deny_overrides):
            deny_server = live_server()
            setattr(deny_server, "_DEDUP_WINDOW", 0)
            deny_user = make_principal(
                principal_id="gate-error-user",
                tenant_id="tenant-errors",
                role="user",
                plan="free",
            )
            policy_payload, policy_error = await call_tool(
                deny_server,
                SAFE_RUNTIME_TOOL,
                {},
                principal=deny_user,
                request_id="error-policy",
            )

        rate_overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(rate_tmp) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(Path(rate_tmp) / "audit.jsonl"),
            "MCP_ACCESS_CONTROL_ENABLED": "0",
            "MCP_PLANS_JSON": json.dumps(
                {
                    "free": {"burst": 1.0, "refill": 0.0, "daily": 1, "concurrency": 1},
                    "enterprise": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 8},
                }
            ),
            "MCP_DEFAULT_PLAN": "free",
        }
        with temporary_env(rate_overrides):
            rate_server = live_server()
            setattr(rate_server, "_DEDUP_WINDOW", 0)
            rate_user = make_principal(
                principal_id="gate-rate-user",
                tenant_id="tenant-errors-rate",
                role="user",
                plan="free",
            )
            first_payload, first_error = await call_tool(
                rate_server,
                SAFE_RUNTIME_TOOL,
                {},
                principal=rate_user,
                request_id="error-rate-1",
            )
            second_payload, second_error = await call_tool(
                rate_server,
                SAFE_RUNTIME_TOOL,
                {},
                principal=rate_user,
                request_id="error-rate-2",
            )

        license_overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(license_tmp) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(Path(license_tmp) / "audit.jsonl"),
            "MCP_ACCESS_CONTROL_ENABLED": "0",
            "MCP_PLANS_JSON": json.dumps(
                {
                    "free": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 2},
                    "enterprise": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 8},
                }
            ),
            "MCP_DEFAULT_PLAN": "free",
        }
        with temporary_env(license_overrides):
            license_server = live_server()
            setattr(license_server, "_DEDUP_WINDOW", 0)

            async def fake_license_execute(_server: Any, _name: str, _arguments: Dict[str, Any]) -> str:
                raise RuntimeError("valid license required")

            setattr(license_server, "_execute_tool", MethodType(fake_license_execute, license_server))
            license_user = make_principal(
                principal_id="gate-license-user",
                tenant_id="tenant-errors-license",
                role="user",
                plan="free",
            )
            license_payload, license_error = await call_tool(
                license_server,
                SAFE_RUNTIME_TOOL,
                {},
                principal=license_user,
                request_id="error-license-1",
            )

        tax_ok = (
            policy_error
            and policy_payload.get("code") == "ALLOWLIST_DENY"
            and policy_payload.get("error") == "tool_not_allowed"
            and (first_error is False)
            and second_error
            and second_payload.get("code") == "RATE_LIMITED"
            and second_payload.get("error") == "rate_limited"
            and license_error
            and license_payload.get("code") == "LICENSE_REQUIRED"
            and license_payload.get("error") == "license_required"
        )

        report.add(
            "error_taxonomy_distinguishes_denials",
            False,
            tax_ok,
            policy_payload=policy_payload,
            quota_payload_first=first_payload,
            quota_payload_second=second_payload,
            license_payload=license_payload,
        )


async def check_interaction_edge_cases(report: VerificationReport) -> None:
    deny_tmp = tempfile.mkdtemp(prefix="frontend_gate_edge_deny_")
    rate_tmp = tempfile.mkdtemp(prefix="frontend_gate_edge_rate_")
    if deny_tmp and rate_tmp:
        deny_overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(deny_tmp) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(Path(deny_tmp) / "audit.jsonl"),
            "MCP_ACCESS_CONTROL_ENABLED": "1",
            "MCP_ROLE_ALLOWED_CATEGORIES_JSON": json.dumps({"user": []}),
            "MCP_ROLE_DENIED_TOOLS_JSON": json.dumps({"user": []}),
            "MCP_PLANS_JSON": json.dumps(
                {
                    "free": {"burst": 1.0, "refill": 0.0, "daily": 3, "concurrency": 1},
                    "enterprise": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 8},
                }
            ),
            "MCP_DEFAULT_PLAN": "free",
        }

        with temporary_env(deny_overrides):
            deny_server = live_server()
            setattr(deny_server, "_DEDUP_WINDOW", 0)
            deny_user = make_principal(
                principal_id="gate-edge-user-deny",
                tenant_id="tenant-edge",
                role="user",
                plan="free",
            )
            deny_payload, deny_error = await call_tool(
                deny_server,
                SAFE_RUNTIME_TOOL,
                {},
                principal=deny_user,
                request_id="edge-switch-deny",
            )

        rate_overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(rate_tmp) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(Path(rate_tmp) / "audit.jsonl"),
            "MCP_ACCESS_CONTROL_ENABLED": "0",
            "MCP_PLANS_JSON": json.dumps(
                {
                    "free": {"burst": 1.0, "refill": 0.0, "daily": 2, "concurrency": 1},
                    "enterprise": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 8},
                }
            ),
            "MCP_DEFAULT_PLAN": "free",
        }
        with temporary_env(rate_overrides):
            rate_server = live_server()
            setattr(rate_server, "_DEDUP_WINDOW", 0)
            rate_user = make_principal(
                principal_id="gate-edge-user-rate",
                tenant_id="tenant-edge-rate",
                role="user",
                plan="free",
            )

            success_payload, success_error = await call_tool(
                rate_server,
                SAFE_RUNTIME_TOOL,
                {},
                principal=rate_user,
                request_id="edge-switch-success",
            )

            interleaved = await asyncio.gather(
                *[
                    call_tool(
                        rate_server,
                        SAFE_RUNTIME_TOOL,
                        {},
                        principal=rate_user,
                        request_id=f"edge-mix-{index}",
                    )
                    for index in range(1, 4)
                ]
            )

        interleaved_rows = []
        interleaved_ids: List[str] = []
        for payload, is_error in interleaved:
            request_id = str(payload.get("request_id") or "")
            if request_id:
                interleaved_ids.append(request_id)
            interleaved_rows.append(
                {
                    "request_id": request_id,
                    "ok": bool(payload.get("ok")),
                    "code": str(payload.get("code") or ""),
                    "error": str(payload.get("error") or ""),
                    "is_error": bool(is_error),
                }
            )

        has_unique_ids = len(interleaved_ids) == len(set(interleaved_ids))
        has_rate_limited = any(row.get("code") == "RATE_LIMITED" for row in interleaved_rows)
        has_success = any((not row.get("is_error")) for row in interleaved_rows) or (not success_error)
        churn_ok = (
            deny_error
            and deny_payload.get("code") == "ALLOWLIST_DENY"
            and (not success_error)
            and has_unique_ids
            and has_rate_limited
            and has_success
        )

        report.add(
            "interaction_edge_cases",
            False,
            churn_ok,
            denial_step={
                "request_id": deny_payload.get("request_id"),
                "code": deny_payload.get("code"),
                "error": deny_payload.get("error"),
                "is_error": deny_error,
            },
            success_step={
                "request_id": success_payload.get("request_id"),
                "ok": success_payload.get("ok"),
                "is_error": success_error,
            },
            mixed_interleaving=interleaved_rows,
            mixed_interleaving_summary={
                "count": len(interleaved_rows),
                "unique_request_ids": len(set(interleaved_ids)),
                "has_duplicate_request_ids": not has_unique_ids,
                "contains_rate_limited": has_rate_limited,
                "contains_success": has_success,
            },
        )


async def check_request_id_traceability(report: VerificationReport) -> None:
    temp_dir = tempfile.mkdtemp(prefix="frontend_gate_traceability_")
    if temp_dir:
        audit_path = Path(temp_dir) / "audit.jsonl"
        overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(temp_dir) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(audit_path),
        }
        with temporary_env(overrides):
            server = live_server()
            principal = make_principal(
                principal_id="gate-trace",
                tenant_id="tenant-trace",
                role="user",
                plan="enterprise",
            )
            request_id = "trace-req-1"
            payload, is_error = await call_tool(
                server,
                SAFE_RUNTIME_TOOL,
                {},
                principal=principal,
                request_id=request_id,
            )

            audit_records: List[Dict[str, Any]] = []
            if audit_path.exists():
                audit_records = [
                    json.loads(line)
                    for line in audit_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]

            matching_records = [record for record in audit_records if record.get("request_id") == request_id]
            trace_ok = (not is_error) and bool(payload.get("request_id")) and bool(matching_records)

            report.add(
                "request_id_traceability",
                False,
                trace_ok,
                request_id=request_id,
                payload_ok=bool(payload.get("ok")),
                audit_record_count=len(audit_records),
                matching_record_count=len(matching_records),
                matching_sample=matching_records[:1],
            )


async def check_snapshot_reconciliation_payload(report: VerificationReport) -> None:
    dashboard: Any = ReconDashboard(auto_open=False)

    class FakeCallRequest:
        content_length = 128

        async def json(self) -> Dict[str, Any]:
            return {"name": "list_targets", "arguments": {"filter": "reconcile-check"}}

    class FakeSnapshotRequest:
        query: Dict[str, str] = {}

    def fake_call_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ok": False,
            "status": "error",
            "error": "tool_not_allowed",
            "code": "ALLOWLIST_DENY",
            "summary": f"Denied {tool_name} for reconciliation test",
            "data": {"echo": arguments},
            "source": "mcp_proxy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    setattr(dashboard, "_mcp_call_tool_sync", fake_call_tool)
    setattr(dashboard, "_mcp_targets_sync", lambda: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "total": 0}})
    setattr(dashboard, "_mcp_reports_sync", lambda requested: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "requested": requested}})
    setattr(dashboard, "_mcp_fetch_metrics_sync", lambda: {"ok": True, "status": "ok", "data": {"tool_calls_total": 1}})
    setattr(dashboard, "_mcp_fetch_health_sync", lambda: {"ok": True, "data": {"status": "ok"}})

    call_response = await getattr(dashboard, "_handle_mcp_call")(FakeCallRequest())
    call_payload = json.loads(call_response.text)
    snapshot_response = await getattr(dashboard, "_handle_mcp_readonly_snapshot")(FakeSnapshotRequest())
    snapshot_payload = json.loads(snapshot_response.text)
    latest_action = snapshot_payload.get("latest_action") or {}
    recent_actions = snapshot_payload.get("recent_actions") or []

    snapshot_ok = (
        call_payload.get("request_id")
        and latest_action.get("request_id") == call_payload.get("request_id")
        and latest_action.get("status") == call_payload.get("status")
        and latest_action.get("code") == call_payload.get("code")
        and latest_action.get("summary") == call_payload.get("summary")
        and bool(recent_actions)
        and recent_actions[0].get("request_id") == call_payload.get("request_id")
    )

    report.add(
        "snapshot_reconciliation_payload",
        False,
        bool(snapshot_ok),
        call_payload=call_payload,
        latest_action=latest_action,
        recent_actions=recent_actions[:3],
        stream=snapshot_payload.get("stream"),
    )


async def check_snapshot_recent_actions_ordering(report: VerificationReport) -> None:
    dashboard: Any = ReconDashboard(auto_open=False)

    class FakeCallRequest:
        content_length = 128

        def __init__(self, name: str, arguments: Dict[str, Any]):
            self._payload = {"name": name, "arguments": arguments}

        async def json(self) -> Dict[str, Any]:
            return self._payload

    class FakeSnapshotRequest:
        query: Dict[str, str] = {}

    def fake_call_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ok": tool_name != "stop_scan",
            "status": "ok" if tool_name != "stop_scan" else "error",
            "error": "rate_limited" if tool_name == "stop_scan" else "",
            "code": "RATE_LIMITED" if tool_name == "stop_scan" else "",
            "summary": f"Handled {tool_name} for {arguments.get('target') or arguments.get('filter') or arguments.get('path')}",
            "data": {"echo": arguments},
            "source": "mcp_proxy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    setattr(dashboard, "_mcp_call_tool_sync", fake_call_tool)
    setattr(dashboard, "_mcp_targets_sync", lambda: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "total": 0}})
    setattr(dashboard, "_mcp_reports_sync", lambda requested: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "requested": requested}})
    setattr(dashboard, "_mcp_fetch_metrics_sync", lambda: {"ok": True, "status": "ok", "data": {"tool_calls_total": 3}})
    setattr(dashboard, "_mcp_fetch_health_sync", lambda: {"ok": True, "data": {"status": "ok"}})

    calls = [
        FakeCallRequest("list_targets", {"filter": "alpha"}),
        FakeCallRequest("get_report", {"path": "alpha.json"}),
        FakeCallRequest("stop_scan", {"target": "alpha"}),
    ]
    responses = []
    for request in calls:
        response = await getattr(dashboard, "_handle_mcp_call")(request)
        responses.append(json.loads(response.text))

    snapshot_response = await getattr(dashboard, "_handle_mcp_readonly_snapshot")(FakeSnapshotRequest())
    snapshot_payload = json.loads(snapshot_response.text)
    recent_actions = snapshot_payload.get("recent_actions") or []
    recent_ids = [item.get("request_id") for item in recent_actions[:3]]
    expected_ids = [item.get("request_id") for item in reversed(responses)]
    recent_completed = [item.get("completed_at") for item in recent_actions[:3]]
    ordered = all(
        not recent_completed[idx + 1] or recent_completed[idx] >= recent_completed[idx + 1]
        for idx in range(len(recent_completed) - 1)
    ) if len(recent_completed) >= 2 else True

    report.add(
        "snapshot_recent_actions_ordering",
        False,
        bool(recent_actions) and recent_ids == expected_ids and ordered,
        expected_ids=expected_ids,
        recent_ids=recent_ids,
        recent_actions=recent_actions[:3],
    )


async def check_adapter_truth_consistency(report: VerificationReport) -> None:
    """Dynamic invariant: snapshot history remains canonical after burst activity and stream-gap style recovery."""
    dashboard: Any = ReconDashboard(auto_open=False)

    class FakeCallRequest:
        content_length = 128

        def __init__(self, name: str, arguments: Dict[str, Any]):
            self._payload = {"name": name, "arguments": arguments}

        async def json(self) -> Dict[str, Any]:
            return self._payload

    class FakeSnapshotRequest:
        query: Dict[str, str] = {}

    def fake_call_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        target = arguments.get("target") or arguments.get("path") or arguments.get("filter") or "unknown"
        if tool_name == "stop_scan":
            return {
                "ok": False,
                "status": "error",
                "error": "rate_limited",
                "code": "RATE_LIMITED",
                "summary": f"Rate limited stop for {target}",
                "data": {"echo": arguments},
                "source": "mcp_proxy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return {
            "ok": True,
            "status": "ok",
            "error": "",
            "code": "",
            "summary": f"Completed {tool_name} for {target}",
            "data": {"echo": arguments},
            "source": "mcp_proxy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    setattr(dashboard, "_mcp_call_tool_sync", fake_call_tool)
    setattr(dashboard, "_mcp_targets_sync", lambda: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "total": 0}})
    setattr(dashboard, "_mcp_reports_sync", lambda requested: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "requested": requested}})
    setattr(dashboard, "_mcp_fetch_metrics_sync", lambda: {"ok": True, "status": "ok", "data": {"tool_calls_total": 3}})
    setattr(dashboard, "_mcp_fetch_health_sync", lambda: {"ok": True, "data": {"status": "ok"}})

    burst_calls = [
        FakeCallRequest("list_targets", {"filter": "burst-alpha"}),
        FakeCallRequest("get_report", {"path": "burst-alpha.json"}),
        FakeCallRequest("stop_scan", {"target": "burst-alpha"}),
    ]

    # Fire quickly (burst). We intentionally do not attach any SSE listener to emulate a stream gap.
    responses = await asyncio.gather(*[getattr(dashboard, "_handle_mcp_call")(request) for request in burst_calls])
    call_payloads = [json.loads(response.text) for response in responses]

    # Restore path: rely on readonly snapshot as reconciliation truth.
    snapshot_1 = json.loads((await getattr(dashboard, "_handle_mcp_readonly_snapshot")(FakeSnapshotRequest())).text)
    await asyncio.sleep(0.01)
    snapshot_2 = json.loads((await getattr(dashboard, "_handle_mcp_readonly_snapshot")(FakeSnapshotRequest())).text)

    recent_1 = snapshot_1.get("recent_actions") or []
    recent_2 = snapshot_2.get("recent_actions") or []
    expected_ids = [payload.get("request_id") for payload in call_payloads if payload.get("request_id")]
    expected_status = {payload.get("request_id"): payload.get("status") for payload in call_payloads if payload.get("request_id")}

    ids_1 = [action.get("request_id") for action in recent_1 if action.get("request_id")]
    no_duplicates = len(ids_1) == len(set(ids_1))
    all_once = all(ids_1.count(req_id) == 1 for req_id in expected_ids)
    statuses_1 = {action.get("request_id"): action.get("status") for action in recent_1 if action.get("request_id")}
    statuses_2 = {action.get("request_id"): action.get("status") for action in recent_2 if action.get("request_id")}
    final_stable = all(statuses_1.get(req_id) == statuses_2.get(req_id) for req_id in expected_ids)
    converged = all(statuses_1.get(req_id) == expected_status.get(req_id) for req_id in expected_ids)

    report.add(
        "adapter_truth_consistency",
        True,
        no_duplicates and all_once and final_stable and converged,
        expected_ids=expected_ids,
        recent_ids=ids_1,
        no_duplicate_request_id=no_duplicates,
        all_completed_actions_once=all_once,
        final_state_stable=final_stable,
        converged_with_results=converged,
        statuses_snapshot_1=statuses_1,
        statuses_snapshot_2=statuses_2,
        expected_status=expected_status,
    )


async def check_adapter_missing_terminal_recovery(report: VerificationReport) -> None:
    """Simulate pending action with lost terminal SSE and verify snapshot-final replacement semantics."""
    dashboard: Any = ReconDashboard(auto_open=False)

    class FakeCallRequest:
        content_length = 128

        async def json(self) -> Dict[str, Any]:
            return {"name": "list_targets", "arguments": {"filter": "missing-terminal"}}

    class FakeSnapshotRequest:
        query: Dict[str, str] = {}

    request_id = "missing-terminal-r1"
    pending_action = {
        "request_id": request_id,
        "tool": "list_targets",
        "status": "pending",
        "code": "",
        "error": "",
        "summary": "Waiting for result",
        "tenant_id": "control-plane",
        "ok": False,
        "arguments": {"filter": "missing-terminal"},
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    setattr(dashboard, "_mcp_action_history", [dict(pending_action)])
    setattr(dashboard, "_mcp_last_action", dict(pending_action))

    setattr(dashboard, "_mcp_targets_sync", lambda: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "total": 0}})
    setattr(dashboard, "_mcp_reports_sync", lambda requested: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "requested": requested}})
    setattr(dashboard, "_mcp_fetch_metrics_sync", lambda: {"ok": True, "status": "ok", "data": {"tool_calls_total": 1}})
    setattr(dashboard, "_mcp_fetch_health_sync", lambda: {"ok": True, "data": {"status": "ok"}})

    # Snapshot before recovery shows pending state only.
    before_snapshot = json.loads((await getattr(dashboard, "_handle_mcp_readonly_snapshot")(FakeSnapshotRequest())).text)
    before_recent = before_snapshot.get("recent_actions") or []

    # Skip SSE result path; inject terminal result via call response with same request_id.
    def fake_call_tool(_tool_name: str, _arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ok": True,
            "request_id": request_id,
            "tool": "list_targets",
            "status": "ok",
            "code": "",
            "error": "",
            "summary": "Recovered terminal result",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"items": [], "count": 0, "total": 0},
        }

    setattr(dashboard, "_mcp_call_tool_sync", fake_call_tool)
    call_response = await getattr(dashboard, "_handle_mcp_call")(FakeCallRequest())
    call_payload = json.loads(call_response.text)

    after_snapshot = json.loads((await getattr(dashboard, "_handle_mcp_readonly_snapshot")(FakeSnapshotRequest())).text)
    after_recent = after_snapshot.get("recent_actions") or []
    matching_after = [item for item in after_recent if item.get("request_id") == request_id]

    pending_before = [item for item in before_recent if item.get("request_id") == request_id and item.get("status") == "pending"]
    pending_after = [item for item in after_recent if item.get("request_id") == request_id and item.get("status") == "pending"]
    final_after = [item for item in matching_after if item.get("status") == "ok"]

    replaced_not_duplicated = len(matching_after) == 1 and len(final_after) == 1 and len(pending_after) == 0
    no_inconsistent_intermediate = len(pending_after) == 0

    report.add(
        "adapter_missing_terminal_recovery",
        True,
        bool(pending_before) and replaced_not_duplicated and no_inconsistent_intermediate,
        request_id=request_id,
        call_payload=call_payload,
        before_recent=before_recent[:3],
        after_recent=after_recent[:3],
        pending_before_count=len(pending_before),
        pending_after_count=len(pending_after),
        final_after_count=len(final_after),
        replaced_not_duplicated=replaced_not_duplicated,
        no_inconsistent_intermediate=no_inconsistent_intermediate,
    )


async def check_performance_smoke(report: VerificationReport) -> None:
    temp_dir = tempfile.mkdtemp(prefix="frontend_gate_perf_")
    if temp_dir:
        overrides = {
            "MCP_CONTROL_STATE_STORE_FILE": str(Path(temp_dir) / "control.json"),
            "MCP_AUDIT_LOG_FILE": str(Path(temp_dir) / "audit.jsonl"),
            "MCP_PLANS_JSON": json.dumps(
                {
                    "free": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 4},
                    "enterprise": {"burst": 100.0, "refill": 100.0, "daily": 100000, "concurrency": 8},
                }
            ),
            "MCP_DEFAULT_PLAN": "free",
        }
        with temporary_env(overrides):
            server = live_server()
            setattr(server, "_DEDUP_WINDOW", 0)

            async def fake_execute(_server: Any, name: str, _arguments: Dict[str, Any]) -> str:
                await asyncio.sleep(0.03)
                return json.dumps({"tool": name, "ok": True})

            setattr(server, "_execute_tool", MethodType(fake_execute, server))
            principal = make_principal(
                principal_id="gate-performance",
                tenant_id="tenant-performance",
                role="user",
                plan="free",
            )

            latencies_ms: List[float] = []

            async def timed_call(index: int) -> bool:
                started = time.perf_counter()
                _payload, is_error = await call_tool(
                    server,
                    SAFE_RUNTIME_TOOL,
                    {},
                    principal=principal,
                    request_id=f"perf-{index}",
                )
                latencies_ms.append((time.perf_counter() - started) * 1000.0)
                return not is_error

            ok_results = await asyncio.gather(*[timed_call(index) for index in range(20)])
            latencies_ms.sort()
            p95_index = max(0, min(len(latencies_ms) - 1, int(len(latencies_ms) * 0.95) - 1))
            p95_ms = round(latencies_ms[p95_index], 2) if latencies_ms else None

            report.add(
                "performance_smoke_internal_wrapper",
                False,
                all(ok_results) and p95_ms is not None and p95_ms <= 2000.0,
                calls=len(ok_results),
                all_success=all(ok_results),
                p95_ms=p95_ms,
                note="Internal wrapper smoke only; not sufficient to override blocking contract failures.",
            )



async def check_adapter_history_bounds(report: VerificationReport) -> None:
    """Invariant: server-side action history must be bounded and duplicate-free after burst load."""
    _SERVER_HISTORY_LIMIT = 10  # matches server.py [:10] cap
    BURST_COUNT = 250

    dashboard: Any = ReconDashboard(auto_open=False)

    class FakeCallRequest:
        content_length = 64

        def __init__(self, idx: int):
            self._idx = idx

        async def json(self) -> Dict[str, Any]:
            return {"name": "list_targets", "arguments": {"filter": f"bounds-test-{self._idx}"}}

    class FakeSnapshotRequest:
        query: Dict[str, str] = {}

    def fake_call_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ok": True,
            "status": "ok",
            "error": "",
            "code": "",
            "summary": f"Bounds probe {tool_name}",
            "data": {},
            "source": "mcp_proxy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    setattr(dashboard, "_mcp_call_tool_sync", fake_call_tool)
    setattr(dashboard, "_mcp_targets_sync", lambda: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "total": 0}})
    setattr(dashboard, "_mcp_reports_sync", lambda requested: {"ok": True, "status": "ok", "data": {"items": [], "count": 0, "requested": requested}})
    setattr(dashboard, "_mcp_fetch_metrics_sync", lambda: {"ok": True, "status": "ok", "data": {"tool_calls_total": 0}})
    setattr(dashboard, "_mcp_fetch_health_sync", lambda: {"ok": True, "data": {"status": "ok"}})

    sentinel_id = "bounds-sentinel-pending-00000"
    dashboard._mcp_action_history.insert(0, {
        "request_id": sentinel_id,
        "tool": "start_scan",
        "status": "pending",
        "code": "",
        "error": "",
        "summary": "Sentinel in-flight probe",
        "tenant_id": "",
        "ok": False,
        "arguments": {},
        "completed_at": datetime.now(timezone.utc).isoformat(),
    })

    batch_size = 20
    for batch_start in range(0, BURST_COUNT, batch_size):
        batch = [FakeCallRequest(batch_start + i) for i in range(min(batch_size, BURST_COUNT - batch_start))]
        await asyncio.gather(*[getattr(dashboard, "_handle_mcp_call")(req) for req in batch])

    snap = json.loads((await getattr(dashboard, "_handle_mcp_readonly_snapshot")(FakeSnapshotRequest())).text)
    recent = snap.get("recent_actions") or []

    all_ids = [a.get("request_id") for a in recent if a.get("request_id")]
    history_bounded = len(recent) <= _SERVER_HISTORY_LIMIT
    no_duplicates = len(all_ids) == len(set(all_ids))
    sentinel_not_duplicated = all_ids.count(sentinel_id) <= 1

    report.add(
        "adapter_history_bounds",
        True,
        history_bounded and no_duplicates and sentinel_not_duplicated,
        burst_count=BURST_COUNT,
        server_history_limit=_SERVER_HISTORY_LIMIT,
        recent_actions_count=len(recent),
        history_bounded=history_bounded,
        no_duplicate_ids=no_duplicates,
        sentinel_not_duplicated=sentinel_not_duplicated,
        note=(
            "Server history capped at 10; JS adapter history capped at 200 with "
            "pending-action protection in _recordAction trim. Sentinel eviction is expected "
            "(server records terminal-only); duplicate-freedom is the hard invariant."
        ),
    )


async def check_adapter_guardrail(report: VerificationReport) -> None:
    violations: List[Dict[str, Any]] = []
    allowed_file = FRONTEND_JS_ROOT / "mcp-ui-adapter.js"
    scanned_files = sorted(FRONTEND_JS_ROOT.glob("*.js"))

    for path in scanned_files:
        if path == allowed_file:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="ignore")

        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if "/api/mcp/" in stripped:
                violations.append(
                    {
                        "file": str(path.relative_to(CASECRACK_ROOT)).replace("\\", "/"),
                        "line": line_number,
                        "rule": "direct_mcp_path",
                        "content": stripped,
                    }
                )
            if "EventSource(" in stripped or "new window.EventSource(" in stripped:
                violations.append(
                    {
                        "file": str(path.relative_to(CASECRACK_ROOT)).replace("\\", "/"),
                        "line": line_number,
                        "rule": "direct_eventsource",
                        "content": stripped,
                    }
                )

    report.add(
        "adapter_gateway_guardrail",
        True,
        not violations,
        allowed_file=str(allowed_file.relative_to(CASECRACK_ROOT)).replace("\\", "/"),
        scanned_files=[str(path.relative_to(CASECRACK_ROOT)).replace("\\", "/") for path in scanned_files],
        violations=violations,
    )


async def main() -> int:
    report = VerificationReport()
    await check_required_tool_surface(report)
    await check_golden_dataset(report)
    await check_generic_enforcement(report)
    await check_control_plane_integrity(report)
    await check_observability(report)
    await check_sse_contract(report)
    await check_error_taxonomy(report)
    await check_interaction_edge_cases(report)
    await check_request_id_traceability(report)
    await check_snapshot_reconciliation_payload(report)
    await check_snapshot_recent_actions_ordering(report)
    await check_adapter_missing_terminal_recovery(report)
    await check_adapter_truth_consistency(report)
    await check_performance_smoke(report)
    await check_adapter_guardrail(report)
    await check_adapter_history_bounds(report)

    output = report.to_dict()
    REPORT_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))
    return 0 if output["verdict"] == "GO" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
