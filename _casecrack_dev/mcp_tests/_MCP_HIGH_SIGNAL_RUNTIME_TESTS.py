#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent
REPORT_PATH = ROOT / "_MCP_HIGH_SIGNAL_RUNTIME_TEST_REPORT.json"
TMP_AUDIT = ROOT / "_tmp_mcp_high_signal_audit.jsonl"

if str(ROOT / "CaseCrack") not in sys.path:
    sys.path.insert(0, str(ROOT / "CaseCrack"))

# Import after path setup.
from tools.burp_enterprise.mcp.mcp_server import SecurityMCPServer  # type: ignore  # noqa: E402
import tools.burp_enterprise.mcp.mcp_server as mcp_server_mod  # type: ignore  # noqa: E402
from _validate_mcp_browser_recovery import (  # noqa: E402
    scenario_multi_action_outage_recovery,
    scenario_snapshot_sse_race,
)


def _read_terminal_events(audit_path: Path) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    if not audit_path.exists():
        return out
    for idx, raw in enumerate(audit_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        et = str(evt.get("event_type") or "")
        if et not in {"tool_completed", "tool_failed"}:
            continue
        rid = str(evt.get("request_id") or "").strip()
        if not rid:
            continue
        rec = {
            "line": idx,
            "event_type": et,
            "ok": bool(evt.get("ok")),
            "tool": str(evt.get("tool") or ""),
            "error": str(evt.get("error") or ""),
        }
        out.setdefault(rid, []).append(rec)
    return out


async def _test_duplicate_execution_attempt() -> Dict[str, Any]:
    server = SecurityMCPServer(workspace_path="CaseCrack")
    run_count = 0

    async def fake_execute(_name: str, _args: Dict[str, Any]) -> str:
        nonlocal run_count
        run_count += 1
        return json.dumps({"summary": "synthetic-success", "finding_count": 0})

    server._execute_tool = fake_execute  # type: ignore[attr-defined]
    rid = "hs-dup-req-001"

    first_payload, first_error = await server.execute_tool_request(
        "get_report",
        {"path": "..\\_AUDIT_SANITY_REPORT.json"},
        request_id=rid,
    )
    second_payload, second_error = await server.execute_tool_request(
        "get_report",
        {"path": "..\\_AUDIT_SANITY_REPORT.json"},
        request_id=rid,
    )

    events = _read_terminal_events(TMP_AUDIT).get(rid, [])
    passed = (
        run_count == 1
        and first_error is False
        and second_error is False
        and first_payload == second_payload
        and len(events) == 1
        and events[0]["event_type"] == "tool_completed"
    )
    return {
        "name": "duplicate_execution_attempt",
        "passed": passed,
        "details": {
            "run_count": run_count,
            "first_error": first_error,
            "second_error": second_error,
            "terminal_events": events,
        },
    }


async def _test_success_then_sidecar_failure_race() -> Dict[str, Any]:
    server = SecurityMCPServer(workspace_path="CaseCrack")

    async def fake_execute(_name: str, _args: Dict[str, Any]) -> str:
        return json.dumps({"summary": "synthetic-success", "finding_count": 0})

    server._execute_tool = fake_execute  # type: ignore[attr-defined]
    rid = "hs-race-req-001"

    old_hooks_flag = bool(getattr(mcp_server_mod, "_DASHBOARD_HOOKS_AVAILABLE", False))
    old_completed = getattr(mcp_server_mod, "dashboard_mcp_tool_completed", None)

    def explode_completed(**_kw: Any) -> bool:
        raise KeyError("forced-sidecar-keyerror")

    setattr(mcp_server_mod, "_DASHBOARD_HOOKS_AVAILABLE", True)
    setattr(mcp_server_mod, "dashboard_mcp_tool_completed", explode_completed)

    try:
        payload, is_error = await server.execute_tool_request(
            "get_report",
            {"path": "..\\_AUDIT_SANITY_REPORT.json"},
            request_id=rid,
        )
    finally:
        setattr(mcp_server_mod, "_DASHBOARD_HOOKS_AVAILABLE", old_hooks_flag)
        if old_completed is not None:
            setattr(mcp_server_mod, "dashboard_mcp_tool_completed", old_completed)

    parsed = json.loads(payload)
    events = _read_terminal_events(TMP_AUDIT).get(rid, [])
    terminal_types = [e["event_type"] for e in events]
    passed = (
        is_error is False
        and bool(parsed.get("ok"))
        and terminal_types == ["tool_completed"]
    )
    return {
        "name": "success_forced_failure_race",
        "passed": passed,
        "details": {
            "is_error": is_error,
            "response_ok": bool(parsed.get("ok")),
            "terminal_events": events,
        },
    }


async def _test_concurrent_burst() -> Dict[str, Any]:
    server = SecurityMCPServer(workspace_path="CaseCrack")
    old_quota_check = server._check_and_consume_tenant_quota
    server._check_and_consume_tenant_quota = lambda **_kwargs: None  # type: ignore[assignment]

    async def fake_execute(_name: str, args: Dict[str, Any]) -> str:
        await asyncio.sleep(0.003)
        if bool(args.get("force_error")):
            raise ValueError("synthetic-failure")
        return json.dumps({"summary": "burst-success", "finding_count": int(args.get("idx", 0)) % 3})

    server._execute_tool = fake_execute  # type: ignore[attr-defined]

    total = 100
    request_ids = [f"hs-burst-{i:03d}" for i in range(total)]

    async def one(idx: int, rid: str) -> tuple[str, bool]:
        payload, is_error = await server.execute_tool_request(
            "get_report",
            {"idx": idx, "force_error": (idx % 4 == 0)},
            request_id=rid,
        )
        _ = payload
        return rid, is_error

    old_hooks_flag = bool(getattr(mcp_server_mod, "_DASHBOARD_HOOKS_AVAILABLE", False))
    setattr(mcp_server_mod, "_DASHBOARD_HOOKS_AVAILABLE", False)
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(one(i, rid) for i, rid in enumerate(request_ids))),
            timeout=45.0,
        )
    finally:
        setattr(mcp_server_mod, "_DASHBOARD_HOOKS_AVAILABLE", old_hooks_flag)
        server._check_and_consume_tenant_quota = old_quota_check  # type: ignore[assignment]

    events_by_rid = _read_terminal_events(TMP_AUDIT)
    missing = []
    duplicates = []
    conflicts = []
    for rid in request_ids:
        events = events_by_rid.get(rid, [])
        if len(events) == 0:
            missing.append(rid)
            continue
        if len(events) > 1:
            duplicates.append(rid)
        kinds = {e["event_type"] for e in events}
        if "tool_completed" in kinds and "tool_failed" in kinds:
            conflicts.append(rid)

    passed = (
        len(set(request_ids)) == total
        and len(results) == total
        and len(missing) == 0
        and len(duplicates) == 0
        and len(conflicts) == 0
    )
    return {
        "name": "concurrent_burst",
        "passed": passed,
        "details": {
            "total": total,
            "unique_request_ids": len(set(request_ids)),
            "missing_terminal": len(missing),
            "duplicate_terminal": len(duplicates),
            "terminal_conflicts": len(conflicts),
            "missing_examples": missing[:10],
            "duplicate_examples": duplicates[:10],
            "conflict_examples": conflicts[:10],
        },
    }


def _test_sse_drop_recovery() -> Dict[str, Any]:
    details1 = scenario_multi_action_outage_recovery()
    details2 = scenario_snapshot_sse_race()

    history = list(details1.get("history") or [])
    request_ids = [str(item.get("requestId") or "") for item in history]
    duplicate_history = len(request_ids) != len(set(request_ids))
    missing_resolved = any(str(item.get("status") or "") == "pending" for item in history)

    passed = (
        bool(details1.get("hint", "").startswith("Recovered after reconnect"))
        and not duplicate_history
        and not missing_resolved
        and bool((details2.get("entry") or {}).get("status") == "ok")
    )

    return {
        "name": "sse_drop_recovery",
        "passed": passed,
        "details": {
            "outage_recovery": details1,
            "snapshot_sse_race": details2,
            "duplicate_history": duplicate_history,
            "missing_resolved": missing_resolved,
        },
    }


async def _run_all() -> Dict[str, Any]:
    if TMP_AUDIT.exists():
        TMP_AUDIT.unlink()

    os.environ["MCP_AUDIT_LOG_FILE"] = str(TMP_AUDIT)

    results: List[Dict[str, Any]] = []
    failed = False

    tests = [
        _test_duplicate_execution_attempt,
        _test_success_then_sidecar_failure_race,
        _test_concurrent_burst,
    ]
    for fn in tests:
        print(f"[hs-tests] running {fn.__name__}", flush=True)
        try:
            entry = await fn()
            results.append(entry)
            print(f"[hs-tests] done {fn.__name__}: {'PASS' if entry.get('passed') else 'FAIL'}", flush=True)
            if not bool(entry.get("passed")):
                failed = True
        except Exception as exc:
            failed = True
            results.append(
                {
                    "name": fn.__name__,
                    "passed": False,
                    "error": str(exc),
                    "traceback": traceback.format_exc(limit=8),
                }
            )
            print(f"[hs-tests] exception {fn.__name__}: {exc}", flush=True)

    try:
        print("[hs-tests] running sse_drop_recovery", flush=True)
        sse_entry = _test_sse_drop_recovery()
        results.append(sse_entry)
        print(f"[hs-tests] done sse_drop_recovery: {'PASS' if sse_entry.get('passed') else 'FAIL'}", flush=True)
        if not bool(sse_entry.get("passed")):
            failed = True
    except Exception as exc:
        failed = True
        results.append(
            {
                "name": "sse_drop_recovery",
                "passed": False,
                "error": str(exc),
                "traceback": traceback.format_exc(limit=8),
            }
        )

    terminal_map = _read_terminal_events(TMP_AUDIT)
    summary = {
        "verdict": "PASS" if not failed else "FAIL",
        "audit_path": str(TMP_AUDIT),
        "tests": results,
        "terminal_event_request_ids": len(terminal_map),
    }
    return summary


def main() -> int:
    report = asyncio.run(_run_all())
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report.get("verdict") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
