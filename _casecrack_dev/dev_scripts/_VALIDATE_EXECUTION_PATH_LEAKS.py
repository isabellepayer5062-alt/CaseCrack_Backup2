#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
DEFAULT_REPORT = ROOT / "_EXECUTION_PATH_LEAK_REPORT.json"

KNOWN_PATHS = {"MCP", "CLI", "BRIDGE", "MANUAL"}
NON_TERMINAL_EVENTS = {
    "tool_request",
    "bridge_tool_request",
    "cli_command_started",
    "cli_daemon_command_started",
}
TERMINAL_EVENTS = {
    "tool_completed",
    "tool_failed",
    "tool_rejected",
    "bridge_tool_result",
    "cli_command_completed",
    "cli_command_failed",
    "cli_daemon_command_completed",
    "cli_daemon_command_failed",
}


def _entry_point_for(entry: Dict[str, Any], execution_path: str, event_type: str) -> str:
    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
    if metadata:
        explicit = str(metadata.get("entry_point") or "").strip()
        if explicit:
            return explicit
    path = str(execution_path or "").upper()
    et = str(event_type or "")
    if path == "CLI":
        if et.startswith("cli_daemon_"):
            return "cli.daemon.run_daemon"
        return "cli.main._dispatch_command"
    if path == "BRIDGE":
        return "mcp_http_server.handle_call_tool"
    if path == "MANUAL":
        return "manual_or_external"
    return "unknown"


def _user_flow_for(entry: Dict[str, Any], execution_path: str) -> str:
    principal = entry.get("principal") if isinstance(entry.get("principal"), dict) else {}
    auth_type = str(principal.get("auth_type") or "").strip().lower()
    path = str(execution_path or "").upper()
    if path == "CLI":
        return "operator_cli" if auth_type in {"cli", "cli-daemon"} else "cli_orchestrated"
    if path == "BRIDGE":
        return "http_mcp_gateway"
    if path == "MANUAL":
        return "manual_lifecycle"
    return "unknown"


def _feature_for(tool_name: str, execution_path: str, event_type: str) -> str:
    tool = str(tool_name or "").strip().lower()
    path = str(execution_path or "").upper()
    
    # BRIDGE tool → feature mapping (Phase A targets)
    if path == "BRIDGE":
        if tool == "get_system_health":
            return "dashboard_health_monitor"
        if tool == "get_report":
            return "dashboard_export"
        if tool == "help":
            return "ui_help_panel"
    
    # CLI tool → feature mapping (Phase B targets)
    if path == "CLI":
        if tool == "config":
            return "cli_config_management"
        if tool == "scan":
            return "cli_scanning"
        if tool == "exec":
            return "cli_execution"
    
    # Generic fallback
    if path == "BRIDGE":
        return "bridge_generic"
    if path == "CLI":
        return "cli_generic"
    return "unknown_feature"


def _classify_non_mcp_source(execution_path: str, mutation_count: int) -> Dict[str, str]:
    path = str(execution_path or "").upper()
    if path == "CLI" and mutation_count <= 0:
        return {
            "path_type": "CLI read-only",
            "risk": "Safe for correctness",
            "truth_risk": "Medium (state fragmentation)",
            "migration_phase": "Phase B (normalize CLI reads)",
            "action": "Normalize into MCP audit model",
        }
    if path == "CLI" and mutation_count > 0:
        return {
            "path_type": "CLI mutation",
            "risk": "Dangerous for correctness",
            "truth_risk": "Critical (state mutation)",
            "migration_phase": "Phase C (kill mutations)",
            "action": "Block + migrate to MCP",
        }
    if path == "BRIDGE":
        return {
            "path_type": "BRIDGE read command",
            "risk": "Safe for correctness",
            "truth_risk": "Medium (UI fragmentation)",
            "migration_phase": "Phase A (collapse BRIDGE reads)",
            "action": "Convert to MCP call → collapse to transport only",
        }
    if path == "MANUAL":
        return {
            "path_type": "Manual lifecycle",
            "risk": "Dangerous for correctness",
            "truth_risk": "Critical (out-of-band mutation)",
            "migration_phase": "Phase C (kill mutations)",
            "action": "Remove",
        }
    return {
        "path_type": "Unknown path",
        "risk": "Dangerous for correctness",
        "truth_risk": "Unknown",
        "migration_phase": "Phase D (investigate)",
        "action": "Investigate and normalize",
    }


def _compute_trend_stability(trends: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not trends:
        return {
            "trend_stable": False,
            "evaluated_buckets": 0,
            "reason": "no_trend_data",
        }

    tail = trends[-min(6, len(trends)):]
    non_mcp_rates = [float(row.get("non_mcp_execution_rate") or 0.0) for row in tail]
    mutation_rates = [float(row.get("mutation_leak_rate") or 0.0) for row in tail]
    missing_terminal_rates = [float(row.get("missing_terminal_rate") or 0.0) for row in tail]

    spread = max(non_mcp_rates) - min(non_mcp_rates) if non_mcp_rates else 0.0
    stable = (
        len(tail) >= 2
        and spread <= 0.01
        and all(rate == 0.0 for rate in mutation_rates)
        and max(missing_terminal_rates or [0.0]) <= 0.01
    )
    return {
        "trend_stable": bool(stable),
        "evaluated_buckets": len(tail),
        "non_mcp_rate_min": round(min(non_mcp_rates or [0.0]), 6),
        "non_mcp_rate_max": round(max(non_mcp_rates or [0.0]), 6),
        "non_mcp_rate_spread": round(spread, 6),
    }


def _build_migration_plan(non_mcp_sources: List[Dict[str, Any]]) -> Dict[str, Any]:
    phase_a = []  # BRIDGE reads to collapse
    phase_b = []  # CLI reads to normalize
    phase_c = []  # Mutations to block/remove

    for source in non_mcp_sources:
        migration_phase = str(source.get("migration_phase") or "Phase D")
        if "Phase A" in migration_phase:
            phase_a.append(source)
        elif "Phase B" in migration_phase:
            phase_b.append(source)
        elif "Phase C" in migration_phase:
            phase_c.append(source)

    return {
        "phases_ordered": ["Phase A (BRIDGE reads)", "Phase B (CLI reads)", "Phase C (mutations)"],
        "phase_a_bridge_reads": {
            "count": len(phase_a),
            "priority": "HIGH (truth consistency)",
            "sources": phase_a,
            "action": "Convert BRIDGE → MCP call, then bridge becomes transport-only",
            "success_metric": "non_mcp_execution_rate for BRIDGE drops to 0",
        },
        "phase_b_cli_reads": {
            "count": len(phase_b),
            "priority": "MEDIUM (state fragmentation)",
            "sources": phase_b,
            "action": "Option 1: cli → MCP tool call | Option 2: mirror result into MCP audit model",
            "success_metric": "CLI read execution path normalized or reflected in MCP audit",
        },
        "phase_c_mutations": {
            "count": len(phase_c),
            "priority": "CRITICAL (correctness)",
            "sources": phase_c,
            "action": "Block all non-MCP mutations via ILLEGAL_MUTATION_PATH guardrail",
            "success_metric": "mutation_leak_rate stays 0.0, ILLEGAL_MUTATION_PATH logs show 0 violations",
        },
    }


def _safe_rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(numerator) / float(denominator), 6)


def _parse_epoch(ts: str) -> Optional[int]:
    text = str(ts or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _bucket_label(bucket_start_epoch: int) -> str:
    return datetime.fromtimestamp(bucket_start_epoch, tz=timezone.utc).isoformat()


def _compute_bucket_rates(bucket: Dict[str, Any]) -> Dict[str, Any]:
    path_counts: Dict[str, int] = bucket["path_counts"]
    path_total = sum(path_counts.values())
    non_mcp = sum(v for k, v in path_counts.items() if k != "MCP")

    mutation_total = int(bucket["mutation_total"])
    mutation_leaks = int(bucket["mutation_leaks"])

    started_count = int(bucket["started_count"])
    missing_terminal = int(bucket["missing_terminal"])

    missing_request_ids = int(bucket["missing_request_ids"])
    entries_checked = int(bucket["entries_checked"])

    return {
        "bucket_start": _bucket_label(int(bucket["bucket_start_epoch"])),
        "entries_checked": entries_checked,
        "execution_path_distribution": {
            "counts": dict(path_counts),
            "percent": {
                k: _safe_rate(v, path_total) for k, v in path_counts.items()
            },
        },
        "mutation_leak_rate": _safe_rate(mutation_leaks, mutation_total),
        "non_mcp_execution_rate": _safe_rate(non_mcp, path_total),
        "missing_terminal_rate": _safe_rate(missing_terminal, started_count),
        "request_id_gap_rate": _safe_rate(missing_request_ids, entries_checked),
    }


def _default_audit_paths() -> List[Path]:
    return [
        ROOT / "CaseCrack" / "mcp_audit.jsonl",
        ROOT / "mcp_audit.jsonl",
    ]


def _resolve_audit_path(override: Optional[str]) -> Path:
    if override:
        return Path(override)
    for candidate in _default_audit_paths():
        if candidate.exists():
            return candidate
    return _default_audit_paths()[0]


def _scan(path: Path, trend_bucket_minutes: int = 15) -> Dict[str, Any]:
    if not path.exists():
        return {
            "execution_path_leak_validation": "WARN",
            "audit_path": str(path),
            "entries_checked": 0,
            "notes": ["audit_file_missing"],
            "missing_request_ids": 0,
            "unknown_execution_paths": 0,
            "state_mutation_non_mcp": 0,
            "missing_terminal_events": 0,
            "execution_path_distribution": {"counts": {"MCP": 0, "CLI": 0, "BRIDGE": 0, "MANUAL": 0}, "percent": {"MCP": 0.0, "CLI": 0.0, "BRIDGE": 0.0, "MANUAL": 0.0}},
            "mutation_leak_rate": 0.0,
            "non_mcp_execution_rate": 0.0,
            "missing_terminal_rate": 0.0,
            "request_id_gap_rate": 0.0,
            "trends": [],
            "non_mcp_sources": [],
            "cutover_condition": {
                "mutation_leak_rate": 0.0,
                "non_mcp_execution_rate": 0.0,
                "trend_stable": False,
                "ready_for_enforcement": False,
            },
            "details": {
                "state_mutation_non_mcp": [],
                "missing_terminal_request_ids": [],
                "unknown_execution_path_entries": [],
            },
        }

    parsed = 0
    malformed_lines = 0
    missing_request_ids = 0
    unknown_execution_paths = []
    state_mutation_non_mcp = []
    path_counts: Dict[str, int] = {k: 0 for k in sorted(KNOWN_PATHS)}
    mutation_total = 0
    non_mcp_source_map: Dict[tuple, Dict[str, Any]] = {}

    seen_request_ids: Dict[str, Dict[str, bool]] = {}
    request_start_bucket: Dict[str, int] = {}
    request_terminal_bucket: Dict[str, int] = {}

    bucket_seconds = max(1, int(trend_bucket_minutes)) * 60
    trend_acc: Dict[int, Dict[str, Any]] = defaultdict(
        lambda: {
            "bucket_start_epoch": 0,
            "entries_checked": 0,
            "missing_request_ids": 0,
            "path_counts": {k: 0 for k in sorted(KNOWN_PATHS)},
            "mutation_total": 0,
            "mutation_leaks": 0,
            "started_count": 0,
            "missing_terminal": 0,
        }
    )

    def _bucket_for_epoch(epoch: Optional[int]) -> Optional[int]:
        if epoch is None:
            return None
        return int(math.floor(epoch / bucket_seconds) * bucket_seconds)

    def _touch_bucket(bucket_start: int) -> Dict[str, Any]:
        bucket = trend_acc[bucket_start]
        if not bucket["bucket_start_epoch"]:
            bucket["bucket_start_epoch"] = bucket_start
        return bucket

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                malformed_lines += 1
                continue

            parsed += 1
            request_id = str(entry.get("request_id") or "").strip()
            event_type = str(entry.get("event_type") or "").strip()
            execution_path = str(entry.get("execution_path") or "").strip().upper()
            is_state_mutation = bool(entry.get("is_state_mutation"))
            terminal_state = str(entry.get("terminal_state") or "").strip().lower()
            entry_epoch = _parse_epoch(str(entry.get("timestamp") or ""))
            bucket_start = _bucket_for_epoch(entry_epoch)

            if bucket_start is not None:
                bucket = _touch_bucket(bucket_start)
                bucket["entries_checked"] += 1

            if not request_id:
                missing_request_ids += 1
                if bucket_start is not None:
                    bucket["missing_request_ids"] += 1
                continue

            if execution_path and execution_path not in KNOWN_PATHS:
                unknown_execution_paths.append(
                    {
                        "line": line_no,
                        "request_id": request_id,
                        "event_type": event_type,
                        "execution_path": execution_path,
                    }
                )

            if execution_path in KNOWN_PATHS:
                path_counts[execution_path] += 1
                if bucket_start is not None:
                    bucket["path_counts"][execution_path] += 1

            if execution_path and execution_path in KNOWN_PATHS and execution_path != "MCP":
                tool_name = str(entry.get("tool") or "unknown_tool")
                entry_point = _entry_point_for(entry, execution_path, event_type)
                user_flow = _user_flow_for(entry, execution_path)
                feature = _feature_for(tool_name, execution_path, event_type)
                source_key = (execution_path, tool_name, entry_point, user_flow, feature)
                source_row = non_mcp_source_map.setdefault(
                    source_key,
                    {
                        "execution_path": execution_path,
                        "tool": tool_name,
                        "entry_point": entry_point,
                        "user_flow": user_flow,
                        "feature": feature,
                        "count": 0,
                        "mutation_count": 0,
                    },
                )
                source_row["count"] += 1
                if is_state_mutation:
                    source_row["mutation_count"] += 1

            if is_state_mutation:
                mutation_total += 1
                if bucket_start is not None:
                    bucket["mutation_total"] += 1

            if is_state_mutation and execution_path and execution_path != "MCP":
                state_mutation_non_mcp.append(
                    {
                        "line": line_no,
                        "request_id": request_id,
                        "event_type": event_type,
                        "execution_path": execution_path,
                        "tool": entry.get("tool"),
                    }
                )
                if bucket_start is not None:
                    bucket["mutation_leaks"] += 1

            req_state = seen_request_ids.setdefault(request_id, {"has_non_terminal": False, "has_terminal": False})
            if event_type in NON_TERMINAL_EVENTS:
                req_state["has_non_terminal"] = True
                if bucket_start is not None:
                    bucket["started_count"] += 1
                    request_start_bucket[request_id] = bucket_start
            if event_type in TERMINAL_EVENTS or terminal_state == "terminal":
                req_state["has_terminal"] = True
                if bucket_start is not None:
                    request_terminal_bucket[request_id] = bucket_start

    missing_terminal_request_ids = sorted(
        request_id
        for request_id, state in seen_request_ids.items()
        if state.get("has_non_terminal") and not state.get("has_terminal")
    )

    for req_id in missing_terminal_request_ids:
        start_bucket = request_start_bucket.get(req_id)
        if start_bucket is None:
            continue
        bucket = _touch_bucket(start_bucket)
        bucket["missing_terminal"] += 1

    path_total = sum(path_counts.values())
    non_mcp_path_total = sum(v for k, v in path_counts.items() if k != "MCP")

    trend_rows = [_compute_bucket_rates(v) for _, v in sorted(trend_acc.items(), key=lambda kv: kv[0])]
    trend_stability = _compute_trend_stability(trend_rows)

    non_mcp_sources: List[Dict[str, Any]] = []
    for row in non_mcp_source_map.values():
        classification = _classify_non_mcp_source(str(row.get("execution_path") or ""), int(row.get("mutation_count") or 0))
        out = dict(row)
        out.update(classification)
        non_mcp_sources.append(out)
    non_mcp_sources.sort(key=lambda r: int(r.get("count") or 0), reverse=True)

    mutation_leak_rate = _safe_rate(len(state_mutation_non_mcp), mutation_total)
    non_mcp_execution_rate = _safe_rate(non_mcp_path_total, path_total)
    missing_terminal_rate = _safe_rate(len(missing_terminal_request_ids), sum(1 for v in seen_request_ids.values() if v.get("has_non_terminal")))
    request_id_gap_rate = _safe_rate(missing_request_ids, parsed)
    ready_for_enforcement = bool(
        mutation_leak_rate == 0.0
        and non_mcp_execution_rate < 0.01
        and bool(trend_stability.get("trend_stable"))
    )

    verdict = "PASS"
    if (
        missing_request_ids > 0
        or unknown_execution_paths
        or state_mutation_non_mcp
        or missing_terminal_request_ids
        or malformed_lines > 0
    ):
        verdict = "WARN"

    return {
        "execution_path_leak_validation": verdict,
        "audit_path": str(path),
        "entries_checked": parsed,
        "missing_request_ids": missing_request_ids,
        "unknown_execution_paths": len(unknown_execution_paths),
        "state_mutation_non_mcp": len(state_mutation_non_mcp),
        "missing_terminal_events": len(missing_terminal_request_ids),
        "malformed_lines": malformed_lines,
        "execution_path_distribution": {
            "counts": path_counts,
            "percent": {k: _safe_rate(v, path_total) for k, v in path_counts.items()},
        },
        "mutation_leak_rate": mutation_leak_rate,
        "non_mcp_execution_rate": non_mcp_execution_rate,
        "missing_terminal_rate": missing_terminal_rate,
        "request_id_gap_rate": request_id_gap_rate,
        "trends": trend_rows,
        "non_mcp_sources": non_mcp_sources,
        "trend_window": {
            "bucket_minutes": int(trend_bucket_minutes),
            "bucket_count": len(trend_rows),
        },
        "trend_stability": trend_stability,
        "cutover_condition": {
            "mutation_leak_rate": mutation_leak_rate,
            "non_mcp_execution_rate": non_mcp_execution_rate,
            "trend_stable": bool(trend_stability.get("trend_stable")),
            "ready_for_enforcement": ready_for_enforcement,
            "target": {
                "mutation_leak_rate": 0.0,
                "non_mcp_execution_rate_lt": 0.01,
                "trend_stable": True,
            },
        },
        "migration_plan": _build_migration_plan(non_mcp_sources),
        "details": {
            "state_mutation_non_mcp": state_mutation_non_mcp[:200],
            "missing_terminal_request_ids": missing_terminal_request_ids[:200],
            "unknown_execution_path_entries": unknown_execution_paths[:200],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate execution-path leak signals in MCP audit log (output-only).")
    parser.add_argument("--audit-path", default=None, help="Optional explicit path to mcp_audit.jsonl")
    parser.add_argument("--out", default=str(DEFAULT_REPORT), help="Output report JSON path")
    parser.add_argument("--trend-bucket-minutes", type=int, default=15, help="Trend bucket width in minutes (default: 15)")
    args = parser.parse_args()

    audit_path = _resolve_audit_path(args.audit_path)
    report = _scan(audit_path, trend_bucket_minutes=max(1, int(args.trend_bucket_minutes or 15)))

    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

    # Output-only validator: never fail CI or automation yet.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
