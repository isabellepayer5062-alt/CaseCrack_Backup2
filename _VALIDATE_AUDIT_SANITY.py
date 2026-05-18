#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
DEFAULT_REPORT = ROOT / "_AUDIT_SANITY_REPORT.json"

KNOWN_ERROR_CODES = {
    "ALLOWLIST_DENY",
    "LICENSE_REQUIRED",
    "RATE_LIMITED",
    "TENANT_ID_REQUIRED",
    "UNKNOWN_ARGUMENT",
    "VALIDATION_ERROR",
    "INTERNAL_ERROR",
}


@dataclass
class TransitionIssue:
    request_id: str
    line_from: int
    state_from: str
    line_to: int
    state_to: str


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

    # Return primary default even when missing so caller can report cleanly.
    return _default_audit_paths()[0]


def _normalize_state(entry: Dict[str, Any]) -> Optional[str]:
    ok_value = entry.get("ok")
    if isinstance(ok_value, bool):
        return "ok" if ok_value else "error"

    status = str(entry.get("status") or "").strip().lower()
    if status in {"pending", "in_progress", "running"}:
        return "pending"
    if status in {"ok", "success", "completed"}:
        return "ok"
    if status in {"error", "failed", "failure"}:
        return "error"
    return None


def _extract_error_code(entry: Dict[str, Any]) -> Optional[str]:
    code = entry.get("code")
    if isinstance(code, str) and code.strip():
        return code.strip().upper()

    metadata = entry.get("metadata")
    if isinstance(metadata, dict):
        reason_code = metadata.get("reason_code")
        if isinstance(reason_code, str) and reason_code.strip():
            return reason_code.strip().upper()

    error_text = str(entry.get("error") or "").lower()
    if "license_required" in error_text:
        return "LICENSE_REQUIRED"
    if "rate" in error_text and "limit" in error_text:
        return "RATE_LIMITED"
    if "allowlist" in error_text and "deny" in error_text:
        return "ALLOWLIST_DENY"
    if "tenant_id is required" in error_text:
        return "TENANT_ID_REQUIRED"
    if "unknown argument" in error_text:
        return "UNKNOWN_ARGUMENT"
    if error_text:
        return "INTERNAL_ERROR"
    return None


def _is_terminal_tool_event(entry: Dict[str, Any]) -> bool:
    event_type = str(entry.get("event_type") or "")
    return event_type in {"tool_completed", "tool_failed"}


def _is_tool_lifecycle_event(entry: Dict[str, Any]) -> bool:
    event_type = str(entry.get("event_type") or "")
    return event_type.startswith("tool_")


def _scan_audit(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {
            "audit_sanity": "FAIL",
            "audit_path": str(path),
            "entries_checked": 0,
            "duplicate_request_ids": 0,
            "missing_request_ids": 0,
            "missing_terminal_states": 0,
            "invalid_codes": 0,
            "impossible_transitions": 0,
            "malformed_lines": 0,
            "notes": ["audit_file_missing"],
            "details": {
                "duplicate_request_ids": [],
                "missing_terminal_request_ids": [],
                "invalid_code_entries": [],
                "impossible_transitions": [],
                "malformed_lines": [],
            },
        }

    malformed_lines: List[int] = []
    parsed_entries = 0

    expected_terminal_request_ids: set[str] = set()
    terminal_request_ids: set[str] = set()
    missing_request_ids = 0
    invalid_code_entries: List[Dict[str, Any]] = []
    terminal_events_by_request_id: Dict[str, List[Dict[str, Any]]] = {}

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for idx, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                malformed_lines.append(idx)
                continue

            parsed_entries += 1

            request_id = str(entry.get("request_id") or "").strip()
            if not request_id:
                missing_request_ids += 1
                continue

            if _is_tool_lifecycle_event(entry):
                expected_terminal_request_ids.add(request_id)

            if _is_terminal_tool_event(entry):
                terminal_request_ids.add(request_id)
                state = _normalize_state(entry)
                terminal_events_by_request_id.setdefault(request_id, []).append(
                    {
                        "line": idx,
                        "event_type": str(entry.get("event_type") or ""),
                        "state": state,
                        "tool": entry.get("tool"),
                    }
                )
                if state == "error":
                    code = _extract_error_code(entry)
                    if not code or code not in KNOWN_ERROR_CODES:
                        invalid_code_entries.append(
                            {
                                "line": idx,
                                "request_id": request_id,
                                "tool": entry.get("tool"),
                                "code": code,
                                "error": entry.get("error"),
                            }
                        )

    missing_terminal = sorted(expected_terminal_request_ids - terminal_request_ids)

    duplicate_terminal_request_ids = sorted(
        request_id
        for request_id, events in terminal_events_by_request_id.items()
        if len(events) > 1
    )

    conflicting_terminal_request_ids: List[str] = []
    transition_issues: List[TransitionIssue] = []
    for request_id, events in terminal_events_by_request_id.items():
        states = [str(event.get("state") or "") for event in events]
        if "ok" in states and "error" in states:
            conflicting_terminal_request_ids.append(request_id)
            first_ok = next((event for event in events if event.get("state") == "ok"), None)
            first_error = next((event for event in events if event.get("state") == "error"), None)
            if first_ok and first_error:
                transition_issues.append(
                    TransitionIssue(
                        request_id=request_id,
                        line_from=int(first_ok["line"]),
                        state_from="ok",
                        line_to=int(first_error["line"]),
                        state_to="error",
                    )
                )

    sanity_pass = (
        len(duplicate_terminal_request_ids) == 0
        and missing_request_ids == 0
        and len(missing_terminal) == 0
        and len(invalid_code_entries) == 0
        and len(transition_issues) == 0
        and len(malformed_lines) == 0
    )

    return {
        "audit_sanity": "PASS" if sanity_pass else "FAIL",
        "audit_path": str(path),
        "entries_checked": parsed_entries,
        "duplicate_request_ids": len(duplicate_terminal_request_ids),
        "missing_request_ids": missing_request_ids,
        "missing_terminal_states": len(missing_terminal),
        "invalid_codes": len(invalid_code_entries),
        "impossible_transitions": len(transition_issues),
        "malformed_lines": len(malformed_lines),
        "known_error_codes": sorted(KNOWN_ERROR_CODES),
        "terminal_conflicts": len(conflicting_terminal_request_ids),
        "details": {
            "duplicate_request_ids": duplicate_terminal_request_ids,
            "missing_terminal_request_ids": missing_terminal[:200],
            "invalid_code_entries": invalid_code_entries[:200],
            "terminal_conflict_request_ids": conflicting_terminal_request_ids[:200],
            "impossible_transitions": [
                {
                    "request_id": issue.request_id,
                    "line_from": issue.line_from,
                    "state_from": issue.state_from,
                    "line_to": issue.line_to,
                    "state_to": issue.state_to,
                }
                for issue in transition_issues[:200]
            ],
            "malformed_lines": malformed_lines[:200],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate runtime MCP audit log sanity.")
    parser.add_argument(
        "--audit-path",
        default=None,
        help="Optional explicit path to audit JSONL file.",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_REPORT),
        help="Output JSON report path.",
    )
    args = parser.parse_args()

    audit_path = _resolve_audit_path(args.audit_path)
    report = _scan_audit(audit_path)

    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

    return 0 if report.get("audit_sanity") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
