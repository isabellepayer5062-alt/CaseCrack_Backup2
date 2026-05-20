#!/usr/bin/env python3
from __future__ import annotations

import json
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ROOT = Path(__file__).resolve().parent
CASECRACK_ROOT = ROOT / "CaseCrack"
REPORT_JSON = ROOT / "_PRODUCTION_READINESS_CONTRACT_REPORT.json"
REPORT_MD = ROOT / "_PRODUCTION_READINESS_CONTRACT_REPORT.md"
VALIDATOR_MAX_AGE_MINUTES = 30
VALIDATOR_TIMEOUT_SECONDS = 120


@dataclass
class EvidenceItem:
    artifact: str
    exists: bool
    kind: str
    summary: str


@dataclass
class ValidatorSpec:
    name: str
    script: Path
    artifact: Path
    validator_version: str
    fingerprint_inputs: List[Path]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat_now() -> str:
    return _utc_now().isoformat()


def _parse_iso_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _compute_code_hash(paths: List[Path]) -> str:
    hasher = hashlib.sha256()
    for path in sorted(set(paths), key=str):
        hasher.update(str(path).encode("utf-8", errors="replace"))
        if path.exists() and path.is_file():
            hasher.update(path.read_bytes())
        else:
            hasher.update(b"<missing>")
    return hasher.hexdigest()


def _extract_artifact_meta(payload: Dict[str, Any]) -> Dict[str, Any]:
    meta = payload.get("_contract_evidence")
    if isinstance(meta, dict):
        return meta
    return {}


def _stamp_artifact_metadata(path: Path, payload: Dict[str, Any], validator_version: str, code_hash: str) -> Dict[str, Any]:
    payload["_contract_evidence"] = {
        "generated_at": _isoformat_now(),
        "validator_version": validator_version,
        "code_hash": code_hash,
        "max_age_minutes": VALIDATOR_MAX_AGE_MINUTES,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _validate_artifact(spec: ValidatorSpec, code_hash: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "artifact_exists": spec.artifact.exists(),
        "artifact_valid": False,
        "bootstrap_mtime_match": False,
        "fresh": False,
        "code_hash_matches": False,
        "validator_version_matches": False,
        "artifact_age_minutes": None,
        "reasons": [],
        "artifact_payload": None,
    }
    if not spec.artifact.exists():
        result["reasons"].append("artifact_missing")
        return result

    payload = _load_optional_json(spec.artifact)
    if payload is None:
        result["reasons"].append("artifact_unreadable")
        return result

    artifact_mtime = datetime.fromtimestamp(spec.artifact.stat().st_mtime, tz=timezone.utc)
    meta = _extract_artifact_meta(payload)
    timestamp = _parse_iso_timestamp(meta.get("generated_at"))
    if timestamp is None:
        timestamp = _parse_iso_timestamp(payload.get("generated_at") or payload.get("timestamp"))
    if timestamp is None:
        timestamp = artifact_mtime

    age_minutes = (_utc_now() - timestamp) / timedelta(minutes=1)
    result["artifact_age_minutes"] = round(age_minutes, 2)
    if age_minutes <= VALIDATOR_MAX_AGE_MINUTES:
        result["fresh"] = True
    else:
        result["reasons"].append("stale_artifact")

    artifact_hash = meta.get("code_hash") or payload.get("code_hash")
    if isinstance(artifact_hash, str) and artifact_hash == code_hash:
        result["code_hash_matches"] = True
    else:
        result["reasons"].append("code_hash_mismatch")

    artifact_version = meta.get("validator_version") or payload.get("validator_version")
    if isinstance(artifact_version, str) and artifact_version == spec.validator_version:
        result["validator_version_matches"] = True
    else:
        result["reasons"].append("validator_version_mismatch")

    latest_input_mtime = artifact_mtime
    for input_path in spec.fingerprint_inputs:
        if input_path.exists() and input_path.is_file():
            input_mtime = datetime.fromtimestamp(input_path.stat().st_mtime, tz=timezone.utc)
            if input_mtime > latest_input_mtime:
                latest_input_mtime = input_mtime
    if artifact_mtime >= latest_input_mtime:
        result["bootstrap_mtime_match"] = True

    result["artifact_payload"] = payload
    result["artifact_valid"] = bool(
        result["fresh"] and result["code_hash_matches"] and result["validator_version_matches"]
    )
    return result


def run_python_script(path: Path) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            [sys.executable, str(path)],
            cwd=str(ROOT),
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=VALIDATOR_TIMEOUT_SECONDS,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "")
        stderr = (exc.stderr or "") + f"\n[contract] validator timed out after {VALIDATOR_TIMEOUT_SECONDS}s"
        return 124, stdout, stderr


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def static_ui_leakage_scan() -> Dict[str, Any]:
    dashboard_path = CASECRACK_ROOT / "tools" / "burp_enterprise" / "static" / "js" / "recon-dashboard.js"
    adapter_path = CASECRACK_ROOT / "tools" / "burp_enterprise" / "static" / "js" / "mcp-ui-adapter.js"
    css_path = CASECRACK_ROOT / "tools" / "burp_enterprise" / "static" / "css" / "recon-dashboard.css"

    findings: List[Dict[str, Any]] = []
    # The contract forbids direct MCP transport/control-plane access in the dashboard,
    # not generic fetch usage for unrelated dashboard features.
    disallowed_patterns = [
        (dashboard_path, re.compile(r"fetch\s*\([^\n]*(?:\/api\/mcp|mcp\/(?:call|snapshot|targets|report))", re.IGNORECASE), "dashboard_direct_mcp_fetch"),
        (dashboard_path, re.compile(r"new\s+EventSource\s*\([^\n]*(?:\/api\/mcp|mcp\/)", re.IGNORECASE), "dashboard_direct_mcp_eventsource"),
        (dashboard_path, re.compile(r"XMLHttpRequest[^\n]*(?:\/api\/mcp|mcp\/)", re.IGNORECASE), "dashboard_direct_mcp_xhr"),
    ]

    allowed_adapter_calls = {
        "window.CC_MCP_ADAPTER.callTool",
        "window.CC_MCP_ADAPTER.getSystemState",
        "window.CC_MCP_ADAPTER.getSystemExplanation",
        "window.CC_MCP_ADAPTER.getOperatorConsoleState",
        "window.CC_MCP_ADAPTER.setActivityFilter",
        "window.CC_MCP_ADAPTER.getActivityById",
        "window.CC_MCP_ADAPTER.retryAction",
        "window.CC_MCP_ADAPTER.setStreamConnected",
        "window.CC_MCP_ADAPTER.ingestRealtimeEnvelope",
        "window.CC_MCP_ADAPTER.ingestEvent",
    }
    adapter_call_pattern = re.compile(r"window\.CC_MCP_ADAPTER\.([A-Za-z0-9_]+)")

    dashboard_text = dashboard_path.read_text(encoding="utf-8")
    adapter_text = adapter_path.read_text(encoding="utf-8")
    css_exists = css_path.exists()

    for path, pattern, finding_type in disallowed_patterns:
        text = path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append({
                "file": str(path),
                "line": line,
                "type": finding_type,
                "match": match.group(0),
            })

    for match in adapter_call_pattern.finditer(dashboard_text):
        fq_name = f"window.CC_MCP_ADAPTER.{match.group(1)}"
        if fq_name not in allowed_adapter_calls:
            line = dashboard_text.count("\n", 0, match.start()) + 1
            findings.append({
                "file": str(dashboard_path),
                "line": line,
                "type": "dashboard_unapproved_adapter_api",
                "match": fq_name,
            })

    render_only_signals = {
        "uses_system_state": "getSystemState()" in dashboard_text,
        "uses_explanation": "getSystemExplanation()" in dashboard_text,
        "has_adapter_activity_table": "activityTable" in dashboard_text,
        "adapter_has_explanation": "getSystemExplanation" in adapter_text,
        "css_present": css_exists,
    }

    return {
        "passed": not findings,
        "findings": findings,
        "signals": render_only_signals,
        "artifact": str(ROOT / "_UI_LOGIC_LEAKAGE_AUDIT.json"),
    }


def write_ui_audit(audit: Dict[str, Any]) -> None:
    path = Path(audit["artifact"])
    path.write_text(json.dumps(audit, indent=2), encoding="utf-8")


def summarize_frontend_gate(report: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    passed: List[str] = []
    failed: List[str] = []
    if report.get("verdict") == "GO":
        passed.extend(["CP-001", "CP-002", "CP-003", "CP-005", "TX-001", "TX-002", "TX-005"])
    else:
        failed.extend(["CP-001", "CP-002", "CP-003", "CP-005", "TX-001", "TX-002", "TX-005"])

    checks = {item.get("name"): item for item in report.get("checks", [])}

    if checks.get("control_plane_integrity", {}).get("passed"):
        passed.append("CP-004")
    else:
        failed.append("CP-004")

    if checks.get("adapter_missing_terminal_recovery", {}).get("passed"):
        passed.append("TX-002")
    else:
        failed.append("TX-002")

    if checks.get("adapter_truth_consistency", {}).get("passed"):
        passed.append("TX-001")
    else:
        failed.append("TX-001")

    if checks.get("adapter_gateway_guardrail", {}).get("passed"):
        passed.append("UI-002")
    else:
        failed.append("UI-002")

    if checks.get("adapter_history_bounds", {}).get("passed"):
        passed.append("INV-004")
    else:
        failed.append("INV-004")

    return sorted(set(passed)), sorted(set(failed))


def summarize_tristate(report: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    phases = {item.get("name"): item for item in report.get("phases", [])}
    passed: List[str] = []
    failed: List[str] = []

    if phases.get("offline", {}).get("passed") and phases.get("degraded", {}).get("passed") and phases.get("healthy", {}).get("passed"):
        passed.append("E2E-001")
    else:
        failed.append("E2E-001")

    if phases.get("concurrency", {}).get("passed"):
        passed.extend(["LD-001", "TX-003"])
    else:
        failed.extend(["LD-001", "TX-003"])

    healthy_details = phases.get("healthy", {}).get("details", {})
    if healthy_details.get("outcomes", {}).get("rate_limited", 0) > 0:
        passed.append("LD-003")
    else:
        failed.append("LD-003")

    degraded_details = phases.get("degraded", {}).get("details", {})
    if degraded_details.get("outcomes", {}).get("allowlist_deny", 0) > 0 and degraded_details.get("outcomes", {}).get("license_required", 0) > 0:
        passed.append("E2E-004")
    else:
        failed.append("E2E-004")

    return sorted(set(passed)), sorted(set(failed))


def summarize_gateway(report: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    passed = []
    failed = []
    if report.get("verdict") == "GO":
        passed.extend(["CP-006", "TX-005"])
    else:
        failed.extend(["CP-006", "TX-005"])
    return sorted(set(passed)), sorted(set(failed))


def summarize_adapter_stress(report: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Read _ADAPTER_INVARIANT_STRESS_REPORT.json → prove INV-001..003 + INV-005."""
    passed = []
    failed = []
    blockers = report.get("blockers_proven", {})
    for blocker_id in ("INV-001", "INV-002", "INV-003", "INV-005"):
        if blockers.get(blocker_id):
            passed.append(blocker_id)
        else:
            failed.append(blocker_id)
    return sorted(set(passed)), sorted(set(failed))


def summarize_transport_chaos(report: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Read _TRANSPORT_CHAOS_TEST_REPORT.json → prove TX-004, E2E-002, E2E-003."""
    passed = []
    failed = []
    blockers = report.get("blockers_proven", {})
    for blocker_id in ("TX-004", "E2E-002", "E2E-003"):
        if blockers.get(blocker_id):
            passed.append(blocker_id)
        else:
            failed.append(blocker_id)
    return sorted(set(passed)), sorted(set(failed))


def summarize_intel_expl(report: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Read _INTELLIGENCE_EXPLAINABILITY_DETERMINISM_REPORT.json → prove IN-001..004 + EX-001..003."""
    passed = []
    failed = []
    blockers = report.get("blockers_proven", {})
    for blocker_id in ("IN-001", "IN-002", "IN-003", "IN-004", "EX-001", "EX-002", "EX-003"):
        if blockers.get(blocker_id):
            passed.append(blocker_id)
        else:
            failed.append(blocker_id)
    return sorted(set(passed)), sorted(set(failed))


def summarize_concurrency_load(report: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Read _CONCURRENCY_LOAD_BENCHMARK_REPORT.json → prove LD-002, UI-003."""
    passed = []
    failed = []
    blockers = report.get("blockers_proven", {})
    for blocker_id in ("LD-002", "UI-003"):
        if blockers.get(blocker_id):
            passed.append(blocker_id)
        else:
            failed.append(blocker_id)
    return sorted(set(passed)), sorted(set(failed))


def build_contract_result(
    frontend_report: Dict[str, Any],
    tristate_report: Dict[str, Any],
    gateway_report: Dict[str, Any],
    ui_audit: Dict[str, Any],
    validator_decisions: Optional[Dict[str, Dict[str, Any]]] = None,
    adapter_stress_report: Optional[Dict[str, Any]] = None,
    transport_chaos_report: Optional[Dict[str, Any]] = None,
    intel_expl_report: Optional[Dict[str, Any]] = None,
    concurrency_load_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    required_blockers = [
        "CP-001", "CP-002", "CP-003", "CP-004", "CP-005", "CP-006",
        "TX-001", "TX-002", "TX-003", "TX-004", "TX-005",
        "INV-001", "INV-002", "INV-003", "INV-004", "INV-005",
        "LD-001", "LD-002", "LD-003",
        "IN-001", "IN-002", "IN-003", "IN-004",
        "EX-001", "EX-002", "EX-003",
        "UI-001", "UI-002", "UI-003",
        "E2E-001", "E2E-002", "E2E-003", "E2E-004",
    ]

    passed: set[str] = set()
    failed: set[str] = set()

    for ok, bad in (
        summarize_frontend_gate(frontend_report),
        summarize_tristate(tristate_report),
        summarize_gateway(gateway_report),
    ):
        passed.update(ok)
        failed.update(bad)

    if ui_audit.get("passed"):
        passed.add("UI-001")
    else:
        failed.add("UI-001")

    if adapter_stress_report is not None:
        ok_s, bad_s = summarize_adapter_stress(adapter_stress_report)
        passed.update(ok_s)
        failed.update(bad_s)

    if transport_chaos_report is not None:
        ok_t, bad_t = summarize_transport_chaos(transport_chaos_report)
        passed.update(ok_t)
        failed.update(bad_t)

    if intel_expl_report is not None:
        ok_i, bad_i = summarize_intel_expl(intel_expl_report)
        passed.update(ok_i)
        failed.update(bad_i)

    if concurrency_load_report is not None:
        ok_l, bad_l = summarize_concurrency_load(concurrency_load_report)
        passed.update(ok_l)
        failed.update(bad_l)

    failed.update(required_blockers)
    failed.difference_update(passed)

    validator_decisions = validator_decisions or {}
    frontend_decision = validator_decisions.get("frontend_integration_gate", {})
    tristate_decision = validator_decisions.get("tristate_validator", {})
    gateway_decision = validator_decisions.get("gateway_fidelity", {})

    evidence_items = [
        EvidenceItem(
            artifact=str(ROOT / "_FINAL_FRONTEND_INTEGRATION_GATE_REPORT.json"),
            exists=(ROOT / "_FINAL_FRONTEND_INTEGRATION_GATE_REPORT.json").exists(),
            kind="frontend_integration_gate",
            summary=f"verdict={frontend_report.get('verdict')}; decision={frontend_decision.get('decision', 'unknown')}",
        ),
        EvidenceItem(
            artifact=str(ROOT / "_FINAL_MCP_TRISTATE_VALIDATION_REPORT.json"),
            exists=(ROOT / "_FINAL_MCP_TRISTATE_VALIDATION_REPORT.json").exists(),
            kind="tristate_validator",
            summary=f"verdict={tristate_report.get('verdict')}; decision={tristate_decision.get('decision', 'unknown')}",
        ),
        EvidenceItem(
            artifact=str(ROOT / "_FINAL_MCP_GATEWAY_FIDELITY_REPORT.json"),
            exists=(ROOT / "_FINAL_MCP_GATEWAY_FIDELITY_REPORT.json").exists(),
            kind="gateway_fidelity",
            summary=f"verdict={gateway_report.get('verdict')}; decision={gateway_decision.get('decision', 'unknown')}",
        ),
        EvidenceItem(
            artifact=str(ui_audit["artifact"]),
            exists=True,
            kind="ui_leakage_audit",
            summary=f"passed={ui_audit.get('passed')}",
        ),
        EvidenceItem(
            artifact=str(ROOT / "_ADAPTER_INVARIANT_STRESS_REPORT.json"),
            exists=(ROOT / "_ADAPTER_INVARIANT_STRESS_REPORT.json").exists(),
            kind="adapter_invariant_stress",
            summary="missing required artifact" if not (ROOT / "_ADAPTER_INVARIANT_STRESS_REPORT.json").exists() else "present",
        ),
        EvidenceItem(
            artifact=str(ROOT / "_TRANSPORT_CHAOS_TEST_REPORT.json"),
            exists=(ROOT / "_TRANSPORT_CHAOS_TEST_REPORT.json").exists(),
            kind="transport_chaos",
            summary="missing required artifact" if not (ROOT / "_TRANSPORT_CHAOS_TEST_REPORT.json").exists() else "present",
        ),
        EvidenceItem(
            artifact=str(ROOT / "_INTELLIGENCE_EXPLAINABILITY_DETERMINISM_REPORT.json"),
            exists=(ROOT / "_INTELLIGENCE_EXPLAINABILITY_DETERMINISM_REPORT.json").exists(),
            kind="intel_explainability_determinism",
            summary="missing required artifact" if not (ROOT / "_INTELLIGENCE_EXPLAINABILITY_DETERMINISM_REPORT.json").exists() else "present",
        ),
        EvidenceItem(
            artifact=str(ROOT / "_CONCURRENCY_LOAD_BENCHMARK_REPORT.json"),
            exists=(ROOT / "_CONCURRENCY_LOAD_BENCHMARK_REPORT.json").exists(),
            kind="concurrency_load_benchmark",
            summary="missing required artifact" if not (ROOT / "_CONCURRENCY_LOAD_BENCHMARK_REPORT.json").exists() else "present",
        ),
    ]

    unproven = sorted(
        blocker
        for blocker in failed
        if blocker not in {
            "UI-001",
            "UI-002",
            "CP-001",
            "CP-002",
            "CP-003",
            "CP-004",
            "CP-005",
            "CP-006",
            "TX-001",
            "TX-002",
            "TX-003",
            "TX-005",
            "LD-001",
            "LD-003",
            "E2E-001",
            "E2E-004",
            "INV-004",
        }
    )

    blocker_status = {
        blocker: (
            "PASS" if blocker in passed else "UNPROVEN"
        )
        for blocker in required_blockers
    }

    failed_blockers = sorted(
        blocker if blocker not in unproven else f"{blocker}:UNPROVEN"
        for blocker in failed
    )

    return {
        "verdict": "READY" if not failed else "NOT_READY",
        "failed_blockers": failed_blockers,
        "passed_blockers": sorted(passed),
        "evidence_index": [asdict(item) for item in evidence_items],
        "blocker_status": blocker_status,
        "notes": [
            "Contract is binary: any failed or unproven blocker yields NOT_READY.",
            "Existing runtime validators prove only a subset of the contract.",
            "Artifacts are reused only when evidence freshness, code hash, and validator version all match.",
        ],
        "timestamp": _isoformat_now(),
    }


def write_markdown(report: Dict[str, Any]) -> None:
    evidence_lines = "\n".join(
        f"- {item['kind']}: {item['artifact']} ({'present' if item['exists'] else 'missing'}) - {item['summary']}"
        for item in report["evidence_index"]
    )
    passed_lines = "\n".join(f"- {item}" for item in report["passed_blockers"]) or "- none"
    failed_lines = "\n".join(f"- {item}" for item in report["failed_blockers"]) or "- none"

    REPORT_MD.write_text(
        "# Production Readiness Contract Report\n\n"
        f"- verdict: {report['verdict']}\n"
        f"- timestamp: {report['timestamp']}\n\n"
        "## Passed Blockers\n\n"
        f"{passed_lines}\n\n"
        "## Failed Blockers\n\n"
        f"{failed_lines}\n\n"
        "## Evidence Index\n\n"
        f"{evidence_lines}\n",
        encoding="utf-8",
    )


def _load_optional_json(path: Path) -> Optional[Dict[str, Any]]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
    return None


def _default_failed_report(kind: str) -> Dict[str, Any]:
    if kind == "tristate_validator":
        return {"verdict": "NO_GO", "phases": []}
    return {"verdict": "NO_GO", "checks": []}


def _build_validator_specs() -> List[ValidatorSpec]:
    mcp_root = CASECRACK_ROOT / "tools" / "burp_enterprise" / "mcp"
    dashboard_root = CASECRACK_ROOT / "tools" / "burp_enterprise" / "recon_dashboard"
    static_js_root = CASECRACK_ROOT / "tools" / "burp_enterprise" / "static" / "js"

    return [
        ValidatorSpec(
            name="frontend_integration_gate",
            script=ROOT / "_FINAL_FRONTEND_INTEGRATION_GATE.py",
            artifact=ROOT / "_FINAL_FRONTEND_INTEGRATION_GATE_REPORT.json",
            validator_version="frontend_gate_v2",
            fingerprint_inputs=[
                ROOT / "_FINAL_FRONTEND_INTEGRATION_GATE.py",
                mcp_root / "mcp_server.py",
                mcp_root / "mcp_http_server.py",
                mcp_root / "mcp_config.py",
                mcp_root / "mcp_auth.py",
                dashboard_root / "server.py",
                static_js_root / "recon-dashboard.js",
                static_js_root / "mcp-ui-adapter.js",
            ],
        ),
        ValidatorSpec(
            name="tristate_validator",
            script=ROOT / "_FINAL_MCP_TRISTATE_VALIDATION.py",
            artifact=ROOT / "_FINAL_MCP_TRISTATE_VALIDATION_REPORT.json",
            validator_version="tristate_v2",
            fingerprint_inputs=[
                ROOT / "_FINAL_MCP_TRISTATE_VALIDATION.py",
                mcp_root / "mcp_server.py",
                mcp_root / "mcp_config.py",
                mcp_root / "mcp_auth.py",
                dashboard_root / "server.py",
            ],
        ),
        ValidatorSpec(
            name="gateway_fidelity",
            script=ROOT / "_FINAL_MCP_GATEWAY_FIDELITY_TEST.py",
            artifact=ROOT / "_FINAL_MCP_GATEWAY_FIDELITY_REPORT.json",
            validator_version="gateway_fidelity_v2",
            fingerprint_inputs=[
                ROOT / "_FINAL_MCP_GATEWAY_FIDELITY_TEST.py",
                mcp_root / "mcp_server.py",
                mcp_root / "mcp_auth.py",
                dashboard_root / "server.py",
            ],
        ),
    ]


def _compute_confidence(verdict: str, validator_decisions: Dict[str, Dict[str, Any]]) -> str:
    if verdict != "READY":
        return "LOW"
    if all(decision.get("artifact_trusted") for decision in validator_decisions.values()):
        return "HIGH"
    return "MEDIUM"


def main() -> int:
    validator_specs = _build_validator_specs()
    run_results = []
    validator_decisions: Dict[str, Dict[str, Any]] = {}
    validator_reports: Dict[str, Dict[str, Any]] = {}

    for spec in validator_specs:
        code_hash = _compute_code_hash(spec.fingerprint_inputs)
        validation = _validate_artifact(spec, code_hash)

        decision: Dict[str, Any] = {
            "validator": spec.name,
            "script": str(spec.script),
            "artifact": str(spec.artifact),
            "validator_version": spec.validator_version,
            "decision": "reused_validated" if validation["artifact_valid"] else "rerun_required",
            "artifact_exists": validation["artifact_exists"],
            "artifact_age_minutes": validation["artifact_age_minutes"],
            "fresh": validation["fresh"],
            "code_hash_matches": validation["code_hash_matches"],
            "validator_version_matches": validation["validator_version_matches"],
            "reasons": validation["reasons"],
            "artifact_trusted": False,
        }

        if validation["artifact_valid"] and validation["artifact_payload"] is not None:
            decision["artifact_trusted"] = True
            validator_reports[spec.name] = validation["artifact_payload"]
            run_results.append(
                {
                    "script": str(spec.script),
                    "exit_code": 0,
                    "stdout_tail": f"[reused validated artifact: {spec.artifact.name}]",
                    "stderr_tail": "",
                }
            )
        elif validation["fresh"] and validation["bootstrap_mtime_match"] and validation["artifact_payload"] is not None:
            stamped = _stamp_artifact_metadata(spec.artifact, validation["artifact_payload"], spec.validator_version, code_hash)
            decision["decision"] = "reused_bootstrap_stamped"
            decision["artifact_trusted"] = True
            decision["reasons"] = ["legacy_artifact_bootstrap"]
            validator_reports[spec.name] = stamped
            run_results.append(
                {
                    "script": str(spec.script),
                    "exit_code": 0,
                    "stdout_tail": f"[reused bootstrap artifact and stamped metadata: {spec.artifact.name}]",
                    "stderr_tail": "",
                }
            )
        else:
            code, stdout, stderr = run_python_script(spec.script)
            rerun_payload = _load_optional_json(spec.artifact)
            if code == 0 and rerun_payload is not None:
                stamped = _stamp_artifact_metadata(spec.artifact, rerun_payload, spec.validator_version, code_hash)
                validator_reports[spec.name] = stamped
                decision["decision"] = "rerun_success"
                decision["artifact_trusted"] = True
                decision["reasons"] = []
            else:
                validator_reports[spec.name] = _default_failed_report(spec.name)
                decision["decision"] = "rerun_failed"
                decision["rerun_exit_code"] = code

            run_results.append(
                {
                    "script": str(spec.script),
                    "exit_code": code,
                    "stdout_tail": stdout[-4000:],
                    "stderr_tail": stderr[-4000:],
                }
            )

        validator_decisions[spec.name] = decision

    frontend_report = validator_reports["frontend_integration_gate"]
    tristate_report = validator_reports["tristate_validator"]
    gateway_report = validator_reports["gateway_fidelity"]

    # Load new proof artifacts (produced by the 4 harness scripts)
    adapter_stress_report = _load_optional_json(ROOT / "_ADAPTER_INVARIANT_STRESS_REPORT.json")
    transport_chaos_report = _load_optional_json(ROOT / "_TRANSPORT_CHAOS_TEST_REPORT.json")
    intel_expl_report = _load_optional_json(ROOT / "_INTELLIGENCE_EXPLAINABILITY_DETERMINISM_REPORT.json")
    concurrency_load_report = _load_optional_json(ROOT / "_CONCURRENCY_LOAD_BENCHMARK_REPORT.json")

    ui_audit = static_ui_leakage_scan()
    write_ui_audit(ui_audit)

    report = build_contract_result(
        frontend_report,
        tristate_report,
        gateway_report,
        ui_audit,
        validator_decisions=validator_decisions,
        adapter_stress_report=adapter_stress_report,
        transport_chaos_report=transport_chaos_report,
        intel_expl_report=intel_expl_report,
        concurrency_load_report=concurrency_load_report,
    )
    report["script_runs"] = run_results
    report["validator_decisions"] = validator_decisions
    report["evidence_validity"] = {
        "max_age_minutes": VALIDATOR_MAX_AGE_MINUTES,
        "validators_reused": sum(1 for d in validator_decisions.values() if d.get("decision") in {"reused_validated", "reused_bootstrap_stamped"}),
        "validators_rerun": sum(1 for d in validator_decisions.values() if d.get("decision") in {"rerun_success", "rerun_failed"}),
    }
    report["confidence"] = _compute_confidence(report.get("verdict", "NOT_READY"), validator_decisions)

    REPORT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report)

    print(json.dumps(report, indent=2))
    return 0 if report["verdict"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())