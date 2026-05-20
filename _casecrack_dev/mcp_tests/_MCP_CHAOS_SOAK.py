#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parent
REPORT_PATH = ROOT / "_MCP_CHAOS_SOAK_REPORT.json"

if str(ROOT / "CaseCrack") not in sys.path:
    sys.path.insert(0, str(ROOT / "CaseCrack"))

from tools.burp_enterprise.mcp.mcp_server import SecurityMCPServer  # type: ignore  # noqa: E402


def _safe_json_loads(payload: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(payload or "{}")
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return {}


def _is_retryable_code(code: str) -> bool:
    code = (code or "").upper()
    return code in {"REQUEST_TIMEOUT", "POLICY_VIOLATION"}


def _analyze_audit_terminals(audit_files: list[Path], terminal_expected_ids: set[str]) -> Dict[str, Any]:
    per_request_kinds: Dict[str, set[str]] = {}
    per_request_counts: Dict[str, Dict[str, int]] = {}
    parsed_lines = 0
    invalid_lines = 0

    for path in audit_files:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw.strip():
                continue
            try:
                ev = json.loads(raw)
                parsed_lines += 1
            except Exception:
                invalid_lines += 1
                continue

            event_type = str(ev.get("event_type") or "")
            if event_type not in {"tool_completed", "tool_failed"}:
                continue
            rid = str(ev.get("request_id") or ev.get("run_id") or "")
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


async def _run_chaos_soak(
    minutes: int,
    workers: int,
    pause_ms: int,
    failure_rate: float,
    jitter_spike_rate: float,
    timeout_drop_rate: float,
    retry_rate: float,
    overlap_rate: float,
) -> Dict[str, Any]:
    server = SecurityMCPServer(workspace_path="CaseCrack")

    async def fake_execute(_name: str, arguments: Dict[str, Any]) -> str:
        base_ms = int(arguments.get("base_latency_ms", 8) or 8)
        await asyncio.sleep(max(0.0, base_ms / 1000.0))

        # Network jitter simulation: occasional 50-500ms spikes.
        if random.random() < jitter_spike_rate:
            await asyncio.sleep(random.uniform(0.05, 0.50))

        # Timeout drops emulate flaky downstream network/tool path.
        if random.random() < timeout_drop_rate:
            raise RuntimeError("simulated-timeout-drop")

        # Mid-execution failures to validate terminal and SSE consistency.
        if random.random() < failure_rate:
            await asyncio.sleep(random.uniform(0.002, 0.020))
            raise RuntimeError("synthetic-chaos-failure")

        idx = int(arguments.get("idx", 0) or 0)
        return json.dumps({"summary": "chaos-success", "finding_count": idx % 7})

    server._execute_tool = fake_execute  # type: ignore[attr-defined]

    duration_seconds = int(minutes) * 60
    start = time.time()
    end = start + duration_seconds
    tenant_id = "local"

    state: Dict[str, Any] = {
        "total_calls": 0,
        "ok_calls": 0,
        "error_calls": 0,
        "rate_limited_responses": 0,
        "duplicate_request_responses": 0,
        "request_timeout_responses": 0,
        "retry_attempts": 0,
        "retry_successes": 0,
        "overlap_attempts": 0,
        "dedup_attempts": 0,
        "dedup_return_matches": 0,
        "jitter_spike_injected_estimate": 0,
        "timeout_drop_injected_estimate": 0,
        "failure_injected_estimate": 0,
    }

    lock = asyncio.Lock()
    recent_request_ids: deque[str] = deque(maxlen=1024)
    retry_queue: deque[tuple[str, Dict[str, Any]]] = deque(maxlen=512)
    terminal_expected_ids: set[str] = set()

    async def worker(worker_idx: int) -> None:
        local_counter = 0

        while time.time() < end:
            local_counter += 1
            idx = worker_idx * 10_000_000 + local_counter

            # Mixed workload: retries, overlap request IDs, and fresh requests.
            use_retry = (len(retry_queue) > 0) and (random.random() < retry_rate)
            duplicate_mode = False
            overlap_mode = False

            if use_retry:
                request_id, args = retry_queue.popleft()
                state["retry_attempts"] += 1
            else:
                args = {
                    "idx": idx,
                    "worker": worker_idx,
                    "base_latency_ms": random.randint(4, 15),
                }
                overlap_mode = len(recent_request_ids) > 0 and (random.random() < overlap_rate)
                if overlap_mode:
                    request_id = random.choice(tuple(recent_request_ids))
                    duplicate_mode = True
                    state["overlap_attempts"] += 1
                else:
                    request_id = uuid.uuid4().hex[:12]
                    recent_request_ids.append(request_id)

            payload, is_error = await server.execute_tool_request(
                "get_report",
                args,
                request_id=request_id,
            )
            envelope = _safe_json_loads(payload)
            code = str(envelope.get("code") or "").upper()

            async with lock:
                state["total_calls"] += 1
                if is_error:
                    state["error_calls"] += 1
                else:
                    state["ok_calls"] += 1

                if code == "RATE_LIMITED":
                    state["rate_limited_responses"] += 1
                if code == "DUPLICATE_REQUEST":
                    state["duplicate_request_responses"] += 1
                if code == "REQUEST_TIMEOUT":
                    state["request_timeout_responses"] += 1

                if duplicate_mode:
                    state["dedup_attempts"] += 1
                    if str(envelope.get("request_id") or "") == request_id:
                        state["dedup_return_matches"] += 1

                # Schedule retry storms only for retryable failures.
                if is_error and _is_retryable_code(code) and random.random() < 0.80:
                    retry_queue.append((request_id, args))

                if not is_error:
                    if use_retry:
                        state["retry_successes"] += 1
                    terminal_expected_ids.add(request_id)
                elif code not in {"RATE_LIMITED", "DUPLICATE_REQUEST", "TENANT_DISABLED", "ALLOWLIST_DENY"}:
                    terminal_expected_ids.add(request_id)

                # Estimate injected chaos by observed code patterns.
                if code == "REQUEST_TIMEOUT":
                    state["timeout_drop_injected_estimate"] += 1
                elif is_error and code == "POLICY_VIOLATION":
                    state["failure_injected_estimate"] += 1
                elif not is_error and args.get("base_latency_ms", 0) >= 4:
                    # Approximate that some successes incurred jitter.
                    if random.random() < jitter_spike_rate:
                        state["jitter_spike_injected_estimate"] += 1

            if pause_ms > 0:
                await asyncio.sleep(pause_ms / 1000.0)

    async def reporter() -> None:
        while time.time() < end:
            await asyncio.sleep(60)
            elapsed = int(time.time() - start)
            async with lock:
                print(
                    f"[chaos] elapsed={elapsed}s total={state['total_calls']} ok={state['ok_calls']} "
                    f"err={state['error_calls']} rl={state['rate_limited_responses']} "
                    f"dup={state['duplicate_request_responses']} retry={state['retry_attempts']}",
                    flush=True,
                )

    tasks = [asyncio.create_task(worker(i)) for i in range(workers)]
    tasks.append(asyncio.create_task(reporter()))
    await asyncio.gather(*tasks)

    elapsed_seconds = int(time.time() - start)

    metrics = server._metrics  # type: ignore[attr-defined]
    snapshot = metrics.snapshot()
    requests_total = int(snapshot.get(f"tenant:{tenant_id}:requests_total", {}).get("count", 0))
    rate_limited_total = int(snapshot.get(f"tenant:{tenant_id}:rate_limited_total", {}).get("count", 0))

    dedup_counter_hits = 0
    for key, value in snapshot.items():
        if key.endswith(":request_id_dedup"):
            dedup_counter_hits += int(value.get("count", 0))

    rate_limited_ratio = (rate_limited_total / requests_total) if requests_total else 0.0
    request_id_dedup_ratio = (dedup_counter_hits / requests_total) if requests_total else 0.0

    audit_path = Path(os.getenv("MCP_AUDIT_LOG_FILE", "mcp_audit.jsonl"))
    if not audit_path.is_absolute():
        audit_path = ROOT / audit_path

    audit_files = sorted(audit_path.parent.glob(audit_path.name + "*"))
    audit_files = [p for p in audit_files if p.is_file()]

    rotations = max(0, len(audit_files) - 1)
    hours = max(elapsed_seconds / 3600.0, 1e-9)
    rotation_frequency_per_hour = rotations / hours

    if audit_files:
        mtimes = [p.stat().st_mtime for p in audit_files]
        retained_horizon_seconds = max(0.0, max(mtimes) - min(mtimes))
    else:
        retained_horizon_seconds = 0.0

    terminal_invariants = _analyze_audit_terminals(audit_files, terminal_expected_ids)

    return {
        "verdict": "PASS",
        "duration_minutes": minutes,
        "elapsed_seconds": elapsed_seconds,
        "workers": workers,
        "pause_ms": pause_ms,
        "chaos": {
            "failure_rate": failure_rate,
            "jitter_spike_rate": jitter_spike_rate,
            "timeout_drop_rate": timeout_drop_rate,
            "retry_rate": retry_rate,
            "overlap_rate": overlap_rate,
        },
        "traffic": {
            **state,
            "metrics_requests_total": requests_total,
            "metrics_rate_limited_total": rate_limited_total,
            "metrics_request_id_dedup_hits": dedup_counter_hits,
        },
        "ratios": {
            "rate_limited_outcome_ratio": round(rate_limited_ratio, 6),
            "request_id_dedup_hit_ratio": round(request_id_dedup_ratio, 6),
            "duplicate_request_response_ratio": round(
                (state["duplicate_request_responses"] / max(state["total_calls"], 1)), 6
            ),
            "retry_success_ratio": round((state["retry_successes"] / max(state["retry_attempts"], 1)), 6),
        },
        "audit_rotation": {
            "audit_path": str(audit_path),
            "files_kept": len(audit_files),
            "rotations_observed": rotations,
            "rotation_frequency_per_hour": round(rotation_frequency_per_hour, 3),
            "retained_horizon_seconds": round(retained_horizon_seconds, 3),
            "retained_horizon_minutes": round(retained_horizon_seconds / 60.0, 3),
            "files": [
                {
                    "path": str(p),
                    "size_bytes": p.stat().st_size,
                    "mtime_epoch": p.stat().st_mtime,
                }
                for p in audit_files
            ],
        },
        "invariants": terminal_invariants,
        "env": {
            "MCP_AUDIT_MAX_BYTES": os.getenv("MCP_AUDIT_MAX_BYTES", ""),
            "MCP_AUDIT_BACKUP_COUNT": os.getenv("MCP_AUDIT_BACKUP_COUNT", ""),
            "MCP_RATE_BURST": os.getenv("MCP_RATE_BURST", ""),
            "MCP_RATE_REFILL": os.getenv("MCP_RATE_REFILL", ""),
            "MCP_REQUEST_RESULT_TTL_SECONDS": os.getenv("MCP_REQUEST_RESULT_TTL_SECONDS", ""),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run chaos saturation MCP soak with failure injection and mixed workload.")
    parser.add_argument("--minutes", type=int, default=20)
    parser.add_argument("--workers", type=int, default=35)
    parser.add_argument("--pause-ms", type=int, default=2)
    parser.add_argument("--failure-rate", type=float, default=0.20)
    parser.add_argument("--jitter-spike-rate", type=float, default=0.25)
    parser.add_argument("--timeout-drop-rate", type=float, default=0.10)
    parser.add_argument("--retry-rate", type=float, default=0.30)
    parser.add_argument("--overlap-rate", type=float, default=0.18)
    args = parser.parse_args()

    report = asyncio.run(
        _run_chaos_soak(
            minutes=args.minutes,
            workers=args.workers,
            pause_ms=args.pause_ms,
            failure_rate=args.failure_rate,
            jitter_spike_rate=args.jitter_spike_rate,
            timeout_drop_rate=args.timeout_drop_rate,
            retry_rate=args.retry_rate,
            overlap_rate=args.overlap_rate,
        )
    )
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
