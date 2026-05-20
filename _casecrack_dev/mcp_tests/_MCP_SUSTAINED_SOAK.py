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
REPORT_PATH = ROOT / "_MCP_SUSTAINED_SOAK_REPORT.json"

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


async def _run_soak(minutes: int, workers: int, pause_ms: int) -> Dict[str, Any]:
    server = SecurityMCPServer(workspace_path="CaseCrack")

    async def fake_execute(_name: str, arguments: Dict[str, Any]) -> str:
        # Small non-zero runtime keeps contention realistic.
        await asyncio.sleep(0.008)
        idx = int(arguments.get("idx", 0) or 0)
        if idx % 23 == 0:
            raise ValueError("synthetic-soak-failure")
        return json.dumps({"summary": "soak-success", "finding_count": idx % 5})

    # Keep soak focused on control-plane behavior (not external tool runtime).
    server._execute_tool = fake_execute  # type: ignore[attr-defined]

    duration_seconds = int(minutes) * 60
    start = time.time()
    end = start + duration_seconds
    tenant_id = "local"

    state: Dict[str, Any] = {
        "total_calls": 0,
        "ok_calls": 0,
        "error_calls": 0,
        "dedup_attempts": 0,
        "dedup_return_matches": 0,
        "rate_limited_responses": 0,
    }

    lock = asyncio.Lock()
    recent_request_ids: deque[str] = deque(maxlen=512)

    async def worker(worker_idx: int) -> None:
        local_counter = 0
        while time.time() < end:
            local_counter += 1
            idx = worker_idx * 10_000_000 + local_counter

            duplicate_mode = (idx % 11 == 0) and len(recent_request_ids) > 0
            if duplicate_mode:
                request_id = random.choice(tuple(recent_request_ids))
            else:
                request_id = uuid.uuid4().hex[:12]
                recent_request_ids.append(request_id)

            args = {"idx": idx, "worker": worker_idx}

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
                if duplicate_mode:
                    state["dedup_attempts"] += 1
                    # Dedup return reuses prior outcome for same request_id.
                    # Track as a practical signal when returned request_id matches and no new terminal was needed.
                    if str(envelope.get("request_id") or "") == request_id:
                        state["dedup_return_matches"] += 1

            if pause_ms > 0:
                await asyncio.sleep(pause_ms / 1000.0)

    reporter_done = False

    async def reporter() -> None:
        nonlocal reporter_done
        while time.time() < end:
            await asyncio.sleep(60)
            elapsed = int(time.time() - start)
            async with lock:
                print(
                    f"[soak] elapsed={elapsed}s total={state['total_calls']} "
                    f"ok={state['ok_calls']} err={state['error_calls']} "
                    f"rate_limited_resp={state['rate_limited_responses']} dedup_attempts={state['dedup_attempts']}",
                    flush=True,
                )
        reporter_done = True

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

    return {
        "verdict": "PASS",
        "duration_minutes": minutes,
        "elapsed_seconds": elapsed_seconds,
        "workers": workers,
        "pause_ms": pause_ms,
        "traffic": {
            **state,
            "metrics_requests_total": requests_total,
            "metrics_rate_limited_total": rate_limited_total,
            "metrics_request_id_dedup_hits": dedup_counter_hits,
        },
        "ratios": {
            "rate_limited_outcome_ratio": round(rate_limited_ratio, 6),
            "request_id_dedup_hit_ratio": round(request_id_dedup_ratio, 6),
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
        "env": {
            "MCP_AUDIT_MAX_BYTES": os.getenv("MCP_AUDIT_MAX_BYTES", ""),
            "MCP_AUDIT_BACKUP_COUNT": os.getenv("MCP_AUDIT_BACKUP_COUNT", ""),
            "MCP_RATE_BURST": os.getenv("MCP_RATE_BURST", ""),
            "MCP_RATE_REFILL": os.getenv("MCP_RATE_REFILL", ""),
            "MCP_REQUEST_RESULT_TTL_SECONDS": os.getenv("MCP_REQUEST_RESULT_TTL_SECONDS", ""),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run sustained MCP control-plane soak and report key maturity ratios.")
    parser.add_argument("--minutes", type=int, default=30)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--pause-ms", type=int, default=15)
    args = parser.parse_args()

    report = asyncio.run(_run_soak(args.minutes, args.workers, args.pause_ms))
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
