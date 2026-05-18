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
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parent
REPORT_PATH = ROOT / "_MCP_FORCED_SATURATION_PROOF_REPORT.json"

if str(ROOT / "CaseCrack") not in sys.path:
    sys.path.insert(0, str(ROOT / "CaseCrack"))

from tools.burp_enterprise.mcp.mcp_server import SecurityMCPServer  # type: ignore  # noqa: E402


def _safe_json_loads(payload: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(payload or "{}")
        if isinstance(parsed, dict):
            return parsed
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return {}


def _read_request_dedup_hits(snapshot: Dict[str, Dict[str, Any]]) -> int:
    total = 0
    for key, value in snapshot.items():
        if key.endswith(":request_id_dedup"):
            total += int(value.get("count", 0))
    return total


async def _run_forced_saturation(
    duration_seconds: int,
    saturation_workers: int,
    saturation_rps_per_worker: float,
    dedup_workers: int,
    dedup_rps_per_worker: float,
    pause_jitter_ms: int,
    rate_burst: float,
    rate_refill: float,
    tool_name: str,
    high_cost_extra_tokens: float,
) -> Dict[str, Any]:
    os.environ["MCP_RATE_BURST"] = str(max(1.0, float(rate_burst)))
    os.environ["MCP_RATE_REFILL"] = str(max(0.1, float(rate_refill)))
    server = SecurityMCPServer(workspace_path="CaseCrack")

    async def fake_execute(_name: str, arguments: Dict[str, Any]) -> str:
        # Keep execution non-zero to preserve realistic queueing and semaphore behavior.
        await asyncio.sleep(0.010)
        idx = int(arguments.get("idx", 0) or 0)
        return json.dumps({"summary": "forced-saturation", "finding_count": idx % 3})

    # Keep focus on control-plane proof (dedup/rate-limit semantics) not external tool runtime.
    setattr(server, "_execute_tool", fake_execute)
    # Force this test lane onto a high-cost token path to guarantee limiter pressure.
    expensive = getattr(server, "_EXPENSIVE_CATEGORIES")
    expensive["phase1"] = max(0.0, float(high_cost_extra_tokens))

    tenant_id = "local"
    start = time.time()
    end = start + max(1, int(duration_seconds))

    state: Dict[str, Any] = {
        "total_calls": 0,
        "ok_calls": 0,
        "error_calls": 0,
        "rate_limited_responses": 0,
        "duplicate_request_responses": 0,
        "dedup_attempts": 0,
        "dedup_return_matches": 0,
        "saturation_lane": {
            "sent": 0,
            "rate_limited": 0,
            "duplicate_request": 0,
            "errors": 0,
        },
        "dedup_lane": {
            "sent": 0,
            "rate_limited": 0,
            "duplicate_request": 0,
            "errors": 0,
        },
    }

    lock = asyncio.Lock()

    dedup_request_pool = [f"dedup-{i:03d}" for i in range(1, 13)]

    async def submit_request(lane: str, request_id: str, args: Dict[str, Any]) -> None:
        payload, is_error = await server.execute_tool_request(
            tool_name,
            args,
            request_id=request_id,
        )
        envelope = _safe_json_loads(payload)
        code = str(envelope.get("code") or "").upper()

        async with lock:
            state["total_calls"] += 1
            state[lane]["sent"] += 1
            if is_error:
                state["error_calls"] += 1
                state[lane]["errors"] += 1
            else:
                state["ok_calls"] += 1

            if code == "RATE_LIMITED":
                state["rate_limited_responses"] += 1
                state[lane]["rate_limited"] += 1
            if code == "DUPLICATE_REQUEST":
                state["duplicate_request_responses"] += 1
                state[lane]["duplicate_request"] += 1

            if lane == "dedup_lane":
                state["dedup_attempts"] += 1
                if str(envelope.get("request_id") or "") == request_id:
                    state["dedup_return_matches"] += 1

    saturation_counter = 0
    dedup_counter = 0
    interval = 1.0 / max(0.1, saturation_workers * saturation_rps_per_worker)
    next_tick = time.monotonic()
    dedup_every = max(1, int(max(1, saturation_workers) / max(1, dedup_workers)))

    while time.time() < end:
        saturation_counter += 1
        rid = f"sat-{saturation_counter}-{uuid.uuid4().hex[:6]}"
        args = {
            "idx": saturation_counter,
            "lane": "saturation",
            # Unique payload prevents argument-level dedup from intercepting limiter pressure.
            "nonce": uuid.uuid4().hex,
        }
        await submit_request("saturation_lane", rid, args)

        # Explicit dedup probe in the same run: cache one request_id then replay it.
        if saturation_counter % dedup_every == 0:
            dedup_counter += 1
            did = random.choice(dedup_request_pool) + f"-{dedup_counter % 4}"
            dargs = {
                "idx": dedup_counter,
                "lane": "dedup",
                "pool": "small-fixed-id-pool",
            }
            await submit_request("dedup_lane", did, dict(dargs))
            await submit_request("dedup_lane", did, dict(dargs))

        if pause_jitter_ms > 0:
            jitter_s = random.uniform(0.0, pause_jitter_ms / 1000.0)
        else:
            jitter_s = 0.0

        next_tick += interval
        sleep_for = max(0.0, next_tick - time.monotonic()) + jitter_s
        await asyncio.sleep(sleep_for)

    elapsed_seconds = int(time.time() - start)

    metrics = getattr(server, "_metrics")
    snapshot = metrics.snapshot()

    requests_total = int(snapshot.get(f"tenant:{tenant_id}:requests_total", {}).get("count", 0))
    rate_limited_total = int(snapshot.get(f"tenant:{tenant_id}:rate_limited_total", {}).get("count", 0))
    request_id_dedup_hits = _read_request_dedup_hits(snapshot)

    separation_proof = {
        "assert_rate_limited_positive": int(state["saturation_lane"]["rate_limited"]) > 0,
        "assert_dedup_positive": int(request_id_dedup_hits) > 0,
        "assert_saturation_not_dedup_only": int(state["saturation_lane"]["rate_limited"]) > 0
        and int(state["dedup_lane"]["sent"]) > 0,
        "rate_limited_on_uncached_lane": int(state["saturation_lane"]["rate_limited"]),
        "request_id_dedup_hits_total": int(request_id_dedup_hits),
    }

    verdict = "PASS" if all(
        [
            separation_proof["assert_rate_limited_positive"],
            separation_proof["assert_dedup_positive"],
            separation_proof["assert_saturation_not_dedup_only"],
        ]
    ) else "FAIL"

    return {
        "verdict": verdict,
        "duration_seconds": elapsed_seconds,
        "config": {
            "tool_name": tool_name,
            "saturation_workers": saturation_workers,
            "saturation_rps_per_worker": saturation_rps_per_worker,
            "dedup_workers": dedup_workers,
            "dedup_rps_per_worker": dedup_rps_per_worker,
            "pause_jitter_ms": pause_jitter_ms,
            "rate_burst": rate_burst,
            "rate_refill": rate_refill,
            "high_cost_extra_tokens": high_cost_extra_tokens,
        },
        "traffic": {
            **state,
            "metrics_requests_total": requests_total,
            "metrics_rate_limited_total": rate_limited_total,
            "metrics_request_id_dedup_hits": request_id_dedup_hits,
        },
        "separation_proof": separation_proof,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Forced saturation proof: show RATE_LIMITED > 0 while request-id dedup also > 0 in the same run."
    )
    parser.add_argument("--duration-seconds", type=int, default=45)
    parser.add_argument("--saturation-workers", type=int, default=20)
    parser.add_argument("--saturation-rps-per-worker", type=float, default=8.0)
    parser.add_argument("--dedup-workers", type=int, default=3)
    parser.add_argument("--dedup-rps-per-worker", type=float, default=4.0)
    parser.add_argument("--pause-jitter-ms", type=int, default=0)
    parser.add_argument("--rate-burst", type=float, default=2.0)
    parser.add_argument("--rate-refill", type=float, default=0.1)
    parser.add_argument("--high-cost-extra-tokens", type=float, default=9.0)
    parser.add_argument("--tool-name", default="get_report")
    args = parser.parse_args()

    report = asyncio.run(
        _run_forced_saturation(
            duration_seconds=args.duration_seconds,
            saturation_workers=args.saturation_workers,
            saturation_rps_per_worker=args.saturation_rps_per_worker,
            dedup_workers=args.dedup_workers,
            dedup_rps_per_worker=args.dedup_rps_per_worker,
            pause_jitter_ms=args.pause_jitter_ms,
            rate_burst=args.rate_burst,
            rate_refill=args.rate_refill,
            tool_name=args.tool_name,
            high_cost_extra_tokens=args.high_cost_extra_tokens,
        )
    )

    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

    return 0 if report.get("verdict") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
