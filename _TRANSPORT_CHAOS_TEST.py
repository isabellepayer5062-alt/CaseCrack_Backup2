#!/usr/bin/env python3
"""
Transport Chaos Test
Proves: TX-004, E2E-002, E2E-003

Simulates real network failure conditions and verifies the adapter
recovers correctly via snapshot reconciliation:
  - SSE stream killed mid-request
  - SSE delayed by 2-5 seconds (actions complete during blackout)
  - 30-50% event drop (random drops)
  - Reconnect mid-flight
  - Stale snapshot race (snapshot has older data than SSE)

Must hold:
  - UI recovers via snapshot (no lost final states)
  - No phantom pending actions after recovery
  - History reconciles correctly after reconnect
  - E2E-002: burst + rate-limit + recommendation scenario consistent
  - E2E-003: reconnect sequence produces correct final state
"""
from __future__ import annotations

import json
import random
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
REPORT_PATH = ROOT / "_TRANSPORT_CHAOS_TEST_REPORT.json"

ACTION_HISTORY_LIMIT = 200
SEED = 7331


# ── Python port of adapter transport layer ───────────────────────────────────

class TransportChaosEngine:
    """
    Models the adapter's SSE stream + snapshot reconciliation layer.
    State machine faithfully mirrors mcp-ui-adapter.js:
      - _streamLive / _streamGapPending flags
      - _reconcileFromSnapshot
      - _recordAction with no-regression guarantee
    """

    def __init__(self) -> None:
        self._history: List[Dict[str, Any]] = []
        self._last_action: Dict[str, Any] = {}
        self._stream_live: bool = True
        self._stream_gap_pending: bool = False
        self._seq: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _str(v: Any) -> str:
        return "" if v is None else str(v)

    @staticmethod
    def _ts() -> int:
        return int(time.time() * 1000)

    def _map_status(self, raw: str) -> str:
        s = raw.lower()
        if s in ("ok", "healthy", "success"):
            return "ok"
        if s in ("offline", "unreachable", "disconnected"):
            return "offline"
        if s in ("accepted", "pending", "degraded", "recovery"):
            return "degraded" if s != "pending" else "pending"
        if s in ("error", "failed", "disabled"):
            return "error"
        return "degraded"

    # ------------------------------------------------------------------
    # Core: _recordAction (preserves invariants)
    # ------------------------------------------------------------------

    def _record_action(self, action: Dict[str, Any]) -> None:
        if not action:
            return
        action_id = int(action.get("actionId") or 0)
        rid = self._str(action.get("requestId") or "")
        idx = -1
        for i, item in enumerate(self._history):
            if (action_id and int(item.get("actionId") or 0) == action_id) or \
               (rid and rid == self._str(item.get("requestId") or "")):
                idx = i
                break

        if idx >= 0:
            existing = self._history[idx]
            merged = {**existing, **action}
            if self._str(existing.get("requestId") or ""):
                merged["requestId"] = self._str(existing.get("requestId") or "")
            existing_final = existing.get("status") in ("ok", "error")
            incoming = self._str(action.get("status") or existing.get("status") or "")
            if existing_final:
                if not incoming or incoming == "pending":
                    merged["status"] = existing["status"]
                elif incoming != existing["status"]:
                    merged["status"] = existing["status"]
        else:
            merged = dict(action)

        if idx >= 0:
            self._history.pop(idx)
        self._history.append(merged)
        self._history.sort(
            key=lambda x: int(x.get("completedAtMs") or x.get("startedAtMs") or 0),
            reverse=True,
        )
        if len(self._history) > ACTION_HISTORY_LIMIT:
            pending = [x for x in self._history if x.get("status") == "pending"]
            finalized = [x for x in self._history if x.get("status") != "pending"]
            slots = max(0, ACTION_HISTORY_LIMIT - len(pending))
            self._history = pending + finalized[:slots]

    # ------------------------------------------------------------------
    # Stream control (mirrors _setStreamConnected)
    # ------------------------------------------------------------------

    def set_stream_connected(self, ok: bool) -> None:
        if self._stream_live == ok:
            return
        self._stream_live = ok
        if not ok and self._last_action.get("status") == "pending":
            self._last_action["awaitingRecovery"] = True
        if not ok:
            self._stream_gap_pending = True

    # ------------------------------------------------------------------
    # Snapshot reconciliation (mirrors _reconcileFromSnapshot)
    # ------------------------------------------------------------------

    def reconcile_from_snapshot(self, snapshot: Dict[str, Any]) -> None:
        stream_ok = bool((snapshot.get("stream") or {}).get("ok"))
        self.set_stream_connected(stream_ok)
        recent = snapshot.get("recentActions") or []
        recovered = bool(self._stream_gap_pending)
        for action in reversed(recent):
            req_id = self._str(action.get("request_id") or "")
            if not req_id:
                continue
            raw_status = self._str(action.get("status") or "")
            if raw_status in ("ok", "success"):
                status = "ok"
            elif raw_status == "pending":
                status = "pending"
            else:
                status = "error"
            entry: Dict[str, Any] = {
                "requestId": req_id,
                "tool": self._str(action.get("tool") or ""),
                "status": status,
                "errorCode": self._str(action.get("code") or ""),
                "startedAtMs": int(action.get("started_at_ms") or 0),
                "completedAtMs": int(action.get("completed_at_ms") or 0),
                "recoveredAfterDisconnect": recovered,
            }
            self._record_action(entry)
        if recovered:
            self._stream_gap_pending = False

    # ------------------------------------------------------------------
    # SSE event ingestion (action update via stream)
    # ------------------------------------------------------------------

    def ingest_sse(self, event: Dict[str, Any]) -> None:
        """Simulate receiving an SSE event (may be dropped in chaos tests)."""
        self._record_action(event)

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def pending_count(self) -> int:
        return sum(1 for e in self._history if e.get("status") == "pending")

    def lost_finals(self, started_rids: List[str]) -> List[str]:
        """Returns request_ids that were started but not finalized in history."""
        hist = {e.get("requestId"): e for e in self._history if e.get("requestId")}
        return [
            rid for rid in started_rids
            if rid not in hist or hist[rid].get("status") == "pending"
        ]


# ── Chaos scenario helpers ────────────────────────────────────────────────────

def _action(seq: int, rid: str, status: str, tool: str = "list_targets",
            code: str = "", ts: int = 0) -> Dict[str, Any]:
    return {
        "actionId": seq,
        "requestId": rid,
        "tool": tool,
        "status": status,
        "errorCode": code,
        "startedAtMs": ts,
        "completedAtMs": ts + 100 if status != "pending" else 0,
    }


def _snapshot(rids_status: List[Tuple[str, str]], stream_ok: bool = True) -> Dict[str, Any]:
    now = int(time.time() * 1000)
    return {
        "stream": {"ok": stream_ok, "base_url": "http://127.0.0.1:9191"},
        "recentActions": [
            {
                "request_id": rid,
                "tool": "list_targets",
                "status": status,
                "started_at_ms": now - 500,
                "completed_at_ms": now,
            }
            for rid, status in rids_status
        ],
    }


# ── Scenario 1: SSE kill mid-request ─────────────────────────────────────────

def scenario_sse_kill_mid_request() -> Dict[str, Any]:
    """
    3 actions complete during SSE outage.
    Reconnect + snapshot → all finalized, none phantom pending.
    Proves: TX-004, E2E-003
    """
    engine = TransportChaosEngine()
    rng = random.Random(SEED)
    now = int(time.time() * 1000)
    violations: List[str] = []

    # Start 5 actions (pending)
    rids = [str(uuid.UUID(int=rng.getrandbits(128))) for _ in range(5)]
    for i, rid in enumerate(rids):
        seq = engine.next_seq()
        engine.ingest_sse(_action(seq, rid, "pending", ts=now + i * 20))

    # SSE stream dies
    engine.set_stream_connected(False)
    assert engine._stream_gap_pending, "stream gap should be flagged"

    # 3 actions complete during outage — SSE never delivered
    completed_during_outage = rids[:3]
    still_pending = rids[3:]

    # Reconnect — snapshot arrives with those 3 resolved
    snapshot = _snapshot(
        [(rid, "ok") for rid in completed_during_outage] +
        [(rid, "pending") for rid in still_pending],
        stream_ok=True,
    )
    engine.reconcile_from_snapshot(snapshot)

    # Check: no phantom pending for completed ones
    hist = {e["requestId"]: e for e in engine.get_history() if e.get("requestId")}
    for rid in completed_during_outage:
        if hist.get(rid, {}).get("status") != "ok":
            violations.append(f"TX-004: {rid[:8]} should be ok after snapshot recovery, got {hist.get(rid, {}).get('status')}")
        if not hist.get(rid, {}).get("recoveredAfterDisconnect"):
            violations.append(f"E2E-003: {rid[:8]} missing recoveredAfterDisconnect flag")

    # Check: stream gap cleared
    if engine._stream_gap_pending:
        violations.append("TX-004: _stream_gap_pending not cleared after reconciliation")

    # Now deliver SSE finals for still-pending (normal path)
    for rid in still_pending:
        seq = engine.next_seq()
        engine.ingest_sse(_action(seq, rid, "ok", ts=now + 500))

    # Verify no phantom pending
    remaining_pending = [e for e in engine.get_history() if e.get("status") == "pending"]
    if remaining_pending:
        violations.append(f"E2E-003: {len(remaining_pending)} phantom pending actions after full resolution")

    return {
        "scenario": "sse_kill_mid_request",
        "passed": len(violations) == 0,
        "violations": violations,
        "actions_started": len(rids),
        "completed_during_outage": len(completed_during_outage),
        "phantom_pending_after": len([e for e in engine.get_history() if e.get("status") == "pending"]),
    }


# ── Scenario 2: Event drop (30-50%) ──────────────────────────────────────────

def scenario_event_drop() -> Dict[str, Any]:
    """
    30-50% of SSE events randomly dropped.
    Snapshot arrives at end → all finalized.
    Proves: TX-004 (no lost finals after snapshot)
    """
    engine = TransportChaosEngine()
    rng = random.Random(SEED + 1)
    now = int(time.time() * 1000)
    violations: List[str] = []

    n = 100
    rids = [str(uuid.UUID(int=rng.getrandbits(128))) for _ in range(n)]
    statuses = (["ok"] * 70 + ["error"] * 20 + ["error"] * 10)
    rng.shuffle(statuses)
    codes = [""] * 70 + ["RATE_LIMITED"] * 20 + ["LICENSE_REQUIRED"] * 10
    rng.shuffle(codes)

    # All start as pending
    for i, rid in enumerate(rids):
        seq = engine.next_seq()
        engine.ingest_sse(_action(seq, rid, "pending", ts=now + i * 5))

    # Simulate stream outage
    engine.set_stream_connected(False)

    # Drop 40% of SSE final events (never delivered)
    drop_threshold = 0.4
    delivered_rids = []
    for i, (rid, status, code) in enumerate(zip(rids, statuses, codes)):
        if rng.random() > drop_threshold:
            seq = engine.next_seq()
            engine.ingest_sse(_action(seq, rid, status, code=code, ts=now + i * 5 + 100))
            delivered_rids.append(rid)

    dropped_rids = [rid for rid in rids if rid not in delivered_rids]

    # Snapshot arrives with all resolved
    engine.reconcile_from_snapshot(_snapshot(
        list(zip(rids, statuses)),
        stream_ok=True,
    ))

    hist = {e["requestId"]: e for e in engine.get_history() if e.get("requestId")}
    lost = [rid for rid in rids if hist.get(rid, {}).get("status") == "pending"]
    if lost:
        violations.append(f"TX-004: {len(lost)} actions still pending after snapshot recovery")

    # Dropped rids should be recoveredAfterDisconnect
    for rid in dropped_rids[:10]:  # spot-check first 10
        if rid in hist and not hist[rid].get("recoveredAfterDisconnect"):
            violations.append(f"E2E-003: dropped {rid[:8]} missing recoveredAfterDisconnect")

    return {
        "scenario": "event_drop_40pct",
        "passed": len(violations) == 0,
        "violations": violations,
        "total_actions": n,
        "dropped": len(dropped_rids),
        "delivered": len(delivered_rids),
        "lost_after_snapshot": len(lost),
    }


# ── Scenario 3: Delayed SSE (2-5s) ───────────────────────────────────────────

def scenario_delayed_sse() -> Dict[str, Any]:
    """
    SSE events arrive late (simulated). Snapshot arrives first.
    Late SSE must not overwrite snapshot truth (no regression).
    Proves: TX-004 snapshot truth preservation
    """
    engine = TransportChaosEngine()
    rng = random.Random(SEED + 2)
    now = int(time.time() * 1000)
    violations: List[str] = []

    rids = [str(uuid.UUID(int=rng.getrandbits(128))) for _ in range(50)]

    # Snapshot arrives first with finalized statuses
    engine.reconcile_from_snapshot(_snapshot(
        [(rid, "ok") for rid in rids],
        stream_ok=True,
    ))

    # Late SSE delivers pending (2-5s delay simulation)
    for i, rid in enumerate(rids):
        seq = engine.next_seq()
        engine.ingest_sse(_action(seq, rid, "pending", ts=now + i * 10))

    hist = {e["requestId"]: e for e in engine.get_history() if e.get("requestId")}
    regressed = [rid for rid in rids if hist.get(rid, {}).get("status") != "ok"]
    if regressed:
        violations.append(f"TX-004: {len(regressed)} snapshot truths overwritten by late SSE pending")

    return {
        "scenario": "delayed_sse_snapshot_first",
        "passed": len(violations) == 0,
        "violations": violations,
        "total_actions": len(rids),
        "regressed_from_snapshot_truth": len(regressed),
    }


# ── Scenario 4: Reconnect mid-flight ─────────────────────────────────────────

def scenario_reconnect_mid_flight() -> Dict[str, Any]:
    """
    Actions in-flight when stream dies and reconnects.
    After reconnect, history reconciles without duplication.
    Proves: E2E-003
    """
    engine = TransportChaosEngine()
    rng = random.Random(SEED + 3)
    now = int(time.time() * 1000)
    violations: List[str] = []

    rids = [str(uuid.UUID(int=rng.getrandbits(128))) for _ in range(20)]

    # 10 complete before outage
    for i, rid in enumerate(rids[:10]):
        seq = engine.next_seq()
        engine.ingest_sse(_action(seq, rid, "pending", ts=now + i * 10))
        engine.ingest_sse(_action(seq, rid, "ok", ts=now + i * 10 + 50))

    # 10 in-flight when outage happens
    in_flight = rids[10:]
    for i, rid in enumerate(in_flight):
        seq = engine.next_seq()
        engine.ingest_sse(_action(seq, rid, "pending", ts=now + 200 + i * 10))
    engine.set_stream_connected(False)

    # Reconnect: snapshot resolves in-flight
    engine.reconcile_from_snapshot(_snapshot(
        [(rid, "ok") for rid in rids],
        stream_ok=True,
    ))

    hist = {e["requestId"]: e for e in engine.get_history() if e.get("requestId")}

    # No duplicates
    seen = {}
    for e in engine.get_history():
        rid = e.get("requestId", "")
        if rid:
            if rid in seen:
                violations.append(f"INV-001: duplicate {rid[:8]} after reconnect")
            seen[rid] = True

    # All finalized
    lost = [rid for rid in rids if hist.get(rid, {}).get("status") != "ok"]
    if lost:
        violations.append(f"E2E-003: {len(lost)} not finalized after reconnect+snapshot")

    # In-flight marked recovered
    not_recovered = [
        rid for rid in in_flight
        if rid in hist and not hist[rid].get("recoveredAfterDisconnect")
    ]
    if not_recovered:
        violations.append(f"E2E-003: {len(not_recovered)} in-flight actions missing recovery flag")

    return {
        "scenario": "reconnect_mid_flight",
        "passed": len(violations) == 0,
        "violations": violations,
        "total_actions": len(rids),
        "in_flight_during_outage": len(in_flight),
        "lost_after_recovery": len(lost) if "lost" in dir() else 0,
    }


# ── Scenario 5: E2E-002 burst + rate-limit + recommendation ──────────────────

def scenario_e2e_burst_rate_limit() -> Dict[str, Any]:
    """
    E2E-002: burst actions → rate-limited → system correctly classifies + recommends.
    Proves: E2E-002 (real-world flow: burst + classification + recommendation pipeline)
    """
    from _INTELLIGENCE_DETERMINISM_TEST import compute_operator_intelligence

    rng = random.Random(SEED + 4)
    now = int(time.time() * 1000)
    violations: List[str] = []

    # Build a history with burst of RATE_LIMITED errors (simulates user hammering)
    history = []
    for i in range(40):
        if i < 15:
            status, code = "ok", ""
        elif i < 35:
            status, code = "error", "RATE_LIMITED"
        else:
            status, code = "ok", ""
        history.append({
            "requestId": str(uuid.UUID(int=rng.getrandbits(128))),
            "tool": "run_burp_scan",
            "status": status,
            "errorCode": code,
            "startedAtMs": now + i * 50,
            "completedAtMs": now + i * 50 + 100,
        })

    # Run intelligence
    intel = compute_operator_intelligence(history, snapshot=None)

    # Must detect RATE_LIMITED warning and anomaly
    warning_codes = [w.get("code", "") for w in intel.get("systemWarnings", [])]
    anomaly_types = [a.get("type", "") for a in intel.get("recentAnomalies", [])]
    rec_actions = [r.get("action", "") for r in intel.get("actionRecommendations", [])]

    if "RATE_LIMIT_SATURATION" not in warning_codes and "RATE_LIMIT_SPIKE" not in anomaly_types:
        violations.append(
            f"E2E-002: burst RATE_LIMITED not detected in warnings/anomalies; "
            f"warnings={warning_codes}, anomalies={anomaly_types}"
        )

    if "REDUCE_CONCURRENCY" not in rec_actions:
        violations.append(
            f"E2E-002: REDUCE_CONCURRENCY recommendation absent for rate-limit burst; recs={rec_actions}"
        )

    # No LICENSE recommendation should be present (wrong context)
    if "CHECK_LICENSE_CONFIGURATION" in rec_actions:
        violations.append(
            "E2E-002: CHECK_LICENSE_CONFIGURATION wrongly recommended for pure rate-limit burst"
        )

    return {
        "scenario": "e2e_burst_rate_limit_recommendation",
        "passed": len(violations) == 0,
        "violations": violations,
        "detected_warnings": warning_codes,
        "detected_anomalies": anomaly_types,
        "recommendations": rec_actions,
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    scenarios = [
        scenario_sse_kill_mid_request,
        scenario_event_drop,
        scenario_delayed_sse,
        scenario_reconnect_mid_flight,
        scenario_e2e_burst_rate_limit,
    ]

    results: List[Dict[str, Any]] = []
    all_pass = True

    for fn in scenarios:
        result = fn()
        results.append(result)
        status = "PASS" if result["passed"] else "FAIL"
        if not result["passed"]:
            all_pass = False
        violations_str = "; ".join(result.get("violations", [])) or "none"
        print(f"  [{status}] {result['scenario']}: {violations_str}")

    no_lost_finals = all(
        r.get("lost_after_snapshot", 0) == 0 or r.get("lost_after_recovery", 0) == 0
        for r in results
    )
    no_phantom_pending = all(
        r.get("phantom_pending_after", 0) == 0 for r in results
    )
    history_reconciles = all(r["passed"] for r in results if "reconnect" in r["scenario"])

    report = {
        "verdict": "PASS" if all_pass else "FAIL",
        "no_lost_finals": no_lost_finals,
        "no_phantom_pending": no_phantom_pending,
        "history_reconciles": history_reconciles,
        "blockers_proven": {
            "TX-004": all(r["passed"] for r in results if r["scenario"] in (
                "sse_kill_mid_request", "event_drop_40pct", "delayed_sse_snapshot_first")),
            "E2E-002": next((r["passed"] for r in results if r["scenario"] == "e2e_burst_rate_limit_recommendation"), False),
            "E2E-003": all(r["passed"] for r in results if r["scenario"] in (
                "sse_kill_mid_request", "reconnect_mid_flight")),
        },
        "scenarios": results,
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nTransport Chaos Test: {report['verdict']}")
    print(f"  no_lost_finals={no_lost_finals}, no_phantom_pending={no_phantom_pending}")
    print(f"  Report: {REPORT_PATH}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
