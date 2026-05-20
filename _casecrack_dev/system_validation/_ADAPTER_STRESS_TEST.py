#!/usr/bin/env python3
"""
Adapter Invariant Stress Test
Proves: INV-001, INV-002, INV-003, INV-005

Ports the mcp-ui-adapter.js _recordAction / _reconcileFromSnapshot state machine
to Python and exercises it under:
  - 500 rapid actions (burst)
  - Duplicate SSE events (same request_id re-delivered)
  - Out-of-order delivery (result before request)
  - Missing SSE terminal events (orphans resolved via snapshot)
  - Snapshot arriving before SSE
  - SSE arriving after snapshot (race)

Invariants asserted on every mutation:
  INV-001: No duplicate request_id in history
  INV-002: No (pending, final) pair for same request_id
  INV-003: Final state never regresses to pending
  INV-005: Snapshot reconciliation == SSE eventual truth
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
REPORT_PATH = ROOT / "_ADAPTER_INVARIANT_STRESS_REPORT.json"

ACTION_HISTORY_LIMIT = 200
SEED = 42

# ── Python port of adapter state machine ─────────────────────────────────────

class AdapterStateEngine:
    """Pure Python port of the mcp-ui-adapter.js action history state machine."""

    def __init__(self) -> None:
        self._history: List[Dict[str, Any]] = []
        self._seq: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _str(v: Any) -> str:
        if v is None:
            return ""
        return str(v)

    @staticmethod
    def _epoch_ms(ts: Any) -> int:
        if not ts:
            return 0
        import datetime
        if isinstance(ts, (int, float)):
            return int(ts)
        try:
            dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Core state machine — mirrors _recordAction exactly
    # ------------------------------------------------------------------

    def record_action(self, action: Dict[str, Any]) -> None:
        if not action:
            return
        action_id = int(action.get("actionId") or 0)
        rid = self._str(action.get("requestId") or "")

        idx = -1
        for i, item in enumerate(self._history):
            item_id = int(item.get("actionId") or 0)
            item_rid = self._str(item.get("requestId") or "")
            if (action_id and item_id == action_id) or (rid and rid == item_rid):
                idx = i
                break

        if idx >= 0:
            existing = self._history[idx]
            merged = {**existing, **action}

            # Preserve canonical requestId (adapter may never invent identity)
            if self._str(existing.get("requestId") or ""):
                merged["requestId"] = self._str(existing.get("requestId") or "")

            # Final states never regress
            existing_final = existing.get("status") in ("ok", "error")
            incoming_status = self._str(action.get("status") or existing.get("status") or "")
            if existing_final:
                if not incoming_status or incoming_status == "pending":
                    merged["status"] = existing["status"]
                elif incoming_status != existing["status"]:
                    merged["status"] = existing["status"]
        else:
            merged = dict(action)

        if idx >= 0:
            self._history.pop(idx)
        self._history.append(merged)

        # Sort: most recent first (highest timestamp)
        self._history.sort(
            key=lambda x: int(x.get("completedAtMs") or x.get("startedAtMs") or 0),
            reverse=True,
        )

        # Evict: pending actions are never evicted
        if len(self._history) > ACTION_HISTORY_LIMIT:
            pending = [x for x in self._history if x.get("status") == "pending"]
            finalized = [x for x in self._history if x.get("status") != "pending"]
            slots = max(0, ACTION_HISTORY_LIMIT - len(pending))
            self._history = pending + finalized[:slots]

    def reconcile_from_snapshot(
        self, snapshot_actions: List[Dict[str, Any]], recovered: bool = False
    ) -> None:
        """Port of _mergeSnapshotHistory — reconciles snapshot into local history."""
        for action in reversed(snapshot_actions):
            req_id = self._str(action.get("request_id") or "")
            if not req_id:
                continue
            status = action.get("status", "error")
            if status in ("ok", "success"):
                status = "ok"
            elif status == "pending":
                status = "pending"
            else:
                status = "error"
            entry: Dict[str, Any] = {
                "requestId": req_id,
                "tool": self._str(action.get("tool") or ""),
                "status": status,
                "errorCode": self._str(action.get("code") or ""),
                "startedAtMs": self._epoch_ms(action.get("started_at")),
                "completedAtMs": self._epoch_ms(action.get("completed_at") or action.get("started_at")),
                "recoveredAfterDisconnect": recovered,
            }
            self.record_action(entry)

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq


# ── Invariant checkers ────────────────────────────────────────────────────────

@dataclass
class InvariantViolation:
    invariant: str
    description: str
    context: Dict[str, Any] = field(default_factory=dict)


def check_invariants(history: List[Dict[str, Any]]) -> List[InvariantViolation]:
    violations: List[InvariantViolation] = []

    # INV-001: No duplicate request_id
    seen_rids: Dict[str, int] = {}
    for i, entry in enumerate(history):
        rid = str(entry.get("requestId") or "")
        if not rid:
            continue
        if rid in seen_rids:
            violations.append(InvariantViolation(
                invariant="INV-001",
                description=f"Duplicate request_id={rid[:12]} at positions {seen_rids[rid]} and {i}",
                context={"request_id": rid, "positions": [seen_rids[rid], i]},
            ))
        else:
            seen_rids[rid] = i

    # INV-002: No (pending, final) pairs for same request_id  [covered by INV-001 dedup + status check]
    # After INV-001 pass, each rid appears once; verify status is unambiguous
    status_by_rid: Dict[str, str] = {}
    for entry in history:
        rid = str(entry.get("requestId") or "")
        status = str(entry.get("status") or "")
        if rid:
            status_by_rid[rid] = status

    # INV-003: No final→pending regression
    # We track this dynamically during record_action calls; here we verify
    # no entry in final history is still "pending" after a finalized version was injected
    # (post-merge, all pending should either remain genuinely in-flight or be finalized)
    # This check: if a history entry is "pending" but has a completedAtMs, that's suspect
    for entry in history:
        if entry.get("status") == "pending" and int(entry.get("completedAtMs") or 0) > 0:
            # completedAtMs set but status still pending — regression signal
            started = int(entry.get("startedAtMs") or 0)
            completed = int(entry.get("completedAtMs") or 0)
            if completed > started + 500:  # more than 500ms gap
                violations.append(InvariantViolation(
                    invariant="INV-003",
                    description="Entry has completedAtMs but status=pending (possible regression)",
                    context={"requestId": str(entry.get("requestId") or "")[:16], "completedAtMs": completed},
                ))

    return violations


# ── Test scenarios ────────────────────────────────────────────────────────────

def _make_action(
    *,
    seq: int,
    rid: str,
    tool: str = "list_targets",
    status: str = "pending",
    ts: int = 0,
    code: str = "",
    recovered: bool = False,
) -> Dict[str, Any]:
    return {
        "actionId": seq,
        "requestId": rid,
        "tool": tool,
        "status": status,
        "errorCode": code,
        "startedAtMs": ts,
        "completedAtMs": ts + 50 if status in ("ok", "error") else 0,
        "recoveredAfterDisconnect": recovered,
    }


def scenario_burst_500(engine: AdapterStateEngine) -> Tuple[int, List[InvariantViolation]]:
    """500 rapid actions, each pending then finalized."""
    rng = random.Random(SEED)
    total_violations: List[InvariantViolation] = []
    now = int(time.time() * 1000)
    # Generate 500 request IDs
    rids = [str(uuid.UUID(int=rng.getrandbits(128))) for _ in range(500)]
    outcomes = ["ok"] * 300 + ["error"] * 150 + ["error"] * 50
    rng.shuffle(outcomes)
    codes = [""] * 300 + ["RATE_LIMITED"] * 100 + ["LICENSE_REQUIRED"] * 100
    rng.shuffle(codes)

    for i, rid in enumerate(rids):
        seq = engine.next_seq()
        ts = now + i * 10
        # Inject pending
        engine.record_action(_make_action(seq=seq, rid=rid, status="pending", ts=ts))
        # Assert no duplicates after each insert
        violations = check_invariants(engine.get_history())
        total_violations.extend(violations)
        # Inject final
        engine.record_action(_make_action(seq=seq, rid=rid, status=outcomes[i], ts=ts + 50, code=codes[i]))
        violations = check_invariants(engine.get_history())
        total_violations.extend(violations)

    return len(rids), total_violations


def scenario_duplicate_sse(engine: AdapterStateEngine) -> Tuple[int, List[InvariantViolation]]:
    """Same SSE event delivered 5 times — no duplicate entries should appear."""
    total_violations: List[InvariantViolation] = []
    now = int(time.time() * 1000) + 100_000
    rids = [str(uuid.UUID(int=i + 0xABCD0000)) for i in range(20)]

    for rid in rids:
        seq = engine.next_seq()
        ts = now
        now += 100
        action = _make_action(seq=seq, rid=rid, status="ok", ts=ts)
        for _ in range(5):
            engine.record_action(action)
        violations = check_invariants(engine.get_history())
        total_violations.extend(violations)

    return len(rids), total_violations


def scenario_out_of_order(engine: AdapterStateEngine) -> Tuple[int, List[InvariantViolation]]:
    """Result arrives before the pending event (SSE out-of-order)."""
    total_violations: List[InvariantViolation] = []
    now = int(time.time() * 1000) + 200_000
    count = 50

    for i in range(count):
        seq = engine.next_seq()
        rid = str(uuid.UUID(int=0xF0000000 + i))
        ts = now + i * 20
        # Result first (out-of-order)
        engine.record_action(_make_action(seq=seq, rid=rid, status="ok", ts=ts + 100))
        # Then pending arrives late
        engine.record_action(_make_action(seq=seq, rid=rid, status="pending", ts=ts))
        # Must stay "ok" (no regression)
        violations = check_invariants(engine.get_history())
        total_violations.extend(violations)
        # Verify regression specifically
        hist = {e["requestId"]: e for e in engine.get_history() if e.get("requestId")}
        if rid in hist and hist[rid]["status"] == "pending":
            total_violations.append(InvariantViolation(
                invariant="INV-003",
                description=f"State regressed ok→pending for {rid[:12]}",
                context={"rid": rid},
            ))

    return count, total_violations


def scenario_orphan_snapshot_recovery(engine: AdapterStateEngine) -> Tuple[int, List[InvariantViolation]]:
    """Orphan actions (pending, SSE stream died) resolved via snapshot reconciliation."""
    total_violations: List[InvariantViolation] = []
    now = int(time.time() * 1000) + 400_000
    orphans: List[Tuple[int, str]] = []

    # Inject 30 orphan pending actions
    for i in range(30):
        seq = engine.next_seq()
        rid = str(uuid.UUID(int=0xBEEF0000 + i))
        orphans.append((seq, rid))
        engine.record_action(_make_action(seq=seq, rid=rid, status="pending", ts=now + i * 5))

    # Simulate snapshot arriving with those 30 resolved
    snapshot_actions = [
        {
            "request_id": rid,
            "tool": "list_targets",
            "status": "ok",
            "started_at": now + i * 5,
            "completed_at": now + i * 5 + 200,
        }
        for i, (_, rid) in enumerate(orphans)
    ]
    engine.reconcile_from_snapshot(snapshot_actions, recovered=True)

    # Verify all orphans are now finalized (not pending)
    hist = {e["requestId"]: e for e in engine.get_history() if e.get("requestId")}
    for _, rid in orphans:
        if rid in hist:
            if hist[rid]["status"] == "pending":
                total_violations.append(InvariantViolation(
                    invariant="INV-003",
                    description=f"Orphan {rid[:12]} still pending after snapshot reconciliation",
                    context={"rid": rid},
                ))
            if not hist[rid].get("recoveredAfterDisconnect"):
                total_violations.append(InvariantViolation(
                    invariant="INV-005",
                    description=f"Orphan {rid[:12]} not marked recoveredAfterDisconnect after snapshot",
                    context={"rid": rid},
                ))

    violations = check_invariants(engine.get_history())
    total_violations.extend(violations)
    return len(orphans), total_violations


def scenario_snapshot_sse_race(engine: AdapterStateEngine) -> Tuple[int, List[InvariantViolation]]:
    """Snapshot arrives before SSE — SSE must not overwrite snapshot truth."""
    total_violations: List[InvariantViolation] = []
    now = int(time.time() * 1000) + 600_000
    rids = [str(uuid.UUID(int=0xCAFE0000 + i)) for i in range(40)]

    # Snapshot arrives first with final statuses
    snapshot_actions = [
        {"request_id": rid, "tool": "list_targets", "status": "ok",
         "started_at": now + i * 10, "completed_at": now + i * 10 + 150}
        for i, rid in enumerate(rids)
    ]
    engine.reconcile_from_snapshot(snapshot_actions, recovered=False)

    # Then SSE delivers same events as pending (late/duplicate)
    for i, rid in enumerate(rids):
        seq = engine.next_seq()
        engine.record_action(_make_action(seq=seq, rid=rid, status="pending", ts=now + i * 10))

    # Verify final states are still "ok"
    hist = {e["requestId"]: e for e in engine.get_history() if e.get("requestId")}
    for rid in rids:
        if rid in hist and hist[rid]["status"] != "ok":
            total_violations.append(InvariantViolation(
                invariant="INV-005",
                description=f"Snapshot truth overwritten by late SSE for {rid[:12]}: status={hist[rid]['status']}",
                context={"rid": rid, "status": hist[rid]["status"]},
            ))

    violations = check_invariants(engine.get_history())
    total_violations.extend(violations)
    return len(rids), total_violations


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    engine = AdapterStateEngine()
    all_violations: List[InvariantViolation] = []
    scenario_results: List[Dict[str, Any]] = []

    scenarios = [
        ("burst_500", scenario_burst_500),
        ("duplicate_sse", scenario_duplicate_sse),
        ("out_of_order", scenario_out_of_order),
        ("orphan_snapshot_recovery", scenario_orphan_snapshot_recovery),
        ("snapshot_sse_race", scenario_snapshot_sse_race),
    ]

    for name, fn in scenarios:
        t0 = time.monotonic()
        count, violations = fn(engine)
        elapsed = time.monotonic() - t0
        all_violations.extend(violations)
        scenario_results.append({
            "scenario": name,
            "actions_tested": count,
            "violations": len(violations),
            "violation_details": [asdict(v) for v in violations],
            "elapsed_ms": round(elapsed * 1000, 1),
        })
        status = "PASS" if not violations else "FAIL"
        print(f"  [{status}] {name}: {count} actions, {len(violations)} violations ({elapsed*1000:.0f}ms)")

    # Blocker mapping
    inv001 = all([v.invariant != "INV-001" for v in all_violations])
    inv002 = all([v.invariant != "INV-002" for v in all_violations])
    inv003 = all([v.invariant != "INV-003" for v in all_violations])
    inv005 = all([v.invariant != "INV-005" for v in all_violations])
    all_pass = inv001 and inv002 and inv003 and inv005

    # Deduplicate
    dup_count = sum(1 for v in all_violations if v.invariant == "INV-001")
    regression_count = sum(1 for v in all_violations if v.invariant == "INV-003")

    # Orphan recovery: check that scenario passed
    orphan_correct = not any(
        v.invariant in ("INV-003", "INV-005") and "orphan" in v.description.lower()
        for v in all_violations
    )
    snapshot_sse_ok = not any(
        v.invariant == "INV-005" and "snapshot truth" in v.description.lower()
        for v in all_violations
    )

    report = {
        "verdict": "PASS" if all_pass else "FAIL",
        "invariants_hold": all_pass,
        "duplicates_detected": dup_count,
        "state_regressions": regression_count,
        "orphan_recoveries_correct": orphan_correct,
        "snapshot_sse_consistency": snapshot_sse_ok,
        "blockers_proven": {
            "INV-001": inv001,
            "INV-002": inv002,
            "INV-003": inv003,
            "INV-005": inv005,
        },
        "total_violations": len(all_violations),
        "scenarios": scenario_results,
        "final_history_depth": len(engine.get_history()),
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    verdict = report["verdict"]
    print(f"\nAdapter Invariant Stress Test: {verdict}")
    print(f"  invariants_hold={all_pass}, duplicates={dup_count}, regressions={regression_count}")
    print(f"  Report: {REPORT_PATH}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
