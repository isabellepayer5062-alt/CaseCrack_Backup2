#!/usr/bin/env python3
"""Focused browser recovery validation for MCP action lifecycle.

This validator simulates the browser-side adapter state machine for the
disconnect/reconnect cases that remain risky after backend validation:

1. Multi-action outage recovery
2. Orphan result handling
3. Pending -> recovered merge
4. Snapshot + SSE race condition
5. Retry after recovery

It validates browser runtime state transitions, history ordering, recovery
markers, duplicate suppression, and retry semantics without needing a live
browser or dashboard server.

Usage:
    python _validate_mcp_browser_recovery.py

Exit code: 0 on success, 1 on any failed scenario.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import json


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _map_status(raw: Any) -> str:
    status = _text(raw).lower()
    if status in {"ok", "healthy", "success"}:
        return "ok"
    if status in {"accepted", "pending", "degraded", "recovery"}:
        return "pending" if status == "pending" else "degraded"
    if status in {"error", "failed", "disabled"}:
        return "error"
    return "degraded"


def _to_epoch(order: int) -> int:
    return order * 1000


@dataclass
class Action:
    actionId: int = 0
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    requestId: str = ""
    status: str = ""
    errorCode: str = ""
    errorKey: str = ""
    message: str = ""
    error: str = ""
    startedAtMs: int = 0
    completedAtMs: int = 0
    durationMs: int = 0
    awaitingRecovery: bool = False
    recoveredAfterDisconnect: bool = False
    timestamp: str = ""


class AdapterModel:
    def __init__(self) -> None:
        self._action_seq = 0
        self._stream_live = True
        self._stream_gap_pending = False
        self._last_action = Action()
        self._history: list[Action] = []
        self._now = 0

    def _tick(self) -> tuple[int, str]:
        self._now += 1
        return _to_epoch(self._now), f"t{self._now:03d}"

    def _record_action(self, action: Action) -> None:
        idx = -1
        for index, item in enumerate(self._history):
            if (action.actionId and item.actionId == action.actionId) or (
                action.requestId and item.requestId == action.requestId
            ):
                idx = index
                break
        merged = Action(**({**self._history[idx].__dict__, **action.__dict__} if idx >= 0 else action.__dict__))
        if idx >= 0:
            self._history.pop(idx)
        self._history.append(merged)
        self._history.sort(key=lambda item: (item.completedAtMs or item.startedAtMs, item.requestId), reverse=True)
        self._history = self._history[:3]

    def _update_from_action(self, action: Action) -> None:
        self._last_action = Action(**action.__dict__)
        self._record_action(self._last_action)

    def start_action(self, tool: str, args: dict[str, Any], request_id: str | None = None) -> str:
        started_at, ts = self._tick()
        self._action_seq += 1
        self._last_action = Action(
            actionId=self._action_seq,
            tool=tool,
            args=dict(args),
            requestId=request_id or "",
            status="pending",
            message="Waiting for result",
            startedAtMs=started_at,
            timestamp=ts,
        )
        self._record_action(self._last_action)
        return ts

    def ingest_request_event(self, tool: str, request_id: str) -> None:
        if self._last_action.status == "pending" and not self._last_action.requestId and self._last_action.tool == tool:
            self._last_action.requestId = request_id
            self._record_action(self._last_action)
            return
        started_at, ts = self._tick()
        self._action_seq += 1
        self._update_from_action(
            Action(
                actionId=self._action_seq,
                tool=tool,
                requestId=request_id,
                status="pending",
                message="Waiting for result",
                startedAtMs=started_at,
                timestamp=ts,
            )
        )

    def ingest_result_event(self, request_id: str, tool: str, ok: bool, code: str = "", error: str = "", summary: str = "") -> None:
        completed_at, ts = self._tick()
        status = "ok" if ok else "error"
        if request_id == self._last_action.requestId or not self._last_action.requestId:
            started = self._last_action.startedAtMs or completed_at
            self._update_from_action(
                Action(
                    actionId=self._last_action.actionId,
                    tool=self._last_action.tool or tool,
                    args=dict(self._last_action.args),
                    requestId=request_id,
                    status=status,
                    errorCode=code,
                    errorKey=error,
                    message=summary or ("Completed" if ok else error or "Request failed"),
                    error=error,
                    startedAtMs=started,
                    completedAtMs=completed_at,
                    durationMs=max(0, completed_at - started),
                    recoveredAfterDisconnect=self._last_action.recoveredAfterDisconnect,
                    timestamp=ts,
                )
            )
            return
        self._record_action(
            Action(
                tool=tool,
                requestId=request_id,
                status=status,
                errorCode=code,
                errorKey=error,
                message=summary or ("Completed" if ok else error or "Request failed"),
                error=error,
                startedAtMs=completed_at,
                completedAtMs=completed_at,
                timestamp=ts,
            )
        )

    def set_stream_connected(self, ok: bool, source: str) -> None:
        next_state = bool(ok)
        if self._stream_live == next_state:
            return
        self._stream_live = next_state
        if not next_state and self._last_action.status == "pending":
            self._last_action.awaitingRecovery = True
            self._record_action(self._last_action)
        if not next_state:
            self._stream_gap_pending = True
        if next_state and source == "ws":
            return

    def reconcile_snapshot(self, snapshot: dict[str, Any]) -> None:
        self.set_stream_connected(bool((snapshot.get("stream") or {}).get("ok")), "snapshot")
        recent = snapshot.get("recentActions") or []
        recovered = bool(self._stream_gap_pending)
        merged: dict[str, Action] = {}
        for item in reversed(recent):
            local = self._snapshot_action_to_local(item, recovered)
            if local is None:
                continue
            self._record_action(local)
            merged[local.requestId] = local
        latest = snapshot.get("latestAction") or {}
        pending_req = self._last_action.requestId
        match = None
        if self._last_action.status == "pending" and pending_req:
            match = merged.get(pending_req)
            if match is None and pending_req == _text(latest.get("request_id")):
                match = self._snapshot_action_to_local(latest, recovered or self._last_action.awaitingRecovery)
            if match is not None and match.status != "pending":
                started = self._last_action.startedAtMs or match.startedAtMs
                self._update_from_action(
                    Action(
                        actionId=self._last_action.actionId,
                        tool=match.tool or self._last_action.tool,
                        args=dict(match.args or self._last_action.args),
                        requestId=match.requestId,
                        status=match.status,
                        errorCode=match.errorCode,
                        errorKey=match.errorKey,
                        message=match.message,
                        error=match.error,
                        startedAtMs=started,
                        completedAtMs=match.completedAtMs,
                        durationMs=max(0, match.completedAtMs - started),
                        recoveredAfterDisconnect=recovered or self._last_action.awaitingRecovery or match.recoveredAfterDisconnect,
                        timestamp=match.timestamp,
                    )
                )
        if recovered:
            self._stream_gap_pending = False

    def _snapshot_action_to_local(self, action: dict[str, Any], recovered: bool) -> Action | None:
        request_id = _text(action.get("request_id"))
        if not request_id:
            return None
        started_raw = int(action.get("started_order", 0) or 0)
        completed_raw = int(action.get("completed_order", started_raw) or started_raw)
        status = _map_status(action.get("status") or ("ok" if action.get("ok") else "error"))
        return Action(
            tool=_text(action.get("tool")),
            args=dict(action.get("arguments") or {}),
            requestId=request_id,
            status=status,
            errorCode=_text(action.get("code")),
            errorKey=_text(action.get("error")),
            message=_text(action.get("summary") or ("Completed" if status == "ok" else action.get("error") or "Request failed")),
            error=_text(action.get("error")),
            startedAtMs=_to_epoch(started_raw),
            completedAtMs=_to_epoch(completed_raw),
            durationMs=max(0, _to_epoch(completed_raw) - _to_epoch(started_raw)),
            recoveredAfterDisconnect=recovered,
            timestamp=f"t{completed_raw:03d}",
        )

    def history(self) -> list[Action]:
        return list(self._history)

    def last_action(self) -> Action:
        return Action(**self._last_action.__dict__)

    def grouped_hint(self) -> str:
        recovered = [item for item in self._history[:3] if item.recoveredAfterDisconnect]
        if len(recovered) >= 2:
            return f"Recovered after reconnect - {len(recovered)} actions were restored from snapshot reconciliation."
        codes = [_text(item.errorCode).upper() for item in self._history[:3] if _text(item.errorCode)]
        if len(codes) == 3 and codes[0] == codes[1] == codes[2]:
            return f"Repeated {codes[0]} - consider waiting or upgrading plan."
        return ""


def _snapshot(*actions: dict[str, Any], stream_ok: bool = True) -> dict[str, Any]:
    ordered = list(actions)
    latest = ordered[0] if ordered else {}
    return {
        "stream": {"ok": stream_ok},
        "latestAction": latest,
        "recentActions": ordered,
    }


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def scenario_multi_action_outage_recovery() -> dict[str, Any]:
    model = AdapterModel()
    model.start_action("run_burp_scan", {"target": "alpha"})
    model.ingest_request_event("run_burp_scan", "req-1")
    model.ingest_request_event("list_targets", "req-2")
    model.ingest_request_event("get_report", "req-3")
    model.set_stream_connected(False, "ws")
    model.reconcile_snapshot(_snapshot(
        {"request_id": "req-3", "tool": "get_report", "status": "ok", "ok": True, "summary": "Report loaded", "started_order": 3, "completed_order": 7},
        {"request_id": "req-2", "tool": "list_targets", "status": "ok", "ok": True, "summary": "Targets loaded", "started_order": 2, "completed_order": 6},
        {"request_id": "req-1", "tool": "run_burp_scan", "status": "ok", "ok": True, "summary": "Scan queued", "started_order": 1, "completed_order": 5},
    ))
    history = model.history()
    _assert(len(history) == 3, "expected 3 recovered history entries")
    _assert([item.requestId for item in history] == ["req-3", "req-2", "req-1"], "history not ordered by completion")
    _assert(all(item.recoveredAfterDisconnect for item in history), "all outage entries should be marked recovered")
    _assert(len({item.requestId for item in history}) == 3, "history contains duplicate request IDs")
    _assert(model.grouped_hint().startswith("Recovered after reconnect"), "expected grouped reconnect hint")
    return {
        "history": [item.__dict__ for item in history],
        "hint": model.grouped_hint(),
    }


def scenario_orphan_result_handling() -> dict[str, Any]:
    model = AdapterModel()
    model.ingest_result_event("req-orphan", "list_targets", True, summary="Targets loaded")
    history = model.history()
    _assert(len(history) == 1, "orphan result should create one history entry")
    _assert(history[0].requestId == "req-orphan", "orphan result request ID missing")
    _assert(history[0].status == "ok", "orphan result status incorrect")
    _assert(model.last_action().requestId == "req-orphan", "orphan result should become the visible last action")
    _assert(model.last_action().status == "ok", "orphan result should resolve cleanly")
    return {"history": [item.__dict__ for item in history]}


def scenario_pending_recovered_merge() -> dict[str, Any]:
    model = AdapterModel()
    model.start_action("run_burp_scan", {"target": "merge"})
    model.ingest_request_event("run_burp_scan", "req-merge")
    model.set_stream_connected(False, "ws")
    model.reconcile_snapshot(_snapshot(
        {"request_id": "req-merge", "tool": "run_burp_scan", "status": "ok", "ok": True, "summary": "Scan queued", "started_order": 1, "completed_order": 2},
    ))
    history = [item for item in model.history() if item.requestId == "req-merge"]
    _assert(len(history) == 1, "pending + recovered should merge into one history entry")
    _assert(history[0].status == "ok", "merged entry should be resolved")
    _assert(history[0].recoveredAfterDisconnect, "merged entry should carry recovery marker")
    _assert(model.last_action().status == "ok", "last action should resolve after recovery")
    return {"entry": history[0].__dict__}


def scenario_snapshot_sse_race() -> dict[str, Any]:
    model = AdapterModel()
    model.start_action("list_targets", {"filter": "race"})
    model.ingest_request_event("list_targets", "req-race")
    model.set_stream_connected(False, "ws")
    model.reconcile_snapshot(_snapshot(
        {"request_id": "req-race", "tool": "list_targets", "status": "ok", "ok": True, "summary": "Targets loaded", "started_order": 1, "completed_order": 2},
    ))
    model.ingest_result_event("req-race", "list_targets", True, summary="Targets loaded")
    history = [item for item in model.history() if item.requestId == "req-race"]
    _assert(len(history) == 1, "snapshot + SSE race should not duplicate history")
    _assert(history[0].status == "ok", "race result should remain resolved")
    _assert(model.last_action().status == "ok", "race should not regress to pending")
    return {"entry": history[0].__dict__}


def scenario_retry_after_recovery() -> dict[str, Any]:
    model = AdapterModel()
    model.start_action("list_targets", {"filter": "retryable"})
    model.ingest_request_event("list_targets", "req-old")
    model.set_stream_connected(False, "ws")
    model.reconcile_snapshot(_snapshot(
        {"request_id": "req-old", "tool": "list_targets", "status": "error", "ok": False, "error": "rate_limited", "code": "RATE_LIMITED", "summary": "Tenant daily quota exceeded", "started_order": 1, "completed_order": 2},
    ))
    before = [item.__dict__ for item in model.history()]
    old_entry = next(item for item in model.history() if item.requestId == "req-old")
    _assert(old_entry.recoveredAfterDisconnect, "recovered failure should be marked recovered")
    model.start_action("list_targets", {"filter": "retryable"})
    model.ingest_request_event("list_targets", "req-new")
    model.ingest_result_event("req-new", "list_targets", True, summary="Targets loaded")
    history = model.history()
    _assert(any(item.requestId == "req-old" for item in history), "original recovered entry must be preserved")
    _assert(any(item.requestId == "req-new" for item in history), "retry should create a new request entry")
    _assert(len([item for item in history if item.requestId == "req-old"]) == 1, "original entry was mutated or duplicated")
    _assert(model.last_action().requestId == "req-new", "retry should become the new last action")
    return {"before_retry": before, "after_retry": [item.__dict__ for item in history]}


def main() -> int:
    scenarios = [
        ("multi_action_outage_recovery", scenario_multi_action_outage_recovery),
        ("orphan_result_handling", scenario_orphan_result_handling),
        ("pending_recovered_merge", scenario_pending_recovered_merge),
        ("snapshot_sse_race", scenario_snapshot_sse_race),
        ("retry_after_recovery", scenario_retry_after_recovery),
    ]
    results: list[dict[str, Any]] = []
    failed = False
    for name, fn in scenarios:
        try:
            details = fn()
            results.append({"name": name, "passed": True, "details": details})
        except AssertionError as exc:
            failed = True
            results.append({"name": name, "passed": False, "error": str(exc)})

    print(json.dumps({
        "verdict": "PASS" if not failed else "FAIL",
        "results": results,
    }, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())