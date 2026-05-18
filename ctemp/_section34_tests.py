# Section 34: Production Subsystems (Token Budget, FlushGate, Crash Recovery)
# ===============================================================================

import tempfile
import os
import json
import time

from CaseCrack.tools.burp_enterprise.production_subsystems import (
    BudgetAction,
    BudgetTracker,
    COMPLETION_THRESHOLD,
    ContinueDecision,
    CrashRecoveryManager,
    DIMINISHING_THRESHOLD,
    FlushGate,
    FlushGateState,
    MIN_CONTINUATIONS_FOR_DIMINISHING,
    OrderedEventReplay,
    ScanPointer,
    ScanPointerManager,
    StopDecision,
    TokenBudgetController,
    TranscriptLogger,
    check_token_budget,
    get_budget_continuation_message,
    get_crash_recovery_manager,
    get_token_budget_controller,
    reset_crash_recovery_manager,
    reset_token_budget_controller,
    _ndjson_safe_stringify,
    POINTER_TTL_S,
)

print("\n== Section 34: Production Subsystems (Token Budget, FlushGate, Crash Recovery) ==")

# ---------- 34.1: BudgetTracker Dataclass ----------

# 34.1.1: Default creation
_bt = BudgetTracker()
check("34.1.1", _bt.continuation_count == 0 and _bt.last_delta_tokens == 0,
      "BudgetTracker defaults: count=0, delta=0")

# 34.1.2: Reset clears all fields
_bt.continuation_count = 5
_bt.last_delta_tokens = 1000
_bt.last_global_turn_tokens = 2000
_bt.reset()
check("34.1.2", _bt.continuation_count == 0 and _bt.last_delta_tokens == 0 and _bt.last_global_turn_tokens == 0,
      "Reset clears all fields")

# 34.1.3: to_dict serialization
_bt2 = BudgetTracker(continuation_count=3, last_delta_tokens=400, last_global_turn_tokens=1500)
_d = _bt2.to_dict()
check("34.1.3", _d["continuation_count"] == 3 and _d["last_delta_tokens"] == 400 and _d["last_global_turn_tokens"] == 1500,
      "to_dict has correct values")

# ---------- 34.2: Budget Continuation Message ----------

# 34.2.1: Format with basic values
_msg = get_budget_continuation_message(93, 12345, 50000)
check("34.2.1", "93%" in _msg and "12,345" in _msg and "50,000" in _msg,
      f"Message format correct: {_msg[:50]}")

# 34.2.2: Contains 'do not summarize'
check("34.2.2", "do not summarize" in _msg,
      "Contains 'do not summarize' instruction")

# 34.2.3: Contains 'Keep working'
check("34.2.3", "Keep working" in _msg,
      "Contains 'Keep working' instruction")

# ---------- 34.3: check_token_budget — Continue Decision ----------

# 34.3.1: Under budget => continue
_tracker = BudgetTracker()
_decision = check_token_budget(_tracker, 10000, 5000)
check("34.3.1", isinstance(_decision, ContinueDecision) and _decision.action == BudgetAction.CONTINUE,
      "Under budget -> ContinueDecision")

# 34.3.2: Continue increments continuation_count
check("34.3.2", _tracker.continuation_count == 1,
      f"Continuation count incremented to 1: {_tracker.continuation_count}")

# 34.3.3: Continue updates last_global_turn_tokens
check("34.3.3", _tracker.last_global_turn_tokens == 5000,
      f"last_global_turn_tokens updated: {_tracker.last_global_turn_tokens}")

# 34.3.4: Nudge message present
check("34.3.4", len(_decision.nudge_message) > 0 and "50%" in _decision.nudge_message,
      f"Nudge message present: {_decision.nudge_message[:40]}")

# ---------- 34.4: check_token_budget — Stop Decision ----------

# 34.4.1: Over 90% budget => stop
_tracker2 = BudgetTracker()
_decision2 = check_token_budget(_tracker2, 10000, 9500)
check("34.4.1", isinstance(_decision2, StopDecision),
      "Over 90% budget -> StopDecision")

# 34.4.2: No budget => stop
_tracker3 = BudgetTracker()
_decision3 = check_token_budget(_tracker3, None, 5000)
check("34.4.2", isinstance(_decision3, StopDecision),
      "No budget -> StopDecision")

# 34.4.3: Agent call => stop
_tracker4 = BudgetTracker()
_decision4 = check_token_budget(_tracker4, 10000, 5000, is_agent_call=True)
check("34.4.3", isinstance(_decision4, StopDecision),
      "Agent call -> StopDecision")

# 34.4.4: Zero budget => stop
_tracker5 = BudgetTracker()
_decision5 = check_token_budget(_tracker5, 0, 5000)
check("34.4.4", isinstance(_decision5, StopDecision),
      "Zero budget -> StopDecision")

# ---------- 34.5: Diminishing Returns Detection ----------

# 34.5.1: Build up 3+ continuations with small deltas
_dim_tracker = BudgetTracker()
# Simulate 4 continuation checks with small deltas
_dim_tracker.continuation_count = 3
_dim_tracker.last_delta_tokens = 200
_dim_tracker.last_global_turn_tokens = 3000
# Next check: 3200 tokens (delta=200 < 500, last_delta=200 < 500, count >= 3)
_dim_decision = check_token_budget(_dim_tracker, 100000, 3200)
check("34.5.1", isinstance(_dim_decision, StopDecision) and _dim_decision.completion_event is not None,
      "Diminishing returns -> StopDecision with event")

# 34.5.2: Completion event has diminishing_returns flag
check("34.5.2", _dim_decision.completion_event.get("diminishing_returns") is True,
      "Completion event has diminishing_returns=True")

# 34.5.3: Completion event has duration_ms
check("34.5.3", "duration_ms" in _dim_decision.completion_event,
      "Completion event has duration_ms")

# 34.5.4: Large delta prevents diminishing detection
_large_tracker = BudgetTracker()
_large_tracker.continuation_count = 3
_large_tracker.last_delta_tokens = 200
_large_tracker.last_global_turn_tokens = 3000
# Delta = 1000 > DIMINISHING_THRESHOLD
_large_decision = check_token_budget(_large_tracker, 100000, 4000)
check("34.5.4", isinstance(_large_decision, ContinueDecision),
      "Large delta prevents diminishing detection")

# ---------- 34.6: TokenBudgetController ----------

# 34.6.1: Singleton access
reset_token_budget_controller()
_tbc = get_token_budget_controller()
check("34.6.1", isinstance(_tbc, TokenBudgetController),
      "Singleton returns TokenBudgetController")

# 34.6.2: start_turn creates tracker
_tbc2 = TokenBudgetController(default_budget=50000)
_started = _tbc2.start_turn("turn-1", budget=20000)
check("34.6.2", isinstance(_started, BudgetTracker),
      "start_turn returns BudgetTracker")

# 34.6.3: check returns decision
_check_result = _tbc2.check(5000, "turn-1")
check("34.6.3", isinstance(_check_result, (ContinueDecision, StopDecision)),
      f"check returns decision: {type(_check_result).__name__}")

# 34.6.4: end_turn returns final stats
_end_stats = _tbc2.end_turn("turn-1")
check("34.6.4", _end_stats is not None and "continuation_count" in _end_stats,
      "end_turn returns tracker dict")

# 34.6.5: end_turn for nonexistent returns None
_end_none = _tbc2.end_turn("nonexistent")
check("34.6.5", _end_none is None,
      "end_turn nonexistent returns None")

# 34.6.6: Stats accumulate
_stats = _tbc2.get_stats()
check("34.6.6", _stats["total_checks"] >= 1,
      f"Stats accumulate: total_checks={_stats['total_checks']}")

# 34.6.7: Event callback fires
_events_received = []
_tbc3 = TokenBudgetController(default_budget=50000, event_callback=lambda t, d: _events_received.append((t, d)))
_tbc3.start_turn("t1", budget=50000)
_tbc3.check(5000, "t1")
check("34.6.7", len(_events_received) > 0 and _events_received[0][0] == "token_budget.continue",
      f"Event callback fires: {_events_received[0][0] if _events_received else 'none'}")

# ---------- 34.7: FlushGate — Basic State Machine ----------

# 34.7.1: Initial state is INACTIVE
_fg = FlushGate()
check("34.7.1", _fg.state == FlushGateState.INACTIVE and not _fg.active,
      f"Initial state: {_fg.state.value}")

# 34.7.2: start() activates gate
_fg.start()
check("34.7.2", _fg.active and _fg.state == FlushGateState.ACTIVE,
      f"After start: {_fg.state.value}")

# 34.7.3: enqueue returns True when active
_enqueued = _fg.enqueue("msg1", "msg2")
check("34.7.3", _enqueued is True and _fg.pending_count == 2,
      f"Enqueue active: returned={_enqueued}, pending={_fg.pending_count}")

# 34.7.4: end() returns queued items
_drained = _fg.end()
check("34.7.4", _drained == ["msg1", "msg2"] and not _fg.active,
      f"end() drains: {_drained}")

# 34.7.5: enqueue returns False when inactive
_not_enqueued = _fg.enqueue("msg3")
check("34.7.5", _not_enqueued is False,
      "enqueue inactive returns False")

# ---------- 34.8: FlushGate — Drop and Deactivate ----------

# 34.8.1: drop() clears and deactivates
_fg2 = FlushGate()
_fg2.start()
_fg2.enqueue("a", "b", "c")
_dropped = _fg2.drop()
check("34.8.1", _dropped == 3 and not _fg2.active and _fg2.pending_count == 0,
      f"drop: dropped={_dropped}, active={_fg2.active}")

# 34.8.2: deactivate() clears active without dropping
_fg3 = FlushGate()
_fg3.start()
_fg3.enqueue("x", "y")
_fg3.deactivate()
check("34.8.2", not _fg3.active,
      "deactivate clears active flag")

# 34.8.3: Stats tracking
_fg4 = FlushGate()
_fg4.start()
_fg4.enqueue("a", "b")
_fg4.end()
_fg4.start()
_fg4.enqueue("c")
_fg4.drop()
_fgs = _fg4.get_stats()
check("34.8.3", _fgs["total_enqueued"] == 3 and _fgs["total_drained"] == 2 and _fgs["total_dropped"] == 1 and _fgs["flush_count"] == 2,
      f"Stats: enqueued={_fgs['total_enqueued']}, drained={_fgs['total_drained']}, dropped={_fgs['total_dropped']}")

# 34.8.4: to_dict includes all fields
_fg_dict = _fg4.to_dict()
check("34.8.4", "active" in _fg_dict and "pending_count" in _fg_dict and "total_enqueued" in _fg_dict,
      "to_dict has all fields")

# ---------- 34.9: FlushGate — Thread Safety ----------

import threading as _th34

# 34.9.1: Concurrent enqueue is safe
_fg_mt = FlushGate()
_fg_mt.start()
_mt_errors = []

def _mt_enqueue():
    try:
        for i in range(100):
            _fg_mt.enqueue(f"item-{i}")
    except Exception as e:
        _mt_errors.append(str(e))

_threads = [_th34.Thread(target=_mt_enqueue) for _ in range(5)]
for t in _threads:
    t.start()
for t in _threads:
    t.join()
_mt_items = _fg_mt.end()
check("34.9.1", len(_mt_items) == 500 and len(_mt_errors) == 0,
      f"Concurrent enqueue: {len(_mt_items)} items, {len(_mt_errors)} errors")

# ---------- 34.10: OrderedEventReplay ----------

# 34.10.1: Create instance
_oer = OrderedEventReplay()
check("34.10.1", _oer is not None,
      "OrderedEventReplay created")

# 34.10.2: Begin replay activates gate
_oer.begin_replay()
check("34.10.2", _oer._gate.active,
      "begin_replay activates gate")

# 34.10.3: submit_event queues during replay
_submitted = _oer.submit_event({"type": "test", "data": {"key": "val"}})
check("34.10.3", _submitted is True,
      "submit_event during replay returns True")

# 34.10.4: replay_event records event
_oer.replay_event({"type": "hist", "id": "h1", "data": {}})
_oer.replay_event({"type": "hist", "id": "h2", "data": {}})
check("34.10.4", len(_oer._replay_events) == 2,
      f"replay_event records: {len(_oer._replay_events)}")

# 34.10.5: end_replay returns replayed and queued
_replayed, _queued = _oer.end_replay()
check("34.10.5", len(_replayed) == 2 and len(_queued) == 1,
      f"end_replay: replayed={len(_replayed)}, queued={len(_queued)}")

# 34.10.6: Gate deactivated after end
check("34.10.6", not _oer._gate.active,
      "Gate deactivated after end_replay")

# 34.10.7: submit_event returns False when not replaying
_not_sub = _oer.submit_event({"type": "nope"})
check("34.10.7", _not_sub is False,
      "submit_event outside replay returns False")

# 34.10.8: Echo deduplication
_oer2 = OrderedEventReplay()
_oer2.begin_replay()
_oer2.replay_event({"type": "x", "id": "echo-123", "data": {}})
_is_echo = _oer2.is_echo("echo-123")
_not_echo = _oer2.is_echo("unknown-456")
_oer2.end_replay()
check("34.10.8", _is_echo and not _not_echo,
      f"Echo dedup: is_echo={_is_echo}, not_echo={_not_echo}")

# 34.10.9: cancel_replay drops queued events
_oer3 = OrderedEventReplay()
_oer3.begin_replay()
_oer3.submit_event({"type": "a"})
_oer3.submit_event({"type": "b"})
_cancel_count = _oer3.cancel_replay()
check("34.10.9", _cancel_count == 2,
      f"cancel_replay dropped: {_cancel_count}")

# 34.10.10: Stats tracking
_oer4 = OrderedEventReplay()
_oer4.begin_replay()
_oer4.replay_event({"type": "r1", "data": {}})
_oer4.submit_event({"type": "s1"})
_oer4.end_replay()
_oer_stats = _oer4.get_stats()
check("34.10.10", _oer_stats["total_replays"] == 1 and _oer_stats["total_replayed_events"] == 1,
      f"Stats: replays={_oer_stats['total_replays']}, events={_oer_stats['total_replayed_events']}")

# ---------- 34.11: NDJSON Safe Stringify ----------

# 34.11.1: Basic serialization
_json_str = _ndjson_safe_stringify({"key": "value", "num": 42})
_parsed = json.loads(_json_str)
check("34.11.1", _parsed["key"] == "value" and _parsed["num"] == 42,
      "Basic NDJSON serialization roundtrips")

# 34.11.2: Escapes U+2028 line separator
_with_ls = _ndjson_safe_stringify({"text": "hello\u2028world"})
check("34.11.2", "\u2028" not in _with_ls and "\\u2028" in _with_ls,
      "U+2028 escaped")

# 34.11.3: Escapes U+2029 paragraph separator
_with_ps = _ndjson_safe_stringify({"text": "hello\u2029world"})
check("34.11.3", "\u2029" not in _with_ps and "\\u2029" in _with_ps,
      "U+2029 escaped")

# 34.11.4: Escaped output is still valid JSON
_round = json.loads(_with_ls)
check("34.11.4", _round["text"] == "hello\u2028world",
      "Escaped output roundtrips to original value")

# ---------- 34.12: ScanPointer Dataclass ----------

# 34.12.1: Default creation
_sp = ScanPointer()
check("34.12.1", _sp.scan_id == "" and _sp.source == "standalone",
      f"ScanPointer defaults: scan_id='{_sp.scan_id}', source='{_sp.source}'")

# 34.12.2: to_dict
_sp2 = ScanPointer(scan_id="scan-001", target="https://example.com", phase_name="recon")
_sp_dict = _sp2.to_dict()
check("34.12.2", _sp_dict["scan_id"] == "scan-001" and _sp_dict["target"] == "https://example.com",
      "ScanPointer to_dict correct")

# 34.12.3: from_dict roundtrip
_sp3 = ScanPointer.from_dict(_sp_dict)
check("34.12.3", _sp3.scan_id == "scan-001" and _sp3.target == "https://example.com" and _sp3.phase_name == "recon",
      "ScanPointer from_dict roundtrip")

# 34.12.4: Phases completed list
_sp4 = ScanPointer(phases_completed=["recon", "enum", "exploit"])
check("34.12.4", len(_sp4.phases_completed) == 3 and _sp4.phases_completed[0] == "recon",
      f"Phases completed: {_sp4.phases_completed}")

# ---------- 34.13: ScanPointerManager ----------

_tmp13 = tempfile.mkdtemp(prefix="venator_ptr_")

# 34.13.1: Write and read pointer
_pm = ScanPointerManager(pointer_dir=_tmp13, ttl_s=3600)
_write_ok = _pm.write(ScanPointer(scan_id="s1", target="https://t1.com"))
_read_back = _pm.read("s1")
check("34.13.1", _write_ok and _read_back is not None and _read_back.scan_id == "s1",
      f"Write/read pointer: ok={_write_ok}, read={_read_back is not None}")

# 34.13.2: Clear removes pointer
_pm.clear("s1")
_read_gone = _pm.read("s1")
check("34.13.2", _read_gone is None,
      "Clear removes pointer")

# 34.13.3: Stale pointer auto-deleted
_stale_pm = ScanPointerManager(pointer_dir=_tmp13, ttl_s=0.001)
_stale_pm.write(ScanPointer(scan_id="stale1", target="t"))
import time as _time34
_time34.sleep(0.01)
_stale_read = _stale_pm.read("stale1")
check("34.13.3", _stale_read is None,
      "Stale pointer auto-deleted")

# 34.13.4: List pointers
_pm2 = ScanPointerManager(pointer_dir=_tmp13, ttl_s=3600)
_pm2.write(ScanPointer(scan_id="list-1", target="t1"))
_pm2.write(ScanPointer(scan_id="list-2", target="t2"))
_list = _pm2.list_pointers()
_list_ids = {p.scan_id for p in _list}
check("34.13.4", "list-1" in _list_ids and "list-2" in _list_ids,
      f"List pointers: {_list_ids}")

# 34.13.5: Read nonexistent returns None
_none_read = _pm2.read("nonexistent-xyz")
check("34.13.5", _none_read is None,
      "Read nonexistent returns None")

# ---------- 34.14: TranscriptLogger ----------

_tmp14 = tempfile.mkdtemp(prefix="venator_transcript_")

# 34.14.1: Open and append
_tl = TranscriptLogger(transcript_dir=_tmp14, scan_id="tr-001")
_open_ok = _tl.open()
check("34.14.1", _open_ok,
      f"Transcript opened: {_open_ok}")

# 34.14.2: Append events
_app1 = _tl.append({"type": "phase_start", "phase": "recon"})
_app2 = _tl.append({"type": "finding", "title": "XSS", "severity": "high"})
_app3 = _tl.append({"type": "phase_end", "phase": "recon"})
check("34.14.2", _app1 and _app2 and _app3 and _tl.line_count == 3,
      f"Appended 3 events: count={_tl.line_count}")

# 34.14.3: Close returns line count
_close_count = _tl.close()
check("34.14.3", _close_count == 3,
      f"Close returns count: {_close_count}")

# 34.14.4: Read transcript back
_events = TranscriptLogger.read_transcript(_tl.path)
check("34.14.4", len(_events) == 3 and _events[0]["type"] == "phase_start" and _events[2]["type"] == "phase_end",
      f"Read back {len(_events)} events, ordered correctly")

# 34.14.5: Events have _seq and _ts metadata
check("34.14.5", "_seq" in _events[0] and "_ts" in _events[0] and _events[0]["_seq"] == 0,
      f"Events have _seq={_events[0].get('_seq')} and _ts")

# 34.14.6: Read nonexistent file returns empty
_empty = TranscriptLogger.read_transcript("/nonexistent/path/file.jsonl")
check("34.14.6", _empty == [],
      "Read nonexistent returns []")

# 34.14.7: Append after close returns False
_tl_closed = TranscriptLogger(transcript_dir=_tmp14, scan_id="tr-closed")
_tl_closed.open()
_tl_closed.close()
_post_close = _tl_closed.append({"type": "nope"})
check("34.14.7", _post_close is False,
      "Append after close returns False")

# 34.14.8: to_dict has expected keys
_tl2 = TranscriptLogger(transcript_dir=_tmp14, scan_id="tr-dict")
_tl2_dict = _tl2.to_dict()
check("34.14.8", "path" in _tl2_dict and "scan_id" in _tl2_dict and "line_count" in _tl2_dict,
      "to_dict has expected keys")

# ---------- 34.15: CrashRecoveryManager ----------

_tmp15 = tempfile.mkdtemp(prefix="venator_cr_ptr_")
_tmp15t = tempfile.mkdtemp(prefix="venator_cr_transcript_")

# 34.15.1: Begin scan
_crm_events = []
_crm = CrashRecoveryManager(
    pointer_dir=_tmp15,
    transcript_dir=_tmp15t,
    event_callback=lambda t, d: _crm_events.append((t, d)),
)
_begin_ok = _crm.begin_scan("crm-001", "https://target.com")
check("34.15.1", _begin_ok,
      "begin_scan returns True")

# 34.15.2: Log events
_log1 = _crm.log_event({"type": "finding", "title": "SQLi"})
_log2 = _crm.log_event({"type": "finding", "title": "XSS"})
check("34.15.2", _log1 and _log2,
      "log_event returns True")

# 34.15.3: Update phase
_crm.update_phase("recon", 1)
check("34.15.3", _crm._active_pointer is not None and _crm._active_pointer.phase_name == "recon",
      f"Phase updated: {_crm._active_pointer.phase_name if _crm._active_pointer else 'none'}")

# 34.15.4: End scan
_end_result = _crm.end_scan("crm-001")
check("34.15.4", _end_result["events_logged"] == 2 and "transcript_path" in _end_result,
      f"End scan: logged={_end_result['events_logged']}")

# 34.15.5: Event callback fired
check("34.15.5", len(_crm_events) >= 2,
      f"Event callbacks fired: {len(_crm_events)}")

# 34.15.6: Check for recovery (no active scans)
_recovery = _crm.check_for_recovery()
check("34.15.6", isinstance(_recovery, list),
      f"check_for_recovery returns list: {len(_recovery)} items")

# 34.15.7: Stats tracking
_crm_stats = _crm.get_stats()
check("34.15.7", _crm_stats["scans_started"] == 1 and _crm_stats["scans_completed"] == 1 and _crm_stats["events_logged"] == 2,
      f"Stats: started={_crm_stats['scans_started']}, completed={_crm_stats['scans_completed']}")

# ---------- 34.16: Crash Recovery — Simulated Crash ----------

_tmp16 = tempfile.mkdtemp(prefix="venator_crash_ptr_")
_tmp16t = tempfile.mkdtemp(prefix="venator_crash_transcript_")

# 34.16.1: Begin scan and log without ending (simulate crash)
_crash_crm = CrashRecoveryManager(pointer_dir=_tmp16, transcript_dir=_tmp16t)
_crash_crm.begin_scan("crash-sim", "https://crashed.com")
_crash_crm.log_event({"type": "finding", "id": "f1", "title": "RCE"})
_crash_crm.log_event({"type": "finding", "id": "f2", "title": "SSRF"})
_crash_crm.update_phase("exploit", 3)
# Close transcript to flush (simulate orderly file close at process exit)
if _crash_crm._active_transcript:
    _crash_crm._active_transcript.close()

# 34.16.2: New manager detects recoverable scan
_recovery_crm = CrashRecoveryManager(pointer_dir=_tmp16, transcript_dir=_tmp16t)
_recoverable = _recovery_crm.check_for_recovery()
check("34.16.2", len(_recoverable) > 0 and any(p.scan_id == "crash-sim" for p in _recoverable),
      f"Detected recoverable scan: {[p.scan_id for p in _recoverable]}")

# 34.16.3: Recover scan
_recovered = _recovery_crm.recover_scan("crash-sim")
check("34.16.3", _recovered["success"] and _recovered["events_count"] == 2,
      f"Recovery success: events={_recovered.get('events_count')}")

# 34.16.4: Recovered events have correct data
_rec_events = _recovered["events"]
check("34.16.4", _rec_events[0]["title"] == "RCE" and _rec_events[1]["title"] == "SSRF",
      f"Recovered events: {[e.get('title') for e in _rec_events]}")

# 34.16.5: Recovery includes phase info
check("34.16.5", _recovered["phase_name"] == "exploit",
      f"Recovery phase: {_recovered.get('phase_name')}")

# 34.16.6: Clear recovery pointer
_clear_ok = _recovery_crm.clear_recovery("crash-sim")
_post_clear = _recovery_crm.check_for_recovery()
check("34.16.6", _clear_ok and not any(p.scan_id == "crash-sim" for p in _post_clear),
      "Clear recovery removes pointer")

# 34.16.7: Recover nonexistent returns failure
_no_recover = _recovery_crm.recover_scan("nonexistent-scan")
check("34.16.7", not _no_recover["success"] and _no_recover["reason"] == "no_pointer",
      f"Recover nonexistent: {_no_recover.get('reason')}")

# ---------- 34.17: Singleton Management ----------

# 34.17.1: Token budget singleton
reset_token_budget_controller()
_s1 = get_token_budget_controller()
_s2 = get_token_budget_controller()
check("34.17.1", _s1 is _s2,
      "Token budget singleton identity")

# 34.17.2: Reset creates new instance
reset_token_budget_controller()
_s3 = get_token_budget_controller()
check("34.17.2", _s3 is not _s1,
      "Reset creates new singleton")

# 34.17.3: Crash recovery singleton
reset_crash_recovery_manager()
_cr1 = get_crash_recovery_manager()
_cr2 = get_crash_recovery_manager()
check("34.17.3", _cr1 is _cr2,
      "Crash recovery singleton identity")

# 34.17.4: Reset creates new crash recovery instance
reset_crash_recovery_manager()
_cr3 = get_crash_recovery_manager()
check("34.17.4", _cr3 is not _cr1,
      "Reset creates new crash recovery singleton")

# ---------- 34.18: Constants ----------

# 34.18.1: Completion threshold
check("34.18.1", COMPLETION_THRESHOLD == 0.9,
      f"COMPLETION_THRESHOLD={COMPLETION_THRESHOLD}")

# 34.18.2: Diminishing threshold
check("34.18.2", DIMINISHING_THRESHOLD == 500,
      f"DIMINISHING_THRESHOLD={DIMINISHING_THRESHOLD}")

# 34.18.3: Min continuations
check("34.18.3", MIN_CONTINUATIONS_FOR_DIMINISHING == 3,
      f"MIN_CONTINUATIONS={MIN_CONTINUATIONS_FOR_DIMINISHING}")

# 34.18.4: Pointer TTL
check("34.18.4", POINTER_TTL_S == 4 * 60 * 60,
      f"POINTER_TTL_S={POINTER_TTL_S}")

# ---------- 34.19: Edge Cases ----------

# 34.19.1: FlushGate with no items
_fg_empty = FlushGate()
_fg_empty.start()
_empty_drain = _fg_empty.end()
check("34.19.1", _empty_drain == [],
      "Empty gate end returns []")

# 34.19.2: Multiple start/end cycles
_fg_cycle = FlushGate()
for _i in range(5):
    _fg_cycle.start()
    _fg_cycle.enqueue(f"cycle-{_i}")
    _fg_cycle.end()
_fc_stats = _fg_cycle.get_stats()
check("34.19.2", _fc_stats["flush_count"] == 5 and _fc_stats["total_enqueued"] == 5,
      f"5 cycles: flush_count={_fc_stats['flush_count']}")

# 34.19.3: Budget check at exact threshold (90%)
_thresh_tracker = BudgetTracker()
_thresh_decision = check_token_budget(_thresh_tracker, 10000, 9000)
check("34.19.3", isinstance(_thresh_decision, StopDecision),
      "Exactly at 90% threshold -> Stop")

# 34.19.4: Budget check just under threshold
_under_tracker = BudgetTracker()
_under_decision = check_token_budget(_under_tracker, 10000, 8999)
check("34.19.4", isinstance(_under_decision, ContinueDecision),
      "Just under 90% -> Continue")

# 34.19.5: Transcript with U+2028/U+2029 in event data
_tmp195 = tempfile.mkdtemp(prefix="venator_unicode_")
_tl_uni = TranscriptLogger(transcript_dir=_tmp195, scan_id="unicode-test")
_tl_uni.open()
_tl_uni.append({"text": "line1\u2028line2\u2029line3"})
_tl_uni.close()
_uni_events = TranscriptLogger.read_transcript(_tl_uni.path)
check("34.19.5", len(_uni_events) == 1 and _uni_events[0]["text"] == "line1\u2028line2\u2029line3",
      "Unicode line terminators survive roundtrip")

# ---------- 34.20: Bug Regression Tests ----------

# 34.20.1: Speculative Executor — get_result cache key uses tool_name
from CaseCrack.tools.burp_enterprise.agents.speculative_executor import (
    SpeculativeExecutor, SpeculationRequest, SpeculationPolicy,
    SpeculationOutcome, SpeculativeResult,
)
_se_regr = SpeculativeExecutor()
_req201 = SpeculationRequest(
    action="nuclei_scan", tool_name="nuclei_scan",
    target="https://test.com", expected_value=0.5,
    context={}, triggered_by="test",
)
_out201, _sid201 = _se_regr.request_speculation(_req201)
check("34.20.1", _out201 == SpeculationOutcome.ACCEPTED and _sid201 != "",
      "Speculation accepted with tool_name")

# 34.20.2: get_result with matching tool_name finds cached result
import time as _time_regr
_time_regr.sleep(0.1)  # let background thread complete
_r202 = _se_regr.get_result("nuclei_scan", "https://test.com", {}, tool_name="nuclei_scan")
# Even if not yet completed, the broad match should find it
_r202_broad = _se_regr.get_result("nuclei_scan", "https://test.com", {})
check("34.20.2", _r202 is not None or _r202_broad is not None,
      "get_result finds result via tool_name or broad match")

# 34.20.3: spawn_squad does not reject members due to cooldown
from CaseCrack.tools.burp_enterprise.agents.fork_spawn import (
    AgentSpawnEngine, AgentRegistry, SpawnOutcome as _SO203,
)
_se203 = AgentSpawnEngine(registry=AgentRegistry())
_squad203 = _se203.spawn_squad([
    ("sqli_specialist", "test sqli"),
    ("xss_specialist", "test xss"),
    ("auth_specialist", "test auth"),
])
_cooldown_rejections = [r for r in _squad203.results if r.outcome == _SO203.REJECTED_COOLDOWN]
check("34.20.3", len(_cooldown_rejections) == 0,
      f"Squad spawn: 0 cooldown rejections (got {len(_cooldown_rejections)})")

# 34.20.4: All squad members succeed
check("34.20.4", _squad203.all_succeeded,
      f"Squad spawn: all 3 succeeded ({len(_squad203.successful_agents)}/3)")

# 34.20.5: OrderedEventReplay UUID dedup uses LRU eviction (not clear-all)
_replay205 = OrderedEventReplay()
_replay205.begin_replay()
for _i205 in range(2100):
    _replay205.replay_event({"id": f"evt-{_i205}", "type": "test", "data": {}})
# After 2100 events, the oldest should have been evicted (LRU) but recent ones kept
_has_recent = _replay205.is_echo("evt-2099")
# Very old ones (first 500) should be evicted
_has_old = _replay205.is_echo("evt-0")
_replay205.end_replay()
check("34.20.5", _has_recent and not _has_old,
      f"LRU eviction: recent={_has_recent}, old={_has_old}")

# Cleanup
_se_regr.shutdown(wait=False)
_se203.cleanup_all()

# Cleanup singletons
reset_token_budget_controller()
reset_crash_recovery_manager()

# Cleanup temp dirs
import shutil as _shutil34
for _tmpd in [_tmp13, _tmp14, _tmp15, _tmp15t, _tmp16, _tmp16t, _tmp195]:
    try:
        _shutil34.rmtree(_tmpd, ignore_errors=True)
    except Exception:
        pass
