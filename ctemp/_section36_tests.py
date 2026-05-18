SECTION_36_TESTS = r'''

# ===== SECTION 36: Advanced Orchestration (AO 1-8) =====
print("\n== Section 36: Advanced Orchestration Patterns (AO 1-8) ==")

# --- AO-1: OutputSlotReservation ---
print("  36.1: OutputSlotReservation")

from CaseCrack.tools.burp_enterprise.agents.advanced_orchestration import (
    OutputSlotReservation, EscalationStage, EscalationRecord,
    StreamingToolExecutor, ToolExecState, StreamToolSlot,
    ToolBatchSummariser, ToolBatchEntry, BatchSummary,
    AwaySummary, PresenceState, AwaySummaryResult,
    DiagnosticDeltaTracker, DiagnosticDelta, DiagnosticSnapshot,
    FallbackTombstoner, TombstoneReason, TombstonedMessage, FallbackEvent,
    TriagePriorityQueue, TriagePriority, TriageItem,
    ForkProgressReporter, ProgressLabel,
    get_slot_reservation, get_tool_summariser, get_away_summary,
    get_diagnostic_tracker, get_fallback_tombstoner, get_triage_queue,
    get_progress_reporter,
    reset_slot_reservation, reset_tool_summariser, reset_away_summary,
    reset_diagnostic_tracker, reset_fallback_tombstoner, reset_triage_queue,
    reset_progress_reporter,
)

# AO-1 tests
osr = OutputSlotReservation()
check("36.1.1", osr.current_max_tokens == 8192, "Default capped at 8192")
check("36.1.2", osr.stage == EscalationStage.CAPPED, "Starts in CAPPED stage")

# Normal completion - no escalation
nudge = osr.on_completion("end_turn", 500)
check("36.1.3", nudge is None, "No nudge for normal completion")
check("36.1.4", osr.stage == EscalationStage.CAPPED, "Still CAPPED after normal completion")

# Truncation triggers escalation
nudge = osr.on_completion("max_tokens", 8192)
check("36.1.5", nudge is None, "Silent escalation returns None (retry transparent)")
check("36.1.6", osr.stage == EscalationStage.ESCALATED, "Stage now ESCALATED")
check("36.1.7", osr.current_max_tokens == 65536, "Max tokens now 65536")
check("36.1.8", len(osr.history) == 1, "One escalation in history")
check("36.1.9", osr.history[0].stage == EscalationStage.ESCALATED, "History records escalation")

# Second truncation triggers recovery
nudge = osr.on_completion("max_tokens", 65536)
check("36.1.10", nudge is not None, "Recovery nudge returned")
check("36.1.11", "truncated" in nudge.lower(), "Nudge mentions truncation")
check("36.1.12", osr.stage == EscalationStage.MULTI_TURN_RECOVERY, "Now in MULTI_TURN_RECOVERY")

# Exhaust recovery attempts
for _ in range(3):
    osr.on_completion("max_tokens", 65536)
check("36.1.13", osr.stage == EscalationStage.EXHAUSTED, "Exhausted after max attempts")
nudge_final = osr.on_completion("max_tokens", 65536)
check("36.1.14", nudge_final is None, "No more nudges after exhaustion")

# Custom params
osr2 = OutputSlotReservation(capped_default=4096, escalated_max=32768, max_recovery_attempts=1)
check("36.1.15", osr2.current_max_tokens == 4096, "Custom capped default")
osr2.on_completion("max_tokens", 4096)
check("36.1.16", osr2.current_max_tokens == 32768, "Custom escalated max")

# Reset
osr.reset()
check("36.1.17", osr.stage == EscalationStage.CAPPED, "Reset returns to CAPPED")
check("36.1.18", len(osr.history) == 0, "Reset clears history")

# --- AO-2: StreamingToolExecutor ---
print("  36.2: StreamingToolExecutor")

import asyncio

ste = StreamingToolExecutor(max_parallel=4)
check("36.2.1", ste.stats == {}, "Empty stats initially")
check("36.2.2", ste.get_completed() == {}, "No completed tools initially")

# Test with async executor
async def mock_executor(name, inp):
    await asyncio.sleep(0.01)
    return {"tool": name, "result": "ok"}

async def test_ste_basic():
    ste_inner = StreamingToolExecutor(max_parallel=4)
    await ste_inner.add_tool("t1", "nmap", '{"target":"x"}', mock_executor)
    await ste_inner.add_tool("t2", "nikto", '{"target":"y"}', mock_executor)
    results = await ste_inner.collect(timeout=5.0)
    return results, ste_inner

loop36 = asyncio.new_event_loop()
results_ste, ste_done = loop36.run_until_complete(test_ste_basic())
check("36.2.3", "t1" in results_ste, "Tool t1 completed")
check("36.2.4", "t2" in results_ste, "Tool t2 completed")
check("36.2.5", results_ste["t1"]["tool"] == "nmap", "Tool t1 has correct name")
check("36.2.6", results_ste["t2"]["result"] == "ok", "Tool t2 has correct result")
check("36.2.7", ste_done.stats.get("completed", 0) == 2, "2 completed in stats")

# Test failing executor
async def fail_executor(name, inp):
    raise ValueError("tool failed")

async def test_ste_fail():
    ste_f = StreamingToolExecutor()
    await ste_f.add_tool("t3", "fail_tool", "{}", fail_executor)
    results = await ste_f.collect(timeout=5.0)
    return results, ste_f

res_fail, ste_f = loop36.run_until_complete(test_ste_fail())
check("36.2.8", "t3" in res_fail, "Failed tool in results")
check("36.2.9", "error" in res_fail["t3"], "Failed tool has error key")
check("36.2.10", ste_f.stats.get("failed", 0) == 1, "1 failed in stats")

# Test discard
async def test_ste_discard():
    ste_d = StreamingToolExecutor()
    await ste_d.add_tool("t4", "slow", "{}", mock_executor)
    await ste_d.discard()
    return ste_d

ste_discarded = loop36.run_until_complete(test_ste_discard())
check("36.2.11", ste_discarded.stats == {}, "Stats empty after discard")

# --- AO-3: ToolBatchSummariser ---
print("  36.3: ToolBatchSummariser")

tbs = ToolBatchSummariser()

# Empty batch
async def test_tbs_empty():
    return await tbs.summarise([])

empty_sum = loop36.run_until_complete(test_tbs_empty())
check("36.3.1", empty_sum.summary == "No tools executed", "Empty batch summary")
check("36.3.2", empty_sum.tool_count == 0, "Empty batch count = 0")

# Single tool heuristic
entries_single = [
    ToolBatchEntry(tool_name="nmap", input_preview="target=10.0.0.1", output_preview="80/tcp open", duration_ms=1500)
]

async def test_tbs_single():
    return await tbs.summarise(entries_single)

single_sum = loop36.run_until_complete(test_tbs_single())
check("36.3.3", "nmap" in single_sum.summary.lower(), "Single tool mentions tool name")
check("36.3.4", single_sum.tool_count == 1, "Tool count = 1")
check("36.3.5", len(single_sum.summary) <= 30, "Summary <= 30 chars")

# Multi-tool heuristic
entries_multi = [
    ToolBatchEntry(tool_name="nmap", input_preview="x", output_preview="y", duration_ms=100),
    ToolBatchEntry(tool_name="nikto", input_preview="x", output_preview="y", duration_ms=200),
    ToolBatchEntry(tool_name="ffuf", input_preview="x", output_preview="y", duration_ms=300),
]

async def test_tbs_multi():
    return await tbs.summarise(entries_multi)

multi_sum = loop36.run_until_complete(test_tbs_multi())
check("36.3.6", multi_sum.tool_count == 3, "Multi-tool count = 3")
check("36.3.7", "3" in multi_sum.summary, "Multi-tool mentions count")
check("36.3.8", multi_sum.total_duration_ms == 600, "Total duration calculated")

# History tracking
check("36.3.9", len(tbs.history) == 3, "3 summaries in history")

# With model function
async def mock_model(system, user):
    return "Scanned target ports"

tbs_model = ToolBatchSummariser(model_fn=mock_model)

async def test_tbs_model():
    return await tbs_model.summarise(entries_single)

model_sum = loop36.run_until_complete(test_tbs_model())
check("36.3.10", model_sum.summary == "Scanned target ports", "Model-generated summary")

# Fire and forget + consume
tbs_ff = ToolBatchSummariser(model_fn=mock_model)

async def test_tbs_ff():
    tbs_ff.fire_and_forget(entries_single)
    result = await tbs_ff.consume_pending()
    return result

ff_result = loop36.run_until_complete(test_tbs_ff())
check("36.3.11", ff_result is not None, "Fire-and-forget consumed successfully")
check("36.3.12", ff_result.summary == "Scanned target ports", "Fire-and-forget correct summary")

# --- AO-4: AwaySummary ---
print("  36.4: AwaySummary")

aws = AwaySummary(idle_threshold=0.05, away_threshold=0.1)
check("36.4.1", aws.state == PresenceState.ACTIVE, "Starts ACTIVE")

# Touch returns None when active
result = aws.touch()
check("36.4.2", result is None, "Touch while active returns None")

# Record events while away
import time as time_mod
time_mod.sleep(0.15)  # exceed away threshold
aws.record_event("Found SQL injection in /login")
aws.record_event("Phase 2 complete")
check("36.4.3", aws.state == PresenceState.AWAY, "State transitions to AWAY")

# Touch returns recap on return from away
aws.record_event("Critical vuln in /admin")
recap = aws.touch()
check("36.4.4", recap is not None, "Recap generated on return")
check("36.4.5", recap.events_during_absence == 3, "3 events during absence")
check("36.4.6", recap.away_duration_secs > 0, "Away duration positive")
check("36.4.7", "events" in recap.summary.lower() or "while away" in recap.summary.lower(), "Summary mentions events")
check("36.4.8", len(aws.summaries) == 1, "One summary in history")

# No recap when returning from active
result2 = aws.touch()
check("36.4.9", result2 is None, "No recap when returning from active")

# Custom model fn
async def mock_recap_model(system, user):
    return "Found 2 critical vulns while you were away."

async def test_recap_async():
    events = ["Found SQLi", "Found XSS"]
    aws_m = AwaySummary(model_fn=mock_recap_model)
    return await aws_m.generate_recap_async(events)

recap_async = loop36.run_until_complete(test_recap_async())
check("36.4.10", "critical vulns" in recap_async.lower(), "Async model recap works")

# --- AO-5: DiagnosticDeltaTracker ---
print("  36.5: DiagnosticDeltaTracker")

ddt = DiagnosticDeltaTracker()
check("36.5.1", len(ddt.pending_snapshots) == 0, "No pending snapshots initially")

# Snapshot before edit
before_diags = [
    {"message": "SQL injection possible", "line": 42, "severity": "high"},
    {"message": "Missing CSRF token", "line": 15, "severity": "medium"},
]
snap = ddt.snapshot("/app/login.py", before_diags)
check("36.5.2", snap.file_path == "/app/login.py", "Snapshot captures file path")
check("36.5.3", len(snap.diagnostics) == 2, "Snapshot captures 2 diagnostics")
check("36.5.4", "/app/login.py" in ddt.pending_snapshots, "File in pending snapshots")

# Compute delta after edit
after_diags = [
    {"message": "SQL injection possible", "line": 42, "severity": "high"},  # unchanged
    {"message": "Hardcoded API key", "line": 88, "severity": "critical"},   # NEW
]
delta = ddt.compute_delta("/app/login.py", after_diags)
check("36.5.5", len(delta.new_issues) == 1, "1 new issue detected")
check("36.5.6", delta.new_issues[0]["message"] == "Hardcoded API key", "New issue is API key")
check("36.5.7", len(delta.resolved_issues) == 1, "1 resolved issue")
check("36.5.8", delta.resolved_issues[0]["message"] == "Missing CSRF token", "Resolved CSRF issue")
check("36.5.9", delta.unchanged_count == 1, "1 unchanged issue")
check("36.5.10", delta.file_path == "/app/login.py", "Delta has correct file path")

# No snapshot - all treated as new
delta2 = ddt.compute_delta("/app/other.py", [{"message": "XSS", "line": 1}])
check("36.5.11", len(delta2.new_issues) == 1, "No baseline = all new")
check("36.5.12", len(delta2.resolved_issues) == 0, "No baseline = no resolved")

# History
check("36.5.13", len(ddt.history) == 2, "2 deltas in history")

# Empty diagnostics
ddt.snapshot("/app/empty.py", [])
delta3 = ddt.compute_delta("/app/empty.py", [])
check("36.5.14", len(delta3.new_issues) == 0, "Empty before/after = no changes")

# --- AO-6: FallbackTombstoner ---
print("  36.6: FallbackTombstoner")

ft = FallbackTombstoner(fallback_order=["gpt-4", "gpt-3.5-turbo", "local-llama"])

messages = [
    {"id": "m1", "role": "user", "content": "Scan the target"},
    {"id": "m2", "role": "assistant", "content": "<thinking>Let me analyze the target...</thinking>"},
    {"id": "m3", "role": "assistant", "content": [
        {"type": "tool_use", "id": "tu1", "name": "nmap", "input": {"target": "10.0.0.1"}}
    ]},
    {"id": "m4", "role": "tool", "tool_use_id": "tu1", "content": "80/tcp open"},
    {"id": "m5", "role": "tool", "tool_use_id": "tu_orphan", "content": "orphaned result"},
]

cleaned, next_model, tombstoned = ft.process_fallback(messages, "gpt-4", "rate_limit_exceeded")

check("36.6.1", next_model == "gpt-3.5-turbo", "Falls back to next model")
check("36.6.2", len(tombstoned) == 2, "2 messages tombstoned (thinking + orphan)")

# Verify thinking block was tombstoned
thinking_tombstones = [t for t in tombstoned if t.reason == TombstoneReason.MODEL_FALLBACK]
check("36.6.3", len(thinking_tombstones) == 1, "Thinking block tombstoned")

# Verify orphan tool result was tombstoned
orphan_tombstones = [t for t in tombstoned if t.reason == TombstoneReason.ORPHANED_TOOL_RESULT]
check("36.6.4", len(orphan_tombstones) == 1, "Orphaned tool result tombstoned")

# Valid tool result kept
valid_tool_msgs = [m for m in cleaned if m.get("role") == "tool" and m.get("tool_use_id") == "tu1"]
check("36.6.5", len(valid_tool_msgs) == 1, "Valid tool result preserved")

# System warning injected
warning_msgs = [m for m in cleaned if m.get("role") == "system" and "[FALLBACK]" in str(m.get("content", ""))]
check("36.6.6", len(warning_msgs) == 1, "Fallback warning injected")

# Fallback chain exhaustion
ft2 = FallbackTombstoner(fallback_order=["model-a"])
_, next2, _ = ft2.process_fallback([{"id": "x", "role": "user", "content": "hi"}], "model-a", "error")
check("36.6.7", next2 is None, "No fallback when at end of chain")

# Unknown model gets first in chain
ft3 = FallbackTombstoner(fallback_order=["backup-1", "backup-2"])
_, next3, _ = ft3.process_fallback([{"id": "x", "role": "user", "content": "hi"}], "unknown-model", "error")
check("36.6.8", next3 == "backup-1", "Unknown model falls back to first in chain")

# Events tracked
check("36.6.9", len(ft.events) == 1, "1 fallback event recorded")
check("36.6.10", ft.events[0].from_model == "gpt-4", "Event records source model")
check("36.6.11", ft.events[0].to_model == "gpt-3.5-turbo", "Event records target model")

# Tombstones accumulated
check("36.6.12", len(ft.tombstones) == 2, "Tombstone audit log maintained")

# --- AO-7: TriagePriorityQueue ---
print("  36.7: TriagePriorityQueue")

tpq = TriagePriorityQueue()
check("36.7.1", tpq.total_pending == 0, "Empty queue initially")

# Enqueue items at different priorities
item_now = tpq.enqueue(TriagePriority.NOW, {"vuln": "SQLi critical"}, source="scanner")
item_next = tpq.enqueue(TriagePriority.NEXT, {"phase": "recon complete"}, source="orchestrator")
item_later = tpq.enqueue(TriagePriority.LATER, {"metric": "scan_speed=42"}, source="metrics")

check("36.7.2", item_now is not None, "NOW item enqueued")
check("36.7.3", item_next is not None, "NEXT item enqueued")
check("36.7.4", item_later is not None, "LATER item enqueued")
check("36.7.5", tpq.total_pending == 3, "3 items pending")
check("36.7.6", tpq.counts == {"NOW": 1, "NEXT": 1, "LATER": 1}, "Correct per-tier counts")

# Deduplication
dup = tpq.enqueue(TriagePriority.NOW, {"vuln": "dup"}, item_id=item_now.item_id)
check("36.7.7", dup is None, "Duplicate item_id rejected")
check("36.7.8", tpq.total_pending == 3, "Still 3 items after dedup")

# Drain NOW
now_items = tpq.drain_now()
check("36.7.9", len(now_items) == 1, "Drained 1 NOW item")
check("36.7.10", now_items[0].payload["vuln"] == "SQLi critical", "Correct NOW payload")
check("36.7.11", now_items[0].notified is True, "Marked as notified")
check("36.7.12", now_items[0].notified_at is not None, "Notified timestamp set")

# Drain NEXT with limit
tpq.enqueue(TriagePriority.NEXT, {"info": "phase2 starting"}, source="orch")
next_items = tpq.drain_next(max_items=1)
check("36.7.13", len(next_items) == 1, "Drained 1 NEXT item (limited)")
check("36.7.14", tpq.counts["NEXT"] == 1, "1 NEXT item remaining")

# Drain LATER
later_items = tpq.drain_later()
check("36.7.15", len(later_items) == 1, "Drained 1 LATER item")

# Delivered count
check("36.7.16", tpq.delivered_count == 3, "3 total delivered")

# Peek is non-destructive
tpq.enqueue(TriagePriority.NOW, {"vuln": "XSS"}, source="scanner")
peeked = tpq.peek(TriagePriority.NOW)
check("36.7.17", len(peeked) == 1, "Peek sees 1 NOW item")
check("36.7.18", tpq.counts["NOW"] == 1, "Peek did not drain")

# Reset
tpq.reset()
check("36.7.19", tpq.total_pending == 0, "Reset clears all queues")
check("36.7.20", tpq.delivered_count == 0, "Reset clears delivered count")

# --- AO-8: ForkProgressReporter ---
print("  36.8: ForkProgressReporter")

fpr = ForkProgressReporter()
check("36.8.1", fpr.active_agents == [], "No active agents initially")
check("36.8.2", fpr.get_latest("agent-1") is None, "No labels for unknown agent")

# Test fallback label generation
label = ForkProgressReporter._fallback_label("agent-1", "Scanning login endpoints")
check("36.8.3", "Scanning" in label or "Working" in label, "Fallback label generated")
check("36.8.4", len(label) <= 50, "Fallback label reasonable length")

# Fallback without context
label2 = ForkProgressReporter._fallback_label("agent-xyz-123", "")
check("36.8.5", "agent-xyz" in label2.lower() or "active" in label2.lower(), "Fallback without context")

# ProgressLabel dataclass
pl = ProgressLabel(agent_id="a1", label="Scanning auth endpoints", previous_label="Enumerating subdomains")
check("36.8.6", pl.agent_id == "a1", "ProgressLabel agent_id")
check("36.8.7", pl.label == "Scanning auth endpoints", "ProgressLabel label")
check("36.8.8", pl.previous_label == "Enumerating subdomains", "ProgressLabel previous")

# --- Singleton factories ---
print("  36.9: Singleton Factories")

reset_slot_reservation()
reset_tool_summariser()
reset_away_summary()
reset_diagnostic_tracker()
reset_fallback_tombstoner()
reset_triage_queue()
reset_progress_reporter()

s1 = get_slot_reservation()
s2 = get_slot_reservation()
check("36.9.1", s1 is s2, "Slot reservation singleton")

ts1 = get_tool_summariser()
ts2 = get_tool_summariser()
check("36.9.2", ts1 is ts2, "Tool summariser singleton")

aw1 = get_away_summary()
aw2 = get_away_summary()
check("36.9.3", aw1 is aw2, "Away summary singleton")

dt1 = get_diagnostic_tracker()
dt2 = get_diagnostic_tracker()
check("36.9.4", dt1 is dt2, "Diagnostic tracker singleton")

fb1 = get_fallback_tombstoner()
fb2 = get_fallback_tombstoner()
check("36.9.5", fb1 is fb2, "Fallback tombstoner singleton")

tq1 = get_triage_queue()
tq2 = get_triage_queue()
check("36.9.6", tq1 is tq2, "Triage queue singleton")

pr1 = get_progress_reporter()
pr2 = get_progress_reporter()
check("36.9.7", pr1 is pr2, "Progress reporter singleton")

# --- Import from agents __init__ ---
print("  36.10: Package Exports")

from CaseCrack.tools.burp_enterprise.agents import (
    OutputSlotReservation as OSR_export,
    StreamingToolExecutor as STE_export,
    ToolBatchSummariser as TBS_export,
    AwaySummary as AWS_export,
    DiagnosticDeltaTracker as DDT_export,
    FallbackTombstoner as FT_export,
    TriagePriorityQueue as TPQ_export,
    ForkProgressReporter as FPR_export,
)

check("36.10.1", OSR_export is OutputSlotReservation, "OutputSlotReservation exported")
check("36.10.2", STE_export is StreamingToolExecutor, "StreamingToolExecutor exported")
check("36.10.3", TBS_export is ToolBatchSummariser, "ToolBatchSummariser exported")
check("36.10.4", AWS_export is AwaySummary, "AwaySummary exported")
check("36.10.5", DDT_export is DiagnosticDeltaTracker, "DiagnosticDeltaTracker exported")
check("36.10.6", FT_export is FallbackTombstoner, "FallbackTombstoner exported")
check("36.10.7", TPQ_export is TriagePriorityQueue, "TriagePriorityQueue exported")
check("36.10.8", FPR_export is ForkProgressReporter, "ForkProgressReporter exported")

loop36.close()

'''
