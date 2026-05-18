
# ╔═══════════════════════════════════════════════════════════════════════════════╗
# Section 35: Advanced Agent Patterns (AP-1 through AP-7)
# ╚═══════════════════════════════════════════════════════════════════════════════╝

import json
import os
import tempfile
import threading
import time

from CaseCrack.tools.burp_enterprise.agents.advanced_agent_patterns import (
    CacheOptimizedForker,
    DreamConsolidator,
    DreamCycleStats,
    DreamPhase,
    DreamTurn,
    ForkedMessageSet,
    FuseCircuit,
    FuseState,
    HookOutcome,
    HookPriority,
    HookResult,
    LLMMemoryRetriever,
    MemoryCandidate,
    MemorySelection,
    PostTurnOrchestrator,
    PostTurnResult,
    ResolveOnceGuard,
    StallReport,
    StallVerdict,
    StallWatchdog,
    get_dream_consolidator,
    get_memory_retriever,
    get_post_turn_orchestrator,
    get_stall_watchdog,
    reset_dream_consolidator,
    reset_memory_retriever,
    reset_post_turn_orchestrator,
    reset_stall_watchdog,
)

print("\n== Section 35: Advanced Agent Patterns (AP-1 through AP-7) ==")

# ---------- 35.1: FuseCircuit — AP-7 ----------

# 35.1.1: Fuse starts intact
_fuse1 = FuseCircuit(name="test-fuse", threshold=3)
check("35.1.1", _fuse1.state == FuseState.INTACT and not _fuse1.is_blown,
      "Fuse starts INTACT")

# 35.1.2: Fuse blows after threshold consecutive failures
_fuse1.record_failure("err1")
_fuse1.record_failure("err2")
_blew = _fuse1.record_failure("err3")
check("35.1.2", _blew and _fuse1.is_blown and _fuse1.state == FuseState.BLOWN,
      f"Fuse blows after 3 failures (blown={_fuse1.is_blown})")

# 35.1.3: Success resets consecutive counter but NOT blown state
_fuse1.record_success()
check("35.1.3", _fuse1.is_blown,
      "Success after blown does NOT auto-reset")

# 35.1.4: Manual reset restores fuse
_fuse1.reset()
check("35.1.4", not _fuse1.is_blown and _fuse1.state == FuseState.INTACT,
      "Manual reset restores INTACT")

# 35.1.5: Success between failures prevents blowing
_fuse2 = FuseCircuit(name="resilient", threshold=3)
_fuse2.record_failure("a")
_fuse2.record_failure("b")
_fuse2.record_success()  # resets consecutive count
_fuse2.record_failure("c")
_fuse2.record_failure("d")
check("35.1.5", not _fuse2.is_blown,
      "Success between failures prevents blowing")

# 35.1.6: to_dict serialization
_d16 = _fuse2.to_dict()
check("35.1.6", _d16["name"] == "resilient" and _d16["state"] == "intact" and _d16["total_failures"] == 4,
      "to_dict serializes correctly")

# 35.1.7: Thread safety — concurrent failures
_fuse3 = FuseCircuit(name="threaded", threshold=100)
def _concurrent_fail():
    for _ in range(50):
        _fuse3.record_failure("concurrent")
_threads = [threading.Thread(target=_concurrent_fail) for _ in range(4)]
for t in _threads: t.start()
for t in _threads: t.join()
check("35.1.7", _fuse3.total_failures == 200 and _fuse3.is_blown,
      f"Thread-safe: {_fuse3.total_failures} failures, blown={_fuse3.is_blown}")

# ---------- 35.2: ResolveOnceGuard — AP-5 ----------

# 35.2.1: First claim wins
_guard1 = ResolveOnceGuard()
_r1 = _guard1.claim("allow", source="user")
check("35.2.1", _r1 == "allow" and _guard1.is_resolved and _guard1.result == "allow",
      "First claim wins")

# 35.2.2: Second claim returns None
_r2 = _guard1.claim("deny", source="classifier")
check("35.2.2", _r2 is None and _guard1.result == "allow" and _guard1.source == "user",
      "Second claim rejected, original preserved")

# 35.2.3: Reset allows re-claim
_guard1.reset()
_r3 = _guard1.claim("deny", source="bridge")
check("35.2.3", _r3 == "deny" and _guard1.source == "bridge",
      "After reset, new claim succeeds")

# 35.2.4: Thread safety — only one winner
_guard2 = ResolveOnceGuard()
_winners = []
def _race_claim(val, src):
    result = _guard2.claim(val, source=src)
    if result is not None:
        _winners.append(src)
_race_threads = [
    threading.Thread(target=_race_claim, args=(f"v{i}", f"src{i}"))
    for i in range(10)
]
for t in _race_threads: t.start()
for t in _race_threads: t.join()
check("35.2.4", len(_winners) == 1 and _guard2.is_resolved,
      f"Only 1 winner out of 10 threads: {len(_winners)}")

# 35.2.5: to_dict
_d25 = _guard2.to_dict()
check("35.2.5", _d25["resolved"] and _d25["source"] in [f"src{i}" for i in range(10)],
      "to_dict serializes guard state")

# ---------- 35.3: StallWatchdog — AP-3 ----------

# 35.3.1: Watch/unwatch lifecycle
_sw1 = StallWatchdog(threshold_s=0.5)
_sw1.watch("t1", "nuclei", output_file=None)
_status = _sw1.get_status()
check("35.3.1", _status["watched_count"] == 1,
      "Watch registers tool")

# 35.3.2: Record output resets stall timer
_sw1.record_output("t1", 100)
_sw1.record_output("t1", 200)
_reports = _sw1.check_all()
check("35.3.2", len(_reports) == 0,
      "No stall when output is growing")

# 35.3.3: Stall detected after threshold (no output file)
_sw2 = StallWatchdog(threshold_s=0.1)
_sw2.watch("t2", "ffuf", output_file=None)
time.sleep(0.2)
_reports2 = _sw2.check_all()
check("35.3.3", len(_reports2) == 1 and _reports2[0].verdict == StallVerdict.STALLED_SLOW,
      f"Stall detected (verdict={_reports2[0].verdict.value if _reports2 else 'none'})")

# 35.3.4: Stall with prompt pattern detection
_tmpd34 = tempfile.mkdtemp()
_tmpf34 = os.path.join(_tmpd34, "output.txt")
with open(_tmpf34, "w") as f:
    f.write("Scanning...\nFound 5 results\nOverwrite existing file? [Y/n]")
_sw3 = StallWatchdog(threshold_s=0.1)
_sw3.watch("t3", "sqlmap", output_file=_tmpf34)
# First check sees file size as growth; need two checks after threshold
time.sleep(0.15)
_sw3.check_all()  # resets timer after seeing file content
time.sleep(0.15)
_reports3 = _sw3.check_all()
check("35.3.4", (len(_reports3) == 1
      and _reports3[0].verdict == StallVerdict.STALLED_PROMPT
      and "Y/n" in _reports3[0].matched_pattern),
      f"Prompt stall detected: pattern='{_reports3[0].matched_pattern if _reports3 else ''}'")

# 35.3.5: Remediation advice generated
check("35.3.5", _reports3 and _reports3[0].remediation != "",
      f"Remediation: '{_reports3[0].remediation if _reports3 else ''}'")

# 35.3.6: Unwatch removes tool
_sw1.unwatch("t1")
_s6 = _sw1.get_status()
check("35.3.6", _s6["watched_count"] == 0 or all(not w.get("tool_id") == "t1" for w in _s6.get("active", [])),
      "Unwatch removes tool from monitoring")

# 35.3.7: check_one for specific tool
_sw4 = StallWatchdog(threshold_s=0.1)
_sw4.watch("t4", "nmap")
_r47 = _sw4.check_one("t4")
check("35.3.7", _r47 is not None and _r47.verdict == StallVerdict.RUNNING,
      f"check_one returns RUNNING before threshold")

# 35.3.8: on_stall callback fires
_stall_cb_called = []
def _on_stall(report):
    _stall_cb_called.append(report.tool_name)
_sw5 = StallWatchdog(threshold_s=0.1, on_stall=_on_stall)
_tmpf38 = os.path.join(_tmpd34, "out38.txt")
with open(_tmpf38, "w") as f:
    f.write("Are you sure you want to continue? (y/n)")
_sw5.watch("t5", "custom-tool", output_file=_tmpf38)
time.sleep(0.15)
_sw5.check_all()  # first check sees initial file content as growth
time.sleep(0.15)
_sw5.check_all()  # second check detects actual stall
check("35.3.8", "custom-tool" in _stall_cb_called,
      f"on_stall callback fired: {_stall_cb_called}")

# 35.3.9: Stall not re-notified
_stall_cb_called.clear()
_sw5.check_all()
check("35.3.9", len(_stall_cb_called) == 0,
      "Stall not re-notified after initial report")

# Cleanup temp
import shutil as _shutil35
_shutil35.rmtree(_tmpd34, ignore_errors=True)

# ---------- 35.4: DreamConsolidator — AP-1 ----------

# 35.4.1: Phase starts IDLE
_dc1 = DreamConsolidator(agent_memory=None, consolidation_threshold=2)
check("35.4.1", _dc1.phase == DreamPhase.IDLE,
      "DreamConsolidator starts IDLE")

# 35.4.2: Consolidation with provided episodes
_dc_episodes = [
    {"action": "test_xss", "outcome": "success", "target": "a.com", "tools_used": ["nuclei"]},
    {"action": "test_xss", "outcome": "success", "target": "b.com", "tools_used": ["ffuf", "nuclei"]},
    {"action": "test_xss", "outcome": "failure", "target": "c.com", "error_type": "waf_blocked"},
    {"action": "test_sqli", "outcome": "success", "target": "a.com"},
]
_stats42 = _dc1.consolidate_session(session_id="test", episodes=_dc_episodes)
check("35.4.2", _stats42.episodes_reviewed == 4 and _dc1.phase == DreamPhase.COMPLETE,
      f"Consolidated: reviewed={_stats42.episodes_reviewed}, phase={_dc1.phase.value}")

# 35.4.3: Rules/facts extracted from patterns
check("35.4.3", _stats42.rules_extracted >= 1 or _stats42.facts_updated >= 1,
      f"Patterns extracted: rules={_stats42.rules_extracted}, facts={_stats42.facts_updated}")

# 35.4.4: Below threshold skips consolidation
_dc2 = DreamConsolidator(agent_memory=None, consolidation_threshold=10)
_stats44 = _dc2.consolidate_session(episodes=[{"action": "x", "outcome": "y"}])
check("35.4.4", _stats44.episodes_reviewed == 1 and _stats44.rules_extracted == 0,
      "Below threshold: skipped (no rules extracted)")

# 35.4.5: Turns sliding window (MAX_DREAM_TURNS = 30)
_dc3 = DreamConsolidator(max_turns=5)
for _i in range(10):
    _dc3._add_turn(f"action_{_i}", f"detail_{_i}")
_turns45 = _dc3.get_turns()
check("35.4.5", len(_turns45) == 5 and _turns45[0]["action"] == "action_5",
      f"Sliding window: {len(_turns45)} turns, first={_turns45[0]['action'] if _turns45 else ''}")

# 35.4.6: Fuse blows after repeated failures
_dc4 = DreamConsolidator(agent_memory=None, consolidation_threshold=1)
# Simulate failures by passing un-iterable episodes
for _i46 in range(5):
    try:
        _dc4._fuse.record_failure(f"simulated-{_i46}")
    except Exception:
        pass
_stats46 = _dc4.consolidate_session(episodes=[{"action": "x", "outcome": "y"}, {"action": "x", "outcome": "y"}])
check("35.4.6", _dc4._fuse.is_blown and _stats46.episodes_reviewed == 0,
      f"Fuse blown: {_dc4._fuse.is_blown}, skipped consolidation")

# 35.4.7: to_dict serialization
_d47 = _dc1.to_dict()
check("35.4.7", "phase" in _d47 and "stats" in _d47 and "fuse" in _d47,
      f"to_dict keys: {list(_d47.keys())}")

# ---------- 35.5: LLMMemoryRetriever — AP-2 ----------

# 35.5.1: Select with no LLM fn (fallback to confidence sort)
_mr1 = LLMMemoryRetriever(llm_fn=None, max_results=3)
_candidates = [
    MemoryCandidate(key="k1", summary="XSS on login", category="finding", confidence=0.9),
    MemoryCandidate(key="k2", summary="SQLi time-based", category="technique", confidence=0.7),
    MemoryCandidate(key="k3", summary="WAF bypass", category="reference", confidence=0.95),
    MemoryCandidate(key="k4", summary="IDOR on API", category="finding", confidence=0.5),
]
_sel51 = _mr1.select(task="Test login for XSS", candidates=_candidates)
check("35.5.1", len(_sel51.selected_keys) == 3 and _sel51.selected_keys[0] == "k3",
      f"Fallback select: {_sel51.selected_keys}")

# 35.5.2: Already-surfaced keys excluded
_sel52 = _mr1.select(
    task="Test XSS", candidates=_candidates,
    already_surfaced={"k3", "k1"},
)
check("35.5.2", "k3" not in _sel52.selected_keys and "k1" not in _sel52.selected_keys,
      f"Already-surfaced excluded: {_sel52.selected_keys}")

# 35.5.3: Empty candidates returns empty
_sel53 = _mr1.select(task="anything", candidates=[])
check("35.5.3", len(_sel53.selected_keys) == 0,
      "Empty candidates -> empty selection")

# 35.5.4: LLM fn integration
def _mock_llm(system_prompt, user_prompt):
    return json.dumps({"selected": ["k1", "k4"]})
_mr2 = LLMMemoryRetriever(llm_fn=_mock_llm, max_results=5)
_sel54 = _mr2.select(task="Test IDOR", candidates=_candidates)
check("35.5.4", _sel54.selected_keys == ["k1", "k4"],
      f"LLM-guided selection: {_sel54.selected_keys}")

# 35.5.5: LLM fn with invalid JSON degrades gracefully
def _bad_llm(system_prompt, user_prompt):
    return "Sorry, I cannot help with that"
_mr3 = LLMMemoryRetriever(llm_fn=_bad_llm, max_results=5)
_sel55 = _mr3.select(task="anything", candidates=_candidates)
check("35.5.5", len(_sel55.selected_keys) == 0,
      "Bad LLM response -> empty selection (graceful)")

# 35.5.6: LLM fn hallucinated keys filtered
def _hallucinating_llm(system_prompt, user_prompt):
    return json.dumps({"selected": ["k1", "nonexistent_key", "k2"]})
_mr4 = LLMMemoryRetriever(llm_fn=_hallucinating_llm)
_sel56 = _mr4.select(task="test", candidates=_candidates)
check("35.5.6", "nonexistent_key" not in _sel56.selected_keys and "k1" in _sel56.selected_keys,
      f"Hallucinated keys filtered: {_sel56.selected_keys}")

# 35.5.7: Fuse blows after repeated LLM failures
def _crashing_llm(system_prompt, user_prompt):
    raise ConnectionError("LLM service down")
_mr5 = LLMMemoryRetriever(llm_fn=_crashing_llm)
for _i57 in range(4):
    _mr5.select(task="test", candidates=_candidates)
check("35.5.7", _mr5._fuse.is_blown,
      f"Fuse blown after 3 LLM failures: {_mr5._fuse.is_blown}")

# 35.5.8: MemoryCandidate manifest with staleness
_old_candidate = MemoryCandidate(key="old", summary="Ancient finding", age_days=30)
_line = _old_candidate.manifest_line()
check("35.5.8", "30d old" in _line and "stale" in _line.lower(),
      "Staleness warning in manifest line")

# 35.5.9: Surfaced tracking accumulates
_mr6 = LLMMemoryRetriever(llm_fn=None, max_results=2)
_mr6.select(task="t1", candidates=_candidates)
_mr6.select(task="t2", candidates=_candidates)
_d59 = _mr6.to_dict()
check("35.5.9", _d59["surfaced_count"] >= 2,
      f"Surfaced tracking: {_d59['surfaced_count']}")

# 35.5.10: clear_surfaced resets tracking
_mr6.clear_surfaced()
check("35.5.10", _mr6.to_dict()["surfaced_count"] == 0,
      "clear_surfaced resets count")

# ---------- 35.6: PostTurnOrchestrator — AP-4 ----------

# 35.6.1: Register and execute hooks
_pto1 = PostTurnOrchestrator()
_hook_calls = []
def _hook_a(ctx):
    _hook_calls.append("a")
def _hook_b(ctx):
    _hook_calls.append("b")
_pto1.register("hook_a", _hook_a, HookPriority.CRITICAL)
_pto1.register("hook_b", _hook_b, HookPriority.NORMAL)
_result61 = _pto1.execute(context={"turn": 1})
check("35.6.1", _hook_calls == ["a", "b"] and len(_result61.hook_results) == 2,
      f"Hooks executed in priority order: {_hook_calls}")

# 35.6.2: Fire-and-forget hooks don't block
_ff_called = threading.Event()
def _ff_hook(ctx):
    time.sleep(0.1)
    _ff_called.set()
_pto2 = PostTurnOrchestrator()
_pto2.register("ff", _ff_hook, HookPriority.LOW, fire_and_forget=True)
_r62_start = time.monotonic()
_r62 = _pto2.execute()
_r62_dur = time.monotonic() - _r62_start
check("35.6.2", _r62_dur < 0.05 and _r62.hook_results[0].outcome == HookOutcome.SUCCESS,
      f"Fire-and-forget returned immediately ({_r62_dur:.3f}s)")

# 35.6.3: Hook timeout
_pto3 = PostTurnOrchestrator(timeout_s=0.2)
def _slow_hook(ctx):
    time.sleep(5)
_pto3.register("slow", _slow_hook, HookPriority.NORMAL)
_r63 = _pto3.execute()
check("35.6.3", _r63.hook_results[0].outcome == HookOutcome.TIMEOUT,
      f"Slow hook timed out: {_r63.hook_results[0].outcome.value}")

# 35.6.4: Hook failure with blocking error
_pto4 = PostTurnOrchestrator()
def _failing_hook(ctx):
    raise ValueError("Critical failure")
_pto4.register("crash", _failing_hook, HookPriority.HIGH)
_r64 = _pto4.execute()
check("35.6.4", (len(_r64.blocking_errors) == 1
      and "Critical failure" in _r64.blocking_errors[0]),
      f"Blocking error captured: {_r64.blocking_errors}")

# 35.6.5: prevent_continuation from hook return value
_pto5 = PostTurnOrchestrator()
def _stopping_hook(ctx):
    return {"prevent_continuation": True}
_pto5.register("stopper", _stopping_hook, HookPriority.CRITICAL)
_r65 = _pto5.execute()
check("35.6.5", _r65.prevent_continuation,
      "Hook can prevent continuation via return value")

# 35.6.6: Abort signal skips remaining hooks
_pto6 = PostTurnOrchestrator()
_abort = threading.Event()
_abort.set()  # pre-set abort
_pto6.register("h1", lambda ctx: None, HookPriority.NORMAL)
_pto6.register("h2", lambda ctx: None, HookPriority.LOW)
_r66 = _pto6.execute(abort_signal=_abort)
_skipped = [h for h in _r66.hook_results if h.outcome == HookOutcome.SKIPPED]
check("35.6.6", len(_skipped) == 2,
      f"Abort signal skipped {len(_skipped)} hooks")

# 35.6.7: Duplicate registration prevented
_pto7 = PostTurnOrchestrator()
_pto7.register("dup", lambda ctx: None)
_pto7.register("dup", lambda ctx: None)  # should be ignored
_s67 = _pto7.get_stats()
check("35.6.7", _s67["registered_hooks"] == 1,
      "Duplicate registration prevented")

# 35.6.8: Unregister hook
_removed = _pto7.unregister("dup")
check("35.6.8", _removed and _pto7.get_stats()["registered_hooks"] == 0,
      "Unregister removes hook")

# 35.6.9: get_stats includes execution counts
_pto8 = PostTurnOrchestrator()
_pto8.register("counter", lambda ctx: None)
_pto8.execute()
_pto8.execute()
_s69 = _pto8.get_stats()
check("35.6.9", _s69["total_executions"] == 2,
      f"Execution count: {_s69['total_executions']}")

# ---------- 35.7: CacheOptimizedForker — AP-6 ----------

# 35.7.1: Build fork messages
_cof1 = CacheOptimizedForker()
_ctx71 = {
    "target": "example.com",
    "scan_phase": "exploit",
    "findings_so_far": [
        {"severity": "high", "title": "SQL Injection in /login"},
        {"severity": "medium", "title": "XSS in search"},
    ],
}
_directives71 = [
    "Test all login forms for SQL injection",
    "Test all input fields for XSS",
    "Enumerate API endpoints for IDOR",
]
_msgs71 = _cof1.build_fork_messages(_ctx71, _directives71)
check("35.7.1", len(_msgs71) == 3,
      f"Built {len(_msgs71)} message sets for 3 directives")

# 35.7.2: All children share same cache key (prefix is identical)
_keys72 = {ms.cache_key for ms in _msgs71}
check("35.7.2", len(_keys72) == 1,
      f"All children share 1 cache key (got {len(_keys72)})")

# 35.7.3: Shared prefix is identical across children
_prefix_a = _msgs71[0].shared_prefix
_prefix_b = _msgs71[1].shared_prefix
check("35.7.3", _prefix_a == _prefix_b,
      "Shared prefix identical across children")

# 35.7.4: Directives differ between children
_dir_a = _msgs71[0].child_directive
_dir_b = _msgs71[1].child_directive
check("35.7.4", _dir_a != _dir_b,
      "Directives differ between children")

# 35.7.5: full_messages() combines prefix + suffix
_full75 = _msgs71[0].full_messages()
check("35.7.5", len(_full75) > 1 and _full75[-1]["role"] == "user",
      f"full_messages: {len(_full75)} messages, last role={_full75[-1]['role']}")

# 35.7.6: Child directive includes rules
_suffix76 = _msgs71[0].child_suffix["content"]
check("35.7.6", "DIRECTIVE:" in _suffix76 and "RULES:" in _suffix76 and "Scope:" in _suffix76,
      "Child message includes DIRECTIVE, RULES, and Scope instruction")

# 35.7.7: Shared prefix includes target context
_has_target = any(
    "example.com" in json.dumps(msg, default=str)
    for msg in _prefix_a
)
check("35.7.7", _has_target,
      "Shared prefix includes target context")

# 35.7.8: Shared prefix includes findings
_has_findings = any(
    "SQL Injection" in json.dumps(msg, default=str)
    for msg in _prefix_a
)
check("35.7.8", _has_findings,
      "Shared prefix includes prior findings")

# 35.7.9: Cache savings estimation
_savings = _cof1.estimate_cache_savings(num_children=5, prefix_tokens=3000)
check("35.7.9", _savings["savings_pct"] > 50 and _savings["tokens_saved"] > 0,
      f"Cache savings: {_savings['savings_pct']}% ({_savings['tokens_saved']} tokens)")

# 35.7.10: Empty findings still works
_msgs710 = _cof1.build_fork_messages(
    {"target": "test.com"}, ["directive"],
)
check("35.7.10", len(_msgs710) == 1 and len(_msgs710[0].shared_prefix) >= 1,
      "Works with empty findings")

# ---------- 35.8: Module-level singletons ----------

# 35.8.1: Stall watchdog singleton
reset_stall_watchdog()
_sw81 = get_stall_watchdog()
_sw81b = get_stall_watchdog()
check("35.8.1", _sw81 is _sw81b,
      "Stall watchdog singleton returns same instance")

# 35.8.2: Post-turn orchestrator singleton
reset_post_turn_orchestrator()
_pto81 = get_post_turn_orchestrator()
_pto81b = get_post_turn_orchestrator()
check("35.8.2", _pto81 is _pto81b,
      "PostTurnOrchestrator singleton returns same instance")

# 35.8.3: Dream consolidator singleton
reset_dream_consolidator()
_dc81 = get_dream_consolidator()
_dc81b = get_dream_consolidator()
check("35.8.3", _dc81 is _dc81b,
      "DreamConsolidator singleton returns same instance")

# 35.8.4: Memory retriever singleton
reset_memory_retriever()
_mr81 = get_memory_retriever()
_mr81b = get_memory_retriever()
check("35.8.4", _mr81 is _mr81b,
      "LLMMemoryRetriever singleton returns same instance")

# 35.8.5: Reset clears singleton
reset_stall_watchdog()
_sw82 = get_stall_watchdog()
check("35.8.5", _sw82 is not _sw81,
      "Reset creates new singleton instance")

# ---------- 35.9: Cross-component integration ----------

# 35.9.1: PostTurnOrchestrator with DreamConsolidator hook
reset_post_turn_orchestrator()
reset_dream_consolidator()
_pto91 = get_post_turn_orchestrator()
_dc91 = get_dream_consolidator(consolidation_threshold=2)
_dream_ran = []
def _dream_hook(ctx):
    eps = ctx.get("episodes", [])
    if eps:
        stats = _dc91.consolidate_session(episodes=eps)
        _dream_ran.append(stats.episodes_reviewed)
_pto91.register("auto_dream", _dream_hook, HookPriority.LOW)
_pto91.execute(context={
    "episodes": [
        {"action": "scan", "outcome": "success"},
        {"action": "scan", "outcome": "failure"},
        {"action": "scan", "outcome": "success"},
    ]
})
check("35.9.1", len(_dream_ran) == 1 and _dream_ran[0] == 3,
      f"Dream hook executed via PostTurnOrchestrator: {_dream_ran}")

# 35.9.2: StallWatchdog with FuseCircuit
_fuse92 = FuseCircuit(name="stall-fuse", threshold=2)
_stall_count = [0]
def _stall_with_fuse(report):
    _stall_count[0] += 1
    _fuse92.record_failure(f"Tool {report.tool_name} stalled")
_tmpd92 = tempfile.mkdtemp()
_tmpf92a = os.path.join(_tmpd92, "out_a.txt")
_tmpf92b = os.path.join(_tmpd92, "out_b.txt")
with open(_tmpf92a, "w") as f:
    f.write("Processing...\nConfirm deletion? (y/n)")
with open(_tmpf92b, "w") as f:
    f.write("Ready.\nContinue?")
_sw92_2 = StallWatchdog(threshold_s=0.1, on_stall=_stall_with_fuse)
_sw92_2.watch("s1", "tool1", output_file=_tmpf92a)
_sw92_2.watch("s2", "tool2", output_file=_tmpf92b)
time.sleep(0.15)
_sw92_2.check_all()  # first check sees initial content as growth
time.sleep(0.15)
_sw92_2.check_all()  # second check detects prompt stall
check("35.9.2", _stall_count[0] >= 1,
      f"StallWatchdog + FuseCircuit integration: {_stall_count[0]} stalls detected")
_shutil35.rmtree(_tmpd92, ignore_errors=True)

# 35.9.3: CacheOptimizedForker with ResolveOnceGuard
_guard93 = ResolveOnceGuard()
_forker93 = CacheOptimizedForker()
_msgs93 = _forker93.build_fork_messages(
    {"target": "t.com"}, ["dir1", "dir2"],
)
# Simulate: first child to complete claims the guard
_guard93.claim(_msgs93[0].child_directive, source="child-0")
_second = _guard93.claim(_msgs93[1].child_directive, source="child-1")
check("35.9.3", _second is None and _guard93.source == "child-0",
      "First fork child claims guard; second rejected")

# Cleanup singletons
reset_stall_watchdog()
reset_post_turn_orchestrator()
reset_dream_consolidator()
reset_memory_retriever()
