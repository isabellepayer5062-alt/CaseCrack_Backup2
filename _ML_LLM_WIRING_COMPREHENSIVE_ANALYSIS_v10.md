# ML/LLM Wiring Comprehensive Analysis -- V10

**Date:** 2026-04-12
**Scope:** Full-system ML/LLM subsystem integration audit -- all modules, all feedback loops, all event paths
**Methodology:** 4 parallel deep-dive subagent audits (LLM Bridge, Autonomous Loop + DO, LLE + EventBus + ExploitGraph, Stealth + Atlas + MCP + SDK + Runner) -> cross-verification against actual code -> severity classification
**Prior:** V2-V9: **254 total fixes**. 376/376 tests passing.
**Verification:** All CRITICAL findings cross-verified via grep/code inspection. HIGH findings spot-checked.

---

## Summary

| Severity | Count | IDs |
|----------|-------|-----|
| **CRITICAL** | 4 | V10-1, V10-2, V10-3, V10-4 |
| **HIGH** | 12 | V10-5 through V10-16 |
| **MEDIUM** | 18 | V10-17 through V10-34 |
| **LOW** | 6 | V10-35 through V10-40 |
| **Total** | **40** | |

---

## Severity Legend

| Level | Meaning |
|-------|---------|
| CRITICAL | Core function demonstrably broken -- method missing, goal ignored, learning disabled |
| HIGH | Subsystem disconnected -- intelligence not consumed, security bypass, feedback loop open |
| MEDIUM | Feature degraded -- stale state, partial coverage, write-only telemetry |
| LOW | Architectural debt -- observability gaps, documentation, edge cases |

---

## CRITICAL Findings (4)

### V10-1 -- CRITICAL -- `update_world_state()` Does Not Exist on DecisionOrchestrator -- Loop State Never Pushed

**File:** `loop/autonomous_loop.py` L1048; `decision_orchestrator.py`
**Verified:** grep `def update_world_state` in DO -> zero matches

V9-21 added a call in `_observe()`:
```python
_upd = getattr(_do, "update_world_state", None)
if callable(_upd):
    _upd(world)
```

But `DecisionOrchestrator` has NO `update_world_state()` method. `getattr()` returns `None`, `callable(None)` is `False`, the call silently never executes.

**Cascade Impact:**
- DO makes all strategic decisions on outdated state throughout entire scan
- New technologies, endpoints, findings discovered by loop never reach DO
- EV scoring uses stale context (wrong tech stack, wrong finding counts)
- `_phase_ev_dirty` never set from world state updates -> cached phase EVs not recomputed
- Campaign mode cross-target intelligence never propagated

**Fix:** Add `update_world_state(world)` method to DecisionOrchestrator that ingests key WorldState fields (technologies, findings count, endpoints, WAF state) and sets `_phase_ev_dirty = True`.

---

### V10-2 -- CRITICAL -- Goal Achievement Never Stops the Autonomous Loop

**File:** `loop/autonomous_loop.py` L3074-3086 (`_should_terminate`)
**Verified:** grep `goal_achieved` in autonomous_loop.py -> zero matches

`_should_terminate()` checks only: `_abort`, `max_iterations`, `wall_clock`, `stagnation`. DecisionOrchestrator tracks `_goal_achieved` and `_goal_progress` and emits `goal.achieved` events, but the autonomous loop **never reads this flag**.

**Cascade Impact:**
- After finding critical RCE (goal: "full_compromise"), loop continues 1000+ iterations
- Unnecessary tool execution increases detection risk and wastes time budget
- Goal-mode system is effectively decorative -- cannot terminate the scan
- Goal intensity reduction (`_intensity_reduced`) also never propagated to loop

**Fix:** In `_should_terminate()`, check `_do._goal_achieved` (or subscribe to `goal.achieved` event).

---

### V10-3 -- CRITICAL -- ExploitGraph Event Handler Accumulation -- Memory Leak Across Scans

**File:** `exploit_chains/exploit_graph.py` L1694-1707
**Verified:** `_register_events()` calls `bus.on()` 6 times, discards all subscription IDs. No `close()` caller exists.

`ExploitGraphEngine._register_events()` registers 6 EventBus handlers but stores no subscription IDs. The `close()` method exists but is never called from any lifecycle path (runner finalization, scan end, etc). When the same engine instance survives across scans, handlers accumulate.

**Cascade Impact:**
- After N scans: each `VULN_DETECTED` event fires N duplicate handlers
- O(N) processing overhead per event
- Memory leak from handler closures retaining references
- Duplicate finding processing (same vuln ingested N times)

**Fix:** Store subscription IDs in `self._sub_ids`; call `close()` in runner finalization. Alternatively, guard `_register_events()` with `self._events_registered` flag.

---

### V10-4 -- CRITICAL -- `train_end_of_session()` Missing from Failure/Cancel Paths

**File:** `learning_loop_engine.py` L1809
**Verified:** Called from: autonomous_loop normal completion (L842), runner finalization (L6580), atexit fallback (5s timeout). NOT called on SCAN_FAILED, SCAN_CANCELLED, or exception paths.

The 8-step epoch training (ToolLedger persist, Q-table update, RL sync, StrategyEvolver, Bayesian update, model consolidation, metrics flush, cross-session transfer) only runs on successful scan completion.

**Cascade Impact:**
- Crashed/timed-out/cancelled scans lose ALL accumulated learning
- Tools that caused the crash receive no negative feedback
- Bayesian priors never updated for failed scan types
- Cross-session transfer doesn't capture partial intelligence

**Fix:** Wrap scan execution in try/finally that calls `train_end_of_session()`. Subscribe to `SCAN_FAILED`/`SCAN_CANCELLED` events.

---

## HIGH Findings (12)

### V10-5 -- HIGH -- DO Module Bindings Never Validated -- Runs in "Half-Awake" State

**File:** `decision_orchestrator.py` L985-1080, L1085-1200
**Evidence:** 12+ `bind_*()` methods defined but no centralized initialization ensures they're called.

DecisionOrchestrator has lazy bindings for: exploit_graph, bayesian, goal_planner, reasoning_engine, scan_intel, hypothesis_engine, session_intel, learning_engine, cognitive_bridge, lookahead, world_model, foresight. Every scoring path checks `if self._X is not None` and silently skips when unbound. No warning emitted for missing critical modules.

**Impact:** Without Bayesian + ExploitGraph, EV scoring is pure static heuristic. DO silently degrades to a lookup table without any indication to operators or logs.

**Fix:** Add `_validate_bindings()` that logs WARNING for missing critical modules (Bayesian, ExploitGraph) at first `recommend_actions()` call.

---

### V10-6 -- HIGH -- `agent_chat()` Local Path Bypasses Rate Limiting

**File:** `agents/llm_bridge.py` L2979-3040
**Evidence:** Cloud path calls `tracker.enforce_rate_limit()` pre-flight. Local model path does NOT.

**Impact:** Local model calls burst over RPM/TPM limits in high-concurrency scenarios. Budget enforcement bypassed. Dashboard metrics lag behind actual usage.

**Fix:** Add `await self.tracker.enforce_rate_limit()` before `client.complete_chat()` in local path.

---

### V10-7 -- HIGH -- `agent_chat()` Local Path Missing Canary Leakage Check

**File:** `agents/llm_bridge.py` L2979-3096
**Evidence:** `_complete()` calls `get_canary_validator().check_leakage()` on responses. `agent_chat()` local path does not.

**Impact:** Prompt injection attacks undetected in interactive agent chat. Security blind spot for the most user-facing LLM path.

**Fix:** Add canary leakage detection after local model response.

---

### V10-8 -- HIGH -- `suggest_payloads()` Missing Cost/Token Tracking

**File:** `agents/llm_bridge.py` L2406-2439
**Evidence:** Method calls `_complete()` (which tracks internally) but never calls `tracker.record_usage()` explicitly. However, since it uses `_complete()`, the inner tracking SHOULD fire. Need to verify if `_complete()` always records.

**Impact:** If `_complete()` records usage internally, this is a non-issue. If it returns before tracking (e.g. cache hit), payload generation costs are invisible.

---

### V10-9 -- HIGH -- `discover_chains()` Has No Error Handling/Fallback

**File:** `agents/llm_bridge.py` L2763-2780
**Evidence:** No try/except wrapper. Other methods (e.g. `validate_finding`) have symbolic fallbacks on LLM failure. `discover_chains()` doesn't.

**Impact:** Single LLM outage cascades to entire chain discovery pipeline. No graceful degradation. Inconsistent with other methods' error handling.

**Fix:** Wrap in try/except; return `{"chains": [], "_fallback": True}` on error.

---

### V10-10 -- HIGH -- StealthOrchestrator Tool Substitutes Not Re-Gated

**File:** `stealth_orchestrator.py` L1027-1065
**Evidence:** When `gate_tool()` returns `GateDecision.SUBSTITUTE` with an alternative tool, the substitute is added to the execution plan without being re-checked against current heat level.

**Impact:** At BURNING heat, a substitute tool may still be too noisy. The substitute could be as loud as the original (e.g. switching from sqlmap to nuclei at BURNING level).

**Fix:** Re-gate the substitute tool: `gate_result_sub = self.gate_tool(alt)` and verify it passes.

---

### V10-11 -- HIGH -- StealthOrchestrator Never Finalized in Runner

**File:** `recon_dashboard/runner.py` L6505-6800 (finalization)
**Evidence:** Runner finalization calls close/finalize on DO, ACE, LLE, SOS, UAG, but NOT StealthOrchestrator. Heat state, evasion profiles, and defense detection history are lost.

**Impact:** Multi-scan campaigns lose stealth learning between scans. No stealth telemetry persisted.

**Fix:** Add `stealth_orchestrator.finalize()` to runner finalization block.

---

### V10-12 -- HIGH -- WAF State Never Synced Back from DO to Loop

**File:** `loop/autonomous_loop.py` L1046-1050
**Evidence:** Loop reads `self._waf_detected` (local field) when building WorldState. DO may update its own `_waf_detected` from stealth events, but loop never reads DO's value.

**Impact:** Loop and DO have divergent WAF state. EV scoring gets wrong WAF context. Tool selection doesn't adapt to new WAF detections.

**Fix:** In `_observe()`, sync WAF/cloud state from DO before building WorldState.

---

### V10-13 -- HIGH -- Defense Event Emission Failures Silently Swallowed

**File:** `stealth_orchestrator.py` L1335-1345
**Evidence:** EventBus `emit()` failures caught with bare `except: pass` (no logging).

**Impact:** Learning systems subscribed to stealth defense events never receive signals. Debugging impossible.

**Fix:** Log at WARNING level.

---

### V10-14 -- HIGH -- HTTP 451/410 Heat Inference Defaults to 0.30

**File:** `stealth_orchestrator.py` L565-600
**Evidence:** `_compute_heat()` has no special handling for HTTP 451 (legal block), 410 (gone), or vendor-specific WAF response patterns.

**Impact:** Legal blocks treated as mild noise (0.30) instead of severe detection (0.80+). Scanner continues aggressive scanning despite legal injunction response.

**Fix:** Map HTTP 451/410 and known WAF signatures to appropriate severity scores.

---

### V10-15 -- HIGH -- Finding Dedup Across Iterations Incomplete

**File:** `loop/autonomous_loop.py` L2250-2350
**Evidence:** `_evaluate()` deduplicates new_findings against the current iteration only. Does not check against `self._all_findings` or DO's `_outcome_log` for cross-iteration duplicates.

**Impact:** Same finding re-discovered in later iterations is treated as new. Learning systems receive duplicate signals. Bayesian priors inflated.

**Fix:** Check new findings against `self._all_findings` (vuln_type + endpoint combination) before appending.

---

### V10-16 -- HIGH -- Bayesian FP Signal from Automated Triage Disconnected

**File:** `learning_loop_engine.py` L1616-1637
**Evidence:** `_on_finding_status_changed` listens for `"finding.status_changed"` events but these are only emitted from dashboard triage (findings_store.py L569), not from automated scanning pipelines.

**Impact:** Bayesian priors don't receive false-positive feedback from most scans. Thompson sampling recommends high-FP tools. Posteriors are overly optimistic.

**Fix:** Emit `finding.status_changed` from automated validation/triage paths too.

---

## MEDIUM Findings (18)

### V10-17 -- MEDIUM -- EV Formula Uses Stale Technologies (Lock Timeout Skip)

**File:** `decision_orchestrator.py` L1289-1330
**Evidence:** `update_state()` has 0.05s lock timeout. On timeout, technology update silently skipped.

**Impact:** After lock contention, `_technologies` not updated. EV scoring uses stale tech list.

---

### V10-18 -- MEDIUM -- Adaptive Table Context Set Inconsistently in Buffered Drain

**File:** `decision_orchestrator.py` L1810-1830
**Evidence:** `set_context()` called inside buffer drain loop but also called in main outcome path. Context may differ between buffered and main paths.

**Impact:** Same action learns different keyed values across context fingerprints.

---

### V10-19 -- MEDIUM -- Buffered Outcome Drain Builds Context Multiple Times

**File:** `decision_orchestrator.py` L1850-1900
**Evidence:** `_build_context()` called per buffered item. State may change between calls.

**Impact:** Hypothesis engine and lookahead receive inconsistent contexts for sequential buffered items.

---

### V10-20 -- MEDIUM -- ExploitGraph Adjusted via Two Different Instances

**File:** `loop/autonomous_loop.py` L2880-2925
**Evidence:** `extract_state()` uses `self._attack_graph`. `adjust_probabilities()` uses `get_exploit_graph()` singleton. May be different objects.

**Impact:** Graph updates split across instances; transition probabilities inconsistent.

---

### V10-21 -- MEDIUM -- GitHubModelsClient Missing `complete_chat_stream()` Implementation

**File:** `agents/llm_clients.py` L1435-1560
**Evidence:** OllamaClient implements streaming; GitHubModelsClient does not.

**Impact:** Streaming unavailable for GitHub Models. Provider parity broken.

---

### V10-22 -- MEDIUM -- Ollama Token Counting Uses len/4 Estimate Instead of API Response

**File:** `agents/llm_clients.py` L1061-1230
**Evidence:** OpenAI reads `completion_tokens` from API. Ollama estimates `len(content) // 4`.

**Impact:** Cost underestimation. Rate limit bypass. Budget overshoot.

---

### V10-23 -- MEDIUM -- `plan_and_execute()` Never Records Quality to Feedback Engine

**File:** `agents/llm_bridge.py` L2859-2926
**Evidence:** No `feedback_engine.record_quality()` call after planning response.

**Impact:** Planning prompts never improve via learned feedback.

---

### V10-24 -- MEDIUM -- Output Guard Schema Validation Inconsistent Across Methods

**File:** `agents/llm_bridge.py` L2191-2780
**Evidence:** Some methods pass `purpose` to `_parse_json_response()`; others may not.

**Impact:** Unvalidated JSON may propagate downstream with unexpected fields.

---

### V10-25 -- MEDIUM -- ConfidenceEnsemble Data Starvation on First Runs

**File:** `learning_loop_engine.py` L2181-2186
**Evidence:** Ensemble fed only at init with historical data. No real-time refresh during scan.

**Impact:** Tool confidence weights skewed for first N scans after system reset.

---

### V10-26 -- MEDIUM -- AtlasNexus Circuit Breaker 60s Lockout After Single Failure

**File:** `atlas/atlas_nexus.py`
**Evidence:** Circuit breaker opens on single failure with 60s recovery. No graduated response.

**Impact:** Transient LLM hiccup disables Atlas learning for full minute.

---

### V10-27 -- MEDIUM -- CognitiveBridge Lock Protection Incomplete in Hypothesis Iteration

**File:** `agents/cognitive_bridge.py`
**Evidence:** Reads hypothesis list outside lock during iteration.

**Impact:** Concurrent modification could cause iteration errors.

---

### V10-28 -- MEDIUM -- StealthOrchestrator Emits Defense Events Twice

**File:** `stealth_orchestrator.py`
**Evidence:** Duplicate event processing in some defense detection paths.

**Impact:** Downstream subscribers receive doubled signals; heat computation inflated.

---

### V10-29 -- MEDIUM -- Progress Tracking Miscalculates on Partial Phase Selection

**File:** `recon_dashboard/runner.py`
**Evidence:** Progress percentage computed against total phases, not selected subset.

**Impact:** Dashboard shows misleading progress (e.g. 50% when scan is 100% complete for selected phases).

---

### V10-30 -- MEDIUM -- `analyze_response()` Missing A/B Experiment Recording

**File:** `agents/llm_bridge.py` L2191-2217
**Evidence:** No `experiment_engine.record_outcome()` call.

**Impact:** Analysis variants not testable. Model comparison blind for analysis tasks.

---

### V10-31 -- MEDIUM -- Chain-of-Thought In-Flight Wait Timeout Race Condition

**File:** `agents/llm_bridge.py` L2478-2509
**Evidence:** `asyncio.Event` replaced on timeout; old waiters may not see `set()` signal.

**Impact:** Coroutines may hang beyond timeout in high-concurrency.

---

### V10-32 -- MEDIUM -- `train_end_of_session()` Lock Timeout Returns Silent Empty Result

**File:** `learning_loop_engine.py` L1819-1832
**Evidence:** 5s lock timeout -> training skipped with `return {}`. Logged as WARNING only.

**Impact:** Silent training loss. All learning subsystems not updated.

---

### V10-33 -- MEDIUM -- ThreadPoolExecutor Never Shutdown (Thread Leak)

**File:** `recon_dashboard/runner.py`
**Evidence:** Thread pool created but `shutdown()` never called in finalization.

**Impact:** Thread leak across multiple scan runs.

---

### V10-34 -- MEDIUM -- `suggest_payloads()` Missing Feedback Engine Record

**File:** `agents/llm_bridge.py` L2430-2436
**Evidence:** Reads from feedback engine but never records quality back.

**Impact:** Feedback loop asymmetric. Payload generation prompts never improve from learned feedback.

---

## LOW Findings (6)

### V10-35 -- LOW -- RAG Engine Augmentation Metrics Never Exported

**File:** `agents/llm_bridge.py` L766-796
**Evidence:** `_rag_hits` and `_rag_misses` counters incremented but never exported to dashboard/metrics.

---

### V10-36 -- LOW -- Cache TTL Not Refreshed on Quality Pass

**File:** `agents/llm_bridge.py` L1178-1206
**Evidence:** Valid cached entries nearing expiry aren't refreshed, causing repeated quality checks.

---

### V10-37 -- LOW -- Hard-Reject Provider Profile Lookup May Fail with Enum Type

**File:** `agents/llm_bridge.py` L1521-1555
**Evidence:** Provider name coercion may fail on unexpected types.

---

### V10-38 -- LOW -- Cloud Fallback Retry Behavior Undocumented

**File:** `agents/llm_bridge.py` L3048-3075
**Evidence:** Total retry budget for local + cloud fallback unclear.

---

### V10-39 -- LOW -- Glob Pattern Validation Missing in EventBus.on()

**File:** `event_bus.py` L1084-1130
**Evidence:** Invalid glob patterns accepted silently; subscribers never notified of mismatch.

---

### V10-40 -- LOW -- `chaos_harness` Initialized But Never Used

**File:** `agents/llm_bridge.py` L448
**Evidence:** `ChaosTestHarness()` instantiated in `__init__()`, never referenced.

---

## Cross-Cutting Systemic Patterns

### Pattern A: "Write-Only Intelligence"
Multiple intelligence systems compute sophisticated outputs that no caller consumes:
- DO goal_achieved flag (V10-2)
- DO update_world_state (V10-1)
- StealthOrchestrator finalization (V10-11)
- FeedbackLearning quality signals from several LLM methods (V10-23, V10-34)

### Pattern B: "Silent Failure Normalization"
Bare `except: pass` blocks suppress critical integration failures:
- Defense event emission (V10-13)
- train_end_of_session lock timeout (V10-32)
- Module binding validation (V10-5)

### Pattern C: "Divergent State"
Multiple modules maintain independent copies of shared state that drift:
- WAF detection state (Loop vs DO) (V10-12)
- Technologies list (Lock timeout skips) (V10-17)
- ExploitGraph instances (V10-20)

### Pattern D: "Provider Path Asymmetry"
Security and tracking features present in `_complete()` cloud path but missing from local/agent_chat path:
- Rate limiting (V10-6)
- Canary leakage (V10-7)
- Streaming (V10-21)

---

## Priority Action Plan

### Priority 1 -- CRITICAL (Fix Immediately)
| ID | Fix | Files |
|----|-----|-------|
| V10-1 | Add `update_world_state()` to DO | decision_orchestrator.py |
| V10-2 | Check `goal_achieved` in `_should_terminate()` | autonomous_loop.py |
| V10-3 | Guard ExploitGraph event re-registration + call `close()` | exploit_graph.py, runner.py |
| V10-4 | Wrap scan in try/finally for `train_end_of_session()` | runner.py, autonomous_loop.py |

### Priority 2 -- HIGH (This Sprint)
| ID | Fix | Files |
|----|-----|-------|
| V10-5 | Add binding validation + WARNING log | decision_orchestrator.py |
| V10-6 | Add rate limit pre-check to agent_chat local | llm_bridge.py |
| V10-7 | Add canary check to agent_chat local | llm_bridge.py |
| V10-9 | Add error handling to discover_chains() | llm_bridge.py |
| V10-10 | Re-gate substitute tools | stealth_orchestrator.py |
| V10-11 | Add stealth finalization | runner.py |
| V10-12 | Sync WAF state from DO | autonomous_loop.py |
| V10-13 | Log defense event failures | stealth_orchestrator.py |
| V10-14 | Map HTTP 451/410 heat scores | stealth_orchestrator.py |
| V10-15 | Cross-iteration finding dedup | autonomous_loop.py |
| V10-16 | Emit finding.status_changed from auto-triage | multi_request_validator.py |

### Priority 3 -- MEDIUM (Next Sprint)
V10-17 through V10-34 (18 items)

### Priority 4 -- LOW (Backlog)
V10-35 through V10-40 (6 items)

---

## Quantitative Summary

| Metric | Value |
|--------|-------|
| Files Audited | 20+ |
| Total Findings | 40 |
| CRITICAL | 4 |
| HIGH | 12 |
| MEDIUM | 18 |
| LOW | 6 |
| Prior Fixes (V2-V9) | 254 |
| Tests Passing | 376/376 |
| Subsystems Covered | LLM Bridge, Autonomous Loop, Decision Orchestrator, Learning Loop Engine, EventBus, ExploitGraph, Bayesian Prioritizer, StealthOrchestrator, Atlas Nexus, MCP Server, Copilot SDK Engine, CognitiveBridge, Runner, Recon Pipeline, Multi-Request Validator |
