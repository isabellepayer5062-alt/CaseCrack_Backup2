# ML/LLM Wiring Comprehensive Analysis — V6
## Full-Scope Integration Audit: Disconnections, Bugs & Improvements

**Date:** 2026-04-11
**Scope:** Complete ML/LLM subsystem wiring map — cross-module feedback loops, dead code, event bus integrity, stealth/exploit/cognitive integration, resource lifecycle
**Baseline:** 345/345 tests passing (V2–V5 all implemented)

---

## Executive Summary

V6 expands the audit to the **full integration surface** across 10 subsystem areas. While V2–V5 addressed 110+ individual bugs, this analysis reveals **systemic wiring gaps** where entire subsystems are built but never plugged into execution paths. The most critical pattern: intelligence engines (Stealth, ExploitGraph, Atlas, PSE, CognitiveBridge) compute sophisticated outputs that **no caller consumes**.

**Findings:** 27 total (5 Critical, 8 High, 9 Medium, 5 Low)
**Positive:** Model Router, Dashboard API, DB connections, thread pools, deque bounds all verified healthy.

---

## Section 1 — LLM Bridge Pipeline Gaps

### V6-1 [CRITICAL] `_complete_structured()` is Dead Code
**File:** `agents/llm_bridge.py`
**Evidence:** All 15 public LLM call methods (`analyze_finding`, `generate_hypothesis`, `strategic_analysis`, etc.) route through `_complete()`. Zero methods call `_complete_structured()`.
**Impact:** If `_complete_structured()` were ever called, it **lacks**:
- Hard-reject policy enforcement (SECURITY — unsafe outputs pass through)
- Canary token verification (SECURITY — prompt injection undetected)
- Role-based temperature selection
- Stream detection
**Fix:** Either (a) wire structured calls through `_complete()` for full pipeline coverage, or (b) delete `_complete_structured()` as unreachable code.
**Priority:** P1

### V6-2 [MEDIUM] `self.chaos_harness` Initialized But Never Used
**File:** `agents/llm_bridge.py` L448
**Evidence:** `ChaosTestHarness()` instantiated in `__init__()`, no method references `self.chaos_harness`.
**Fix:** Remove initialization or wire into testing mode.
**Priority:** P3

### V6-3 [MEDIUM] Deployment Profile Validation Silently Ignores Errors
**File:** `agents/llm_bridge.py` L481–497
**Evidence:** Misconfigured deployment profiles proceed without warning. Invalid model/provider combinations are silently accepted.
**Fix:** Log warning or raise on invalid deployment configs.
**Priority:** P3

### V6-4 [LOW] Dual Shutdown Paths May Conflict
**File:** `agents/llm_bridge.py` L503–652
**Evidence:** Primary shutdown coordinator + legacy `atexit` handler both run cleanup. Possible double-close of resources.
**Fix:** Unify to single shutdown path with guard flag.
**Priority:** P4

### V6-5 [LOW] RAG Augmentation Opacity
**File:** `agents/llm_bridge.py`
**Evidence:** `_augment_with_rag()` returns augmented prompt but callers cannot tell if RAG cache hit or miss. No observability on RAG effectiveness.
**Fix:** Return `(prompt, rag_hit: bool)` tuple or add metric.
**Priority:** P4

---

## Section 2 — EventBus Integrity

### V6-6 [HIGH] 4 Dead Emitters — Events Broadcast Into Void
**Events emitted but ZERO subscribers:**
| Event | Emitter File | Line |
|-------|-------------|------|
| `GOAL_ACHIEVED` | `decision_orchestrator.py` | EventBus emit |
| `GOAL_PROGRESS` | `decision_orchestrator.py` | EventBus emit |
| `GRAPH_POSITION_UPDATED` | Registered in `event_bridge.py` | Never emitted |
| `GRAPH_RESET` | Registered in `event_bridge.py` | Never emitted |
**Impact:** Goal state changes broadcast but nobody listens. DecisionOrchestrator's goal planning is effectively deaf.
**Fix:** Wire subscribers in learning/dashboard systems, or remove dead emitters.
**Priority:** P2

### V6-7 [HIGH] 8 Ad-Hoc String Events Outside Enum — No Subscribers
**Events using raw strings instead of BusEventType enum:**
| Event String | Emitter | Subscriber |
|-------------|---------|------------|
| `"cognitive.copilot_reasoning"` | `cognitive_bridge.py` | ❌ None |
| `"sdk.finding.discovered"` | `copilot_sdk_engine.py` | ❌ None |
| `"streaming.schema_progress"` | `streaming_structured.py` | ❌ None |
| `"streaming.schema_complete"` | `streaming_structured.py` | ❌ None |
| `"decision.outcome_recorded"` | `decision_orchestrator.py` | ❌ None |
| `"decision.explanation"` | `autonomous_loop.py` | ❌ None |
| `"system.resource.snapshot"` | `resource_monitor.py` | Dashboard (glob) |
| `"finding.status_changed"` | `findings_store.py` | ❌ None |
**Impact:** 7 of 8 events fire into void. Intelligence data lost.
**Fix:** Add to BusEventType enum; wire subscribers in relevant consumers.
**Priority:** P2

---

## Section 3 — Learning Pipeline & Feedback Gaps

### V6-8 [CRITICAL] `train_end_of_session()` — Single Point of Failure
**File:** `learning_loop_engine.py` L1711
**Evidence:** Only 1–2 call sites (atlas/adapter.py post_scan completion path). If scan doesn't reach normal completion (timeout, crash, Ctrl+C), the entire 8-step epoch training never executes:
1. ToolLedger persistence
2. Q-table epoch update
3. RLRewardEngine sync
4. StrategyEvolver evolution
5. Bayesian update
6. Model consolidation
7. Session metrics flush
8. Cross-session transfer
**Impact:** Interrupted scans lose ALL accumulated learning for that session.
**Fix:** Add `atexit.register(train_end_of_session)` and signal handler for graceful shutdown.
**Priority:** P1

### V6-9 [HIGH] Finding Lifecycle NOT Propagated to ML Systems
**File:** `multi_request_validator.py` L2857–2933
**Evidence:** Validated findings fed to learning_loop_engine only for PoC generation. Finding status transitions (confirmed → exploited → remediated) never trigger learning events.
**Fix:** Emit `BusEventType.FINDING_LIFECYCLE_CHANGE` on status transitions; wire to Bayesian prioritizer and hypothesis dampening.
**Priority:** P2

### V6-10 [HIGH] Triage/Dismiss Actions Invisible to ML
**File:** `findings_store.py`
**Evidence:** No event/webhook when finding status changes from "open" → "triaged" or "dismissed". Bayesian prioritizer never learns which findings were false positives.
**Fix:** Emit event on triage/dismiss; feed to `bayesian_prioritizer.record_fp_outcome()`.
**Priority:** P2

---

## Section 4 — Stealth Orchestrator: Built But Unwired

### V6-11 [CRITICAL] `gate_tool()` Never Called From Execution Path
**File:** `stealth_orchestrator.py` L1433, L1491
**Evidence:** `gate_tool()` and `record_tool_outcome()` exist but are **never called** from runner, autonomous_loop, executor, or any execution path. Heat level can compute BURNING but tools still execute unchecked.
**Impact:** Stealth intelligence completely bypassed. Scanner triggers WAF/rate-limit without constraint.
**Fix:** Insert `stealth.gate_tool(tool_name, context)` check before every tool launch in execution loop.
**Priority:** P1

### V6-12 [HIGH] Stealth Event Handlers Don't Emit Back to EventBus
**File:** `stealth_orchestrator.py` L1372–1407
**Evidence:** `_on_waf_detected()`, `_on_rate_limit()`, `_on_bot_challenge()` record signals internally but never emit events. Dashboard, LearningLoop, DecisionOrchestrator blind to stealth state changes.
**Fix:** Add `self._event_bus.emit("stealth.defense_response", {...})` in each handler.
**Priority:** P2

### V6-13 [MEDIUM] Pre-Tool Delays/Phase Cooldowns Computed But Ignored
**File:** `stealth_orchestrator.py` L1555–1613
**Evidence:** `get_pre_tool_delay()` and `get_phase_cooldown()` return delay values but no caller sleeps.
**Fix:** Consume delay values in execution loop.
**Priority:** P3

### V6-14 [MEDIUM] WARM Heat Level Silent
**File:** `stealth_orchestrator.py` L1526
**Evidence:** Only HOT/BURNING/COMPROMISED emit events. WARM transitions don't signal DecisionOrchestrator for preemptive throttling.
**Fix:** Add WARM-level event emission.
**Priority:** P3

---

## Section 5 — Exploit Graph: Intelligence Island

### V6-15 [CRITICAL] `suggest_next_tests()` Never Called
**File:** `exploit_chains/exploit_graph.py` L1483
**Evidence:** Method delegates to graph_suggestions module, computes highest-value state transitions, but **no call sites** exist in autonomous loop, runner, or decision orchestrator.
**Impact:** Exploit graph intelligence (cross-dimension prereqs, cascade logic) completely unused for test prioritization.
**Fix:** Autonomous loop should call `graph.suggest_next_tests()` each cycle.
**Priority:** P1

### V6-16 [MEDIUM] Dashboard Graph Updates Not Broadcast
**File:** `exploit_chains/exploit_graph.py`
**Evidence:** Graph state changes (position advances, new transitions) never emitted to EventBus. Dashboard shows stale graph state.
**Fix:** Emit `"graph.state_changed"` event on position advance.
**Priority:** P3

---

## Section 6 — Cognitive Bridge: One-Way Street

### V6-17 [CRITICAL] Bidirectional Reasoning Not Implemented
**File:** `agents/cognitive_bridge.py` L418+
**Evidence:** `build_findings_context()` sends Python state TO Copilot (works). **No `apply_copilot_reasoning()` method** to apply Copilot LLM updates back to Python systems. Dataclasses `HypothesisUpdate`, `StrategicGuidance` defined but never consumed.
**Impact:** LLM reasoning fusion is one-way only. Copilot insights never update hypothesis probabilities or strategy weights.
**Fix:** Implement reverse path: Copilot reasoning → hypothesis probability update → Bayesian fusion.
**Priority:** P1

### V6-18 [HIGH] SDK Tool Results Don't Reach Learning Systems
**File:** `agents/copilot_sdk_engine.py` L823+
**Evidence:** `_event_bus` and `_learning_engine` attributes declared but **never initialized** via setter. Tools execute and produce findings but results bypass learning loop entirely.
**Fix:** Call `engine.set_event_bus()` and `engine.set_learning_engine()` during initialization.
**Priority:** P2

---

## Section 7 — Atlas Nexus: Intelligence Trap

### V6-19 [HIGH] Atlas Pattern Intelligence Isolated
**File:** `atlas/atlas_nexus.py` L305–430
**Evidence:** 9 event handlers feed data INTO Atlas. **No emissions back to EventBus** with discovered patterns. DecisionOrchestrator, Prioritizer, PSE never query Atlas intelligence.
**Fix:** Emit `"atlas.pattern_probability_boosted"` and `"atlas.archetype_matched"` events.
**Priority:** P2

### V6-20 [HIGH] Archetype Matching Not Used in Decisions
**File:** `atlas/atlas_nexus.py` L502, L535
**Evidence:** `get_vuln_intel_boost()` and `get_bayesian_sync()` exist but have **zero call sites** in prioritizer or decision systems.
**Fix:** DecisionOrchestrator should query Atlas before deciding on next test.
**Priority:** P2

---

## Section 8 — Payload Synthesis Engine: Orphaned Output

### V6-21 [HIGH] PSE Synthesis Schedule Never Executed
**File:** `exploit_chains/payload_synthesis_engine.py` L368
**Evidence:** `synthesize_payloads()` returns `SynthesisResult` with `.schedule` (execution order). **No code iterates the schedule and executes payloads.** 5-phase synthesis work is abandoned.
**Fix:** Execution handler should consume `result.schedule` and execute payloads in order.
**Priority:** P2

### V6-22 [MEDIUM] PSE Feedback Loop Completely Missing
**File:** `exploit_chains/payload_synthesis_engine.py` L806
**Evidence:** `record_feedback()` defined (updates WeightTuner, SafetyGuard, StabilityGuard) but **never called from any execution path**. PSE weights never tuned based on actual outcomes.
**Fix:** After each payload execution, call `pse.record_feedback(payload, context, outcome)`.
**Priority:** P3

---

## Section 9 — Resource Lifecycle

### V6-23 [HIGH] SQLite Checkpoint Connections Not Auto-Closed
**Files:** `graph/runner.py` L25–96, `graph/reasoning/runner.py` L75, `graph/multi_agent/runner.py` L79
**Evidence:** Each runner manages checkpoint SQLite connections in `_active_connections` list. `close_checkpointer_connections()` exists but:
- NOT automatically called on shutdown
- NOT registered with atexit
- 3 runner instances × 50 max connections = 150 unclosed connections possible
**Fix:** `atexit.register(close_checkpointer_connections)` in each runner module.
**Priority:** P2

---

## Section 10 — Configuration & Documentation

### V6-24 [MEDIUM] 13 Undocumented Environment Variables
**Files:** `agents/llm_routing.py`, `agents/ab_testing.py`
| Variable | Default | Purpose |
|----------|---------|---------|
| `LLM_QUALITY_EMA_ALPHA` | 0.3 | Quality EMA smoothing |
| `LLM_QUALITY_DOWNRANK_THRESHOLD` | 0.20 | Model violation rate limit |
| `LLM_QUALITY_BONUS_WEIGHT` | 0.15 | Quality bonus weighting |
| `LLM_TEMP_FACTUAL` | 0.1 | Factual role temperature |
| `LLM_TEMP_ANALYTICAL` | 0.5 | Analytical role temperature |
| `LLM_TEMP_CREATIVE` | 0.8 | Creative role temperature |
| `AB_DEFAULT_TRAFFIC` | 0.20 | A/B test traffic split |
| `AB_MIN_SAMPLES` | 50 | Minimum samples for validity |
| `AB_SIGNIFICANCE_LEVEL` | 0.05 | Statistical significance threshold |
| `AB_MIN_EFFECT_SIZE` | 0.2 | Minimum detectable effect |
| `AB_MAX_ACTIVE` | 5 | Max concurrent experiments |
| `AB_AUTO_CONCLUDE_SAMPLES` | 200 | Auto-conclude threshold |
| `AB_MAX_ERROR_INCREASE` | 0.05 | Max allowed error increase |
**Fix:** Add to `.env.example` with descriptions, or consolidate into config YAML.
**Priority:** P3

### V6-25 [MEDIUM] Hardcoded Limits Should Be Config
| Constant | Value | File | Line |
|----------|-------|------|------|
| `_QUALITY_MAX_HISTORY` | 200 | `llm_routing.py` | 103 |
| `_MAX_CACHED_CONNECTIONS` | 50 | `graph/runner.py` | 75 |
| `_FALLBACK_CHAINS` | dict | `llm_routing.py` | 157–179 |
**Fix:** Expose as environment variables or config settings.
**Priority:** P3

### V6-26 [LOW] Deduplication May Double-Count Cross-Source Confirmations
**File:** `findings_store.py` L180–198
**Evidence:** Dedup keyed on `finding_hash + target_domain`. Multiple scanners (ghauri, jsluice, custom) can insert same finding without properly aggregating confirmation count across sources.
**Fix:** Aggregate confirmations across all sources for same `finding_hash`.
**Priority:** P4

### V6-27 [LOW] Session Metrics Mutable Public Attributes
**File:** `agents/llm_bridge.py`
**Evidence:** `session_cost`, `session_tokens` are mutable public attributes. External code can corrupt running metrics.
**Fix:** Use `@property` with read-only access or `__slots__`.
**Priority:** P4

---

## Section 11 — Positive Findings (Working Correctly)

| Area | Status | Details |
|------|--------|---------|
| **Model Router** | ✅ Working | Quality-based routing, EMA scoring, downranking, fallback chains all functional |
| **Dashboard API** | ✅ Working | All 14 route files properly integrated, zero hardcoded responses |
| **Learning Pipeline Inputs** | ✅ Working | 6 input paths to `record_tool_outcome()` all active |
| **ToolLedger Consumers** | ✅ Working | 5 readers (atlas_api, dashboard, learning_bridge, qtable_advisor, confidence_ensemble) |
| **Q-Table Consumers** | ✅ Working | 5 readers (decision_orch, qtable_advisor, dashboard, multi_req_val, learning_bridge) |
| **RLRewardEngine** | ✅ Working | Bidirectional sync with 0.85 decay |
| **StrategyEvolver** | ✅ Working | Output consumed by decision logic and dashboard |
| **Database Connections** | ✅ Safe | All wrapped in context managers |
| **Thread Pools** | ✅ Safe | Proper shutdown with `wait` + `cancel_futures` |
| **Collection Bounds** | ✅ Safe | All history collections use `deque(maxlen=N)` |
| **Thread Safety** | ✅ Sound | PATTERN-B lock hierarchy, RLock prevents ABBA deadlock |
| **ExploitGraph Feed** | ✅ Working | `process_finding()` called from copilot_loop.py |
| **Atlas Ingest** | ✅ Working | `on_finding()` called from graph/nodes.py |

---

## Summary by Priority

| Priority | Count | Key Items |
|----------|-------|-----------|
| **P1 (Critical)** | 5 | Dead `_complete_structured`, train_end_of_session SPOF, stealth `gate_tool` unwired, `suggest_next_tests` unwired, CognitiveBridge one-way |
| **P2 (High)** | 8 | Dead EventBus emitters, ad-hoc string events, finding lifecycle missing, triage invisible, SDK learning unwired, Atlas isolated, PSE schedule orphaned, SQLite leak |
| **P3 (Medium)** | 9 | chaos_harness unused, deployment validation silent, stealth delays ignored, WARM silent, graph broadcast missing, PSE feedback missing, env vars undocumented, hardcoded limits, dedup gaps |
| **P4 (Low)** | 5 | Dual shutdown, RAG opacity, session metrics mutable, dedup cross-source, config values |
| **Total** | **27** | |

---

## Recommended Implementation Order

**Phase 1 — Critical Wiring (P1):**
1. V6-8: `train_end_of_session()` atexit + signal handler
2. V6-11: Wire `stealth.gate_tool()` into execution loop
3. V6-15: Wire `graph.suggest_next_tests()` into autonomous loop
4. V6-17: Implement CognitiveBridge reverse path
5. V6-1: Route structured calls through `_complete()` pipeline

**Phase 2 — High Integration (P2):**
6. V6-6 + V6-7: Wire EventBus subscribers for dead/ad-hoc events
7. V6-9 + V6-10: Finding lifecycle + triage feedback to ML
8. V6-18: SDK engine learning wiring
9. V6-19 + V6-20: Atlas pattern emission + decision integration
10. V6-21: PSE schedule execution
11. V6-23: SQLite checkpoint auto-close

**Phase 3 — Medium Polish (P3):**
12. V6-2: Remove `chaos_harness`
13. V6-3: Deployment validation warnings
14. V6-12 + V6-13 + V6-14: Stealth event emissions + delay consumption + WARM level
15. V6-16: Graph state broadcast
16. V6-22: PSE feedback loop
17. V6-24 + V6-25: Env var documentation + config extraction

**Phase 4 — Low Priority (P4):**
18. V6-4 + V6-5 + V6-26 + V6-27: Cleanup items
