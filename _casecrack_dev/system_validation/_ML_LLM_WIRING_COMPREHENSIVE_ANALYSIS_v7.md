# ML/LLM Wiring Comprehensive Analysis — V7

**Date:** 2026-04-12  
**Scope:** Full-system ML/LLM subsystem integration audit — autonomous loop, LLM Bridge, Decision Orchestrator, Learning Loop Engine, EventBus, ExploitGraph, Stealth Orchestrator, CognitiveBridge, MCP Server, LangGraph, SDK Agents, Security, Resource Management  
**Methodology:** Subagent deep-dive per subsystem → cross-verification of critical findings against actual code → severity classification  
**Prior:** V2 (35 fixes), V3 (46 fixes), V4 (29 fixes), V5 (15 fixes), V6 (12 fixes) — 137 total fixes across V2–V6. 345/345 tests passing.

---

## Summary

| Severity | Count | IDs |
|----------|-------|-----|
| **CRITICAL** | 3 | V7-1, V7-2, V7-3 |
| **HIGH** | 7 | V7-4 through V7-10 |
| **MEDIUM** | 10 | V7-11 through V7-20 |
| **LOW** | 8 | V7-21 through V7-28 |
| **Total** | **28** | |

---

## CRITICAL Findings

### V7-1 — CRITICAL — `LearningLoopEngine.bind_event_bus()` is NEVER called — all 10 event subscriptions are dead

**File:** `learning_loop_engine.py` L1529–L1571  
**Impact:** The LLE defines 10 EventBus subscriptions (`VULN_DETECTED`, `VULN_CONFIRMED`, `SECRET_FOUND`, `goal.*`, `atlas.*`, `STRATEGY_RECOMMENDED`, `finding.status_changed`, `decision.outcome_recorded`, `sdk.finding.discovered`, `stealth.*`) — including V6-6/V6-7 fixes. But `bind_event_bus()` is **never called** from any production code path. Verified via codebase-wide grep: zero callers.

**Consequence:** The LLE operates entirely passively — it only learns when explicitly called (via `record_tool_outcome()`, `train_end_of_session()`). All reactive real-time learning from vulnerability discoveries, goal events, stealth events, and decision outcomes is completely dead. The V4-20, V6-6, and V6-7 fixes are unreachable code.

**Fix:** The runner (or autonomous loop `__init__`) must call `get_learning_loop_engine().bind_event_bus(get_event_bus())` during subsystem initialization.

---

### V7-2 — CRITICAL — Autonomous loop `_act()` has NO stealth gate integration — tools execute unthrottled

**File:** `loop/autonomous_loop.py` L1813–L1960  
**Impact:** The `_act()` method dispatches tool execution directly to `_parallel_executor.execute_parallel()` or `_executor.execute_batch()` with zero stealth gating. No reference to `stealth_orchestrator`, `gate_tool()`, or `get_pre_tool_delay()` anywhere in the 2900-line file (only a hardcoded `stealth_score=0.4` placeholder at L2674). Meanwhile, the recon dashboard runner (runner.py L2029) and execution orchestrator (L1248) DO call `gate_tool()`.

**Consequence:** The autonomous loop — the most aggressive scanner path — is the one path where stealth gating is missing. All adaptive throttling, WAF detection response, and rate-limit avoidance are bypassed. This makes the autonomous loop the noisiest execution path despite being intended as the most intelligent.

**Fix:** Wrap tool dispatch in `_act()` with `stealth_orchestrator.gate_tool(tool_name)` check and `time.sleep(gate.delay_seconds)`.

---

### V7-3 — CRITICAL — `agent_chat_stream()` L4325: `scorer.score(prompt, collected)` passes `str` instead of `LLMResponse` — quality scoring dead in streaming path

**File:** `agents/llm_bridge.py` L4325  
**Impact:** `QualityScorer.score()` expects `(prompt: str, response: LLMResponse)` and accesses `response.content` at L769. But L4325 passes `collected` (a `str`) as the second argument instead of the `resp = LLMResponse(...)` constructed at L4311–4320. This raises `AttributeError` on every call, caught by the surrounding `try/except` at L4323.

**Consequence:** Quality scoring, FeedbackLearningEngine recording, and A/B experiment outcome recording are ALL silently dead for the `agent_chat_stream()` local Ollama path. This means the streaming path — likely the most common path for interactive use — has zero quality tracking.

**Fix:** Change L4325 to `_qs = self.scorer.score(prompt, resp)`.

---

## HIGH Findings

### V7-4 — HIGH — Autonomous loop emits only 1 diagnostic event to EventBus — no lifecycle events

**File:** `loop/autonomous_loop.py`  
**Impact:** The entire 2900-line autonomous loop emits exactly ONE event to EventBus: `decision.explanation` at L1435 (inside a try/except with bare `pass`). There are ZERO events for: loop start/end, iteration start/end, phase transitions (OBSERVE→THINK→ACT→EVALUATE→LEARN), finding discovery, stagnation detection, or termination.

**Consequence:** All subsystems that subscribe to scan lifecycle events (dashboard bridge, LLE, stealth orchestrator) are completely blind to autonomous loop activity. The dashboard cannot show loop state or progress from this path.

---

### V7-5 — HIGH — 40+ of 63 BusEventType enum members have zero production emitters

**File:** `event_bus.py` L78–L202  
**Impact:** The EventBus defines 63 event types. Only ~20 are actually emitted in production: `SCAN_STARTED/PROGRESS/COMPLETE/FAILED` (ProgressTracker), `WORKFLOW_TRIGGERED/FAILED` (WorkflowEngine), `GRAPH_STATE_CHANGED` (exploit_graph), `INJECTION_ALERT_*` (prompt_security), `STRATEGY_RECOMMENDED` (DO), plus ad-hoc string events. At least 40 enum members including `VULN_DETECTED`, `VULN_CONFIRMED`, `SECRET_FOUND`, `WAF_DETECTED`, `STEALTH_*`, `ATLAS_*`, `GOAL_*`, `AGENT_INTENT_*`, `MULTI_AGENT_*` have zero emitters.

**Note:** Goal events (`goal.progress`, `goal.achieved`, `goal.intensity_reduced`) ARE emitted by DO using string paths, NOT the BusEventType enum. And the dashboard bridge subscribes to `"goal.*"` glob.

**Consequence:** The event-driven architecture is largely aspirational. Most event types are defined but never fire, making the system's event-driven learning and monitoring substantially weaker than its architecture suggests.

---

### V7-6 — HIGH — `_observe()` does NOT feed ExploitGraph — two disconnected graph systems

**File:** `loop/autonomous_loop.py` L886–940  
**Impact:** `_observe()` feeds `TargetMentalModel.ingest_world_state()` but NOT `exploit_chains/exploit_graph.py`. Meanwhile, `_learn()` L2398 calls `self._attack_graph.extract_state([r])` which feeds `loop/attack_graph.py` (`StatefulAttackGraph`) — a COMPLETELY DIFFERENT graph that only does regex extraction. The proper `ExploitGraph` (which tracks chain completion, blast radius, multi-hop paths) is never fed from the autonomous loop's observation pipeline.

**Consequence:** The ExploitGraph's sophisticated chain analysis is blind to autonomous loop discoveries. The loop uses a primitive regex-based graph while a full-featured exploit chain graph exists unused.

---

### V7-7 — HIGH — No PromptSecurityScanner input scanning in LLM Bridge — `llm_adv_defense` not imported

**File:** `agents/llm_bridge.py`  
**Impact:** LLM Bridge does NOT directly import or use `llm_advanced_defense.py`. The `sanitize_untrusted_text()` function in `prompt_security.py` (which calls `NovelInjectionDetector`) IS available, but LLM Bridge's `_complete()`, `agent_chat()`, and `agent_chat_stream()` do not call it on user prompts before submission to the LLM. The `UserSafeguards.check_request_allowed()` at L1102 does abuse/rate-limit detection, NOT prompt injection scanning.

**Mitigation:** Input sanitization exists at `prompt_security.py:353` and IS called from some callers higher up the stack (e.g., MCP server sanitizes inputs). But the bridge itself has no centralized injection defense for all paths.

---

### V7-8 — HIGH — `ModelRouter.record_quality()` not called from `agent_chat()` local path or `agent_chat_stream()` local path

**File:** `agents/llm_bridge.py`  
**Impact:** `router.record_quality()` is called in `_complete()` L1438, `_complete_structured()` L1719, and `_complete_structured_stream()` L1923. But `agent_chat()` local Ollama path and `agent_chat_stream()` local Ollama path do NOT call it. These paths likely represent ~50% of traffic. The ModelRouter's EMA quality model for adaptive model selection is blind to this traffic.

---

### V7-9 — HIGH — No per-iteration timeout in autonomous loop — LLM hang blocks the entire loop permanently

**File:** `loop/autonomous_loop.py`  
**Impact:** `_should_terminate()` (L2722–2734) checks wall-clock and stagnation, but only runs BETWEEN iterations. If a single LLM call or tool execution hangs indefinitely within `_run_iteration()`, the iteration never returns. There is no `asyncio.wait_for()` or `concurrent.futures.wait(timeout=...)` wrapper around iteration execution.

**Consequence:** A single stuck Ollama inference, hung subprocess, or stalled network connection will permanently freeze the autonomous loop with no recovery mechanism.

---

### V7-10 — HIGH — Hard-reject policy only on 2 of 5 LLM call paths — streaming and local paths bypass quality floor

**File:** `agents/llm_bridge.py`  
**Impact:** Hard-reject (GAP-SEC-6) is enforced in `_complete()` L1365 and `_complete_structured()` L1758. NOT enforced in: `agent_chat()` local path, `agent_chat_stream()` local path, `_complete_structured_stream()`. These three paths can return arbitrarily low-quality output without quality floor rejection.

---

## MEDIUM Findings

### V7-11 — MEDIUM — DO `bind_goal_planner()` is a dead bind — GOAP planner stored but never queried

**File:** `decision_orchestrator.py` L1105  
**Impact:** `_goal_planner` is set by `bind_goal_planner()` but only checked `is not None` in `get_metrics()` L3666. The GOAP planning promised in the docstring is entirely unrealized. No scoring, recommendation, or feedback path uses it.

---

### V7-12 — MEDIUM — DO `_campaign_prior_registry` is a dead bind — Tier-0 global priors never queried

**File:** `decision_orchestrator.py` L1197  
**Impact:** `_campaign_prior_registry` is bound via `bind_campaign_intelligence()` but only checked `is not None` in `get_metrics()` L3669. The prior registry, which should provide global priors from historical data across all campaigns, is never actually queried for prior values during scoring.

---

### V7-13 — MEDIUM — Autonomous loop `_think()` does NOT query Atlas Nexus intelligence

**File:** `loop/autonomous_loop.py`  
**Impact:** No call to `atlas_nexus`, `AtlasNexus`, or any Atlas-specific query anywhere in the 2900-line file. The loop's thinking step operates without access to the knowledge base's archetype matching, pattern analysis, or cross-scan intelligence. Atlas is only indirectly accessed via `train_end_of_session()` at loop end (L801).

---

### V7-14 — MEDIUM — `ExploitGraph.suggest_next_tests()` only in strategic LLM path — not injected into fallback paths

**File:** `loop/autonomous_loop.py` L1007–1020  
**Impact:** `suggest_next_tests()` is called only in `_think()` Path 0 (Strategic LLM Layer, L1012). If the strategic layer is unavailable and execution falls into Path A (`_think_with_llm`) or Path B (hypothesis engine), ExploitGraph suggestions are never consulted.

---

### V7-15 — MEDIUM — Arbitration disconnected from ExploitGraph and DecisionOrchestrator

**File:** `agents/unified_arbitration.py`  
**Impact:** The `FindingArbitrator` performs finding evaluation and verdict classification but has zero references to `ExploitGraph`, `DecisionOrchestrator`, or `EventBus`. Arbitration results (confirmed/rejected/inconclusive verdicts) are not propagated to the exploit chain graph and do not update DO's scoring intelligence.

---

### V7-16 — MEDIUM — FindingsStore `insert()`/`insert_batch()` do not emit EventBus events

**File:** `recon_dashboard/findings_store.py`  
**Impact:** Only `update_status()` emits `"finding.status_changed"` to EventBus. When new findings are first stored via `insert()` or `insert_batch()`, no event is emitted. Subsystems subscribing to finding events cannot react to new findings in real time.

---

### V7-17 — MEDIUM — `_complete_structured()` lacks global timeout protection

**File:** `agents/llm_bridge.py` L1601–1860  
**Impact:** Unlike `_complete()` which has a budget/timeout framework, `_complete_structured()` retry loop has no H-TO1 global timeout. If the LLM provider is slow but responsive, retries could continue indefinitely.

---

### V7-18 — MEDIUM — `_complete_structured()` lacks UserSafeguards check

**File:** `agents/llm_bridge.py` L1601  
**Impact:** `_complete()` checks `UserSafeguards.check_request_allowed()` at L1101 to enforce tenant rate limits and abuse detection. `_complete_structured()` skips this check entirely. Callers using structured output can bypass all safeguard limits.

---

### V7-19 — MEDIUM — Q-table `next_max_q` always 0.0 — temporal difference learning disabled

**File:** `learning_loop_engine.py` L1711, L1302  
**Impact:** The Q-update formula uses `gamma * next_max_q` for temporal-difference learning, but `next_max_q` is always `max(self._q_table.get(next_state, {}).values(), default=0.0)` where `next_state` is the raw action string. Since states are never repeated identically, `next_max_q` is always 0.0. The `gamma` parameter is meaningless and TD-learning reduces to simple reward averaging.

---

### V7-20 — MEDIUM — 4–5 `requests.Session()` in `ai_ml/` modules lack close/cleanup

**Files:** `ai_ml/_model_endpoint.py` L141, `ai_ml/_llm_exfiltration.py` L65, `ai_ml/_ai_api_proxy.py` L80, `ai_ml/_vector_db.py` L71, `ai_ml/_rag_pipeline.py` L99  
**Impact:** Five `requests.Session()` instances are created without close/cleanup methods. While GC will eventually collect them, leaked sessions may hold open TCP connections to external services.

---

## LOW Findings

### V7-21 — LOW — Autonomous loop Platt-scaling recalibration at L2227 has bare `except Exception: pass`

**File:** `loop/autonomous_loop.py` L2227  
**Impact:** If confidence recalibration fails, raw (potentially miscalibrated) LLM confidence is used for threshold filtering with no indication. Could admit bad findings or reject good ones.

---

### V7-22 — LOW — DO `_get_decision_orchestrator()` at L671 bare `except Exception: return None`

**File:** `loop/autonomous_loop.py` L671  
**Impact:** Silently disables DO for entire session on any initialization error.

---

### V7-23 — LOW — DO N-14 buffered outcomes get reduced feedback propagation

**File:** `decision_orchestrator.py` L1770–1789  
**Impact:** When outcomes are buffered (during lock contention), the drain loop only propagates to BayesianPrioritizer + AdaptiveTables. It does NOT propagate to HypothesisEngine, SessionIntelligence, CampaignIntelligence, LookaheadEngine, or DecisionTrace.

---

### V7-24 — LOW — DO cost penalty structurally small — `cost × det_risk × 0.1`

**File:** `decision_orchestrator.py` L2876–2906  
**Impact:** The `× 0.1` scaling factor means even maximum cost+detection-risk only subtracts 0.10 from EV — less than many bonuses. Cost is underweighted relative to the overall EV range.

---

### V7-25 — LOW — Version pinning (V5-2) only in `agent_chat()` local path

**File:** `agents/llm_bridge.py` L2847–2852  
**Impact:** `_complete()` and `agent_chat_stream()` do not check version pinning. Model version pins only apply to one of three major call paths.

---

### V7-26 — LOW — CognitiveBridge not directly wired to DecisionOrchestrator

**File:** `agents/cognitive_bridge.py`  
**Impact:** CognitiveBridge operates at the CopilotLoop level and influences DO indirectly through hypothesis probability modification. There is no `bind_cognitive_bridge()` on DO and no direct event subscription between them. The cognitive fusion intelligence path is second-hand.

---

### V7-27 — LOW — `graph/tracing.py` L187 opens file handle without context manager

**File:** `graph/tracing.py` L187  
**Impact:** `self._file = open(self._path, "a", ...)` is held open indefinitely. Has manual `close()` and rotation, but a crash between open/close leaks the handle.

---

### V7-28 — LOW — No integration tests for prompt injection defense stack

**Impact:** `sanitize_untrusted_text()`, `CanaryTokenValidator`, `NovelInjectionDetector`, `AdversarialOutputDetector`, `CrossPhaseInjectionTracker`, `InjectionAlertAggregator`, `HardBlockPolicy` — none have dedicated unit or integration tests. The only defense test is `test_canary_detector.py` which tests a different (honeypot target) canary system.

---

## Cross-Subsystem Wiring Map

```
Autonomous Loop ──► LLM Bridge (_think_with_llm)
                 ──► DecisionOrchestrator (recommend_actions)
                 ──► StatefulAttackGraph (extract_state) ←── NOT ExploitGraph
                 ──► LearningLoopEngine (record_tool_outcome, train_end_of_session)
                 ──► TargetMentalModel (ingest_world_state)
                 ──✗ StealthOrchestrator (NOT CALLED)
                 ──✗ Atlas Nexus (NOT QUERIED)
                 ──✗ EventBus (1 diagnostic emit only)
                 ──✗ ExploitGraph (NOT FED)
                 ──✗ CognitiveBridge (NOT USED)

LLM Bridge      ──► QualityScorer (score — BROKEN on stream path)
                 ──► ModelRouter (record_quality — MISSING on local paths)
                 ──► FeedbackLearningEngine (record_quality — MISSING on stream)
                 ──► CostTracker (record_usage — ALL PATHS OK)
                 ──► CanaryTokenValidator (check_leakage — 2 of 5 paths)
                 ──► HardRejectThreshold (enforce — 2 of 5 paths)
                 ──► MetricsCollector (PARTIAL coverage)

Decision Orch   ──► BayesianPrioritizer (score + record)
                 ──► AdaptiveTableLearner (7 tables, all bidirectional)
                 ──► HypothesisEngine (get_weight + signal_*)
                 ──► LookaheadEngine (lookahead_ev + record_outcome)
                 ──► SessionIntelligence (get_context + record_result)
                 ──► ExploitGraph + UAG (graph bonuses in scoring)
                 ──► StealthOrchestrator (heat penalty via event + polling)
                 ──► Atlas Nexus (get_bayesian_sync in scoring)
                 ──► WorldModel (counterfactual in scoring)
                 ──✗ GoalPlanner (DEAD BIND)
                 ──✗ CampaignPriorRegistry (DEAD BIND)
                 ──✗ CognitiveBridge (NOT WIRED)
                 ──✗ ToolLedger (NOT QUERIED)

LearningLoopEngine ──► Q-table (record + advise — TD disabled)
                    ──► ToolLedger (record_outcome)
                    ──► BayesianPrioritizer (train_on_session only)
                    ──✗ EventBus (bind_event_bus NEVER CALLED)

EventBus        ──► 63 event types defined
                 ──► ~20 actually emitted
                 ──► ~40+ dead enum members
                 ──► Dashboard bridge subscribes to goal/atlas/learning/security globs

ExploitGraph    ──► process_finding → graph.position.updated event
                 ──► process_finding_multihop → cascade chains
                 ──► suggest_next_tests → 5 callers (copilot_loop, DO, CLI)
                 ──✗ Autonomous loop (NOT FED)
                 ──✗ Arbitration results (NOT RECEIVED)

StealthOrchestrator ──► gate_tool → 4 callers (runner, exec_orch, MCP)
                     ──► emit stealth.heat_escalated → DO subscribes
                     ──✗ Autonomous loop (NOT CALLED)

MCP Server      ──► 134 tools, all wired to backends
                 ──► Rate limiting + schema validation + shell sanitization
                 ──✗ EventBus (NO DIRECT INTEGRATION)

LangGraph       ──► 3 runners, all with V6-23 atexit cleanup
                 ──► Reasoning subgraph connected to main graph
                 ──► Bounded state reducers (H-18)
                 ──► Real LLM inference with heuristic fallback
```

---

## Verification Notes

All 28 findings were cross-verified against actual source code to prevent false positives (lesson from V6 where 15/27 initial findings were false positives):

- **V7-1 verified:** `grep -r "bind_event_bus" *.py` across entire codebase confirms zero callers of LLE's method
- **V7-2 verified:** `grep "stealth\|gate_tool\|StealthOrch" autonomous_loop.py` returns only hardcoded placeholder
- **V7-3 verified:** `QualityScorer.score()` signature requires `LLMResponse` at L740, but L4325 passes `collected` (str), while `resp = LLMResponse(...)` is constructed at L4311 but not passed
- **V7-4 verified:** Only 4 grep hits for `event_bus|EventBus|\.emit\(` in autonomous_loop.py — all one location
- **V7-5 verified:** Dashboard bridge DOES subscribe to `"goal.*"` at event_bus.py L1768 (partially corrects DO subagent finding of "zero subscribers")
- **V7-7 clarified:** `sanitize_untrusted_text()` exists and is called by MCP callers, but bridge itself doesn't centrally enforce it
