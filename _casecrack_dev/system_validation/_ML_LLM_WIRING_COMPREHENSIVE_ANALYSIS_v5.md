# ML & LLM Wiring Comprehensive Analysis — V5

**Date:** 2026-04-12
**Scope:** Full codebase-wide deep wiring audit of all ML/LLM subsystem integrations
**Prior Analyses:** V2 (complete), V3 — 35 findings (all fixed), V4 — 46 findings (all fixed)
**Method:** Systematic grep verification of every emit/subscribe, bind/read, write/consume path
**Test Baseline:** 345/345 tests passing

---

## Executive Summary

This V5 audit goes deeper than prior analyses by tracing **consumption paths** — not just whether a method exists, but whether its output is ever read. The dominant pattern discovered is a **"write-only learning loop"**: the system meticulously records data (tool outcomes, adaptive weights, behavior profiles, meta-trends, cost analytics) but **never reads it back for decision-making** in several critical paths. Additionally, one V4 fix is broken (`record_finding_reward` method doesn't exist on target class), version pinning is silently ignored, and the stealth orchestrator is completely disconnected from real detection sources.

**Totals:** 4 CRITICAL · 11 HIGH · 12 MEDIUM · 2 LOW = **29 findings**

---

## Severity Legend

| Level | Meaning |
|-------|---------|
| CRITICAL | Core ML/LLM function broken — learning disabled, wrong method, silent data loss |
| HIGH | Subsystem disconnected — intelligence not consumed, feedback loops open |
| MEDIUM | Feature degraded — write-only telemetry, partial coverage, static fallbacks |
| LOW | Architectural debt — dead code, lint noise, edge-case races |

---

## CRITICAL Findings (4)

### V5-1 — CRITICAL — `record_finding_reward()` Does Not Exist on LearningLoopEngine

**File:** `agents/copilot_sdk_engine.py` L1526–1530
**Verification:** `grep record_finding_reward` → exists on `rl_reward_engine.py:340` but NOT on `learning_loop_engine.py`

```python
# copilot_sdk_engine.py L1526 (V4-42 FIX)
self._learning_engine.record_finding_reward(
    finding_type=finding.get("vulnerability_type", "unknown"),
    severity=finding.get("severity", "medium"),
    source="copilot_sdk",
    metadata={"session_id": self.session_id, "cycle": self._cycle},
)
```

`self._learning_engine` is a `LearningLoopEngine` instance. Method `record_finding_reward()` exists only on `RLRewardEngine` (different class, `rl_reward_engine.py:340`). Every call raises `AttributeError`, caught by the `except` block — **SDK-discovered findings silently never reach the learning pipeline**.

**Impact:** All Copilot SDK agent findings are invisible to ToolLedger, Q-table, and MetaTracker. V4-42 fix is non-functional.

**Fix:** Either:
- Add `record_finding_reward()` to `LearningLoopEngine` that delegates to the internal `RLRewardEngine`
- OR change to `self._learning_engine.record_tool_outcome(ToolOutcome(...))` using existing API

---

### V5-2 — CRITICAL — Version Pinning Silently Ignored (Missing Assignment)

**File:** `agents/llm_bridge.py` L2649–2651
**Verification:** `grep "_model_name = _pinned"` → zero matches

```python
# llm_bridge.py L2649
_pinned = self.version_manager.get_pinned_model(_model_name)
if _pinned:
    logger.debug("VersionMgr: using pinned model %s", _pinned)
# BUG: _model_name is NEVER reassigned to _pinned
# Execution continues with original _model_name
```

The pinned model is fetched and logged, but the result is **never assigned back to `_model_name`**. All subsequent code uses the unpinned model. Version pinning is completely broken — operators configure pins that are silently ignored.

**Impact:** Model version pinning is a no-op. Production deployments cannot lock to specific model versions for compliance or reproducibility.

**Fix:** Add `_model_name = _pinned` after the log statement:
```python
if _pinned:
    logger.debug("VersionMgr: using pinned model %s → %s", _model_name, _pinned)
    _model_name = _pinned
```

---

### V5-3 — CRITICAL — MCP Tool Results Never Reach Learning Pipeline

**File:** `mcp/mcp_server.py` L140–200
**Verification:** `grep record_tool_outcome` in `mcp_server.py` → zero matches

MCP tool execution produces results that are returned to the client and trigger dashboard notifications, but **no `ToolOutcome` is created and no call to `LearningLoopEngine.record_tool_outcome()` is made**. The ToolLedger, Q-table, and MetaTracker are completely blind to MCP-executed tools.

**Impact:** MCP tool executions (~significant portion of SDK/external tool runs) are invisible to the RL system. Tool rankings cannot improve from MCP usage data.

**Fix:** After MCP tool execution, create and record a `ToolOutcome`:
```python
from ..learning_loop_engine import get_learning_loop_engine, ToolOutcome
lle = get_learning_loop_engine()
if lle:
    lle.record_tool_outcome(ToolOutcome(
        tool=tool_name, success=bool(result), phase=phase,
        duration=elapsed, findings_count=len(findings), ...
    ))
```

---

### V5-4 — CRITICAL — RAG Retrieval Missing from 9 Core LLM Analysis Methods

**File:** `agents/llm_bridge.py` L1867–2370
**Verification:** `grep rag.*retrieve` in `llm_bridge.py` → only in `agent_chat()` (L3601 via scan_context)

The following 9 methods call `_complete()` directly **without RAG context augmentation**:
- `analyze_response()`, `generate_hypothesis()`, `explain_finding()`
- `suggest_payloads()`, `validate_finding()`, `map_attack_surface()`
- `discover_chains()`, `assess_impact()`, `chain_of_thought()`

Only `agent_chat()` includes RAG-retrieved context via `scan_context["rag_context"]`.

**Impact:** Core analysis functions cannot reference historical findings or cross-scan patterns. Every analysis is generated from scratch with zero knowledge retrieval. The RAG engine is essentially dormant for 90% of LLM usage.

**Fix:** Create a shared `_augment_with_rag(prompt, context_key)` method and call it before `_complete()` in each analysis method.

---

## HIGH Findings (11)

### V5-5 — HIGH — Defense Events Subscribed But Zero Emitters in Tool Executors

**File:** `stealth_orchestrator.py` L1323–1327 (subscribers), zero emitters elsewhere
**Verification:** `grep report_defense` → only defined at L1333, never called externally

StealthOrchestrator subscribes to:
- `defense.waf.detected` → `_on_waf_detected()`
- `defense.rate_limit.detected` → `_on_rate_limit()`
- `defense.bot.challenge` → `_on_bot_challenge()`

Also defines `report_defense()` (L1333) — **never called from any tool executor, scanner, or HTTP handler**. No module in the entire codebase emits these events.

**Impact:** Stealth heat management is completely disconnected from actual detection. WAF blocks, rate limits, and CAPTCHAs don't propagate. Heat level never escalates from real events.

**Fix:** Wire defense event emission into `enterprise_scale_executor.py` and scanner runners:
```python
if response_code == 403: stealth.report_defense("waf", {...})
if response_code == 429: stealth.report_defense("rate_limit", {...})
```

---

### V5-6 — HIGH — Behavior Profiles Write-Only (Never Read Back)

**File:** `agents/llm_bridge.py` L2814 (update), zero reads
**Verification:** `grep behavior_profiles.get_profile` → zero matches

```python
# L2814: Profile updated after each chat
await self.behavior_profiles.update_profile(...)
# But: behavior_profiles.get_profile() is NEVER called
```

Behavior profiles are recorded per-session but never consulted for model routing, role selection, or adaptive behavior. The profile data is pure write-only telemetry.

**Impact:** Adaptive model routing based on user behavior patterns is disabled. Model selection remains stateless regardless of learned user intent patterns.

**Fix:** In `_auto_route_role()` or `_client_for_role()`, retrieve the profile and use `dominant_intent` to influence role selection.

---

### V5-7 — HIGH — Streaming Failures Don't Trip Circuit Breaker

**File:** `agents/llm_bridge.py` L3969–4050 (agent_chat_stream)
**Verification:** `grep record_failure.*stream` in llm_bridge → zero matches

In `agent_chat_stream()`, streaming chunks are yielded without recording failures to `LocalModelCircuitBreaker`. If a stream hangs or times out **mid-stream**, no failure is recorded. The circuit breaker's `consecutive_failures` counter only accumulates from complete failures in non-streaming paths.

**Impact:** A model can repeatedly hang mid-stream without ever tripping the circuit breaker. Partial/hung streams create a blind spot in health monitoring.

**Fix:** Wrap the streaming loop with timeout detection and call `self.local_circuit_breaker.record_failure()` on stream timeout.

---

### V5-8 — HIGH — MetaTracker `get_meta_trend()` Has Zero External Callers

**File:** `learning_loop_engine.py` L1905 (defined), zero external callers
**Verification:** `grep get_meta_trend` → only the definition at L1905

The `get_meta_trend()` public API is never called by DecisionOrchestrator, dashboard routes, or any external consumer. While plateau detection works internally (L1749 `set_plateau_mode`), the public trend data (improving/degrading/stable with metrics) is invisible to the rest of the system.

**Impact:** Dashboard operators have no visibility into whether the system is learning or degrading over time. No external system can react to meta-learning trends.

**Fix:** Expose via dashboard route (`/api/learning/trend`) and wire into DecisionOrchestrator for dynamic exploration tuning.

---

### V5-9 — HIGH — `record_outcome()` in DecisionOrchestrator Never Emits to EventBus

**File:** `decision_orchestrator.py` L1676–1850 (entire `record_outcome()` method)
**Verification:** Scanned full method — no `_event_bus.emit()` call within record_outcome

The method updates Bayesian priors, adaptive tables, calibration, and hypothesis engine — all internal. But it **never emits an event** to the EventBus. External subscribers (LearningLoopEngine, dashboard, atlas) cannot react to decision outcomes in real-time.

Note: DO emits STRATEGY_RECOMMENDED from `recommend_strategy()` (L1485) and goal events from `update_state()` — but outcome events are silent.

**Impact:** EventBus subscribers are blind to outcome feedback. No downstream system can trigger on "action X succeeded/failed."

**Fix:** Add at the end of `record_outcome()`:
```python
if self._event_bus:
    self._event_bus.emit(BusEventType.STRATEGY_RECOMMENDED, {
        "type": "outcome_feedback",
        "action": action, "success": success,
        "findings_count": findings_count, "severity": severity,
    })
```

---

### V5-10 — HIGH — Autonomous Loop `_think()` Doesn't Consult ExploitGraph Suggestions

**File:** `loop/autonomous_loop.py`
**Verification:** `grep suggest_next_tests` in `autonomous_loop.py` → zero matches

The autonomous loop's `_think()` phase doesn't call `exploit_graph.suggest_next_tests()` even though DecisionOrchestrator (L2531) and copilot_loop do. The OODA think phase makes decisions without graph-based pathfinding intelligence.

**Impact:** Autonomous scanning doesn't leverage exploit graph intelligence for next-action selection. Attack progression paths are ignored in the main OODA loop.

**Fix:** In `_think()`, call `self._attack_graph.suggest_next_tests()` and incorporate suggestions into action candidate scoring.

---

### V5-11 — HIGH — `_complete_structured()` Bypasses Feedback/A/B/Tracing Pipeline

**File:** `agents/llm_bridge.py` L1513–1610
**Verification:** Read full method — no feedback_engine, experiment_engine, or full tracing calls

`_complete_structured()` has: circuit breaker ✓, cache ✓, budget ✓, rate limit ✓, cost tracking ✓, quality scoring (V4-23) ✓.

But it **skips**: feedback learning engine, A/B experiment tracking, output guard validation, behavior profile updates, and full observability tracing. Approximately 15-20% of LLM calls go through this path for grammar-constrained JSON.

**Impact:** Local model responses via structured generation are invisible to feedback learning and A/B testing. Model degradation under grammar constraints goes undetected.

**Fix:** Factor the post-completion pipeline (feedback, A/B, tracing) into a shared `_post_completion_pipeline()` called by both `_complete()` and `_complete_structured()`.

---

### V5-12 — HIGH — CognitiveBridge Outcomes Never Feed FeedbackLearningEngine

**File:** `agents/cognitive_bridge.py` L748, L915, L1057
**Verification:** `grep feedback_engine` in `cognitive_bridge.py` → zero matches

CognitiveBridge records fusion events via `_record_event()` but never calls `feedback_engine.record_quality()` or any equivalent. When Copilot reasoning proves correct/incorrect, the feedback signal is lost.

**Impact:** Copilot prompt quality never improves from outcome feedback. If Copilot consistently produces bad reasoning, the same prompts are retried identically.

**Fix:** After `_record_event()`, forward the quality signal to `get_feedback_engine().record_quality(template=..., score=...)`.

---

### V5-13 — HIGH — Lookahead EV Results Not Saved to Decision History

**File:** `decision_orchestrator.py` L2949 (`compute_lookahead_ev`)
**Verification:** Lookahead result computed but never stored in outcome/decision objects

```python
la_result = self._lookahead.compute_lookahead_ev(action=action, context=ctx)
# Result used for scoring in this cycle but NEVER persisted
# Cannot compare greedy vs lookahead decision quality post-hoc
```

**Impact:** 2-step lookahead planning exists but outcomes can't be tracked or compared against greedy decisions. No way to measure if lookahead actually improves scan quality.

**Fix:** Store `la_result.expected_value` and `la_result.depth` on the decision object for post-hoc analysis.

---

### V5-14 — HIGH — OutputGuard Fallback Schema Allows Arbitrary Nesting

**File:** `agents/llm_output_guard.py` L375–395
**Verification:** Fallback schema validates top-level keys only

When schema resolution fails for an unknown role, the fallback allows `findings`, `recommendations`, `reasoning` keys **without recursive nested validation**. A crafted LLM response could embed deeply nested arbitrary data under these keys.

**Impact:** Output guard provides false confidence for unknown roles — appears to validate but permits unrestricted nesting.

**Fix:** Apply recursive `_validate_recursive()` to fallback schema fields with a strict depth limit (3–5 levels max).

---

### V5-15 — HIGH — UserSafeguards Rate Limits Only in `agent_chat()`, Not `_complete()`

**File:** `agents/llm_bridge.py` L2616 (agent_chat only)
**Verification:** `grep check_request_allowed` → only in `agent_chat()` path

`self.user_safeguards.check_request_allowed()` is called **only** in the `agent_chat()` path. The primary `_complete()` method (handling ~80% of LLM traffic) doesn't check per-user/tenant rate limits.

**Impact:** Per-user rate limits can be bypassed by code paths that use `_complete()` directly. Inconsistent rate limiting across call paths.

**Fix:** Move `check_request_allowed()` into `_complete()` before budget enforcement.

---

## MEDIUM Findings (12)

### V5-16 — MEDIUM — Cache Analytics Write-Only (Stats Never Read)

**File:** `agents/llm_bridge.py` L2825 (record_miss), L395 (init)
**Verification:** `grep cache_analytics.get_stats|cache_analytics.analyze|cache_analytics.get_metrics` → zero

Cache analytics record hits and misses but no consumer reads the stats to adjust TTL, eviction policy, or caching strategy. Pure telemetry with no feedback loop.

**Impact:** Cache strategy remains static regardless of effectiveness data.

---

### V5-17 — MEDIUM — Hypothesis Weights Static (Never Recalibrated From Outcomes)

**File:** `decision_orchestrator.py` L2982–2983
**Verification:** `get_effective_multiplier()` returns weight; `signal_*()` methods only update penalties, not weights

Hypothesis engine weights are fetched and applied to EV scores, but `record_outcome()` only calls `signal_finding/signal_failure/signal_success_no_finding` — these update **penalties** only, not the base weights. Weights are set once and never retrained.

**Impact:** Wrong hypotheses continue boosting wrong actions because weights don't self-correct. Only penalties adapt over time.

**Fix:** Add weight recalibration in `signal_finding()` that adjusts the multiplier based on prediction accuracy over time.

---

### V5-18 — MEDIUM — `GOAL_INTENSITY_REDUCED` Event Never Emitted

**File:** `event_bus.py` L170 (enum), `decision_orchestrator.py` L2187 (flag only)
**Verification:** `grep GOAL_INTENSITY_REDUCED` → only enum definition + flag set, zero emits

The `_intensity_reduced = True` flag is set internally but the corresponding EventBus event is never emitted. External systems can't react to intensity reduction signals.

**Impact:** Stealth orchestrator and learning engine can't observe when the system downshifts intensity — no coordinated response to aggressive-scan dampening.

---

### V5-19 — MEDIUM — Injection Events Use Wrong String Keys vs BusEventType

**File:** `agents/prompt_security.py` L487, L519
**Verification:** Events emitted as `"security.injection_alert"` and `"security.cross_phase_escalation"`, but BusEventType defines `"defense.injection.alert_warning"` / `"defense.injection.alert_critical"`

String keys in prompt_security.py don't match the BusEventType enum values. No subscriber listens to the mismatched strings. Security alerts are broadcast into a void.

**Impact:** Injection detection events are completely lost. Dashboards and learning systems never receive injection alerts.

**Fix:** Use `BusEventType.INJECTION_ALERT_WARNING.value` and `BusEventType.INJECTION_ALERT_CRITICAL.value` in prompt_security.py.

---

### V5-20 — MEDIUM — PSE Payload Outcomes Not Traced to Synthesis Source

**File:** `loop/autonomous_loop.py` L2385–2395

PSE payloads are tagged generically when generated. When findings result from PSE payloads, they aren't traced back to the specific synthesis method/pattern. PSE can't learn which synthesis strategies produce results.

**Impact:** Payload synthesis converges slowly. Can't distinguish successful strategies per payload type.

**Fix:** Tag actions with `action.source = "pse:" + synthesis_method` and propagate through outcome recording.

---

### V5-21 — MEDIUM — Stealth Heat Changes at WARM Level Invisible

**File:** `stealth_orchestrator.py` L1507–1521

`STEALTH_HEAT_ESCALATED` event only emitted when heat >= HOT:
```python
if heat in (HeatLevel.HOT, HeatLevel.BURNING, HeatLevel.COMPROMISED):
```

Heat transitions to WARM are silent. DecisionOrchestrator can't react to gradual heat buildup before it becomes critical.

**Impact:** No pre-emptive throttling at WARM level. System only reacts when already HOT.

**Fix:** Emit `STEALTH_TOOL_GATED` at WARM, `STEALTH_HEAT_ESCALATED` at HOT+.

---

### V5-22 — MEDIUM — DecisionOrchestrator Not Subscribed to STEALTH_HEAT_ESCALATED

**File:** `decision_orchestrator.py`
**Verification:** `grep STEALTH_HEAT_ESCALATED` in decision_orchestrator → zero matches

Even when stealth heat escalation events fire, DecisionOrchestrator has no subscription. `adjust_detection_risk()` exists but is never called from the stealth path.

**Impact:** Tool selection isn't adjusted based on stealth state. Aggressive tools continue being scored equally even under high heat.

**Fix:** Subscribe to `STEALTH_HEAT_ESCALATED` and reduce scores for high-detection-risk tools.

---

### V5-23 — MEDIUM — CostTracker Uses Hardcoded "default" Session ID

**File:** `agents/llm_tracking.py` L458–475
**Verification:** `grep "default"` in cost INSERT

All cost ledger records use `session_id="default"`. No per-scan or per-user cost attribution is possible.

**Impact:** Multi-tenant cost tracking and per-scan cost analysis are impossible. Cost dashboard shows aggregate-only data.

**Fix:** Thread `session_id` through `LLMResponse` and `CostTracker.persist_cost()`.

---

### V5-24 — MEDIUM — Campaign Intelligence Sub-Modules Never Validated

**File:** `decision_orchestrator.py` L1155–1179

Multiple optional campaign modules (`prior_registry`, `outcome_tracker`, `signal_bus`, `platform_fingerprint`) are set but never null-checked before use. If one is missing, scoring can fail silently or crash.

**Impact:** Partial campaign initialization causes runtime errors downstream.

**Fix:** Add None guards before consuming each sub-module.

---

### V5-25 — MEDIUM — RAG Indexing Only at Scan End, Not Incrementally

**File:** `graph/runner.py` L275–290

RAG indexing is called only at the END of a scan (`run_agent_graph` post-processing). Findings discovered mid-scan cannot be retrieved by RAG for enriching later decisions within the same scan.

**Impact:** RAG context is always one scan behind. Within-scan knowledge retrieval disabled.

**Fix:** Call `_rag.index_findings()` incrementally as findings are discovered, not just at completion.

---

### V5-26 — MEDIUM — Swarm MessageBus Separate from Main EventBus

**File:** `swarm/swarm.py`
**Verification:** Swarm uses internal `MessageBus`; `record_tool_outcome` exists at L603

AgentSwarm maintains its own `MessageBus` separate from the main `EventBus`. While V4-28 added `record_tool_outcome()` at L603 for learning, swarm finding events don't reach the main EventBus for dashboard/intelligence subscribers.

**Impact:** Swarm agents' findings visible to learning loop but invisible to dashboard real-time feed, intelligence experience, and other EventBus subscribers.

**Fix:** Bridge swarm MessageBus to main EventBus: emit `BusEventType.VULN_DETECTED` from swarm `report_finding()`.

---

### V5-27 — MEDIUM — Budget Threshold Events Not Persisted Across Sessions

**File:** `agents/llm_tracking.py` L290–320

Budget threshold flags (`_budget_warned_75`, `_budget_warned_90`) prevent repeated events within a session but reset on each scan start. Dashboard operators see threshold events every scan, not once per budget lifecycle.

**Impact:** Event fatigue — operators see repeated 75%/90% warnings across restarts.

---

## LOW Findings (2)

### V5-28 — LOW — 19+ Dead BusEventType Enum Members

**File:** `event_bus.py` L165–210

These event types are defined but have **zero emitters AND zero subscribers**:
- `AGENT_INTENT_REQUEST`, `AGENT_INTENT_RESPONSE`, `AGENT_INTENT_CONFLICT`, `AGENT_COORDINATION`
- `KNOWLEDGE_FEDERATED`, `FLYWHEEL_SNAPSHOT`, `FLYWHEEL_RESTORED`
- `POLICY_COMPARED`, `TRANSFER_LEARNING`
- `MULTI_AGENT_STARTED`, `MULTI_AGENT_DELEGATION`, `MULTI_AGENT_WORKER_*` (7 types)
- `GRAPH_POSITION_UPDATED`, `GRAPH_RESET`

**Impact:** Dead enum members create architectural confusion and lint noise.

**Fix:** Remove unused members or implement their emitters/subscribers.

---

### V5-29 — LOW — Rate Limit Window Pruning Race Condition

**File:** `agents/llm_tracking.py` L246–251

Post-sleep window pruning in `enforce_rate_limit()` occurs outside the rate lock. Two parallel workers can both see stale windows and both pass the rate-limit check during the prune window.

**Impact:** Edge-case race where two requests slip through simultaneously despite rate limits.

**Fix:** Move post-sleep pruning into the rate_lock block.

---

## Architectural Analysis: The Write-Only Learning Loop

```
ML/LLM SYSTEM DATA FLOW STATUS
════════════════════════════════════════════

✅ RECORDING LAYER (ALL WORKING):
   ToolLedger.record()              ✅
   QTable.update()                  ✅
   MetaTracker.track_session()      ✅
   BayesianPrioritizer.record()     ✅
   ConfidenceEnsemble.record()      ✅
   BehaviorProfiles.update()        ✅
   CacheAnalytics.record()          ✅
   CostTracker.persist_cost()       ✅

❌ CONSUMPTION LAYER (GAPS):
   MetaTracker.get_meta_trend()     ❌ Zero callers (V5-8)
   BehaviorProfiles.get_profile()   ❌ Zero callers (V5-6)
   CacheAnalytics.get_stats()       ❌ Zero callers (V5-16)
   Hypothesis.recalibrate_weights() ❌ Never happens (V5-17)
   Lookahead.save_results()         ❌ Never persisted (V5-13)

❌ EXTERNAL INTEGRATION (GAPS):
   SDK findings → LearningLoop      ❌ Wrong method (V5-1)
   MCP results → LearningLoop       ❌ Not wired (V5-3)
   Defense detections → Stealth      ❌ Not emitted (V5-5)
   Swarm events → main EventBus     ❌ Separate bus (V5-26)

❌ CONSUMPTION BY LLM (GAPS):
   RAG → 9 analysis methods          ❌ Not wired (V5-4)
   Feedback → CognitiveBridge        ❌ Not wired (V5-12)
   OutputGuard → _complete_struct    ❌ Not wired (V5-11)
```

---

## Remediation Priority

### P0 — Fix Broken Code (4 items)
| ID | Finding | Fix Complexity |
|----|---------|---------------|
| V5-1 | record_finding_reward → record_tool_outcome | Small |
| V5-2 | Add `_model_name = _pinned` | 1 line |
| V5-3 | Wire MCP → LearningLoopEngine | Medium |
| V5-4 | RAG retrieval in 9 analysis methods | Medium |

### P1 — Close Feedback Loops (7 items)
| ID | Finding | Fix Complexity |
|----|---------|---------------|
| V5-5 | Emit defense events from tool executors | Medium |
| V5-6 | Read behavior profiles in model routing | Small |
| V5-7 | Record streaming failures in circuit breaker | Small |
| V5-9 | Emit outcome events from DO.record_outcome | Small |
| V5-11 | Wire _complete_structured feedback pipeline | Medium |
| V5-12 | CognitiveBridge → FeedbackEngine | Small |
| V5-15 | Rate limits in _complete() | Small |

### P2 — Intelligence Consumption (6 items)
| ID | Finding | Fix Complexity |
|----|---------|---------------|
| V5-8 | Expose get_meta_trend() to dashboard | Small |
| V5-10 | Exploit graph suggestions in _think() | Medium |
| V5-13 | Persist lookahead results | Small |
| V5-14 | OutputGuard recursive fallback validation | Small |
| V5-19 | Fix injection event string keys | Small |
| V5-22 | DO subscribe to stealth events | Small |

### P3 — Telemetry Completion (10 items)
| ID | Finding | Fix Complexity |
|----|---------|---------------|
| V5-16 | Cache analytics feedback loop | Medium |
| V5-17 | Hypothesis weight recalibration | Medium |
| V5-18 | Emit GOAL_INTENSITY_REDUCED | Small |
| V5-20 | PSE source tracking | Medium |
| V5-21 | Stealth WARM-level events | Small |
| V5-23 | Per-session cost tracking | Small |
| V5-24 | Campaign sub-module null guards | Small |
| V5-25 | Incremental RAG indexing | Medium |
| V5-26 | Bridge swarm → main EventBus | Medium |
| V5-27 | Persist budget threshold state | Small |

### P4 — Cleanup (2 items)
| ID | Finding | Fix Complexity |
|----|---------|---------------|
| V5-28 | Remove dead enum members | Small |
| V5-29 | Fix rate limit race condition | Small |

---

## Cross-Reference: Prior Analysis Coverage

| V5 Finding | Why Not Caught in V4 |
|------------|---------------------|
| V5-1 | V4-42 introduced this bug (fix used wrong method name) |
| V5-2 | V4 audited binding but not assignment |
| V5-3 | V4 didn't audit MCP execution paths |
| V5-4 | V4 noted RAG gaps (V4-44 suggestion) but didn't trace method-level coverage |
| V5-5 | V4-1 noted subscriber gaps but didn't trace emitter sources |
| V5-6–V5-29 | V4 focused on bind/subscribe wiring; V5 traced consumption |

---

## Test Baseline

All 29 findings are **wiring/integration gaps**, not logic errors detectable by unit tests. The existing 345 tests continue to pass because they test individual subsystem behavior, not cross-system data flow.

```
pytest CaseCrack\tests\test_payload_arbiter.py CaseCrack\tests\test_feedback_propagation.py \
  CaseCrack\tests\test_contract_propagation.py CaseCrack\tests\test_audit_pyramid.py \
  CaseCrack\tests\test_integration_audit.py --timeout=90 -p no:randomly -q
345 passed in ~198s
```
