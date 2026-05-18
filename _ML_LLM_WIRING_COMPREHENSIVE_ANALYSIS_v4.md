# ML / LLM Wiring — Comprehensive Analysis V4

**Scope:** `CaseCrack/tools/burp_enterprise/event_bus.py`, `decision_orchestrator.py`, `learning_loop_engine.py`  
**Date:** 2026-04-12  
**Excludes:** All items N-1 through N-35 (V3), all V2 items

---

## FOCUS AREA 1: Event Bus Wiring (`event_bus.py`)

### V4-1 — CRITICAL — 50+ BusEventType enum values have ZERO subscribers in production code

**Lines:** event_bus.py L80–200 (BusEventType definition)

The `BusEventType` enum defines **~80 event types**. A codebase-wide grep for `bus.on(` / `_bus.on(` reveals the **complete subscriber map**:

| Subscriber Module | Events Subscribed |
|---|---|
| `DashboardBridge` (event_bus.py L1733–1758) | `SCAN_PROGRESS`, `SCAN_COMPLETE`, `SCAN_STARTED`, `SCAN_FAILED`, `recon.vuln.*`, `recon.secret.*`, `recon.error.*`, `module.*` |
| `resilience_wiring.py` (L110–114) | `SCAN_STARTED`, `SCAN_COMPLETE`, `SCAN_FAILED`, `VULN_DETECTED`, `VULN_CONFIRMED` |
| `exploit_graph.py` (L1682–1687) | `VULN_DETECTED`, `VULN_CONFIRMED`, `VULN_EXPLOITED`, `SUBDOMAIN_DISCOVERED`, `ENDPOINT_DISCOVERED`, `SECRET_FOUND` |
| `scan_intelligence.py` (L2226–2271) | `recon.vuln.*`, `recon.tech.*`, `recon.secret.*`, `recon.subdomain.*`, `recon.endpoint.*`, `module.*`, `recon.scan.*`, + 4 more |
| `stealth_orchestrator.py` (L1323–1327) | `defense.waf.detected`, `defense.rate_limit.detected`, `defense.bot.challenge`, `system.rate_limited`, `system.error` |
| `chain_execution_loop.py` (L699) | `recon.vuln.detected` |
| `attack_strategy_engine.py` (L570) | `recon.vuln.detected` |
| `event_bridge.py` (L141) | `*` (wildcard — recon dashboard bridge) |
| `IntentNegotiationProtocol` (event_bus.py L2077–2080) | `AGENT_INTENT_REQUEST`, `AGENT_INTENT_RESPONSE` |
| `atlas_nexus.py` (L214) | `GRAPH_TRANSITION_CONFIRMED` — via `_emit_event`, not `bus.on` |

**The following event type categories have ZERO production subscribers:**

- **STEALTH_***: `STEALTH_HEAT_ESCALATED`, `STEALTH_TOOL_GATED`, `STEALTH_TOOL_SUBSTITUTED` — defined but no module subscribes. The stealth_orchestrator *emits* to `defense.*` events but nobody listens to `stealth.*` events.
- **GOAL_***: `GOAL_ACHIEVED`, `GOAL_PROGRESS`, `GOAL_INTENSITY_REDUCED` — emitted by DecisionOrchestrator (L2180, L2205) but **zero subscribers**. Goal state changes are broadcast into the void.
- **STRATEGY_***: `STRATEGY_SIMULATED`, `STRATEGY_COMPARED` — defined, never emitted. `STRATEGY_RECOMMENDED` emitted by DecisionOrchestrator (L1495) but no subscriber.
- **KNOWLEDGE_***: `KNOWLEDGE_FEDERATED`, `FLYWHEEL_SNAPSHOT`, `FLYWHEEL_RESTORED`, `POLICY_COMPARED`, `TRANSFER_LEARNING` — all 5 defined, **zero emitters** and **zero subscribers**. Completely dead.
- **MULTI_AGENT_***: All 10 types (`MULTI_AGENT_STARTED` through `MULTI_AGENT_RESUMED`) — **zero emitters** and **zero subscribers** in production.
- **LLM Defense**: `INJECTION_DETECTED`, `INJECTION_ALERT_WARNING`, `INJECTION_ALERT_CRITICAL`, `INJECTION_HARD_BLOCKED`, `LLM_QUALITY_REJECTED` — all defined via BusEventType enum but **prompt_security.py emits `security.injection_alert`** (a string, not a BusEventType). The enum values are never used.
- **ATLAS_***: `ATLAS_ARCHETYPE_MATCHED`, `ATLAS_HEALTH_DEGRADED` — defined but never emitted. `ATLAS_PATTERN_UPDATED` and `ATLAS_LEARNING_COMPLETE` are emitted by atlas_nexus.py via `_emit_event()` but nobody subscribes to them.
- **GRAPH_***: `GRAPH_STATE_CHANGED`, `GRAPH_POSITION_UPDATED`, `GRAPH_RESET` — defined, never emitted. Only `GRAPH_TRANSITION_CONFIRMED` has an emitter+subscriber pair (atlas_nexus).
- **Misc dead**: `SCAN_PAUSED`, `SCAN_RESUMED`, `SCAN_CANCELLED`, `WARNING_ISSUED`, `JUICY_FILE_FOUND`, `ERROR_PATTERN_FOUND`, `DIRECTORY_FOUND`, `DNS_RECORD_FOUND`, `PORT_DISCOVERED`, `SERVICE_DETECTED` — defined, no confirmed emitters or subscribers.

**Impact:** ~50 of ~80 event types are permanently dead wiring. Intelligence signals (goal achievement, stealth state, AtlAS patterns, multi-agent coordination, knowledge federation) are never delivered to any consumer. This means:
- Goal achievement doesn't propagate to other subsystems
- Stealth state changes are invisible to ML layers  
- Atlas learning events go unheard by the decision engine
- Multi-agent coordination is entirely non-functional at the event layer

**Fix:** Either wire subscribers for critical events (GOAL_*, STEALTH_*, ATLAS_*) into DecisionOrchestrator/LearningLoopEngine, or remove dead enum values to prevent confusion.

---

### V4-2 — HIGH — `prompt_security.py` emits string events that bypass typed BusEventType enum

**Lines:** prompt_security.py L487, L519; event_bus.py L196–200

`prompt_security.py` emits:
```python
get_event_bus().emit("security.injection_alert", {...})
get_event_bus().emit("security.cross_phase_escalation", {...})
```

But the BusEventType enum defines:
```python
INJECTION_DETECTED = "defense.injection.detected"
INJECTION_ALERT_WARNING = "defense.injection.alert_warning"
INJECTION_ALERT_CRITICAL = "defense.injection.alert_critical"
```

The emitted string keys (`security.injection_alert`) **don't match** the enum values (`defense.injection.*`). No subscriber listens to either pattern. Injection detection events are completely lost.

**Fix:** Use `BusEventType.INJECTION_ALERT_WARNING.value` in prompt_security.py, and wire a subscriber in stealth_orchestrator or DecisionOrchestrator.

---

### V4-3 — MEDIUM — `resource_monitor.py` emits raw string `"RESOURCE_SNAPSHOT"` incompatible with dotted naming convention

**Line:** resource_monitor.py L415

```python
bus.emit("RESOURCE_SNAPSHOT", snap.to_dict())
```

All other event types use dotted `domain.entity.action` naming. `"RESOURCE_SNAPSHOT"` matches no glob pattern and no subscriber. Dead emit.

---

### V4-4 — MEDIUM — `recon_pipeline.py` emits `"recon.pipeline.started"` and `"recon.pipeline.completed"` — no matching BusEventType and no subscriber

**Lines:** recon_pipeline.py L534, L598

These string events don't correspond to any BusEventType enum member. The `recon.scan.*` glob in scan_intelligence would NOT match `recon.pipeline.*`. No subscriber consumes pipeline lifecycle events.

---

## FOCUS AREA 2: Decision Orchestrator Complete Audit (`decision_orchestrator.py`)

### V4-5 — HIGH — Duplicate initialization of `_outcome_buffer` and `_last_recommendations` in `__init__`

**Lines:** decision_orchestrator.py L1005–1018

```python
# First occurrence:
self._outcome_buffer: deque[dict[str, Any]] = deque(maxlen=200)
self._last_recommendations: list[RankedDecision] = []

# Exact duplicate 6 lines later:
self._outcome_buffer: deque[dict[str, Any]] = deque(maxlen=200)
self._last_recommendations: list[RankedDecision] = []
```

Both the N-14 outcome buffer and N-15 stale recommendation cache are declared twice with identical comments. The second assignment overwrites the first. Not a runtime bug (both are identical), but indicates a copy-paste error and masks future divergence if one is updated without the other.

**Fix:** Delete the duplicate block (lines ~1011–1018).

---

### V4-6 — HIGH — `_reasoning_engine` is bound but NEVER queried by `_score_action` or any scoring method

**Lines:** decision_orchestrator.py L993, L1107–1109, L3541

`bind_reasoning_engine()` stores the engine at L1109:
```python
def bind_reasoning_engine(self, engine: Any) -> None:
    self._reasoning_engine = engine
```

The only other references to `self._reasoning_engine` are:
1. L993: Declaration `self._reasoning_engine: Any = None`
2. L3541: `get_metrics()` reports whether it's bound: `"reasoning_engine": self._reasoning_engine is not None`

**Zero reads in `_score_action`, `_estimate_p_success`, `recommend_actions`, `record_outcome`, or any scoring/feedback path.** The reasoning engine is wired in but its intelligence is never consulted.

Note: `_estimate_p_success` (L3113) imports `TECH_VULN_PROBABILITY` from `reasoning_engine` as a **module-level constant**, not via the bound instance. The bound `_reasoning_engine` object is entirely unused.

**Fix:** Either use `self._reasoning_engine.score()` / `self._reasoning_engine.get_recommendations()` in `_score_action`, or remove the dead binding to avoid false metrics.

---

### V4-7 — MEDIUM — `'_action_lower' in dir()` is a fragile scoping guard in `_score_action`

**Line:** decision_orchestrator.py L2919

```python
_action_lower = _action_lower if '_action_lower' in dir() else action.lower()
```

`dir()` inside a function returns the **module-level** namespace, not local variables. If signal 11 (TMM boost, L2896) succeeds, `_action_lower` is a local variable defined inside the `try` block. If it fails, `_action_lower` doesn't exist. The `'_action_lower' in dir()` check does NOT reliably detect whether the local variable exists — `dir()` returns module globals + builtins, not function locals.

In CPython, this works by accident because the variable is in scope as long as it was assigned anywhere in the function (Python's function-level scoping). But this is fragile and confusing.

**Fix:** Define `_action_lower = action.lower()` once at the top of `_score_action` (before signal 11), and remove the `dir()` guard.

---

### V4-8 — MEDIUM — `GOAL_ACHIEVED`, `GOAL_PROGRESS` events emitted but have zero subscribers

**Lines:** decision_orchestrator.py L2179–2211

`_evaluate_goal_progress()` emits `"goal.progress"` and `"goal.achieved"` via `self._event_bus.emit(...)`. As confirmed in V4-1, **no module subscribes** to these events. Goal achievement broadcasts are silently discarded.

Consequence: Other subsystems (LearningLoopEngine, StealthOrchestrator, AtlasNexus) that could benefit from knowing when a goal is achieved never receive this signal.

---

### V4-9 — MEDIUM — `STRATEGY_RECOMMENDED` emitted but zero subscribers

**Line:** decision_orchestrator.py L1494–1499

When `recommend_strategy()` determines a recommended strategy, it emits `BusEventType.STRATEGY_RECOMMENDED` via the event bus. No module subscribes to `strategy.recommended`. The strategic recommendation is broadcast but never consumed.

---

### V4-10 — LOW — `_GOAL_PHASE_RELEVANCE` declares explicit `"full_compromise"` set but `_is_phase_goal_irrelevant` still has a `None` fallback

**Lines:** decision_orchestrator.py L3449–3480, L3482–3489

The V11-L5 FIX comment explains that an explicit `full_compromise` entry was added. But `_is_phase_goal_irrelevant` still checks `if relevant is None: return False`. Since `full_compromise` is now in the dict, this `None` guard only fires for goal modes not in the dict at all (e.g. typos). The fallback is harmless but misleading — a warning log would be more appropriate for unknown goal modes.

---

### V4-11 — LOW — `goal.achieved` event uses inline dynamic Enum construction for priority

**Line:** decision_orchestrator.py L2210

```python
priority=__import__("enum").IntEnum("P", {"C": 1})(1),
```

This creates a throwaway `IntEnum` class at every emit to pass priority=CRITICAL. This is an anti-pattern — it should use `EventPriority.CRITICAL` from event_bus.

---

## FOCUS AREA 3: Learning Loop Engine Complete Audit (`learning_loop_engine.py`)

### V4-12 — CRITICAL — `get_learning_loop_engine()` factory accesses `_engine_instance.ledger` but attribute is `_engine_instance._ledger`

**Line:** learning_loop_engine.py L1945

```python
tool_ranking = _engine_instance.ledger.get_tool_ranking()
```

The `LearningLoopEngine` class stores its ledger as `self._ledger` (private, L1472). The factory function accesses `.ledger` (no underscore). This raises `AttributeError` at runtime when the OPP-8 ConfidenceEnsemble historical feed attempts to read tool rankings.

Because this is inside a `try/except Exception`, the error is silently swallowed:
```python
except Exception as exc:
    logger.debug("I-6: ConfidenceEnsemble historical feed failed: %s", exc)
```

**Impact:** Every time the LearningLoopEngine singleton is created, the ConfidenceEnsemble NEVER receives historical tool rankings. The confidence ensemble starts cold every session.

**Fix:** Change `_engine_instance.ledger` → `_engine_instance._ledger` at L1945.

---

### V4-13 — HIGH — `StrategyEvolver.evolve_exploitation_paths()` is dead code — zero callers

**Line:** learning_loop_engine.py L1011–1017

```python
def evolve_exploitation_paths(
    self,
    q_table: QTablePersistence,
    available_paths: list[str],
) -> list[tuple[str, float]]:
    """Rank exploitation paths by Q-value from persistent Q-table."""
    return q_table.get_action_ranking("exploit", available_paths)
```

A codebase-wide search for `evolve_exploitation_paths(` returns exactly **one hit** — the definition itself. No module calls this method. The exploitation path ranking feature is defined but never integrated.

Meanwhile, `evolve_tool_rankings()` (the sibling method) IS called in 3 places. `evolve_exploitation_paths` appears to be a planned feature that was never wired.

---

### V4-14 — HIGH — `SessionEpochTrainer` uses `self._ledger` but is constructed with a `ledger` parameter that's stored differently

**Lines:** learning_loop_engine.py L1216, L1269, L1335

The `SessionEpochTrainer.__init__` stores:
```python
self._ledger = ledger
```

This is fine internally. But the `LearningLoopEngine` constructs the trainer at L1478:
```python
self._trainer = SessionEpochTrainer(
    self._ledger, self._q_table, self._meta, self._evolver, ...
)
```

If `LearningLoopEngine.start_new_session()` (L1500–1510) recreates `self._ledger` (L1504), the trainer still holds a reference to the **old** ledger:
```python
self._ledger = ToolLedger(persist_path=base / "tool_ledger.json")
...
self._trainer = SessionEpochTrainer(
    self._ledger, self._q_table, self._meta, self._evolver, ...
)
```

The trainer IS recreated too (L1508), so this is not currently a bug. But the pattern is fragile — if `start_new_session` is refactored to reuse the trainer, stale ledger references would cause data loss.

**Severity downgrade to MEDIUM** since both are recreated together.

---

### V4-15 — MEDIUM — `_sync_q_to_rl()` bidirectional sync may cause infinite feedback loops

**Lines:** learning_loop_engine.py ~L1760–1795

```python
def _sync_q_to_rl(self) -> None:
    # Direction 1: Q-table → RL engine
    ...
    # Direction 2: RL engine → Q-table
    ...
```

This method synchronises Q-values bidirectionally between `QTablePersistence` and the RL engine. If called repeatedly (e.g., in successive `train_end_of_session` calls), values from the RL engine get written into Q-tables, then on the next sync those Q-values are read back and fed into the RL engine again. Without decay or dampening between syncs, values can amplify over sessions.

The Q-table does apply a `_decay_factor` on load, which partially mitigates this — but the RL engine side has no equivalent decay during the sync-back direction.

---

### V4-16 — MEDIUM — `MetaTracker.detect_trend()` output is logged but never consumed by any decision

**Lines:** learning_loop_engine.py L1075–1120 (MetaTracker), L1371 (called in train_end_of_session)

`MetaTracker.detect_trend()` returns `"improving"`, `"degrading"`, or `"stable"` based on recent session performance. The result is stored in the training result dict:
```python
result["meta_trend"] = self._meta.detect_trend()
```

But no module reads this trend to adjust behavior. DecisionOrchestrator never queries MetaTracker. The self-improvement detection system detects trends but takes no action on them.

---

### V4-17 — MEDIUM — `LearningLoopEngine.bind_bayesian()` stores reference but `_trainer` doesn't use it for posterior updates

**Line:** learning_loop_engine.py L1524

```python
def bind_bayesian(self, bayesian: Any) -> None:
    self._bayesian = bayesian
```

`self._bayesian` is stored but the `SessionEpochTrainer.train_on_session()` step 4 does its own Bayesian update via a separately-passed `bayesian` parameter (L1300–1310). The `bind_bayesian` reference on the engine itself is only used at L1800–1805 for `get_tool_recommendations` context. The two Bayesian references could diverge if different instances are passed.

---

### V4-18 — LOW — `RewardCalculator.compute()` has hardcoded reward for `exploitation_verification` that ignores actual finding quality

**Lines:** learning_loop_engine.py ~L700–740

The reward calculation gives a flat bonus for `exploitation_verification` findings regardless of whether the verification actually confirmed exploitability. The finding's `verified` or `exploitable` field isn't checked.

---

## CROSS-CUTTING FINDINGS

### V4-19 — CRITICAL — DecisionOrchestrator event bus is wired but emits into a void — zero ML subscribers react to DO-emitted events

**Lines:** decision_orchestrator.py L2179–2211, L1494–1499

The DecisionOrchestrator emits three event types via its bound `_event_bus`:
1. `"goal.progress"` — zero subscribers
2. `"goal.achieved"` — zero subscribers  
3. `BusEventType.STRATEGY_RECOMMENDED` — zero subscribers

These are the only events the DO emits. All three go undelivered. The event bus connection in the Decision Orchestrator is **write-only** — it broadcasts but nothing listens.

Meanwhile, the DO itself **never subscribes** to any events (no `bus.on(` calls within decision_orchestrator.py). The `bind_event_bus()` method stores the bus for emit-only use.

**Impact:** Goal achievement and strategic recommendations cannot propagate through the event system to trigger reactive behavior in other modules.

---

### V4-20 — HIGH — LearningLoopEngine has no EventBus integration at all

**Lines:** learning_loop_engine.py (entire file)

A search for `event_bus`, `bus.on`, `bus.emit`, `BusEventType` in learning_loop_engine.py returns **zero hits**. The learning loop engine:
- Does NOT subscribe to any events (no reactive learning from real-time signals)
- Does NOT emit any events (learning milestones, trend changes, Q-table updates are invisible)

All learning occurs only via direct method calls (`record_tool_outcome`, `train_end_of_session`). There is no event-driven learning feedback path.

**Impact:** Learning cannot react to real-time scan events (VULN_DETECTED, SECRET_FOUND, etc.) — it only learns when explicitly told via method calls from the autonomous loop.

---

### V4-21 — MEDIUM — `atlas_nexus.py` emits Atlas events to main EventBus but nobody subscribes

**Lines:** atlas_nexus.py L727–734

Atlas emits events like `ATLAS_LEARNING_COMPLETE` and `ATLAS_PATTERN_UPDATED` via `_emit_event()` which delegates to the global `EventBus` singleton (`from ..event_bus import emit as bus_emit`). The events DO reach the main bus. However, as documented in V4-1, **no module subscribes** to `atlas.*` events. The events are correctly emitted but discarded.

**Impact:** Atlas learning progress and pattern discoveries are broadcast but never consumed by DecisionOrchestrator, LearningLoopEngine, or any other subsystem.

---

### V4-22 — MEDIUM — `stealth_orchestrator.py` subscribes to `defense.*` events but the BusEventType strings use different naming

**Lines:** stealth_orchestrator.py L1323–1327

The stealth orchestrator subscribes to literal strings:
```python
bus.on("defense.waf.detected", ...)
bus.on("defense.rate_limit.detected", ...)
bus.on("defense.bot.challenge", ...)
bus.on("system.rate_limited", ...)
bus.on("system.error", ...)
```

These match `BusEventType.WAF_DETECTED`, `RATE_LIMIT_DETECTED`, `BOT_CHALLENGE_DETECTED`, `RATE_LIMITED`, `ERROR_OCCURRED`. **However**, only `self_healing.py` (L936) actually emits `BusEventType.ERROR_OCCURRED`. No code emits `WAF_DETECTED`, `RATE_LIMIT_DETECTED`, or `BOT_CHALLENGE_DETECTED` via the event bus. The stealth orchestrator's defense subscriptions are **listening to events that nobody emits**.

---

## SUMMARY TABLE

| ID | Severity | File | Issue |
|----|----------|------|-------|
| V4-1 | CRITICAL | event_bus.py | ~50 of 80 BusEventType values have zero subscribers |
| V4-2 | HIGH | prompt_security.py / event_bus.py | Injection events use wrong string keys, bypass enum |
| V4-3 | MEDIUM | resource_monitor.py | `"RESOURCE_SNAPSHOT"` breaks naming convention, dead emit |
| V4-4 | MEDIUM | recon_pipeline.py | Pipeline events don't match any subscriber pattern |
| V4-5 | HIGH | decision_orchestrator.py | Duplicate `_outcome_buffer` / `_last_recommendations` init |
| V4-6 | HIGH | decision_orchestrator.py | `_reasoning_engine` bound but never queried |
| V4-7 | MEDIUM | decision_orchestrator.py | `dir()` guard for `_action_lower` is fragile |
| V4-8 | MEDIUM | decision_orchestrator.py | GOAL events emitted but zero subscribers |
| V4-9 | MEDIUM | decision_orchestrator.py | STRATEGY_RECOMMENDED emitted but no subscriber |
| V4-10 | LOW | decision_orchestrator.py | Redundant None fallback after explicit full_compromise entry |
| V4-11 | LOW | decision_orchestrator.py | Inline `IntEnum` construction for priority |
| V4-12 | CRITICAL | learning_loop_engine.py | `.ledger` vs `._ledger` AttributeError in factory |
| V4-13 | HIGH | learning_loop_engine.py | `evolve_exploitation_paths()` dead code |
| V4-14 | MEDIUM | learning_loop_engine.py | Fragile ledger reference pattern in trainer |
| V4-15 | MEDIUM | learning_loop_engine.py | Bidirectional Q-RL sync amplification risk |
| V4-16 | MEDIUM | learning_loop_engine.py | MetaTracker trend output unused by decisions |
| V4-17 | MEDIUM | learning_loop_engine.py | Dual Bayesian references may diverge |
| V4-18 | LOW | learning_loop_engine.py | exploitation_verification reward ignores quality |
| V4-19 | CRITICAL | cross-cutting | DO emits 3 event types, zero subscribers exist |
| V4-20 | HIGH | cross-cutting | LearningLoopEngine has zero EventBus integration |
| V4-21 | MEDIUM | cross-cutting | Atlas events reach main EventBus but nobody subscribes |
| V4-22 | MEDIUM | cross-cutting | Stealth subscribes to defense events nobody emits |

**Totals:** 3 CRITICAL, 5 HIGH, 11 MEDIUM, 3 LOW = **22 findings**

---

## FOCUS AREA 4: LLM Bridge Pipeline Audit (`agents/llm_bridge.py`)

### V4-23 — HIGH — `_complete_structured` bypasses quality scoring, feedback learning, A/B testing, and tracing

**Lines:** llm_bridge.py L1487–1607

The `_complete_structured()` method is a parallel entry point to `_complete()` for grammar-constrained JSON output. When the client supports native structured generation, it takes a completely separate code path that SKIPS:

1. **Quality scoring** — no `scorer.score()` call, no quality threshold check
2. **Feedback learning** — no `feedback_engine.record_quality()` call
3. **A/B testing** — no `experiment_engine.assign()` call
4. **Tracing** — no `tracer.start_span()` / `set_span_attributes()` calls
5. **Model router quality** — no `router.record_quality()` call
6. **Output guard** — schema validation not applied
7. **EventBus events** — no `_emit_llm_event()` calls for quality failures/escalation

Only cost tracking (`tracker.record_usage()`) and caching are preserved.

When the client does NOT support structured output, it falls back to `_complete()` which has all pipelines wired. The gap only affects structured-capable clients (e.g., `LocalLlamaClient` with GBNF grammars).

**Impact:** Local model responses via structured generation are never quality-scored, never feed the learning system, and are invisible to observability/tracing. Model degradation under grammar constraints goes undetected.

**Fix:** Factor the quality/feedback/tracing pipeline into a shared `_post_completion_pipeline()` method called by both `_complete()` and `_complete_structured()`.

---

### V4-24 — MEDIUM — `_complete_structured_stream` also bypasses quality and feedback

**Lines:** llm_bridge.py L1608–1680

The streaming structured variant has the same omissions as V4-23. It performs cost tracking but skips quality/feedback/A/B/tracing entirely.

---

### V4-25 — MEDIUM — 9 core methods call `_complete()` → `_parse_json_response()` but NEVER inject feedback signals into prompts

**Lines:** llm_bridge.py L1867–2370

The following methods use the basic `_complete() → _parse_json_response()` pattern WITHOUT consulting the `FeedbackLearningEngine.get_prompt_signal()` for prior quality information:

1. `analyze_response()` — L1867
2. `generate_hypothesis()` — L1931
3. `explain_finding()` — L1976
4. `suggest_payloads()` — L2028
5. `chain_of_thought()` — L2084/L2117/L2122
6. `validate_finding()` — L2176
7. `map_attack_surface()` — L2334
8. `discover_chains()` — L2366
9. `assess_impact()` — L4290

By contrast, `agent_chat()` (L2069), `agent_chat_stream()` (L3206/L3754), and `plan_and_execute()` DO consult the feedback engine. The pattern is inconsistent — only the "conversational" paths have feedback-informed prompting.

**Impact:** These 9 methods cannot adapt their prompting based on prior quality failures. If the LLM consistently produces bad analysis for a specific template, the same prompt is retried identically instead of being augmented with "prior issues" context.

**Fix:** Add a `get_prompt_signal() → augmentation` block to each method before calling `_complete()`, similar to the pattern in `agent_chat()`.

---

### V4-26 — MEDIUM — RAG context enrichment only used in `agent_chat`, missing from all other analysis methods

**Lines:** llm_bridge.py L3489–3492

RAG context (retrieved knowledge augmentation) is only consumed when it appears in `scan_context.get("rag_context")` during `agent_chat()` prompt construction. None of the core analysis methods (`analyze_response`, `generate_hypothesis`, `explain_finding`, etc.) incorporate RAG-retrieved knowledge.

**Impact:** The RAG system can only inform conversational chat queries — it cannot enrich automated analysis, hypothesis generation, or finding explanations with historical knowledge.

---

## FOCUS AREA 5: Agent Swarm Integration Audit (`swarm/`)

### V4-27 — CRITICAL — Swarm findings are completely isolated — no bridge to main EventBus or pipeline

**Lines:** swarm/swarm.py L500–530, swarm/message_bus.py (entire file)

The `AgentSwarm` uses its OWN `MessageBus` (from `swarm/message_bus.py`) which is a completely separate pub/sub system from the main `EventBus` (from `event_bus.py`). The two buses:

- Have different APIs (`bus.subscribe()` vs `bus.on()`)
- Use different message formats (`Message` vs `Event`)
- Use different topic naming (`"finding"` vs `"recon.vuln.detected"`)
- Have no bridge, adapter, or proxy between them

When `AgentSwarm.report_finding()` is called (L500), findings are:
1. Published to swarm's internal `MessageBus` — received only by other swarm agents
2. Stored in `self._all_findings` list — accessible only via `swarm.findings` property

But findings are NEVER:
- Emitted to the main `EventBus` (no EventBus import or reference in swarm.py)
- Fed to `LearningLoopEngine.record_tool_outcome()`
- Fed to `DecisionOrchestrator.record_outcome()`
- Inserted into the `ExploitGraph`
- Added to the `findings_store` for dashboard display

**Impact:** The entire multi-agent swarm subsystem operates in complete isolation. Swarm-discovered vulnerabilities, subdomains, and attack chains are invisible to the rest of the system. This is the single largest wiring disconnection in the codebase.

**Fix:** Add an `EventBusBridge` that converts swarm `Message` objects to `Event` objects and publishes them to the main `EventBus`. Alternatively, have `report_finding()` directly call `get_event_bus().emit(BusEventType.VULN_DETECTED, ...)`.

---

### V4-28 — HIGH — Swarm agents don't share learning state with LearningLoopEngine

**Lines:** swarm/swarm.py (entire file)

The swarm has no import or reference to `LearningLoopEngine`. Individual swarm agents (`AgentRole.RECON_ANALYST`, `EXPLOIT_GENERATOR`, etc.) receive tasks and produce findings, but:

- Tool outcomes from swarm agents are never recorded in the persistent Q-table
- The Q-table's tool recommendations are not used to prioritize swarm agent tasks
- `train_end_of_session()` is never called from the swarm lifecycle

**Impact:** The swarm operates without any memory of past performance. Each swarm session starts cold with no learning from prior runs.

---

### V4-29 — HIGH — `_tick()` in AgentSwarm is a high-level stub — agents don't actually execute tools

**Lines:** swarm/swarm.py L658–682

```python
async def _tick(self) -> None:
    """Execute one iteration cycle across all agents."""
    for agent in self._agents.values():
        if agent.is_available and agent.current_task is not None:
            agent.transition(SwarmAgentState.WORKING)
            self._total_iterations += 1
            # Agent work happens here through the model
            await asyncio.sleep(0)  # Yield control
            agent.work_iteration()
```

The `work_iteration()` method on `SwarmAgent` (defined in `agent_roles.py`) simply increments counters — it does not actually invoke tools, call LLM, or produce findings. The agent "work" is simulated. Real findings can only enter via the explicit `report_finding()` API.

**Impact:** The swarm tick loop is a lifecycle skeleton without actual tool execution. Agents don't autonomously scan — they just cycle through states.

---

### V4-30 — MEDIUM — Swarm findings not fed into ExploitGraph

**Lines:** swarm/swarm.py L500–530

`report_finding()` stores findings locally and distributes to other swarm agents, but never updates the ExploitGraph's state-transition model. Exploit chains discovered by swarm agents are invisible to the graph-based attack path analysis.

---

## FOCUS AREA 6: Reasoning Engine Integration (`agents/reasoning_engine.py`)

### V4-31 — MEDIUM — Reasoning engine `reason()` chain-of-thought traces are logged but never consumed

**Lines:** reasoning_engine.py

The `ReasoningEngine.reason()` method produces detailed chain-of-thought traces including hypothesis prioritization, evidence analysis, and recommended actions. These traces are:
- Logged at DEBUG level
- Returned to the caller

However, the `autonomous_loop.py` does NOT call `reasoning_engine.reason()` directly. The loop uses `DecisionOrchestrator.recommend_actions()` which imports `TECH_VULN_PROBABILITY` as a module-level constant from reasoning_engine but never invokes the reasoning engine's inference methods.

**Impact:** The full chain-of-thought reasoning capability is defined but not used in the main execution loop. Only the static probability tables are consumed.

---

### V4-32 — LOW — Thompson Sampling state in reasoning_engine not persisted between sessions

**Lines:** reasoning_engine.py

The reasoning engine maintains Thompson Sampling parameters (alpha/beta) for hypothesis exploration. These are stored in memory and lost at session end. Unlike the Q-table (which persists to JSON) and the Bayesian prior (which saves to file), Thompson Sampling state resets every session.

---

## FOCUS AREA 7: Cognitive Bridge Integration (`agents/cognitive_bridge.py`)

### V4-33 — HIGH — `_record_event()` call in `build_copilot_reasoning_context` has TWO bugs — wrong types AND extra kwarg

**Lines:** cognitive_bridge.py L1193–1198

`build_copilot_reasoning_context()` calls `_record_event()` with:
1. **Wrong types**: `direction="outbound"` (string) instead of `FusionDirection.PYTHON_TO_COPILOT` (enum), and `event_type="copilot_reasoning_context"` (string) instead of `FusionEventType` enum value
2. **Extra keyword argument**: passes `source="CognitiveBridge.build_copilot_reasoning_context"` — but `_record_event(self, direction, event_type, data)` has NO `source` parameter and NO `**kwargs`

Bug #2 means `_record_event()` raises `TypeError: _record_event() got an unexpected keyword argument 'source'` EVERY time `build_copilot_reasoning_context` is called. Since this is in a `try/except Exception` block (L1200), the error is silently swallowed and the method returns `{"copilot_reasoning": False, "error": "..."}`.

Note: The other 3 `_record_event()` call sites (L724, L891, L1027) correctly use enum types and don't pass `source=`. Only L1193 is broken.

**Fix:** Remove `source=`, use `FusionDirection.PYTHON_TO_COPILOT` and `FusionEventType.REASONING_EXPLAINED`.

---

### V4-34 — MEDIUM — CognitiveBridge never feeds outcomes to FeedbackLearningEngine

**Lines:** cognitive_bridge.py L418–500

When Copilot guidance proves correct (hypothesis confirmed) or incorrect (hypothesis rejected), this outcome is tracked in the fusion event log but never propagated to the `FeedbackLearningEngine`. The learning system cannot improve future Copilot prompting quality based on actual outcomes.

---

### V4-35 — MEDIUM — Two independent CognitiveBridge implementations with separate state

**Files:** agents/cognitive_bridge.py, mcp/cognitive_bridge.py

Two entirely separate `CognitiveBridge` classes exist with different implementations, different singletons, and different APIs:
- `agents/` version — used by `CopilotLoop` and the autonomous execution path
- `mcp/` version — used by MCP tool calls (`reason_about_findings`, `request_strategic_guidance`)

These share no state. MCP-based cognitive operations may see completely different hypothesis state than what the main loop is using.

**Fix:** Have the MCP version delegate to the agents version's singleton.

---

## FOCUS AREA 8: LLM Intelligence Layer (`agents/llm_intelligence.py`)

### V4-36 — MEDIUM — All 7 intelligence functions call `bridge._complete()` directly (private method)

**Lines:** llm_intelligence.py (all functions)

All 7 functions (`generate_executive_summary`, `generate_smart_remediation`, `prioritize_findings`, `analyze_false_positives`, `generate_compliance_narrative`, `generate_target_profile`, `recommend_scan_tuning`) accept `bridge: Any` and call `bridge._complete()` — a private method.

This bypasses any future public API changes and creates tight coupling to internal implementation. The `Any` type annotation provides no safety.

---

### V4-37 — HIGH — Intelligence functions lack feedback learning — LLM results not recorded

**Lines:** llm_intelligence.py (all functions)

None of the 7 intelligence functions call:
- `feedback_engine.record_quality()` — no quality tracking for intelligence outputs
- `feedback_engine.get_prompt_signal()` — no feedback-informed prompt augmentation
- `feedback_engine.store_feedback()` — no outcome tracking

The LLM intelligence layer is a pure one-shot pipeline with no ability to learn from past quality issues or improve over time.

**Fix:** Add feedback recording at the end of each function, similar to the pattern in `_complete()`.

---

## SUMMARY TABLE

| ID | Severity | File | Issue |
|----|----------|------|-------|
| V4-1 | CRITICAL | event_bus.py | ~50 of 80 BusEventType values have zero subscribers |
| V4-2 | HIGH | prompt_security.py / event_bus.py | Injection events use wrong string keys, bypass enum |
| V4-3 | MEDIUM | resource_monitor.py | `"RESOURCE_SNAPSHOT"` breaks naming convention, dead emit |
| V4-4 | MEDIUM | recon_pipeline.py | Pipeline events don't match any subscriber pattern |
| V4-5 | HIGH | decision_orchestrator.py | Duplicate `_outcome_buffer` / `_last_recommendations` init |
| V4-6 | HIGH | decision_orchestrator.py | `_reasoning_engine` bound but never queried |
| V4-7 | MEDIUM | decision_orchestrator.py | `dir()` guard for `_action_lower` is fragile |
| V4-8 | MEDIUM | decision_orchestrator.py | GOAL events emitted but zero subscribers |
| V4-9 | MEDIUM | decision_orchestrator.py | STRATEGY_RECOMMENDED emitted but no subscriber |
| V4-10 | LOW | decision_orchestrator.py | Redundant None fallback after explicit full_compromise entry |
| V4-11 | LOW | decision_orchestrator.py | Inline `IntEnum` construction for priority |
| V4-12 | CRITICAL | learning_loop_engine.py | `.ledger` vs `._ledger` AttributeError in factory |
| V4-13 | HIGH | learning_loop_engine.py | `evolve_exploitation_paths()` dead code |
| V4-14 | MEDIUM | learning_loop_engine.py | Fragile ledger reference pattern in trainer |
| V4-15 | MEDIUM | learning_loop_engine.py | Bidirectional Q-RL sync amplification risk |
| V4-16 | MEDIUM | learning_loop_engine.py | MetaTracker trend output unused by decisions |
| V4-17 | MEDIUM | learning_loop_engine.py | Dual Bayesian references may diverge |
| V4-18 | LOW | learning_loop_engine.py | exploitation_verification reward ignores quality |
| V4-19 | CRITICAL | cross-cutting | DO emits 3 event types, zero subscribers exist |
| V4-20 | HIGH | cross-cutting | LearningLoopEngine has zero EventBus integration |
| V4-21 | MEDIUM | cross-cutting | Atlas events reach main EventBus but nobody subscribes |
| V4-22 | MEDIUM | cross-cutting | Stealth subscribes to defense events nobody emits |
| V4-23 | HIGH | agents/llm_bridge.py | `_complete_structured` bypasses quality, feedback, A/B, tracing |
| V4-24 | MEDIUM | agents/llm_bridge.py | `_complete_structured_stream` also bypasses quality/feedback |
| V4-25 | MEDIUM | agents/llm_bridge.py | 9 core methods never inject feedback signals into prompts |
| V4-26 | MEDIUM | agents/llm_bridge.py | RAG context only used in agent_chat, missing elsewhere |
| V4-27 | CRITICAL | swarm/swarm.py | Swarm findings completely isolated — no EventBus/pipeline bridge |
| V4-28 | HIGH | swarm/swarm.py | Swarm agents don't share learning state with LearningLoopEngine |
| V4-29 | HIGH | swarm/swarm.py | `_tick()` is a stub — agents don't actually execute tools |
| V4-30 | MEDIUM | swarm/swarm.py | Swarm findings not fed into ExploitGraph |
| V4-31 | MEDIUM | reasoning_engine.py | `reason()` chain-of-thought traces never consumed by loop |
| V4-32 | LOW | reasoning_engine.py | Thompson Sampling state not persisted between sessions |
| V4-33 | HIGH | cognitive_bridge.py | `_record_event()` TWO bugs: wrong types + extra kwarg crashes every call |
| V4-34 | MEDIUM | cognitive_bridge.py | CognitiveBridge never feeds outcomes to FeedbackLearningEngine |
| V4-35 | MEDIUM | cognitive_bridge.py | Two independent CognitiveBridge implementations |
| V4-36 | MEDIUM | llm_intelligence.py | All 7 functions call private `_complete()` method |
| V4-37 | HIGH | llm_intelligence.py | Intelligence functions lack feedback learning |

---

## FOCUS AREA 9: Production Stack Integration Audit

### V4-38 — MEDIUM — IntentFeedbackLoop weights only persist on shutdown — crash loses learned weights

**Lines:** llm_adaptive.py L199–219, llm_bridge.py L2676

`IntentFeedbackLoop.persist()` is called every 10 requests in `agent_chat()` and during shutdown. However, if the process is killed (SIGKILL, OOM, crash) between persist cycles, all learned intent weights since the last flush are lost. No WAL or periodic auto-save exists independent of the 10-request cadence.

---

### V4-39 — MEDIUM — Output guard schema validation has no nested field validation in fallback path

**Lines:** llm_output_guard.py L375–395

When `_resolve_schema()` returns None (unknown role), the guard correctly applies a fail-closed restrictive allowlist (BUG-11 fix). However, the fallback allows `findings`, `recommendations`, and `reasoning` keys wholesale WITHOUT recursive nested validation. A crafted LLM response could embed arbitrary nested data under these keys. Known-role schemas also lack recursive depth validation.

---

### V4-40 — MEDIUM — LLM budget threshold events emitted but no subscriber adjusts behavior

**Lines:** llm_tracking.py L259–281

Budget tracker emits `"llm.budget_threshold"` events at 75% and 90% utilization via `self._event_callback`, but no code subscribes to these events. When the LLM token budget is nearly exhausted, no automatic behavior change occurs — the DecisionOrchestrator and autonomous loop continue scheduling LLM calls normally until the hard limit is hit.

---

### V4-41 — MEDIUM — prompt_security `wrap_untrusted()` not globally applied to all LLM inputs

**Lines:** prompt_security.py L569–615

`wrap_untrusted()` provides sandwich defense for untrusted data in prompts, but is only used in 2 code paths (llm_intelligence.py and graph code). NOT applied to: scanner output fed to analysis methods, HTTP response bodies in findings, user input in agent_chat, or dynamically constructed prompts in the 9 core analysis methods. Developers must remember to call it manually — no enforcement layer.

---

### V4-42 — HIGH — CopilotSDKEngine events isolated — findings don't reach learning systems

**Lines:** copilot_sdk_engine.py L115–200

CopilotSDKEngine has its own event emission via `SecurityHooks` and `_emit_event()` but these events never bridge to the main EventBus. Findings extracted by SDK tools are returned to callers but never fed to: DecisionOrchestrator (for strategy evolution), LearningLoopEngine (for tool reward), or ExploitGraph (for chain analysis). SDK-discovered vulnerabilities are invisible to the learning pipeline.

---

### V4-43 — MEDIUM — UnifiedAgent `AgentEvent` system duplicates EventBus with no bridge

**Lines:** unified_agent.py L200–250

`unified_agent.py` defines its own `AgentEvent`, `Perception`, and `AgentAction` dataclasses with a local event system. These include perception-action cycles and agent state transitions. None of these events are emitted to the main EventBus, so unified_agent intelligence is invisible to operator dashboards and learning systems.

---

### V4-44 — MEDIUM — llm_ops infrastructure health events emitted but never trigger remediation

**Lines:** llm_ops.py L161+

`MultiRegionResilience` and other ops components emit health events (e.g. `"infra.redis_down"`, `"infra.model_timeout"`), but no code subscribes to these events. Health degradation is logged but never: scales down concurrent LLM calls, triggers failover, or alerts operators. Events are emitted into a void.

---

### V4-45 — MEDIUM — ModelHealthMonitor detects degradation but health check result is ignored

**Lines:** llm_bridge.py L2525–2527, llm_production.py L303+

`agent_chat()` calls `health_monitor.is_model_disabled(model)` at L2525, but when it returns `True`, the code only logs a warning — it does NOT switch to a fallback model or skip the disabled model. The health monitor's degradation detection is implemented but the routing decision never acts on it.

---

### V4-46 — LOW — self_optimizing_stack event_bus binding is optional — tool optimization invisible without it

**Lines:** self_optimizing_stack.py L1410+

`SelfOptimizingStack.bind_event_bus()` is optional. If not called, tool tier promotion/demotion events (`"optimizer.tool.recorded"`, `"optimizer.system_outage"`) are never emitted. No enforcement or validation ensures the event bus is bound in all deployment paths.

| Finding | Sev | File | Summary |
|---------|-----|------|---------|
| V4-1 | HIGH | event_bus.py | 50+ dead/subscriber-less BusEventType enum values |
| V4-2 | MEDIUM | event_bus.py | `security.injection_alert` wrong naming convention |
| V4-3 | MEDIUM | resource_monitor.py | `"RESOURCE_SNAPSHOT"` breaks naming convention, dead emit |
| V4-4 | MEDIUM | recon_pipeline.py | Pipeline events don't match any subscriber pattern |
| V4-5 | HIGH | decision_orchestrator.py | Duplicate `_outcome_buffer` / `_last_recommendations` init |
| V4-6 | HIGH | decision_orchestrator.py | `_reasoning_engine` bound but never queried |
| V4-7 | MEDIUM | decision_orchestrator.py | `dir()` guard for `_action_lower` is fragile |
| V4-8 | MEDIUM | decision_orchestrator.py | GOAL events emitted but zero subscribers |
| V4-9 | MEDIUM | decision_orchestrator.py | STRATEGY_RECOMMENDED emitted but no subscriber |
| V4-10 | LOW | decision_orchestrator.py | Redundant None fallback after explicit full_compromise entry |
| V4-11 | LOW | decision_orchestrator.py | Inline `IntEnum` construction for priority |
| V4-12 | CRITICAL | learning_loop_engine.py | `.ledger` vs `._ledger` AttributeError in factory |
| V4-13 | HIGH | learning_loop_engine.py | `evolve_exploitation_paths()` dead code |
| V4-14 | MEDIUM | learning_loop_engine.py | Fragile ledger reference pattern in trainer |
| V4-15 | MEDIUM | learning_loop_engine.py | Bidirectional Q-RL sync amplification risk |
| V4-16 | MEDIUM | learning_loop_engine.py | MetaTracker trend output unused by decisions |
| V4-17 | MEDIUM | learning_loop_engine.py | Dual Bayesian references may diverge |
| V4-18 | LOW | learning_loop_engine.py | exploitation_verification reward ignores quality |
| V4-19 | CRITICAL | cross-cutting | DO emits 3 event types, zero subscribers exist |
| V4-20 | HIGH | cross-cutting | LearningLoopEngine has zero EventBus integration |
| V4-21 | MEDIUM | cross-cutting | Atlas events reach main EventBus but nobody subscribes |
| V4-22 | MEDIUM | cross-cutting | Stealth subscribes to defense events nobody emits |
| V4-23 | HIGH | agents/llm_bridge.py | `_complete_structured` bypasses quality, feedback, A/B, tracing |
| V4-24 | MEDIUM | agents/llm_bridge.py | `_complete_structured_stream` also bypasses quality/feedback |
| V4-25 | MEDIUM | agents/llm_bridge.py | 9 core methods never inject feedback signals into prompts |
| V4-26 | MEDIUM | agents/llm_bridge.py | RAG context only used in agent_chat, missing elsewhere |
| V4-27 | CRITICAL | swarm/swarm.py | Swarm findings completely isolated — no EventBus/pipeline bridge |
| V4-28 | HIGH | swarm/swarm.py | Swarm agents don't share learning state with LearningLoopEngine |
| V4-29 | HIGH | swarm/swarm.py | `_tick()` is a stub — agents don't actually execute tools |
| V4-30 | MEDIUM | swarm/swarm.py | Swarm findings not fed into ExploitGraph |
| V4-31 | MEDIUM | reasoning_engine.py | `reason()` chain-of-thought traces never consumed by loop |
| V4-32 | LOW | reasoning_engine.py | Thompson Sampling state not persisted between sessions |
| V4-33 | HIGH | cognitive_bridge.py | `_record_event()` TWO bugs: wrong types + extra kwarg crashes every call |
| V4-34 | MEDIUM | cognitive_bridge.py | CognitiveBridge never feeds outcomes to FeedbackLearningEngine |
| V4-35 | MEDIUM | cognitive_bridge.py | Two independent CognitiveBridge implementations |
| V4-36 | MEDIUM | llm_intelligence.py | All 7 functions call private `_complete()` method |
| V4-37 | HIGH | llm_intelligence.py | Intelligence functions lack feedback learning |
| V4-38 | MEDIUM | llm_adaptive.py | IntentFeedbackLoop weights only persist on shutdown/10-req cycle |
| V4-39 | MEDIUM | llm_output_guard.py | Fallback schema allows nested data without recursive validation |
| V4-40 | MEDIUM | llm_tracking.py | Budget threshold events emitted but no subscriber adjusts behavior |
| V4-41 | MEDIUM | prompt_security.py | `wrap_untrusted()` not globally applied to all LLM inputs |
| V4-42 | HIGH | copilot_sdk_engine.py | SDK findings don't reach learning pipeline or EventBus |
| V4-43 | MEDIUM | unified_agent.py | AgentEvent system duplicates EventBus with no bridge |
| V4-44 | MEDIUM | llm_ops.py | Infrastructure health events emitted but never trigger remediation |
| V4-45 | MEDIUM | llm_bridge.py / llm_production.py | ModelHealthMonitor detects degradation but result is ignored |
| V4-46 | LOW | self_optimizing_stack.py | Event bus binding optional — tool optimization invisible without it |

**Totals:** 4 CRITICAL, 12 HIGH, 25 MEDIUM, 5 LOW = **46 findings**
