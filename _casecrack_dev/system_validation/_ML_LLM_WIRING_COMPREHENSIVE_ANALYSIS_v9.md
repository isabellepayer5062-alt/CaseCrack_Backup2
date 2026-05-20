# ML/LLM Wiring Comprehensive Analysis — V9

**Date:** 2026-04-12  
**Scope:** Full-system ML/LLM subsystem integration audit — LLM Bridge, Autonomous Loop, Decision Orchestrator, Learning Loop Engine, EventBus, ExploitGraph, StealthOrchestrator, CognitiveBridge, Atlas Nexus, MCP Server, Copilot SDK Engine, Prompt Security, Runner lifecycle  
**Methodology:** 5 parallel deep-dive subagents → cross-verification of all CRITICAL/HIGH findings against actual source code → severity classification  
**Prior:** V2–V8: **205 total fixes**. 376/376 tests passing.  
**Verification:** All CRITICAL findings confirmed against actual code. HIGH findings spot-checked.

---

## Summary

| Severity | Count | IDs |
|----------|-------|-----|
| **CRITICAL** | 5 | V9-1, V9-2, V9-3, V9-4, V9-5 |
| **HIGH** | 14 | V9-6 through V9-19 |
| **MEDIUM** | 22 | V9-20 through V9-41 |
| **LOW** | 11 | V9-42 through V9-52 |
| **Total** | **52** | |

---

## Severity Legend

| Level | Meaning |
|-------|---------|
| CRITICAL | Core ML/LLM function demonstrably broken — wrong method call, missing attribute, data silently lost |
| HIGH | Subsystem disconnected — intelligence not consumed, feedback loops permanently open |
| MEDIUM | Feature degraded — write-only telemetry, partial coverage, stale state, inconsistency |
| LOW | Architectural debt — dead code, lint, edge-case races, maintenance burden |

---

## CRITICAL Findings (5)

### V9-1 — CRITICAL — `bus.subscribe()` Does Not Exist on EventBus — Stealth Heat Penalty Permanently Dead

**File:** `decision_orchestrator.py` L1117  
**Verified:** ✅ Confirmed — EventBus has `.on()`, `.once()`, `.on_filter()` but NO `.subscribe()` method

```python
# decision_orchestrator.py L1117
try:
    bus.subscribe("stealth.heat_escalated", self._on_stealth_heat_escalated)
except Exception as exc:
    logger.debug("V5-22: Failed to subscribe to stealth events: %s", exc)
```

EventBus API only has `.on()`. The `subscribe()` call raises `AttributeError`, caught by the debug-level `except`. The handler is never registered.

**Cascade Impact:**
- `_stealth_heat_penalty` at L1031 stays `0.0` forever
- The V5-22 stealth heat EV penalty system (L3335–3350 in `_score_action()`) that dampens sqlmap/nuclei/ffuf/dalfox when defenses escalate to HOT/BURNING/COMPROMISED **never fires**
- The stealth orchestrator's heat management is completely disconnected from strategic decision-making
- The handler `_on_stealth_heat_escalated()` (L1121–1133) is dead code

**Fix:** Replace `bus.subscribe(...)` with `bus.on("stealth.heat_escalated", self._on_stealth_heat_escalated, name="do-stealth-heat")`

---

### V9-2 — CRITICAL — `self._tool_ledger` Wrong Attribute Name — ConfidenceEnsemble Data-Starved

**File:** `learning_loop_engine.py` L1769  
**Verified:** ✅ Confirmed — attribute is `self._ledger` (set at L1237, L1496)

```python
# learning_loop_engine.py L1769
_ts = self._tool_ledger.get_tool_stats(outcome.tool_name)
```

`self._tool_ledger` doesn't exist — the correct attribute is `self._ledger`. The `AttributeError` is caught by the bare `except Exception: pass` at L1774. `_predicted_conf` falls back to hardcoded `0.5`.

**Cascade Impact:**
- V8-19 fix (feed real tool reliability into ConfidenceEnsemble) is completely bypassed
- ConfidenceEnsemble always receives neutral 0.5 confidence instead of actual `win_rate`
- Tool reliability learning cannot distinguish reliable vs unreliable tools
- Tools with 90% success rate and tools with 10% success rate both produce identical confidence signals

**Fix:** Change `self._tool_ledger` → `self._ledger`

---

### V9-3 — CRITICAL — `FusionEventType.HYPOTHESIS_CREATED` / `.STRATEGY_SYNC` Don't Exist — CognitiveBridge Feedback Dead

**File:** `agents/cognitive_bridge.py` L1153–1154  
**Verified:** ✅ Confirmed — FusionEventType enum (L102–110) only has: `HYPOTHESIS_UPDATED`, `GUIDANCE_RECEIVED`, `REASONING_EXPLAINED`, `PROBABILITY_ADJUSTED`, `STRATEGY_CHANGED`

```python
# cognitive_bridge.py L1153-1154 — inside _record_event() dict
FusionEventType.HYPOTHESIS_CREATED: 0.80,  # DOESN'T EXIST
FusionEventType.STRATEGY_SYNC: 0.75,       # DOESN'T EXIST
```

Accessing non-existent enum members raises `AttributeError` at module load or dict creation time. The containing `try/except` swallows the error, making the entire FeedbackLearningEngine forwarding block at L1148–1162 dead.

**Cascade Impact:**
- CognitiveBridge operations (hypothesis updates, guidance, probability adjustments) generate NO quality metrics for the feedback learning loop
- The V4-34 fix is implemented but never activates
- The feedback learning engine cannot learn from cognitive bridge quality patterns

**Fix:** Replace `HYPOTHESIS_CREATED` → `HYPOTHESIS_UPDATED` and `STRATEGY_SYNC` → `STRATEGY_CHANGED`

---

### V9-4 — CRITICAL — `_learn()` Ignores `new_findings` Parameter — EVALUATE Phase Work Discarded

**File:** `loop/autonomous_loop.py` L2558–2566  
**Verified:** ✅ Confirmed — `new_findings` param never referenced in method body

```python
def _learn(
    self,
    results: list[ActionResult],
    new_findings: list[FindingSummary],   # ← NEVER USED
) -> dict[str, int]:
```

The `_learn` method accepts LLM-arbitrated `FindingSummary` objects from the EVALUATE phase but never references them. Instead, it iterates `results` and reads `r.findings` — **raw, unvalidated** tool output dicts.

**Cascade Impact:**
- All 10+ learning subsystems receive RAW tool severity/confidence instead of LLM-arbitrated values
- The entire EVALUATE phase's work (confidence recalibration, doubt injection, confirmation engine, unified arbitration protocol) is **discarded** by LEARN
- Bayesian prioritizer learns from tool-reported severity (often over-stated) instead of verified severity
- Q-table rewards based on unvalidated tool output instead of confirmed intelligence

**Fix:** In `_learn()`, iterate `new_findings` for finding-related learning updates (Bayesian, DO, learning loop), use `results` only for tool-level outcome tracking (tool success/failure, execution times).

---

### V9-5 — CRITICAL — `.get()` Called on Frozen Dataclass — RAG Context Silently Crashes

**File:** `loop/autonomous_loop.py` L1358  
**Verified:** ✅ Confirmed — `FindingSummary` is `@dataclass(frozen=True)` with no `.get()` method

```python
# autonomous_loop.py L1358
for f in world.findings[-10:]:
    _ft = f.get("type") or f.get("vuln_type") or f.get("finding_type", "")
```

`world.findings` is `list[FindingSummary]`. `FindingSummary` is a frozen dataclass — it has no `.get()` method. This raises `AttributeError` immediately, caught by the outer `try/except`.

**Cascade Impact:**
- RAG context injection silently fails every iteration when findings exist
- The LLM never receives RAG-retrieved intelligence about prior findings/CVEs
- All RAG augmentation for the THINK phase's hypothesis generation is dead
- Historical pattern matching and cross-scan intelligence lookup are bypassed

**Fix:** Replace `f.get("type")` with `f.vulnerability_type` (the actual dataclass attribute name)

---

## HIGH Findings (14)

### V9-6 — HIGH — `_on_stealth_heat_escalated` Handler Would Crash Even If V9-1 Were Fixed

**File:** `decision_orchestrator.py` L1121–1133  
**Verified:** ✅ Confirmed

```python
def _on_stealth_heat_escalated(self, data: dict[str, Any]) -> None:
    heat_level = data.get("heat_level", "")
```

EventBus `.on()` passes an `Event` object, not a raw `dict`. The handler calls `.get()` on the `Event`, which raises `AttributeError`. Every LLE handler correctly does `data = event.data if hasattr(event, "data") else {}` — this handler missed that pattern.

**Fix:** Change parameter to `event: Any`, add `data = getattr(event, "data", {}) if not isinstance(event, dict) else event`

---

### V9-7 — HIGH — EVALUATE→LEARN Data Disconnect: `vulnerability_type` Set to Tool Name

**File:** `loop/autonomous_loop.py` L2468  
**Verified:** ✅ Confirmed

```python
vulnerability_type=ev.get("action_tool", "unknown"),  # "nuclei_scan" not "xss"
```

`_evaluate_with_llm` creates `FindingSummary` with `vulnerability_type` set to the **tool name** (e.g., "nuclei_scan", "xss_scan") instead of the actual vulnerability type. The `action_tool` field is the tool identifier.

**Impact:** Even if V9-4 were fixed and `_learn()` started using `new_findings`, the Bayesian prioritizer would receive tool names instead of vuln types: `record(vuln_type="nuclei_scan")` instead of `record(vuln_type="xss")`.

**Fix:** Use `ev.get("vulnerability_type") or ev.get("finding_type", "unknown")` instead of `ev.get("action_tool", "unknown")`

---

### V9-8 — HIGH — WAF/Cloud/Auth State Lost Every Iteration in `_observe()`

**File:** `loop/autonomous_loop.py` L979–993  
**Verified:** ✅ Confirmed

```python
self._world = WorldState(
    target_url=self._target,
    # ... no waf_detected, no cloud_provider, no auth_model
)
```

`_observe` creates a new `WorldState` every iteration without passing `waf_detected`, `cloud_provider`, or `auth_model`. Even if `inject_waf()` (L3020) sets WAF detection on the previous `_world`, the next `_observe()` call erases it. There are no persistent `self._waf_detected` or `self._cloud_provider` attributes.

**Impact:** WAF detection data is lost every iteration. `_think_with_hypothesis_engine` reads `world.waf_detected` as always-empty, so WAF-aware tool selection and payload adaptation never trigger. The scanner cannot avoid WAF detection patterns because it immediately forgets WAF was detected.

**Fix:** Add `self._waf_detected = ""` and `self._cloud_provider = ""` to `__init__`. Update `inject_waf()` to persist to `self._waf_detected`. Pass in `_observe()`: `waf_detected=self._waf_detected, cloud_provider=self._cloud_provider`.

---

### V9-9 — HIGH — AtlasNexus NEVER Activated in Runner Standalone Mode

**File:** `recon_dashboard/runner.py` (all 8672 lines)  
**Verified:** ✅ Confirmed — zero references to `atlas_nexus`, `AtlasNexus`

The `run()` method initializes LearningLoopEngine, UnifiedAttackGraph, ChainExecutionLoop, SynthesisTracer, but **never activates AtlasNexus**. Only `server.py` L689 (`_ensure_atlas_nexus()`) activates it. Every standalone/headless scan (CLI, test, any non-dashboard path) runs without Atlas.

**Impact:** All standalone scans have zero Atlas intelligence — no pattern recognition, no archetype matching, no Bayesian learning from recon events. The entire `atlas/` subsystem (~2500 lines) is dormant in headless mode.

**Fix:** Add `_ensure_atlas_nexus()` call in `run()` after LLE initialization.

---

### V9-10 — HIGH — Runner `abort()` Never Shuts Down ML Subsystems

**File:** `recon_dashboard/runner.py` abort path  
**Verified:** ✅ Confirmed via pattern search

The `abort()` method kills processes, stops sweeper/ETA/governor, cancels timers, cleans Docker — but never calls:
- `_learning_loop_engine.end_session()` (final Q-table update + persistence)
- `_stealth_orchestrator.shutdown()`
- `_decision_orchestrator.shutdown()`
- `_adaptive_chain_engine.shutdown()`
- AtlasNexus `deactivate()`

The normal `run()` completion path (L6700–6780) does call `end_session()`, but the abort path skips everything.

**Impact:** Aborted scans leak daemon threads (Atlas learning timer, stealth monitor), don't persist Q-table updates, and lose all accumulated learning for that session.

**Fix:** Add ML subsystem shutdown calls to `abort()`.

---

### V9-11 — HIGH — `fp_key` Computed But Never Used — Campaign Scoring Unscoped

**File:** `decision_orchestrator.py` L3543  
**Verified:** ✅ Confirmed

```python
fp_key = self._campaign_fingerprint.fingerprint_key()
campaign_score = self._campaign_outcome_tracker.get_campaign_score(
    role="pentester", context_key=action, exclude_target=ctx.get("target", ""),
)
# fp_key never passed to get_campaign_score()
```

The campaign fingerprint is computed but never scoped. Campaign scoring queries across **all** platforms instead of filtering by the current target's fingerprint.

**Impact:** Cross-target intelligence is unscoped — a WordPress vuln success rate inflates `P(success)` for a Java Spring target.

**Fix:** Pass `fingerprint_key=fp_key` to `get_campaign_score()`.

---

### V9-12 — HIGH — DecisionOrchestrator Has No atexit Handler — Adaptive Table Learning Lost

**File:** `decision_orchestrator.py` singleton factory  
**Verified:** ✅ Confirmed — no atexit registration

`AdaptiveTableLearner` accumulates EMA values for cost/impact/detection_risk (~860 lines of learning logic) with a `.save()` method, but nothing calls it on process exit. Contrast: LearningLoopEngine correctly registers `atexit` + `SIGTERM`.

**Impact:** All adaptive table learning from the current session is lost on clean or abnormal shutdown.

**Fix:** Add `atexit.register(lambda: _instance._adaptive_tables.save())` in `get_decision_orchestrator()`.

---

### V9-13 — HIGH — ExploitGraph `adjust_probabilities()` Never Called — Env Factors Ignored

**File:** `exploit_chains/exploit_graph.py`  
**Verified:** Via subagent

`adjust_probabilities(factors)` accepts environmental factors `{"waf_detected": True, "cloud_provider": "aws", ...}` and modifies transition weights. But zero production callers invoke it.

**Impact:** Exploit chain probability scores don't account for defensive posture, WAF presence, or cloud environment. Chain suggestions are blind to environmental factors.

**Fix:** Call `graph.adjust_probabilities(world_factors)` from the autonomous loop's OBSERVE or THINK phase.

---

### V9-14 — HIGH — ExploitGraph `get_chain_recommendations()` Never Called

**File:** `exploit_chains/exploit_graph.py`  
**Verified:** Via subagent

A sophisticated chain recommendation method that combines graph position, transition probabilities, and blast radius analysis exists but is never called from the autonomous loop, runner, or any decision path. The loop uses `suggest_chains()` from the simpler `StatefulAttackGraph` instead.

**Impact:** The exploit graph's most valuable output (chain recommendations) is never consumed. The decision-making system operates without exploit chain intelligence.

**Fix:** Integrate `get_chain_recommendations()` into `_think()` as a supplementary signal alongside DO's `recommend_actions()`.

---

### V9-15 — HIGH — `ATLAS_ARCHETYPE_MATCHED` / `ATLAS_STRATEGY_RECOMMENDED` Events Never Emitted

**File:** `atlas/atlas_nexus.py` L49–51  
**Verified:** Via subagent — no `_emit_event(ATLAS_ARCHETYPE_MATCHED, ...)` calls exist

The constants are defined and `scan_intelligence.py` (L2265, L2272) subscribes to them, but **no code anywhere emits these events**. AtlasNexus only emits `ATLAS_PATTERN_UPDATED` and `ATLAS_LEARNING_COMPLETE`.

**Impact:** ScanIntelligence never receives archetype/strategy events — cannot adapt scanning based on Atlas classification or strategy recommendations. Two EventBus subscribers are permanently dormant.

**Fix:** Emit `ATLAS_ARCHETYPE_MATCHED` in the archetype classification path and `ATLAS_STRATEGY_RECOMMENDED` in the strategy recommendation path inside AtlasNexus.

---

### V9-16 — HIGH — `create_engine_for_loop()` SDK Factory Doesn't Bind EventBus/LLE

**File:** `agents/copilot_sdk_engine.py`  
**Verified:** Via subagent  

The factory function that creates `CopilotAgenticEngine` instances for the copilot loop does NOT call `bind_event_bus()` or `bind_learning_engine()`. The engine operates without event emission or learning feedback.

**Impact:** SDK agent cycles (reconnaissance, exploitation, reporting) don't emit events and don't feed outcomes to the learning pipeline unless the caller manually binds these afterwards.

**Fix:** Add `engine.bind_event_bus(get_event_bus())` and `engine.bind_learning_engine(get_learning_loop_engine())` in the factory.

---

### V9-17 — HIGH — StealthOrchestrator `report_defense()` Has Zero External Callers

**File:** `stealth_orchestrator.py`  
**Verified:** Via subagent

`report_defense(defense_type, details)` is defined to feed WAF/rate-limit/CAPTCHA detection into the heat management system. But no tool executor, scanner, or HTTP handler calls it. The only heat sources are pre-programmed tool weights, not actual detection events.

**Impact:** Stealth heat level never escalates from real defense encounters. The scanner could be actively blocked by a WAF and the stealth system would remain at COOL. Defense adaptation is entirely theoretical.

**Fix:** Wire `report_defense()` into the HTTP execution layer when 403/429/challenges are received.

---

### V9-18 — HIGH — CognitiveBridge Quality Scoring Never Wired to FeedbackLearningEngine

**File:** `agents/cognitive_bridge.py`  
**Verified:** Direct consequence of V9-3

Even after fixing V9-3 (wrong enum members), the CognitiveBridge's `_record_event()` method calls `quality_mapper.get()` with the corrected event types, but the actual `FeedbackLearningEngine.record_quality()` call at L1160 references `self._feedback_engine` which is `None` (never bound via any setter).

**Impact:** Even after V9-3 fix, cognitive bridge quality metrics are computed but never reach the feedback learning system.

**Fix:** Add `bind_feedback_engine(engine)` method and call it during initialization.

---

### V9-19 — HIGH — MCP `_builtin_send_agent_feedback` Not in Tool Dispatch Chain

**File:** `mcp/mcp_server.py`  
**Verified:** Via subagent

The MCP tool `send_agent_feedback` is registered in the tool list but the handler `_builtin_send_agent_feedback` is NOT in the dispatch `match`/`if` chain inside `call_tool()`. Attempting to call this tool from an MCP client returns "Tool not found" or falls through to the unknown tool handler.

**Impact:** MCP clients cannot send agent feedback — the feedback loop from external tools back through the MCP protocol is broken.

**Fix:** Add the handler to the dispatch chain in `call_tool()`.

---

## MEDIUM Findings (22)

### V9-20 — MEDIUM — `_observe()` Doesn't Populate WorldState Strategic Fields

**File:** `loop/autonomous_loop.py` L982–993

`WorldState` has fields `risk_score`, `goal_mode`, `strategic_confidence`, `top_recommended_actions`, `attacker_position`, `subdomains`, `auth_model`. None are populated by `_observe()`. They all default to empty/zero. The `to_prompt_context()` method renders `top_recommended_actions` for the LLM, but since it's never populated, the "Strategic recommendations" section never appears in the prompt.

**Impact:** The LLM never sees strategic recommendations in the world state prompt, even when DO produces them.

---

### V9-21 — MEDIUM — `_observe()` Doesn't Feed DecisionOrchestrator World State

**File:** `loop/autonomous_loop.py` L965–1012

`_observe` feeds TMM (L1003) but never calls `DO.update_world_state()` or passes the world observation. DO is only queried in `_think` and fed outcomes in `_learn`, but it never receives the aggregate world picture.

**Impact:** DO's strategic recommendations are based on stale state — it knows per-action outcomes but not endpoint count, attack phase, stagnation level, or total findings.

---

### V9-22 — MEDIUM — `_tech_stack` Attribute Never Defined — Always Empty

**File:** `loop/autonomous_loop.py` L2391, L2448

```python
tech_stack=getattr(self, "_tech_stack", ""),
```

`_tech_stack` is never set on `self`. The actual data is in `self._technologies` (a list). The `getattr` fallback always returns `""`.

**Impact:** Doubt injection (OPP-3) and the arbitrator's doubt context never receive technology stack information. False positive analysis that depends on target tech stack operates blind.

**Fix:** Replace `getattr(self, "_tech_stack", "")` with `", ".join(self._technologies)`.

---

### V9-23 — MEDIUM — `_evaluate_with_llm` FindingSummary Missing endpoint/parameter

**File:** `loop/autonomous_loop.py` L2465–2472

LLM evaluation creates `FindingSummary` without setting `endpoint` or `parameter` fields (they default to `""`). Downstream consumers (TMM, ExploitGraph, signal extractor, adaptive chain engine) all receive empty endpoint/parameter.

**Impact:** Finding location information is lost in the LLM evaluation path, degrading chain analysis and deduplication.

---

### V9-24 — MEDIUM — Severity Count: "informational" vs "info" Key Mismatch

**File:** `loop/autonomous_loop.py` L974

```python
sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
```

The `_EVALUATE_SCHEMA` (L395) defines severity enum as `["critical", "high", "medium", "low", "informational"]`. Findings with `severity="informational"` never match the `"info"` key.

**Impact:** Informational findings are silently omitted from severity reporting.

**Fix:** Add `"informational": 0` to sev_counts or normalize: `key = "info" if key == "informational" else key`.

---

### V9-25 — MEDIUM — `inject_*` Methods Lack `_state_lock` Protection

**File:** `loop/autonomous_loop.py` L3006–3030

`inject_technologies()`, `inject_endpoints()`, `inject_waf()` mutate `_technologies`, `_endpoints`, and `_world` without holding `_state_lock`. These are called externally from the runner while the loop is running.

**Impact:** Race condition: runner calling `inject_endpoints` during `_observe`'s lock-held rebuild can cause `RuntimeError: list changed size during iteration`.

**Fix:** Acquire `self._state_lock` in each `inject_*` method.

---

### V9-26 — MEDIUM — `_complete_structured_stream` Missing UserSafeguards Check

**File:** `agents/llm_bridge.py` L1958–2000

Both `_complete()` and `_complete_structured()` run `user_safeguards.check_request_allowed()` before LLM calls. `_complete_structured_stream()` does not — it only checks rate limit.

**Impact:** Structured streaming requests bypass per-user quota enforcement. A runaway client can exhaust resources without hitting tenant limits.

---

### V9-27 — MEDIUM — `reset_global_bus()` Does Not Stop Async Worker Thread

**File:** `event_bus.py` L2452

`reset_global_bus()` calls `off_all()` but doesn't call `stop_async()`. If `start_async()` was called, the background dispatch thread keeps running after reset.

**Impact:** Thread leak on bus reset. In tests that call `reset_global_bus()`, orphaned threads accumulate.

**Fix:** Call `_global_bus.stop_async()` before `off_all()`.

---

### V9-28 — MEDIUM — `GRAPH_RESET` Event Defined But Never Emitted

**File:** `event_bus.py` L149, `recon_dashboard/event_bridge.py` L56

`BusEventType.GRAPH_RESET` has a subscriber (event_bridge for dashboard translation) but the CLI graph reset command calls `engine.graph.reset()` directly without emitting the bus event.

**Impact:** Dashboard shows stale graph nodes after CLI graph reset.

---

### V9-29 — MEDIUM — Stealth Events Not Re-Emitted to EventBus by Handlers

**File:** `stealth_orchestrator.py` L1372–1407

`_on_waf_detected()`, `_on_rate_limit()`, `_on_bot_challenge()` record signals internally but never emit events back to EventBus.

**Impact:** Dashboard, LearningLoop, DecisionOrchestrator are blind to stealth state changes. No subsystem outside StealthOrchestrator knows about defense encounters.

---

### V9-30 — MEDIUM — Stealth Intelligence Doesn't Reach ExploitGraph

**File:** `stealth_orchestrator.py` + `exploit_graph.py`

No code connects stealth heat (detection risk) to exploit graph transition scoring. `adjust_probabilities()` accepts `{"waf_detected": True}` but nobody feeds it from StealthOrchestrator.

**Impact:** Exploit graph suggests chains involving aggressive tools even when at BURNING heat.

---

### V9-31 — MEDIUM — CognitiveBridge `build_copilot_reasoning_context()` Dead Code

**File:** `agents/cognitive_bridge.py` L1197

The N-35 FIX method integrates `CopilotContextGenerator` into the cognitive bridge, but no production code calls it. Copilot uses older `build_findings_context()`/`build_guidance_context()` APIs exclusively.

**Impact:** CopilotContextGenerator enrichment feature exists but is unused.

---

### V9-32 — MEDIUM — CognitiveBridge Doesn't Consume ExploitGraph Position

**File:** `agents/cognitive_bridge.py`

`build_findings_context()` and `build_guidance_context()` don't include the attacker's current position from the exploit graph. `to_world_state_facts()` exists and is used by goal_planner but the cognitive bridge doesn't reference it.

**Impact:** Copilot strategic reasoning lacks attacker-position context (auth level, privilege level, data access).

---

### V9-33 — MEDIUM — MCP `_agent_sessions` Class-Level Dict Shadows Module-Level Dict

**File:** `mcp/mcp_server.py`

Both a module-level `_agent_sessions: dict = {}` and a class attribute `self._agent_sessions` exist. The class attribute shadows the module-level dict, creating confusion about session state scope.

**Impact:** Session lookup may return stale data if queries hit the wrong scope.

---

### V9-34 — MEDIUM — SDK Engine Non-Streaming Fallback Uses Hardcoded Token Divisor

**File:** `agents/copilot_sdk_engine.py`

Streaming path uses `self._chars_per_token`, but non-streaming fallback uses `// 4`. Token accounting is inconsistent.

**Impact:** Budget exhaustion check inaccurate in non-streaming mode — could under/over-count by ~15%.

---

### V9-35 — MEDIUM — SDK Engine `_goal_mode` Never Set — Always Empty

**File:** `agents/copilot_sdk_engine.py` L1538

```python
goal_mode=getattr(self, "_goal_mode", ""),
```

`_goal_mode` is never assigned. The `getattr` fallback always returns `""`.

**Impact:** Goal-mode-aware reward shaping in LearningLoopEngine is always in fallback mode for SDK findings.

---

### V9-36 — MEDIUM — Atlas `get_vuln_intel_boost()` Has Zero Call Sites

**File:** `atlas/atlas_nexus.py` L609–653

A 44-line method fusing CVE/EPSS/CVSS with Atlas pattern intelligence into a combined risk score. Zero callers.

**Impact:** EPSS+CVSS+Atlas fusion intelligence unavailable to all decision systems.

---

### V9-37 — MEDIUM — Atlas Nexus Never Emits `HEALTH_DEGRADED` on Breaker Trips

**File:** `atlas/atlas_nexus.py` L53

When the circuit breaker trips, only a counter is incremented and debug log emitted. No health degradation event fires.

**Impact:** Dashboard/monitoring never learns about Nexus circuit breaker problems.

---

### V9-38 — MEDIUM — MCP Tool Outcomes Bypass Atlas/EventBus

**File:** `mcp/mcp_server.py`

MCP's `call_tool()` feeds outcomes into LLE but not Atlas Nexus or EventBus. MCP-discovered findings never reach Atlas pattern learning.

**Impact:** MCP-driven vulnerability discoveries invisible to Atlas pattern recognition.

---

### V9-39 — MEDIUM — LLE `bind_atlas_store` Creates Fresh AtlasStore Instead of Singleton

**File:** `recon_dashboard/runner.py` L804–805

```python
engine.bind_atlas_store(AtlasStore())
```

Each call creates a fresh `AtlasStore()`. If AtlasStore opens SQLite connections, this creates competing connections with WAL contention.

**Impact:** Potential WAL contention on atlas.db; LLE may see inconsistent data.

---

### V9-40 — MEDIUM — `_calibration_engine` Never Declared in DO `__init__` — Race Condition

**File:** `decision_orchestrator.py` L3097

Created lazily by 3 different code paths using `getattr(self, "_calibration_engine", None)`. Two concurrent threads can both see None and create separate instances. One overwrites the other, losing trained calibration data.

**Fix:** Add `self._calibration_engine: Any = None` to `__init__()`.

---

### V9-41 — MEDIUM — `CognitiveBridge.apply_strategic_guidance()` Mutates Private `_quit` Attribute

**File:** `agents/cognitive_bridge.py` L968

When guidance_type is COMPLETE, the bridge sets `copilot_loop._quit = True` directly — bypassing the loop's termination protocol and unprotected by any lock.

**Impact:** If loop termination mechanism changes, this direct mutation breaks silently.

---

## LOW Findings (11)

### V9-42 — LOW — `_campaign_mode` Not Initialized in `__init__`

**File:** `loop/autonomous_loop.py` L729

First set inside `run()`, not in `__init__`. Code accessing before `run()` gets `AttributeError`.

---

### V9-43 — LOW — Double Heuristic Evaluation on LLM-Empty Result

**File:** `loop/autonomous_loop.py` L2128–2140

When LLM finds nothing, it internally calls `_evaluate_heuristic()` as fallback. Then `_evaluate()` calls it again unconditionally. Dedup prevents duplicates, but compute is wasted.

---

### V9-44 — LOW — `'scored' in dir()` is Fragile Local Variable Check

**File:** `loop/autonomous_loop.py` L733

`dir()` in function context is implementation-defined for checking locals. Should be `'scored' in locals()`.

---

### V9-45 — LOW — `_campaign_signal_bus` Attribute Initialized But Never Used

**File:** `decision_orchestrator.py` L1064

Declared as `None`, never set or read. Dead attribute.

---

### V9-46 — LOW — EventStore `close()` Doesn't Flush Ring Buffer

**File:** `event_bus.py` L716

`close()` closes file handle but `_buffer` deque is not flushed to disk. Events in ring buffer but not yet flushed are lost.

---

### V9-47 — LOW — WorkflowEngine Rules Scanned Linearly Per Event

**File:** `event_bus.py` L1500

Rule lookup iterates all rules per event. O(n) for large rule sets.

---

### V9-48 — LOW — SDK `run_agentic_assessment()` Sync Wrapper Dead Code

**File:** `agents/copilot_sdk_engine.py` L1687–1757

70-line function never called from any production path.

---

### V9-49 — LOW — SDK `run_compliance()` Dead Code

**File:** `agents/copilot_sdk_engine.py` L1173–1197

Compliance assessment path defined but never invoked.

---

### V9-50 — LOW — CognitiveBridge `get_probability_drift()`/`get_fusion_history()` Only Called From Tests

**File:** `agents/cognitive_bridge.py` L1187–1192

Observability methods exercised only in tests. No MCP tool, dashboard, or CLI exposes them.

---

### V9-51 — LOW — `import requests` and `import sqlite3` Unused in LLM Bridge

**File:** `agents/llm_bridge.py` L63–64

Both imported with `noqa: F401` but neither used anywhere in the file.

---

### V9-52 — LOW — SDK `_ws_drops` Not Initialized in `__init__`

**File:** `agents/copilot_sdk_engine.py` L586

Created via `getattr` fallback on first use rather than declared in `__init__()`.

---

## Priority Action Plan

### Priority 1 — CRITICAL Fixes (5 items, highest impact per line changed)

| V9-ID | Fix Description | Files | LOC |
|-------|----------------|-------|-----|
| V9-1 | `bus.subscribe()` → `bus.on()` | decision_orchestrator.py | 1 |
| V9-2 | `self._tool_ledger` → `self._ledger` | learning_loop_engine.py | 1 |
| V9-3 | Fix FusionEventType member names | cognitive_bridge.py | 2 |
| V9-4 | Wire `new_findings` into `_learn()` subsystem feeds | autonomous_loop.py | ~30 |
| V9-5 | Replace `.get()` with dataclass attribute access | autonomous_loop.py | 3 |

### Priority 2 — HIGH Fixes (14 items, significant impact)

| V9-ID | Fix Description | Files | LOC |
|-------|----------------|-------|-----|
| V9-6 | Fix handler Event param | decision_orchestrator.py | 3 |
| V9-7 | Use vulnerability_type not action_tool | autonomous_loop.py | 1 |
| V9-8 | Persist WAF/cloud in _observe | autonomous_loop.py | ~10 |
| V9-9 | Activate AtlasNexus in runner | runner.py | ~8 |
| V9-10 | Add ML shutdown to abort() | runner.py | ~15 |
| V9-11 | Pass fp_key to campaign scoring | decision_orchestrator.py | 1 |
| V9-12 | Add atexit for adaptive tables | decision_orchestrator.py | 5 |
| V9-13 | Call adjust_probabilities | autonomous_loop.py | ~5 |
| V9-14 | Call get_chain_recommendations | autonomous_loop.py | ~10 |
| V9-15 | Emit ATLAS_ARCHETYPE/STRATEGY events | atlas_nexus.py | ~10 |
| V9-16 | Bind EventBus/LLE in SDK factory | copilot_sdk_engine.py | 5 |
| V9-17 | Wire report_defense() callers | execution layer | ~10 |
| V9-18 | Bind FeedbackLearningEngine in CB | cognitive_bridge.py | ~5 |
| V9-19 | Add MCP feedback handler to dispatch | mcp_server.py | ~5 |

### Priority 3 — MEDIUM Fixes (22 items)
### Priority 4 — LOW Fixes (11 items)

---

## Quantitative Summary

| Metric | Value |
|--------|-------|
| Total Findings | **52** |
| CRITICAL | 5 |
| HIGH | 14 |
| MEDIUM | 22 |
| LOW | 11 |
| Files Affected | 13 |
| Prior Fixes (V2–V8) | 205 |
| Estimated Fix LOC | ~200 |
| Test Baseline | 376/376 passing |

---

## Cross-Reference: Systemic Patterns

### Pattern A — EVALUATE→LEARN Disconnection
V9-4 (new_findings ignored), V9-7 (vuln_type=tool_name), V9-5 (.get on dataclass), V9-23 (missing endpoint/parameter). The EVALUATE phase does sophisticated LLM arbitration, but LEARN phase throws it all away and uses raw tool output.

### Pattern B — Stealth Subsystem Dead End
V9-1 (bus.subscribe), V9-6 (handler crash), V9-17 (no report_defense callers), V9-29 (no re-emit), V9-30 (no graph feed). The stealth orchestrator is a complete island — no real input, no downstream output.

### Pattern C — Atlas Intelligence Island
V9-9 (not in runner), V9-15 (events never emitted), V9-36 (vuln intel boost unused), V9-37 (health degraded not emitted), V9-38 (MCP bypass). Atlas computes intelligence that nobody consumes.

### Pattern D — Wrong Attribute / Wrong Method Name (Silent Failures)
V9-1 (`subscribe` → `on`), V9-2 (`_tool_ledger` → `_ledger`), V9-3 (wrong enum members), V9-5 (`.get()` on dataclass), V9-22 (`_tech_stack` → `_technologies`). All caught by `except Exception` and silently converted to fallback behavior.
