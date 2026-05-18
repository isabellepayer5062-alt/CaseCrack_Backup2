# 🧠 ACTION LOOP GAP — Comprehensive Analysis

**Date:** 2026-04-13  
**Scope:** Why CaseCrack is an adaptive orchestrator, not yet an adaptive researcher  
**Method:** Full code-level audit of the execution pipeline across 15+ files, 3000+ lines read

---

## Executive Summary

CaseCrack's intelligence stack has three layers:

| Layer | Status | Evidence |
|-------|--------|----------|
| **Decision** (what to do next) | ✅ Excellent | AdaptiveExplorationPolicy, Thompson Sampling, budget shaping — 81 tests |
| **Prioritization** (in what order) | ✅ Excellent | PhasePriorityQueue composite scoring, evidence-tier sorting, cluster arms |
| **Explanation** (why it matters) | ✅ Excellent | AttackGraphNarrativeDriver, evidence-gated chain summaries, decision telemetry |
| **Execution** (how to actually do it) | 🔴 **Static** | Predefined commands, no mid-scan adaptation, broken feedback loops |

**The gap:** Every tool invocation uses hardcoded arguments determined at phase start. No tool modifies its behavior based on what another tool discovered mid-scan. The system executes a **predetermined plan with adaptive ordering**, not an **adaptive plan with adaptive execution**.

---

## 1. Current Architecture — The 6-Layer Delegation Stack

```
┌─────────────────────────────────────────────────────────────────┐
│  AdaptiveExplorationPolicy  (decides WHICH phase)         ✅   │
│  ↓                                                              │
│  BudgetController  (decides HOW MUCH time/parallelism)    ✅   │
│  ↓                                                              │
│  ReconPipeline._run_sequential()  (executes phases)       🟡   │
│  ↓                                                              │
│  Helper modules (subdomain.py, dns_intel.py, etc.)        🔴   │
│  ↓                                                              │
│  subprocess.run([tool, "-d", domain, "-silent", "-json"]) 🔴   │
│  ↓                                                              │
│  Output parsed → findings → next phase (NO FEEDBACK)      🔴   │
└─────────────────────────────────────────────────────────────────┘
```

### What happens at each layer:

**Layer 1-2 (Adaptive):** The policy uses a 5-factor weighted composite (DI-EV×0.35 + uncertainty×0.25 + Thompson×0.20 + backpressure×0.10 + inertia×0.10) to select the next phase. Budget is shaped by priority score and backpressure. **This is genuinely sophisticated.**

**Layer 3 (Semi-static):** `recon_pipeline.py` executes stages. It passes a `ctx` object between stages, but stages never READ ctx to adapt their own behavior. Each stage receives ctx but ignores what previous stages discovered.

**Layer 4-5 (Fully static):** Helper modules construct hardcoded subprocess commands:
```python
# subdomain_external.py L88-110 — ALWAYS identical args
proc = subprocess.run(
    [exe, "-d", domain, "-silent", "-json"],
    capture_output=True, text=True, timeout=timeout,
)

# amass — ALWAYS passive, even if passive returned zero results
proc = subprocess.run(
    [exe, "enum", "-d", domain, "-passive", "-json", tmp_path],
    ...
)
```

**Layer 6 (Broken):** Output is collected and stored, but NOTHING feeds back to modify the next invocation.

---

## 2. The Five Broken Feedback Loops

### 2.1 — Payload Synthesis → Execution → (NOTHING)

**Files:** `payload_synthesis_engine.py`, `synthesis_feedback.py`, `genetic_forge.py`

The PayloadSynthesisEngine has a sophisticated 5-stage pipeline:
1. Grammar synthesis → 30 payloads  
2. LLM synthesis (if grammar confidence < 0.70) → 5 payloads  
3. GeneticForge evolution → GA-ranked payloads  
4. PayloadArbiter scoring → 8-signal weighting  
5. ExecutionScheduler → ordered execution  

**The break:** After payloads execute, `record_feedback()` is defined on `SynthesisFeedbackCollector` (synthesis_feedback.py L228) and propagates to 7 subsystems. **But the GeneticForge propagation is a no-op:**

```python
# synthesis_feedback.py L342-360
def _propagate_to_genetic_forge(self, event: FeedbackEvent) -> None:
    """GeneticForge does not have a per-event fitness injection API;
    it consumes feedback indirectly through HypothesisEngine boosts
    and WAFAdaptive arm stats when evolve() is called."""
    if self._genetic_forge is None:
        return
    if hasattr(self._genetic_forge, "inject_fitness_signal"):
        self._genetic_forge.inject_fitness_signal(...)
    # No other direct API — GeneticForge learns via its bindings
```

And `genetic_forge.py` `evolve()` (L416) takes `(context, grammar_seeds, generations, mutation_biases)` — **no `execution_feedback` parameter**. The GA population is frozen at generation time and never receives real-time fitness signals from execution.

**Impact:** Payloads that work brilliantly get the same weight as payloads that get WAF-blocked. The system never learns "this payload pattern succeeds against this target."

```
CURRENT:
  Synthesis → Payloads → Execute → Feedback Collected → DEAD END
                                                          ↑
  Next Synthesis starts fresh ─── NO CONNECTION ──────────┘

NEEDED:
  Synthesis ← Feedback ← Execution
     ↑                     ↑
     └── GA Re-ranks ──────┘
```

### 2.2 — Phase Execution → (NO INTER-PHASE ADAPTATION)

**File:** `recon/recon_pipeline.py` L770+

```python
# _run_sequential() — each stage gets ctx but IGNORES prior results
for stage_name in self._stages:
    self._execute_stage_handler(stage_name)  # Static invocation
```

**What should happen (but doesn't):**
- If subdomain enumeration discovers 200+ subdomains → DNS brute should use a smaller wordlist (already covered)
- If WAF is detected in crawl results → all subsequent scanners should use evasion mode
- If parameter discovery finds `?debug=1` → vulnerability scanners should prioritize debug endpoints
- If port scanning reveals non-standard ports → endpoint discovery should scan those ports

**What actually happens:** Each stage runs its predefined command regardless of what previous stages found. The budget multiplier is computed once at phase start and never updated.

### 2.3 — Chain Verification → (NO TECHNIQUE PIVOTING)

**File:** `chain_executor.py` L680-800

When a chain step fails:
```python
# chain_executor.py L774-789
elif result.outcome == StepOutcome.FAILURE:
    if result.propagated_data:
        propagated_data.update(result.propagated_data)
    consecutive_failures += 1
    if consecutive_failures >= _CONSECUTIVE_FAILURE_LIMIT:
        chain_broken = True  # ← Chain just GIVES UP
```

**What should happen:** If step 2 gets a 403 WAF block, the system should:
1. Try alternative encoding (base64, hex, double-URL)
2. Try evasion (header mutation, TLS fingerprint change)
3. Try alternative technique (if SQLi blocked, try NoSQLi)

**What actually happens:** Two consecutive failures → chain abandoned. No alternatives attempted.

### 2.4 — WAF Detection → (NO EXECUTION ADAPTATION)

**Files:** `scanners/waf_adaptive.py`, `testing_tools/evasion_engine.py`

These are **fully implemented** but **completely disconnected:**

| Module | Capability | Integration |
|--------|-----------|-------------|
| `waf_adaptive.py` | Thompson Sampling bandit for WAF bypass mutation selection | **0 callers** from execution path |
| `evasion_engine.py` | TLS fingerprint randomization, browser impersonation, timing jitter, 24 mutation operators | **0 callers** from execution path |

The evasion engine has a `benchmark_evasion(target)` that picks the optimal profile — but it's only called at init (if at all), never re-evaluated when results change.

### 2.5 — LLM Intelligence → (NO COMMAND MODIFICATION)

**Files:** `agents/llm_bridge.py`, `decision_orchestrator.py`

The LLM bridge returns `Analysis`, `Explanation`, `Finding` — all read-only insights. **No method** for:
- `suggest_tool_parameters()` ✗
- `recommend_phase_order()` ✗  
- `modify_command_template()` ✗

The `DecisionOrchestrator.RankedDecision` has `action` (string) and `probability_success`, but **no `execution_directives`** field. LLM analysis is consumed by the narrative/report layer but never flows back to tool invocation.

---

## 3. What "Adaptive Execution Shaping" Actually Means

### 3.1 — The OODA Loop Assessment

| Phase | Status | Evidence |
|-------|--------|----------|
| **OBSERVE** | ✅ Working | StepEvidence captures: status, headers, body, timing (chain_executor.py L583-610) |
| **ORIENT** | ⚠️ Static pattern matching | VERIFICATION_STRATEGIES regex dict — no trend analysis, no "last 3 payloads all got 403" detection |
| **DECIDE** | ❌ Missing | No threshold-based adaptation; decision_framework.py is post-hoc measurement only |
| **ACT** | ❌ Missing | All execution follows predetermined plan; no mid-execution plan mutation |

### 3.2 — Concrete Examples of What's Missing

**Example 1: Dynamic Payload Modification Mid-Scan**
```
CURRENT:
  XSS payload <script>alert(1)</script> → 403 WAF block
  XSS payload <img onerror=alert(1)> → 403 WAF block  
  XSS payload <svg onload=alert(1)> → 403 WAF block
  → All 30 payloads tried with same encoding → 30 × 403 → FAIL

NEEDED:
  XSS payload <script>alert(1)</script> → 403 WAF block
  [ORIENT: WAF detected, <script> blocked]
  [DECIDE: Switch to event-handler evasion]
  XSS payload <img src=x onerror=alert(1)> → 403  
  [ORIENT: Event handlers also blocked]
  [DECIDE: Try encoding mutation + non-standard events]  
  XSS payload <details open ontoggle=alert(1)> → 200 ✅
```

**Example 2: Fuzzing Strategy Evolution**
```
CURRENT:
  ffuf -w wordlist.txt -u https://target/FUZZ → 10,000 requests → 3 hits
  [Done. Next phase.]

NEEDED:
  ffuf batch 1 (1000 words) → hits on /api/v1, /api/v2, /internal
  [ORIENT: API prefix pattern detected]
  [DECIDE: Expand API-prefixed wordlist, prune non-API words]
  ffuf batch 2 (500 words, API-focused) → hits on /api/v1/admin, /api/v1/debug
  [ORIENT: Admin/debug paths exist behind /api/v1/]
  [DECIDE: Deep-fuzz /api/v1/ with admin-focused wordlist]
  ffuf batch 3 (200 words, /api/v1/ prefix, admin-focused) → /api/v1/admin/users ✅
```

**Example 3: Exploit Technique Auto-Pivot**
```
CURRENT:
  SQLi on /search?q= → WAF blocks all payloads → FAIL
  [Chain broken. Moving to next finding.]

NEEDED:
  SQLi on /search?q= → WAF blocks standard payloads
  [ORIENT: WAF blocking SQLi signatures in 'q' parameter]
  [DECIDE: Try blind SQLi via timing]
  SQLi blind timing: /search?q=1' AND SLEEP(5)-- → Response: 5.2s ✅
  [ORIENT: Blind SQLi confirmed via timing]
  [DECIDE: Extract data via time-based blind]
```

---

## 4. Root Cause — Architectural Mismatch

The system was designed as a **pipeline** (linear flow), not a **loop** (iterative flow):

```
CURRENT ARCHITECTURE (Pipeline):
  Phase 1 → Phase 2 → Phase 3 → ... → Phase N → Report
  [each phase is an independent batch operation]

NEEDED ARCHITECTURE (Loop):
  Phase N → Execute → Observe → Orient → Decide → {
    Continue Phase N with modified params, OR
    Insert new micro-phase, OR  
    Skip remaining phases, OR
    Pivot technique entirely
  }
```

### 4.1 — The Pipeline Model

```python
# This is what the system does today:
for phase in selected_phases:
    budget = budget_controller.compute(phase)  # Computed ONCE
    result = execute_phase(phase, budget)       # Static execution
    store_results(result)                        # Results stored
    # NOTHING reads result before next phase
```

### 4.2 — The Adaptive Loop Model (What's Needed)

```python
# This is what the system SHOULD do:
for phase in adaptive_sequence():
    budget = budget_controller.compute(phase, prior_results)
    
    for batch in phase.batches():
        result = execute_batch(batch)
        
        # INTRA-PHASE ADAPTATION:
        orientation = orient(result)  # "WAF blocking", "high miss rate", etc.
        if orientation.requires_adaptation:
            batch.adapt(orientation)  # Modify next batch's params
            
        # INTER-PHASE ADAPTATION:
        if result.suggests_new_phase:
            adaptive_sequence.inject(result.suggested_phase)
        if result.invalidates_planned_phase:
            adaptive_sequence.skip(result.invalidated_phase)
```

---

## 5. Inventory of Built-But-Unwired Infrastructure

These subsystems exist, are tested, and work — but have zero callers in the execution path:

### 5.1 — WAF Adaptive (waf_adaptive.py)
- **What it does:** Thompson Sampling bandit selection for WAF bypass mutations
- **Reward signals:** BYPASSED=1.0, SOFT_BYPASS=0.6, BLOCKED=-0.3, RATE_LIMITED=-0.1
- **24 mutation operators** available
- **Status:** ❌ Zero callers from execution pipeline
- **Wiring needed:** Before each HTTP request in chain_executor.py, query the bandit for the optimal mutation. After response, update the arm.

### 5.2 — Evasion Engine (evasion_engine.py)
- **What it does:** TLS fingerprint randomization (JA3/JA4), browser impersonation (Chrome/Firefox/Safari/Edge), request timing jitter, header ordering mutation, connection pooling
- **Status:** ❌ Zero callers from execution pipeline
- **Wiring needed:** Wrap all HTTP requests through evasion_engine.request() instead of raw requests.session.request()

### 5.3 — Synthesis Feedback Collector (synthesis_feedback.py)
- **What it does:** Routes execution results to 7 subsystems (WAF, GA, Hypothesis, Campaign, Reasoning, StateMachine, WeightTuner)
- **Status:** ⚠️ Partially wired — record_feedback() works but GA propagation is a no-op
- **Wiring needed:** 
  1. Make GA propagation real (inject_fitness_signal → actual population update)
  2. Call record_feedback() after every chain step execution
  3. Feed execution_history into next synthesize_payloads() call

### 5.4 — LLM Synthesizer (llm_synthesizer.py)
- **What it does:** Generates payloads given target context + prior attempts + known bypasses
- **Status:** ⚠️ Generates payloads but never receives execution feedback
- **Wiring needed:** After execution batch, feed results back as `PRIOR ATTEMPTS` for next batch

### 5.5 — Dynamic Chain Engine (dynamic_chain.py)
- **What it does:** Has AdaptationType enum: INJECT_STEPS, REMOVE_STEPS, REORDER_STEPS, MODIFY_PARAMS, SWITCH_RISK, ADD_CHAIN
- **Status:** ⚠️ Types defined but no ON_FAILURE_SWITCH_TECHNIQUE adaptation
- **Wiring needed:** When chain_executor hits consecutive failures, query dynamic_chain for technique alternatives

---

## 6. Gap Severity Matrix

| Gap ID | Description | Severity | Effort | Impact |
|--------|-------------|----------|--------|--------|
| **G1** | GA fitness never updated from execution results | 🔴 Critical | ~30 lines | Payload evolution dead |
| **G2** | Chain executor has no technique fallback on failure | 🔴 Critical | ~50 lines | Exploit chains brittle |
| **G3** | Phases don't adapt based on prior phase results | 🔴 Critical | ~60 lines | Inter-phase intelligence wasted |
| **G4** | WAF Adaptive bandit never consulted during execution | 🟡 High | ~40 lines | 24 mutation operators unused |
| **G5** | Evasion Engine never wraps HTTP requests | 🟡 High | ~40 lines | TLS/header evasion dead code |
| **G6** | Fuzzing wordlists are static, never adapted | 🟡 High | ~50 lines | 10,000 requests when 500 would do |
| **G7** | LLM never modifies tool command parameters | 🟡 High | ~80 lines | LLM intelligence stops at the report |
| **G8** | Budget multiplier computed once, never re-evaluated | 🟠 Medium | ~20 lines | Time budget can't respond to discoveries |
| **G9** | Execution Scheduler never reschedules based on latency  | 🟠 Medium | ~30 lines | vendor_latency_ema collected but unused |
| **G10** | record_feedback() called but propagation to GA is no-op | 🟠 Medium | ~20 lines | Feedback infrastructure→dead end |

---

## 7. Concrete Wiring Plan

### Phase A — Close the Feedback Loop (G1, G10, G3)
**Goal:** Make execution results actually change the next execution.

#### A1: Wire GA Fitness Injection (G1 + G10)
**File:** `genetic_forge.py` — Add `inject_fitness_signal(payload_str, fitness_delta)` that updates the population member's fitness score in the current generation.

**File:** `synthesis_feedback.py` L342 — Replace the no-op GA propagation with a real call:
```python
def _propagate_to_genetic_forge(self, event):
    if self._genetic_forge is None:
        return
    self._genetic_forge.inject_fitness_signal(
        payload=event.payload.payload,
        fitness_delta=event.reward_signal * 0.2,
    )
```

**File:** `payload_synthesis_engine.py` — Add `execution_feedback` parameter to `_run_forge()` so the GA starts with prior-execution biases.

#### A2: Wire Inter-Phase Adaptation (G3)
**File:** `recon_pipeline.py` — Before each stage, build an `AdaptiveStageContext` from previous results:
```python
def _adapt_stage_config(self, stage_name, ctx):
    """Read prior results to shape this stage's execution."""
    config = {}
    if ctx.waf_detected and stage_name in VULN_SCAN_STAGES:
        config["evasion_mode"] = True
    if ctx.discovered_params and stage_name == "param_fuzzing":
        config["priority_params"] = ctx.discovered_params[:20]
    if len(ctx.subdomains) > 200 and stage_name == "dns_brute":
        config["wordlist_size"] = "small"  # Already well-covered
    return config
```

### Phase B — Add Technique Pivoting (G2, G4, G5)
**Goal:** When a technique fails, try alternatives instead of giving up.

#### B1: Chain Executor Fallback Resolver (G2)
**File:** `chain_executor.py` — After `StepOutcome.FAILURE`, before marking chain_broken:
```python
if result.outcome == StepOutcome.FAILURE:
    # Try alternative technique before giving up
    alt_strategy = _find_alternative_strategy(finding_type, result.evidence)
    if alt_strategy and retry_count < MAX_ALTERNATIVES:
        result = self._step_verifier.verify_step_with_strategy(
            step, propagated_data, alt_strategy
        )
```

#### B2: Wire WAF Adaptive into Chain Executor (G4)
**File:** `chain_executor.py` L585 (before HTTP request) — Consult the bandit:
```python
if self._waf_adaptive:
    mutation = self._waf_adaptive.select_mutation(
        vendor=waf_vendor, attack_type=finding_type
    )
    headers, url, body = mutation.apply(headers, url, body)
```

#### B3: Wire Evasion Engine (G5)
**File:** `chain_executor.py` L585 — Replace raw `self._session.request()` with:
```python
if self._evasion_engine:
    resp = self._evasion_engine.request(method, url, headers=headers, ...)
else:
    resp = self._session.request(method, url, headers=headers, ...)
```

### Phase C — Adaptive Fuzzing (G6)
**Goal:** Make wordlists evolve based on discovered patterns.

#### C1: Pattern-Aware Wordlist Adaptation
**File:** `param_discovery.py` — After brute-force batch 1:
```python
def _adapt_wordlist(self, found_params, original_wordlist):
    """Generate focused wordlist based on discovered parameter patterns."""
    prefixes = set()
    for p in found_params:
        if '_' in p:
            prefixes.add(p.split('_')[0])
    # Generate variations for discovered patterns
    adapted = [
        f"{prefix}_{suffix}"
        for prefix in prefixes
        for suffix in common_suffixes
    ]
    return adapted + original_wordlist[:500]
```

### Phase D — LLM-Guided Execution (G7)
**Goal:** Let the LLM actually modify tool parameters.

#### D1: LLM Execution Directive
**File:** `llm_bridge.py` — Add method:
```python
def suggest_execution_params(self, phase_name, prior_results, target_context):
    """Return tool parameter suggestions based on analysis."""
    # Returns: {"wordlist_bias": "api-focused", "depth": 3, ...}
```

**File:** `recon_pipeline.py` — Before stage execution, query LLM:
```python
if self._llm_bridge:
    params = self._llm_bridge.suggest_execution_params(
        stage_name, ctx.summary(), target_context
    )
    stage_config.update(params)
```

---

## 8. Priority Implementation Order

```
                    EFFORT →
              Low (20-30 LOC)    Medium (40-60 LOC)    High (80+ LOC)
           ┌─────────────────┬────────────────────┬──────────────────┐
  IMPACT   │ A1: GA Fitness   │ B1: Fallback       │ D1: LLM-Guided   │
  Critical │ Injection        │ Resolver           │ Execution        │
  ↑        │ [G1, G10]        │ [G2]               │ [G7]             │
           ├─────────────────┼────────────────────┼──────────────────┤
           │ G8: Budget       │ B2: WAF Adaptive   │ C1: Adaptive     │
  High     │ Re-eval          │ [G4]               │ Fuzzing          │
           │                  │ B3: Evasion Engine │ [G6]             │
           │                  │ [G5]               │                  │
           ├─────────────────┼────────────────────┼──────────────────┤
  Medium   │ G9: Reschedule   │ A2: Inter-Phase    │                  │
           │                  │ Adaptation [G3]    │                  │
           └─────────────────┴────────────────────┴──────────────────┘
```

**Recommended order:**
1. **A1** (GA Fitness Injection) — 30 LOC, closes the most critical dead loop
2. **B1** (Fallback Resolver) — 50 LOC, makes exploit chains non-brittle
3. **B2+B3** (WAF Adaptive + Evasion) — 80 LOC combined, activates 24 mutation operators
4. **A2** (Inter-Phase Adaptation) — 60 LOC, makes phases aware of each other
5. **C1** (Adaptive Fuzzing) — 50 LOC, eliminates 90% of wasted fuzzing requests
6. **D1** (LLM-Guided Execution) — 80 LOC, biggest architectural shift

---

## 9. What Changes Per Fix

| Fix | Before | After |
|-----|--------|-------|
| A1 | Payloads ranked by pre-execution scoring | Payloads evolved by real execution results |
| B1 | Chain fails at step 2 → entire chain abandoned | Chain retries with alternative technique → continues |
| B2+B3 | Every HTTP request identical regardless of WAF | Requests mutated per target's WAF fingerprint |
| A2 | DNS brute runs 100K words even with 200 subdomains found | DNS brute adapts wordlist size based on prior coverage |
| C1 | Fuzzing with static 10K wordlist every time | Wordlist focused after batch 1 based on discovered patterns |
| D1 | LLM writes reports about what tools SHOULD have done | LLM modifies what tools WILL do next |

---

## 10. The "Adaptive Researcher" Test

The system passes the "adaptive researcher" test when it can demonstrate:

| Capability | Test | Current | After Fixes |
|-----------|------|---------|-------------|
| **Payload learning** | Run same vuln type on 3 targets; 3rd target should have better payloads | ❌ Same payloads every time | ✅ GA-evolved payloads informed by prior targets |
| **Technique pivot** | Hit a WAF on SQLi; system should try blind, then encoding, then NoSQL | ❌ Chain breaks after 2 failures | ✅ Automatic fallback through technique alternatives |
| **Fuzzing convergence** | On a target with /api/* pattern; wordlist should converge to API paths | ❌ Same static wordlist | ✅ Adaptive wordlist after batch 1 |
| **WAF evasion** | Target behind Cloudflare; requests should use CF-specific mutations | ❌ Generic HTTP requests | ✅ WAF-adaptive Thompson Sampling mutations |
| **Cross-phase awareness** | If WAF detected in crawl, scanners should use evasion | ❌ Scanners ignorant of crawl results | ✅ AdaptiveStageContext propagates WAF detection |
| **LLM-shaped execution** | LLM analysis of "Java Spring" target → nuclei focuses on Spring templates | ❌ LLM analysis only in report | ✅ LLM directs tool parameters |

---

## 11. Summary Diagram — Current vs Target

```
CURRENT STATE ("Adaptive Orchestrator"):
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Decide  │───→│  Budget  │───→│ Execute  │───→│  Report  │
│  (smart) │    │ (smart)  │    │ (static) │    │ (smart)  │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
                                     ↓
                              [results stored]
                              [never fed back]

TARGET STATE ("Adaptive Researcher"):
┌──────────┐    ┌──────────┐    ┌──────────┐
│  Decide  │←──→│  Budget  │←──→│ Execute  │
│  (smart) │    │ (smart)  │    │ (SMART)  │
└──────────┘    └──────────┘    └────┬─────┘
      ↑              ↑               │
      │              │          ┌────┴─────┐
      │              │          │ Observe  │
      │              │          │ Orient   │
      │              │          │ Decide   │
      │              │          │ Adapt    │
      │              │          └────┬─────┘
      │              │               │
      └──────────────┴───────────────┘
                [continuous feedback loop]
```

**Bottom line:** All the mechanical infrastructure is built.  The intelligent layer is built.  The gap is a ~350-LOC wiring job spread across 6 files to connect the two.
