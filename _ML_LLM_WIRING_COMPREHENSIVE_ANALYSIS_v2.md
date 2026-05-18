# ML & LLM Wiring — Comprehensive Analysis v2

> Full-scope audit of every ML/LLM subsystem, their interconnections,
> disconnections, bugs, and improvement opportunities.
>
> **v2**: Post-Phase 1–3 re-audit with expanded scope (160+ files, 10 ML
> algorithms, 11 architectural layers, 4 feedback loops).
>
> Generated: 2026-04-11

---

## Table of Contents

1. [System Architecture Map (Updated)](#1-system-architecture-map)
2. [Layer Inventory (11 layers, ~160 files)](#2-layer-inventory)
3. [ML Algorithm Catalog (10 algorithms)](#3-ml-algorithm-catalog)
4. [Wiring Matrix — 18 Integration Points](#4-wiring-matrix)
5. [Phase 1–3 Fix Verification](#5-phase-13-fix-verification)
6. [New Disconnections (8 items)](#6-new-disconnections)
7. [Bugs & Defects (20 items)](#7-bugs--defects)
8. [Feedback Loop Audit (4 loops: 2 open, 2 closed)](#8-feedback-loop-audit)
9. [Dead / Dormant Code](#9-dead--dormant-code)
10. [Silent Exception Audit](#10-silent-exception-audit)
11. [Import Graph & Architecture Integrity](#11-import-graph--architecture-integrity)
12. [Improvement Opportunities (Tiered)](#12-improvement-opportunities)
13. [Priority Action Plan — Phase 4+](#13-priority-action-plan)

---

## 1. System Architecture Map

```
┌──────────────────────────────── CaseCrack ML/LLM Architecture (Post-Phase 3) ────────────────────────┐
│                                                                                                       │
│  ┌──────────────── PROMPT LAYER ────────────────┐   ┌──────────── INTELLIGENCE LAYER ──────────────┐ │
│  │ PROMPT_TEMPLATES (14 types)                   │   │ UnifiedReasoningLayer                        │ │
│  │ PromptRegistry (versioning, A/B experiments)  │   │ TargetMentalModel → to_prompt_context()      │ │
│  │ PersonaEngine (attacker personas)             │   │ WorldModel → to_prompt_context()             │ │
│  │ FewShotSelector (TF-IDF episode retrieval)    │   │ HypothesisEngine (signal-driven reranking)   │ │
│  │ ProgressivePromptEngine (complexity scaling)  │   │ ScanIntelligence, ToolIntelligence           │ │
│  │ PromptSecurity (injection defense, canaries)  │   │ RAGContextEngine (TF-IDF + embedding) ← I-8 │ │
│  └──────────────────────┬───────────────────────┘   └────────────────────┬──────────────────────────┘ │
│                         │                                                 │                            │
│                         ▼                                                 ▼                            │
│  ┌─────────────── LLM BRIDGE (Central Hub) ──────────────────────────────────────────────────────┐   │
│  │  LLMBridge: prompt construction + routing + caching + security + streaming + tool calling      │   │
│  │  ├── ModelRouter (complexity → model selection, hardware-aware, fallback chains) ← I-7        │   │
│  │  ├── ResponseCache (hybrid memory+SQLite LRU) + ChainCache                                    │   │
│  │  ├── CostTracker (budget, rate limiting) + QualityScorer                                      │   │
│  │  ├── FeedbackLearningEngine (👍/👎 → storage only, NOT prompt injection) ← NEW-D1            │   │
│  │  ├── LLMTracer (OpenTelemetry spans)                                                          │   │
│  │  ├── MultiAgentDebateArena (Advocate/Skeptic/Arbiter) ← finding validation                    │   │
│  │  ├── NativeToolCallEngine (function calling) ← dashboard only, NOT autonomous loop            │   │
│  │  ├── ContextBudgetAllocator (slot-based budgeting) ← I-5 CONNECTED                           │   │
│  │  ├── WeightTuner context injection ← I-9 CONNECTED                                           │   │
│  │  └── GAP-3 Feedback augmentation ← CONNECTED                                                 │   │
│  └─────────────────────┬──────────────────────────────┬──────────────────────────────────────────┘   │
│                         │                              │                                              │
│           ┌─────────────┴──────────────┐               │                                              │
│           ▼                            ▼               ▼                                              │
│  ┌─── LLM PROVIDERS ──┐  ┌── LOCAL INFERENCE ──┐  ┌── CONSUMERS ────────────────────────────┐       │
│  │ OpenAIClient        │  │ InferenceEngine     │  │ llm_intelligence.py (7 functions)       │       │
│  │ AnthropicClient     │  │ OllamaBackend       │  │ llm_synthesizer.py (payload fallback)   │       │
│  │ OllamaClient        │  │ LlamaBackend (GGUF) │  │ routes_llm.py (HTTP API)                │       │
│  │ GitHubModelsClient  │  │ GPUGovernor         │  │ CognitiveBridge (Copilot MCP)           │       │
│  │ LocalLlamaClient    │  │ KVCacheManager      │  │ CopilotReasoningEngine                  │       │
│  │ MockClient          │  │ ModelManager         │  │ graph/reasoning/ (LangGraph subgraph)   │       │
│  └─────────────────────┘  └─────────────────────┘  └───────────────────────────────────────┘        │
│                                                                                                       │
│  ═══════════════════════════════════════════════════════════════════════════════════════════════════   │
│                                                                                                       │
│  ┌──────────── MACRO RL LAYER ──────────────┐   ┌──────────── MICRO PSE LAYER ──────────────────┐   │
│  │                                           │   │                                                │   │
│  │ LearningLoopEngine                        │   │ PayloadSynthesisEngine                         │   │
│  │ ├── ToolLedger (per-tool stats) ← PERSIST │   │ ├── PayloadArbiter (13-signal scoring)         │   │
│  │ ├── QTablePersistence (Q-values) ← PERSIST│   │ ├── WeightTuner (online ridge) ← I-1 PERSIST  │   │
│  │ ├── SessionEpochTrainer ← NO PERSIST      │   │ ├── GrammarForge, LLMSynthesizer, GeneticForge │   │
│  │ ├── StrategyEvolver                       │   │ ├── SynthesisFeedback (7-subsystem propagation) │   │
│  │ └── MetaTracker                           │   │ ├── FailurePatternExtractor + RAG ← I-8        │   │
│  │                                           │   │ ├── ContextCompiler                            │   │
│  │ RLRewardEngine (Q-learning)     ← PERSIST │   │ └── TemporalStabilityGuard                     │   │
│  │ BayesianPrioritizer (Thompson)  ← PERSIST │   │                                                │   │
│  │ AdaptiveLearner (bandits)                 │   │ ExploitGraph → WeightTuner ← I-4 CONNECTED     │   │
│  │                                           │   │                                                │   │
│  │       ╔═══════════════════════╗           │   │                                                │   │
│  │       ║ BRIDGE EXISTS (I-2)   ║ ←─────────┼───┤                                                │   │
│  │       ║ but singleton unused  ║           │   │                                                │   │
│  │       ╚═══════════════════════╝           │   │                                                │   │
│  └───────────────────────────────────────────┘   └────────────────────────────────────────────────┘   │
│                                                                                                       │
│  ┌──────── DECISION LAYER ──────────┐   ┌──────── EXECUTION LAYER ──────────────────────────────┐   │
│  │ DecisionOrchestrator              │   │                                                        │   │
│  │ ├── EV = P×impact×affinity-cost  │   │  Path A: AutonomousLoop (OODA) ← I-3 PSE CONNECTED    │   │
│  │ ├── ConfidenceCalibration ← LIVE │   │  ├── AIDirectedExecutor (tool commands)                │   │
│  │ ├── HypothesisEngine ← LIVE      │   │  ├── FeedbackLoopBreaker (anti-bias) ← WIRED          │   │
│  │ ├── ScanIntelligence ← LIVE      │   │  ├── ExplorationBiasInjector (anti-overfit) ← WIRED   │   │
│  │ ├── GoalPlanner ← LIVE           │   │  ├── PayloadEvolver (GA)                               │   │
│  │ └── CampaignIntelligence ← LIVE  │   │  ├── RAG context retrieval ← I-8 CONNECTED            │   │
│  │                                   │   │  └── WeightTuner context in prompts ← I-9 CONNECTED   │   │
│  │  ╔═══════════════════════════╗    │   │                                                        │   │
│  │  ║ record_outcome() EXISTS   ║    │   │  Path B: ScanRunner → FindingPipeline                  │   │
│  │  ║ but NOT called from       ║    │   │  ├── PSE feedback via pse_feedback_fn                  │   │
│  │  ║ finding verification UI   ║    │   │  └── ConfidenceCalibration via DecisionOrchestrator    │   │
│  │  ╚═══════════════════════════╝    │   │                                                        │   │
│  └───────────────────────────────────┘   │  Path C: Swarm Campaign ← I-10 ACTIVATED              │   │
│                                          │  ├── AgentSwarm (multi-target orchestrator)             │   │
│                                          │  ├── SharedWeightManager + MessageBus                   │   │
│                                          │  └── Dashboard route /api/swarm/start ← I-10           │   │
│                                          └────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Layer Inventory

### Layer 1: LLM Bridge (Central Hub) — 2 files
| File | Purpose |
|------|---------|
| `agents/llm_bridge.py` | Central LLM orchestrator — all LLM calls route through here |
| `llm_bridge.py` (root) | Backward-compat `__getattr__` proxy |

### Layer 2: Provider Clients — 1 file
| File | Providers |
|------|-----------|
| `agents/llm_clients.py` | OpenAI, Anthropic, Ollama, GitHub Models, LocalLlama, Mock |

### Layer 3: Routing & Hardware — 2 files
| File | Purpose |
|------|---------|
| `agents/llm_routing.py` | ModelRouter — complexity classification, fallback chains (I-7), NO quality feedback |
| `agents/llm_hardware_adapter.py` | GPU/CPU tier detection, purpose-based model selection |

### Layer 4: Types, Caching, Cost — 3 files
| File | Purpose |
|------|---------|
| `agents/llm_types.py` | `PromptType` (14), `PROMPT_TEMPLATES`, `LLMConfig`, `LLMResponse` |
| `agents/llm_cache.py` | `ResponseCache` (memory+SQLite LRU), `ChainCache` |
| `agents/llm_tracking.py` | `CostTracker`, `QualityScorer` |

### Layer 5: Security & Defense — 4 files
| File | Purpose |
|------|---------|
| `agents/prompt_security.py` | Sanitization, canary tokens, 39 role temperatures |
| `agents/llm_output_guard.py` | Per-role JSON schema validation (36 roles) — failures silent, never feed learning |
| `agents/llm_defense_hardening.py` | Injection alert aggregation, hard-block policy |
| `agents/llm_advanced_defense.py` | Novel injection detection, adversarial output detection |

### Layer 6: Observability & Operations — 5 files
| File | Purpose |
|------|---------|
| `agents/llm_tracing.py` | OpenTelemetry spans, correlation IDs |
| `agents/llm_ops.py` | Multi-region resilience, metrics, auto-tuner |
| `agents/llm_production.py` | 8 subsystems (health monitor, circuit breaker, secret vault, etc.) |
| `agents/llm_registry.py` | Lazy service locator singleton |
| `agents/llm_shutdown.py` | Ordered LIFO teardown |

### Layer 7: Adaptive Intelligence — 2 files
| File | Purpose |
|------|---------|
| `agents/llm_adaptive.py` | Intent feedback loop (EMA), adaptive compression, behavior profiles — not persisted |
| `agents/llm_intelligence.py` | 7 higher-order LLM functions (summaries, remediation, FP analysis) |

### Layer 8: Streaming & Tool Calling — 2 files
| File | Purpose |
|------|---------|
| `agents/streaming_structured.py` | Incremental JSON parser, progressive validation |
| `agents/native_tool_calling.py` | Native function calling for OpenAI/Anthropic/Ollama — dashboard only, NOT autonomous loop |

### Layer 9: RAG & Cognitive — 3 files
| File | Purpose |
|------|---------|
| `agents/rag_context.py` | Hybrid TF-IDF + semantic retrieval, RRF fusion, MMR diversity — I-8 broadened |
| `agents/cognitive_bridge.py` | Python↔Copilot bidirectional reasoning (MCP) |
| `agents/copilot_reasoning.py` | Copilot-as-Cognitive-Core structured prompts |

### Layer 10: Local Inference Stack — 9 files
| File | Purpose |
|------|---------|
| `inference/engine.py` | InferenceEngine facade, BackendType routing |
| `inference/ollama_backend.py` | Ollama HTTP backend |
| `inference/llama_backend.py` | Direct llama-cpp-python GGUF loading |
| `inference/model_manager.py` | HuggingFace download, validation, benchmarking — VRAM stubbed to 0 |
| `inference/gpu_governor.py` | Multi-vendor GPU detection, VRAM budgets |
| `inference/grammar.py` | JSON Schema → GBNF constrained generation |
| `inference/kv_cache.py` | Q4_0/Q8_0 KV cache quantization |
| `inference/setup_local_llm.py` | One-command auto-setup CLI |
| `inference/model_management/` | 6 files: registry, downloader, benchmarker, CLI, VRAM selector, finetune |

### Layer 11: ML / Scoring / Learning — 16+ files
| Subsystem | Files | Algorithms |
|-----------|-------|-----------|
| PSE Scoring | `payload_arbiter.py`, `weight_tuner.py` | Online Ridge Regression, 13-signal ranking |
| Macro RL | `learning_loop_engine.py`, `rl_reward_engine.py` | Tabular Q-Learning, ε-greedy |
| Bayesian | `bayesian_prioritizer.py`, `confidence_calibration.py` | Thompson Sampling, Beta-Binomial, Platt scaling |
| Adaptive | `adaptive_learning.py`, `adaptive_chain_engine.py` | Thompson Sampling + bandits, context-shift chaining |
| Feedback | `synthesis_feedback.py`, `feedback_learning.py` | Cross-system signal propagation, storage (not prompt injection) |
| Value | `value_scorer.py`, `chain_impact_scorer.py` | Multi-factor scoring |
| Genetic | `loop/payload_evolution.py` | GA mutation/crossover/selection |
| Decision | `decision_orchestrator.py` | EV scoring: P(success)×impact×affinity−cost×risk |

---

## 3. ML Algorithm Catalog

| # | Algorithm | File | Input | Output | Persistence | Output Consumed? |
|---|-----------|------|-------|--------|-------------|-----------------|
| 1 | **Online Ridge Regression** | `weight_tuner.py` | (13 signals, reward) | 13 blended weights | **Disk** (I-1) | ✅ Yes — prompt injection (I-9) |
| 2 | **Tabular Q-Learning** | `rl_reward_engine.py` | (state, action, reward) | Q-values, ε-greedy | **Disk** | ⚠️ Partial — stored but NOT used for action selection |
| 3 | **Thompson Sampling (Beta-Binomial)** | `bayesian_prioritizer.py` | (tech, vuln_type, outcome) | Ranked hypotheses | **Disk** (JSON) | ✅ Yes — hypothesis boosts |
| 4 | **Thompson Sampling + Bandits** | `adaptive_learning.py` | (scan_outcome, defense) | Test selection | **Disk** (SQLite) | ✅ Yes — copilot_loop, agent_loop |
| 5 | **Bayesian Calibration** | `confidence_calibration.py` | (prediction, ground_truth) | Recalibrated confidence | **Disk** | ⚠️ Partial — only P(success), not full EV |
| 6 | **Genetic Algorithm** | `loop/payload_evolution.py` | Payload population + fitness | Evolved population | **None** | ✅ Yes — autonomous loop |
| 7 | **EV Scoring** | `decision_orchestrator.py` | P(success), impact, affinity, cost | Ranked decisions | **None** | ⚠️ Advisory — limited callers (3 files) |
| 8 | **Chain Impact Scoring** | `chain_impact_scorer.py` | ExploitGraph transitions | Chain severity rankings | **None** | ✅ Yes — copilot_loop |
| 9 | **TF-IDF + Semantic Retrieval** | `rag_context.py` | Query + document corpus | Top-k context chunks | **Disk** (SQLite) | ✅ Yes — prompts (I-8) |
| 10 | **EMA Intent Learning** | `llm_adaptive.py` | Chat message stream | Intent weights | **None** | ⚠️ Limited — per-session only |

---

## 4. Wiring Matrix — 18 Integration Points

| # | From → To | Status | Evidence |
|---|-----------|--------|----------|
| 1 | LLMBridge → WeightTuner | ✅ **CONNECTED** (I-9) | `weight_context_for_prompt()` injected in both local + cloud paths |
| 2 | DecisionOrchestrator → LLMBridge | ⚠️ **By design** | Pure heuristic; no LLM calls |
| 3 | LearningLoopEngine → WeightTuner | ✅ **BRIDGED** (I-2) | Via LearningBridge.propagate() — BUT singleton `get_learning_bridge()` never called |
| 4 | FeedbackLearning → prompts | ❌ **BROKEN** | Feedback stored in DB but NEVER read back for prompt adaptation |
| 5 | RAG → autonomous loop | ✅ **CONNECTED** (I-8) | get_rag_engine() in all 3 prompt paths |
| 6 | RAG → PSE | ✅ **CONNECTED** (I-8) | RAG retrieval in _run_llm() for WAF bypass |
| 7 | RAG → runner (indexing) | ✅ **CONNECTED** (I-8) | index_findings() after graph completion |
| 8 | Swarm → runner | ✅ **ACTIVATED** (I-10) | run_swarm_campaign() + dashboard routes |
| 9 | AutonomousLoop → PSE | ✅ **CONNECTED** (I-3) | PSE accepted via dependency injection |
| 10 | WorldModel/MentalModel → prompts | ✅ **CONNECTED** | `to_prompt_context()` wired into THINK/ACT |
| 11 | ExploitGraph → WeightTuner | ✅ **CONNECTED** (I-4) | `_notify_weight_tuner()` with severity-based rewards |
| 12 | ConfidenceCalibration → decision | ⚠️ **PARTIAL** | Only calibrates P(success), not full EV formula |
| 13 | Q-values → action selection | ❌ **DISCONNECTED** | Q-table learned + persisted but NOT used for decisions |
| 14 | ModelRouter → quality feedback | ❌ **DISCONNECTED** | Router is stateless; zero quality signals |
| 15 | NativeToolCalling → autonomous loop | ❌ **DISCONNECTED** | Dashboard only; loop uses pure reasoning |
| 16 | OutputGuard → learning | ❌ **DISCONNECTED** | Validation failures not counted as quality signal |
| 17 | Finding verification → WeightTuner | ❌ **DISCONNECTED** | UI confirm/reject doesn't trigger weight learning |
| 18 | Finding verification → BayesianPrioritizer | ❌ **DISCONNECTED** | UI confirm/reject doesn't update priors |

---

## 5. Phase 1–3 Fix Verification

### Phase 1: Critical Fixes — 3/4 VERIFIED ✅, 1 INCOMPLETE ⚠️

| Fix | Status | Verification |
|-----|--------|--------------|
| **I-1: WeightTuner persistence** | ✅ PASS | `save()`/`load()` exist; `_try_load()` in `__init__`; `_maybe_auto_persist()` every 20 calibrations |
| **I-5: ContextBudgetAllocator** | ✅ PASS | Allocator imported, instantiated, `.allocate()` called in both local and cloud paths + autonomous loop |
| **I-7: Model fallback** | ✅ PASS | `resolve_model_with_fallback()` with provider-specific chains (gpt-4→gpt-4-turbo→gpt-3.5, etc.) |
| **I-6: Silent catch observability** | ⚠️ **INCOMPLETE** | decision_orchestrator.py: **7 of 8** except blocks still have silent `pass`; learning_loop_engine.py: **16 of 22** silent |

### Phase 2: Strategic Bridges — 3/3 VERIFIED ✅

| Fix | Status | Verification |
|-----|--------|--------------|
| **I-2: LearningBridge** | ✅ PASS | Propagation logic exists in LearningLoopEngine — but `get_learning_bridge()` singleton never called externally |
| **I-3: AutonomousLoop → PSE** | ✅ PASS | PSE injected via constructor parameter, stored as `self._pse` |
| **I-4: ExploitGraph → WeightTuner** | ✅ PASS | `_notify_weight_tuner()` with severity map + cascade depth bonus |

### Phase 3: Enhancement — 4/4 VERIFIED ✅

| Fix | Status | Verification |
|-----|--------|--------------|
| **I-8: Broaden RAG** | ✅ PASS | get_rag_engine() called in autonomous_loop (3 paths), PSE _run_llm(), runner.py indexing |
| **I-9: Weights → prompts** | ✅ PASS | weight_context_for_prompt(top_k=5) injected in both local + cloud LLMBridge paths |
| **I-10: Activate swarm** | ✅ PASS | run_swarm_campaign() in runner.py; routes + server registration verified |
| **I-11: MIN_OBSERVATIONS** | ✅ PASS | 3→13 with progressive ridge regularization |

### Residual Phase 1 Issue: I-6 Incomplete

**decision_orchestrator.py** — 7 silent except blocks at lines ~1447, 2776, 2803, 2839, 2880, 2986, 2996:
- Hypothesis engine binding failures → silent
- Quality feedback recording → silent  
- Session intelligence → silent
- Campaign intelligence → silent

**learning_loop_engine.py** — 16 of 22 except blocks silent (pass/continue without logging).

---

## 6. New Disconnections (8 items)

### NEW-D1: FeedbackLearning Stores But Never Applied [HIGH]

**Path:** User thumb-up/down → dashboard HTTP route → `FeedbackLearningEngine.store_feedback()` → SQLite DB → **DEAD END**

The engine stores feedback to disk but nothing ever reads it back to modify future prompts. `get_quality_stats()` exists for reporting, but no online adaptation occurs.

**Impact:** Every user correction is logged and ignored. The system never learns from explicit human feedback.

**Fix:** Wire `FeedbackLearningEngine.query_similar()` into `llm_bridge.py` prompt assembly — prepend negative examples from feedback DB when generating similar prompts.

---

### NEW-D2: Q-Values Learned But Not Used for Decisions [HIGH]

**Path:** RL episodes → `RLRewardEngine.observe()` → Q-table → `QTablePersistence.save()` → disk → **NEVER READ FOR ACTION SELECTION**

Q-values are computed, stored, and loaded across sessions. But no decision path reads `get_q_value(state, action)` to choose actions. The learning loop records Q-values as observations, not as directives.

**Impact:** Tabular Q-learning runs continuously but is purely observational — it never influences which tool or vulnerability type gets selected next.

**Fix:** In `autonomous_loop._think_with_llm()`, inject Q-table top actions as context: "High-value actions for current state: [tool_x on vuln_y: Q=0.87]".

---

### NEW-D3: ModelRouter Has Zero Quality Feedback [MEDIUM]

**Path:** Model selection → provider → response → **NO FEEDBACK TO ROUTER**

ModelRouter tracks failed API calls (cooldown), but never receives:
- Hallucination rates per model
- Token efficiency (cost per quality)
- Latency profiles
- Schema validation pass/fail rates

**Impact:** Model selection is always rule-based, never adapts based on actual response quality. Same model tier used regardless of quality history.

**Fix:** Add `ModelRouter.record_quality(model_id, score, latency_ms)` — after each LLM call, rate the response quality. Implement EMA tracking per model, use scores to adjust routing preferences.

---

### NEW-D4: OutputGuard Failures Don't Feed Learning [MEDIUM]

**Path:** LLM response → schema validation → strip/fix → **NO SIGNAL**

When OutputGuard detects schema violations (extraneous fields, wrong types), it logs at DEBUG level and silently fixes. This information never reaches:
- ModelRouter (to downrank models that produce bad JSON)
- ConfidenceCalibration (to reduce trust in that model's outputs)
- CostTracker (to account for wasted tokens)

**Impact:** Models that consistently produce malformed output get no negative signal, so they're selected just as often.

**Fix:** Add `OutputGuard.get_violation_stats()` → feed to ModelRouter quality tracking.

---

### NEW-D5: Finding Verification Not Feeding ML [HIGH]

**Path:** Dashboard UI → finding status change (open → confirmed / false_positive) → `findings_store.update_status()` → **NO ML PROPAGATION**

When a user confirms or rejects a finding:
- ❌ WeightTuner doesn't learn which signals predicted the correct outcome
- ❌ BayesianPrioritizer doesn't update (tech, vuln_type) priors
- ❌ ConfidenceCalibration's `record_outcome()` is NOT called from the verification flow
- ❌ HypothesisEngine doesn't learn which hypotheses were validated

**Impact:** The richest learning signal in the system (human ground truth) is completely wasted. All ML models remain blind to verification outcomes.

**Fix:** In `findings_store.update_status()`, emit an event that propagates to all 4 ML subsystems.

---

### NEW-D6: ExploitGraph Learned Weights Don't Flow Back [MEDIUM]

**Path:** ExploitGraph → `_notify_weight_tuner()` → WeightTuner learns → **weights stuck in WeightTuner, not used by graph**

The I-4 fix wired findings into WeightTuner. But learned signal importance never flows back to adjust graph transition probabilities. `suggest_next_tests()` ranking remains static.

**Impact:** One-way intelligence flow; the graph discovers chains and feeds learning, but its own recommendations don't improve.

**Fix:** Periodic sync: `WeightTuner.get_current_weights()` → `ExploitGraph.update_transition_priors(weights)`.

---

### NEW-D7: Calibration Loop Incomplete [MEDIUM]

**Path:** hypothesis → `record_prediction(id, raw_confidence)` → calibration engine → `record_outcome()` exists at decision_orchestrator.py:1773 → **BUT only from DecisionOrchestrator, not from finding verification UI**

The calibration engine can learn from ground truth, but the only caller is the internal decision path. The richer signal from human finding verification never reaches calibration.

Additionally, calibrated confidence only affects P(success) in the EV formula (~20-30% of the score). The other components (impact, affinity, cost, detection_risk, graph_bonus) are all hardcoded.

**Fix:** Wire finding verification outcomes to `calibration_engine.record_outcome()`. Also calibrate impact multipliers over time.

---

### NEW-D8: LearningBridge Singleton Unused [LOW]

**Path:** `get_learning_bridge()` defined at learning_bridge.py:606 → **ZERO CALLERS**

The singleton factory was built but never adopted. PSE creates its own LearningBridge instance internally. Cross-PSE-instance sharing (useful in multi-scan scenarios) is impossible.

**Impact:** Low in single-scan mode. In multi-target campaigns (swarm), each scan creates a separate bridge, so learned intelligence doesn't flow between targets through this path (though RAG provides an alternative sharing mechanism).

**Fix:** In `run_swarm_campaign()`, create a shared LearningBridge singleton and pass to each swarm agent.

---

## 7. Bugs & Defects (20 items)

### Critical (3)

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| B-1 | **I-6 incomplete: 23+ silent `except Exception: pass`** in decision-critical paths | decision_orchestrator.py (7), learning_loop_engine.py (16) | Subsystem failures invisible; system makes uninformed decisions |
| B-2 | **FeedbackLearning stores but never reads** — human 👍/👎 written to DB, never applied to prompt adaptation | `feedback_learning.py` → nowhere | User corrections completely ignored |
| B-3 | **Finding verification outcomes don't feed ANY ML system** — richest signal wasted | `findings_store.update_status()` → no propagation | All ML models blind to ground truth |

### High (5)

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| B-4 | **Q-values computed but never used for action selection** | `rl_reward_engine.py` Q-table → not consumed | Q-learning is purely observational |
| B-5 | **NativeToolCallEngine not in autonomous loop** — loop uses pure reasoning, no tool execution | `native_tool_calling.py` → only llm_bridge dashboard chat | Autonomous mode can't invoke tool functions |
| B-6 | **Thinking budget injection can exceed context window** — `_inject_thinking_budget()` adds budget to `max_tokens` without validating | `llm_bridge.py:277-286` | Large thinking + small model → API error |
| B-7 | **VRAM tracking stubbed to 0** — `vram_used_mb=0` TODO | `model_manager.py:624` | GPU memory management blind |
| B-8 | **ExploitVerifier class orphaned** — defined but never imported in production | `exploit_chains/exploit_verifier.py` | Verification capability disconnected |

### Medium (7)

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| B-9 | **ModelRouter has zero quality feedback** — stateless, no learning from response quality | `llm_routing.py` | Model choice never adapts to quality |
| B-10 | **OutputGuard validation failures silent** — stripped fields never counted as quality signal | `llm_output_guard.py` | Bad-JSON models get no negative signal |
| B-11 | **ExploitGraph weights one-way** — learned weights don't flow back to graph transitions | `exploit_graph.py` | Graph recommendations static |
| B-12 | **Calibration only affects P(success)** — 70-80% of EV formula uncalibrated | `decision_orchestrator.py` | Impact, cost, affinity hardcoded |
| B-13 | **EMA intent weights not persisted** — chat intent classification restarts every session | `llm_adaptive.py` | Minor re-learning overhead |
| B-14 | **SessionEpochTrainer lacks persistence** — session learnings lost between runs | `learning_loop_engine.py` | Session-specific patterns not retained |
| B-15 | **get_learning_bridge() singleton never called** — factory exists but unused | `learning_bridge.py:606` | Cross-scan sharing impossible |

### Low (5)

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| B-16 | **PromptRegistry A/B variant selection underutilized** — only prompt_chains uses resolve() | `prompt_registry.py` | Most prompts bypass experiment logic |
| B-17 | **agents/__init__.py empty** — no re-exports, requires deep imports | `agents/__init__.py` | Ergonomic issue |
| B-18 | **exploit_chains/ missing __init__.py** (or has minimal exports) | `exploit_chains/` | Classes only via full path |
| B-19 | **DecisionOrchestrator.recommend() has only 3 callers** — advisory system underadopted | `decision_orchestrator.py` | Rich EV scoring not used in main paths |
| B-20 | **Shim chain adds import indirection** — 7 backward-compat shim files | Root-level `*.py` shims | Marginal confusion |

---

## 8. Feedback Loop Audit (4 loops: 2 open, 2 closed)

### Loop 1: PSE Synthesis Feedback — ✅ CLOSED

```
Payload synthesized → execution → outcome observed
    ↓
SynthesisFeedbackCollector.record_feedback()
    ├─→ WeightTuner.observe()         ← learns signal importance
    ├─→ GeneticForge.inject_fitness() ← evolves population
    ├─→ WAFAdaptive (Thompson)        ← adapts bypass strategy
    ├─→ HypothesisEngine              ← boosts/kills hypotheses
    ├─→ UnifiedReasoning              ← records outcome
    ├─→ CampaignIntelligence          ← cross-target signal
    └─→ StateMachine (if bound)       ← intent progression
```

**Verdict:** 7-way fan-out, properly closed. All 7 consumers verified.

---

### Loop 2: Macro RL Learning — ✅ CLOSED (but limited downstream)

```
Tool executed → outcome → reward computed
    ↓
LearningLoopEngine.record_tool_outcome()
    ├─→ ToolLedger.record()           ← per-tool win rate
    ├─→ RLRewardEngine.observe()      ← Q-value update
    ├─→ SessionEpochTrainer           ← session patterns
    ├─→ StrategyEvolver               ← tool rankings
    └─→ LearningBridge.propagate()    ← macro→micro bridge
```

**Issue:** Q-values are updated but never read for action selection. StrategyEvolver updates rankings but these are advisory. The loop is technically closed but its output isn't actionable.

---

### Loop 3: Human Feedback — ❌ OPEN

```
User gives 👍/👎 in dashboard chat
    ↓
HTTP route → FeedbackLearningEngine.store_feedback()
    ↓
SQLite DB  ← feedback stored here
    ↓
╔════════════════════════════════════╗
║ NOBODY READS IT BACK              ║
║ No prompt adaptation              ║
║ No quality signal to model router ║
║ No learning from corrections      ║
╚════════════════════════════════════╝
```

**Impact:** The most expensive signal (human expert judgment) is captured and wasted.

---

### Loop 4: Finding Verification — ❌ OPEN

```
Finding discovered → displayed in dashboard
    ↓
User clicks "Confirm" or "False Positive"
    ↓
findings_store.update_status()  ← status stored
    ↓
╔════════════════════════════════════════════════╗
║ NO propagation to:                             ║
║ - WeightTuner (should adjust signal weights)   ║
║ - BayesianPrioritizer (should update priors)   ║
║ - ConfidenceCalibration (should record outcome) ║
║ - HypothesisEngine (should validate/kill)      ║
║ - ModelRouter (should rate model accuracy)      ║
╚════════════════════════════════════════════════╝
```

**Impact:** Ground truth — the most reliable learning signal — never feeds back into any ML model.

---

## 9. Dead / Dormant Code

### Previously Dead, Now Activated (Phase 3)

| Subsystem | Status Change | Evidence |
|-----------|--------------|----------|
| **`swarm/`** | DEAD → **ACTIVATED** (I-10) | `run_swarm_campaign()` + dashboard routes |
| **`rag_context.py`** | Dashboard-only → **BROADENED** (I-8) | Now in autonomous loop, PSE, runner |
| **WeightTuner persistence** | None → **DISK** (I-1) | save/load/auto-persist every 20 calibrations |

### Still Dead / Orphaned

| Module | Files | Status | Evidence |
|--------|-------|--------|----------|
| **ExploitVerifier** | `exploit_chains/exploit_verifier.py` | **ORPHANED** | No external callers in production code |
| **AI/ML Scanner Engines** | `ai_ml/*.py` (~5 engines) | **ORPHANED** | LLMDataExfiltration, AIAPIProxy, PromptInjection, ModelEndpoint, RAGPipeline — only in tests |
| **get_learning_bridge() singleton** | `learning_bridge.py:606` | **UNUSED FACTORY** | Defined but zero callers |
| **FeedbackLearning → prompt adaptation** | `feedback_learning.py` read path | **DEAD END** | Stores to DB, nothing reads back |
| **ContextBudgetAllocator fallback path** | `llm_bridge.py` except ImportError | **DEAD CODE** | Import at module level means except never triggers |

### Partially Dormant

| Module | Status | Evidence |
|--------|--------|----------|
| **Q-table action selection** | Observational only | Q-values computed but NOT used to choose actions |
| **DecisionOrchestrator.recommend()** | Advisory only | Only 3 callers; not mandatory in primary execution paths |
| **PromptRegistry A/B experiments** | Underutilized | Only prompt_chains calls `resolve()`; most prompts bypass |
| **NativeToolCallEngine** | Dashboard only | Not wired into autonomous loop |

---

## 10. Silent Exception Audit

### Quantitative Summary

| File | Total except | With Logging | Silent (pass/continue/return) |
|------|-------------|--------------|-------------------------------|
| `decision_orchestrator.py` | 21 | 14 | **7 silent** |
| `learning_loop_engine.py` | 22 | 6 | **16 silent** |
| `autonomous_loop.py` | 29 | 19 | 10 (at-load pragmas) |
| `exploit_graph.py` | ~15 | ~12 | **~3 silent** |
| `llm_bridge.py` | 20+ | 8 | **12+ silent** |
| `payload_synthesis_engine.py` | 11 | 8 | **3 silent** |
| **Total** | **118+** | **67** | **51+ silent (43%)** |

### Highest-Risk Silent Blocks

These are in decision-critical paths where silent failure means uninformed decisions:

1. **decision_orchestrator.py** — hypothesis engine binding, quality feedback, session intelligence, campaign intelligence (7 blocks)
2. **learning_loop_engine.py** — reward computation, Q-table updates, bridge propagation (16 blocks)
3. **llm_bridge.py** — defense hardening, feedback injection, budget allocation fallbacks (12+ blocks)

### Recommendation

Add at minimum `logger.debug("subsystem X failed: %s", exc)` to all 51 silent blocks. For decision-critical paths (hypothesis, calibration, reward), escalate to `logger.warning()`.

---

## 11. Import Graph & Architecture Integrity

### Top-Level Import Graph (ML Components)

```
                    ┌─────────── PayloadSynthesisEngine ───────────┐
                    │ imports: WeightTuner, GrammarForge,           │
                    │   LLMSynthesizer, GeneticForge, Arbiter,     │
                    │   SynthesisFeedback, RAG (I-8)               │
                    └──────────┬────────────────────────────────────┘
                               │
                               ▼
┌──────────────┐    ┌─────────────────────┐    ┌────────────────────────┐
│ WeightTuner  │◄───│ LearningBridge      │───►│ LearningLoopEngine     │
│ (singleton)  │    │ (macro↔micro)       │    │ ├── ToolLedger          │
│ persist: ✅   │    │ singleton: NOT USED │    │ ├── QTablePersistence   │
└──────┬───────┘    └─────────────────────┘    │ ├── RLRewardEngine      │
       │                                         │ └── StrategyEvolver     │
       ▼                                         └────────────┬───────────┘
┌──────────────┐    ┌─────────────────────┐                   │
│ LLM Bridge   │    │ AutonomousLoop      │◄──────────────────┘
│ (I-9 inject) │    │ (I-3: PSE wired)    │
│ (I-5 budget) │    │ (I-8: RAG wired)    │
│ (I-8 RAG)    │    │ (FeedbackBreaker ✅)│
└──────────────┘    │ (ExplorationBias ✅) │
                    │ (ValueScorer ✅)     │
                    └─────────────────────┘

┌──────────────────────────────────┐
│ DecisionOrchestrator             │
│ ├── ConfidenceCalibration ← ✅   │
│ ├── HypothesisEngine ← ✅        │
│ ├── BayesianPrioritizer ← ✅     │
│ ├── CampaignIntelligence ← ✅    │
│ └── recommend() ← 3 callers only│
└──────────────────────────────────┘
```

### __init__.py Re-Export Status

| Package | Has __init__.py | Re-exports | Assessment |
|---------|----------------|------------|------------|
| `loop/` | ✅ Yes | 15+ classes | ✅ Good API surface |
| `agents/` | ✅ Yes | Empty file | ⚠️ Deep imports required |
| `exploit_chains/` | ✅ Yes | Minimal | ⚠️ Deep imports required |
| `swarm/` | ✅ Yes | Partial | ⚠️ Missing some exports |
| `inference/` | ✅ Yes | Good | ✅ Functional |

### Circular Import Risk

All potentially circular pairs use **lazy imports** (inside functions or under `TYPE_CHECKING`):

| Pair | Safety Mechanism |
|------|-----------------|
| decision_orchestrator ↔ learning_loop_engine | Both use local `from` inside methods |
| exploit_graph ↔ exploit_chains subtypes | Forward refs + TYPE_CHECKING |
| llm_bridge ↔ agents submodules | Module-level imports with try/except |

**Verdict:** No active circular import risk detected.

---

## 12. Improvement Opportunities (Tiered)

### Phase 4 — Critical Feedback Loop Closure

#### I-12: Close Finding Verification → ML Loop [CRITICAL]

When a finding is confirmed or rejected in the dashboard:

1. **WeightTuner:** Extract the payload's 13 signals → `observe(signals, reward=+1.0 or -0.5)`
2. **BayesianPrioritizer:** `record(tech_stack, vuln_type, outcome=True/False)`
3. **ConfidenceCalibration:** `record_outcome(prediction_id, ground_truth=True/False)`
4. **HypothesisEngine:** Kill or boost the hypothesis that generated the finding

**Implementation:** Add event emission in `findings_store.update_status()` → fan-out to all 4 systems.

#### I-13: Close Human Feedback → Prompt Loop [CRITICAL]

Wire `FeedbackLearningEngine` read path into `llm_bridge.py`:

1. On each LLM call, query `feedback_learning.query_similar(role, context_hash)`
2. If negative feedback found for similar queries, prepend "Avoid: [previous bad output]"
3. If positive feedback found, prepend "Good example: [previous good output]"

#### I-14: Wire Q-Values Into Decision Context [HIGH]

In `autonomous_loop._think_with_llm()`, add a `qtable_decision_section`:

```python
if rl_engine:
    top_actions = rl_engine.get_top_actions(current_state, top_k=5)
    qtable_decision_section = "## Q-Learning Recommendations\n"
    for action, q_val in top_actions:
        qtable_decision_section += f"- {action}: Q={q_val:.3f}\n"
```

This makes Q-learning prescriptive, not just observational.

#### I-15: Complete I-6 Silent Catch Remediation [HIGH]

Add logging to all 51 silent except blocks across 6 critical files:
- `decision_orchestrator.py`: 7 blocks
- `learning_loop_engine.py`: 16 blocks
- `llm_bridge.py`: 12+ blocks
- `exploit_graph.py`: 3 blocks
- `payload_synthesis_engine.py`: 3 blocks

### Phase 5 — Model Intelligence

#### I-16: ModelRouter Quality Tracking [MEDIUM]

Add to ModelRouter:
- `record_quality(model_id, quality_score, latency_ms, token_count)`
- EMA tracking per model (exponential moving average)
- Quality-weighted routing: prefer models with higher EMA scores
- Automatic downranking of models with >20% validation failures

#### I-17: OutputGuard → Quality Signal [MEDIUM]

When OutputGuard strips/fixes schema violations:
- Increment per-model violation counter
- Feed violation rate to ModelRouter quality tracking
- Log at INFO level (not DEBUG) for high violation rates

#### I-18: NativeToolCalling in Autonomous Loop [MEDIUM]

Wire `NativeToolCallEngine` into `_think_with_llm()`:
- Parse tool calls from LLM response
- Execute via `ToolCallEngine.execute_tool_calls()`
- Inject tool results back into conversation for follow-up reasoning

### Phase 6 — Architecture Polish

#### I-19: Shared LearningBridge in Swarm [LOW]

In `run_swarm_campaign()`:
- Create a single LearningBridge singleton via `get_learning_bridge()`
- Pass it to each swarm agent so cross-target intelligence flows bidirectionally

#### I-20: Calibrate Full EV Formula [LOW]

Extend ConfidenceCalibration to track impact, cost, and affinity accuracy:
- Record predicted vs actual impact for confirmed findings
- Track actual tool cost vs estimated cost
- Learn affinity multipliers from (goal, vuln_type) success rates

#### I-21: ExploitGraph Bidirectional Weights [LOW]

Periodic sync: `WeightTuner.get_current_weights()` → `ExploitGraph.adjust_transition_probabilities()`
- Boost transitions through vulnerability types that have high weight correlation
- Prune low-probability transitions more aggressively

#### I-22: Activate AI/ML Scanner Engines [LOW]

Wire the 5 orphaned AI/ML scanner engines into the scanning pipeline:
- LLMDataExfiltration, AIAPIProxy, PromptInjection, ModelEndpoint, RAGPipeline
- These exist with tests but are never loaded by the scanner registry

---

## 13. Priority Action Plan — Phase 4+

### Phase 4: Close Open Feedback Loops (5 items)

| Priority | Item | Fixes | Impact |
|----------|------|-------|--------|
| **P0** | I-12: Finding verification → ML | B-3, NEW-D5, NEW-D7 | Ground truth feeds all ML models |
| **P0** | I-13: Human feedback → prompts | B-2, NEW-D1 | User corrections actually applied |
| **P0** | I-14: Q-values → decision context | B-4, NEW-D2 | Q-learning becomes prescriptive |
| **P1** | I-15: Complete silent catch remediation | B-1 | 51 silent failures become visible |
| **P1** | I-12 extended: ExploitVerifier integration | B-8 | Verification logic reconnected |

### Phase 5: Model Intelligence (3 items)

| Priority | Item | Fixes |
|----------|------|-------|
| **P2** | I-16: ModelRouter quality tracking | B-9, NEW-D3 |
| **P2** | I-17: OutputGuard → quality signal | B-10, NEW-D4 |
| **P2** | I-18: NativeToolCalling in loop | B-5 |

### Phase 6: Architecture Polish (4 items)

| Priority | Item | Fixes |
|----------|------|-------|
| **P3** | I-19: Shared LearningBridge in swarm | B-15, NEW-D8 |
| **P3** | I-20: Calibrate full EV formula | B-12 |
| **P3** | I-21: ExploitGraph bidirectional weights | B-11, NEW-D6 |
| **P3** | I-22: Activate AI/ML scanner engines | Dormant code |

---

## Quantitative Summary

| Metric | v1 (Pre-Phase 1) | v2 (Post-Phase 3) | Delta |
|--------|-------------------|---------------------|-------|
| **Total ML/LLM files** | ~160 | ~160 | +0 |
| **Wired files** | ~150 | ~155 | +5 |
| **Dead/orphaned files** | ~10 | ~5 | -5 (swarm, RAG activated) |
| **Integration points (wiring matrix)** | 10 | 18 | +8 (finer granularity) |
| **Connected integrations** | 4/10 | 10/18 (56%) | Improved |
| **Disconnected integrations** | 6/10 | 8/18 (44%) | 8 new gaps found |
| **Feedback loops** | 2 closed, 2 open | 2 closed, 2 open | Unchanged |
| **ML algorithms** | 10 | 10 | +0 |
| **Algorithms with consumed output** | 5/10 | 7/10 | +2 (WeightTuner, RAG) |
| **Bugs cataloged** | 12 | 20 | +8 new |
| **Silent except blocks** | Unknown | 51+ (of 118) | Now quantified |
| **Tests passing** | 345/345 | 345/345 | Stable |

---

## LLM Bridge Prompt Section Inventory (9 sections)

The complete system prompt assembly order (verified in both local and cloud paths):

| # | Section | Source | Always Present? |
|---|---------|--------|----------------|
| 1 | Base template + scan metadata | `PROMPT_TEMPLATES[role]` | ✅ Yes |
| 2 | Key findings summary | `findings_summary` | ✅ Yes (may be empty) |
| 3 | Exploit graph state | `exploit_graph_prompt` | ✅ Yes (may be empty) |
| 4 | Context details | `deep_context` | ✅ Yes |
| 5 | Available tools | `tool_list_text` | ✅ Yes |
| 6 | Chat history | `history_text` | ✅ Yes |
| 7 | GAP-3: Feedback augmentation | `FeedbackLearningEngine.query_similar()` | ⚠️ Conditional |
| 8 | I-9: ML signal intelligence | `weight_context_for_prompt()` | ⚠️ Conditional (needs MIN_OBSERVATIONS) |
| 9 | I-5: Budget allocation | `ContextBudgetAllocator.allocate()` | ✅ Yes (with fallback) |

---

*End of analysis. 345/345 tests passing. 8 new disconnections mapped. 20 bugs cataloged. 11 improvement items prioritized across 3 phases.*
