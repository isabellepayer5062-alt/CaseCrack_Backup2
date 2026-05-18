# ML & LLM Wiring — Comprehensive Analysis

> Full-scope audit of every ML/LLM subsystem, their interconnections,
> disconnections, bugs, and improvement opportunities.
>
> Generated: 2026-04-11

---

## Table of Contents

1. [System Architecture Map](#1-system-architecture-map)
2. [Layer Inventory (11 layers, ~95 files)](#2-layer-inventory)
3. [ML Algorithm Catalog](#3-ml-algorithm-catalog)
4. [Wiring Matrix — 10 Critical Integration Points](#4-wiring-matrix)
5. [Disconnections (4 Critical)](#5-disconnections)
6. [Bugs & Defects (12 items)](#6-bugs--defects)
7. [Dead / Dormant Code](#7-dead--dormant-code)
8. [Improvement Opportunities](#8-improvement-opportunities)
9. [Priority Action Plan](#9-priority-action-plan)

---

## 1. System Architecture Map

```
┌─────────────────────────────────── CaseCrack ML/LLM Architecture ────────────────────────────────────┐
│                                                                                                       │
│  ┌──────────────── PROMPT LAYER ────────────────┐   ┌──────────── INTELLIGENCE LAYER ──────────────┐ │
│  │ PROMPT_TEMPLATES (14 types)                   │   │ UnifiedReasoningLayer                        │ │
│  │ PromptRegistry (versioning, A/B experiments)  │   │ TargetMentalModel → to_prompt_context()      │ │
│  │ PersonaEngine (attacker personas)             │   │ WorldModel → to_prompt_context()             │ │
│  │ FewShotSelector (TF-IDF episode retrieval)    │   │ HypothesisEngine (signal-driven reranking)   │ │
│  │ ProgressivePromptEngine (complexity scaling)  │   │ ScanIntelligence, ToolIntelligence           │ │
│  │ PromptSecurity (injection defense, canaries)  │   │ RAGContextEngine (TF-IDF + embedding)        │ │
│  └──────────────────────┬───────────────────────┘   └────────────────────┬──────────────────────────┘ │
│                         │                                                 │                            │
│                         ▼                                                 ▼                            │
│  ┌─────────────── LLM BRIDGE (Central Hub) ──────────────────────────────────────────────────────┐   │
│  │  LLMBridge: prompt construction + routing + caching + security + streaming + tool calling      │   │
│  │  ├── ModelRouter (complexity → model selection, hardware-aware)                                │   │
│  │  ├── ResponseCache (hybrid memory+SQLite LRU) + ChainCache                                    │   │
│  │  ├── CostTracker (budget, rate limiting) + QualityScorer                                      │   │
│  │  ├── FeedbackLearningEngine (👍/👎 → prompt augmentation) ← CONNECTED                        │   │
│  │  ├── LLMTracer (OpenTelemetry spans)                                                          │   │
│  │  ├── MultiAgentDebateArena (Advocate/Skeptic/Arbiter)                                         │   │
│  │  └── NativeToolCallEngine (function calling for OpenAI/Anthropic/Ollama)                      │   │
│  └─────────────────────┬──────────────────────────────────┬──────────────────────────────────────┘   │
│                         │                                  │                                          │
│           ┌─────────────┴──────────────┐                   │                                          │
│           ▼                            ▼                   ▼                                          │
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
│  │ ├── QTablePersistence (Q-values) ← PERSIST│   │ ├── WeightTuner (ridge regression) ← NO SAVE  │   │
│  │ ├── SessionEpochTrainer                   │   │ ├── GrammarForge, LLMSynthesizer, GeneticForge │   │
│  │ ├── StrategyEvolver                       │   │ ├── SynthesisFeedback (closed loop)            │   │
│  │ └── MetaTracker                           │   │ ├── FailurePatternExtractor                    │   │
│  │                                           │   │ ├── ContextCompiler                            │   │
│  │ RLRewardEngine (Q-learning)     ← PERSIST │   │ └── TemporalStabilityGuard                     │   │
│  │ BayesianPrioritizer (Thompson)  ← PERSIST │   │                                                │   │
│  │ AdaptiveLearner (bandits)                 │   │ ExploitGraph → topology only, no weight learn   │   │
│  │                                           │   │                                                │   │
│  │       ╔══════════════╗                    │   │                                                │   │
│  │       ║ NO BRIDGE !! ║ ←──────────────────┼───┤                                                │   │
│  │       ╚══════════════╝                    │   │                                                │   │
│  └───────────────────────────────────────────┘   └────────────────────────────────────────────────┘   │
│                                                                                                       │
│  ┌──────── DECISION LAYER ──────────┐   ┌──────── EXECUTION LAYER ──────────────────────────────┐   │
│  │ DecisionOrchestrator              │   │                                                        │   │
│  │ ├── EV = P×impact×affinity-cost  │   │  Path A: AutonomousLoop (OODA)                         │   │
│  │ ├── ConfidenceCalibration ← LIVE │   │  ├── AIDirectedExecutor (tool commands)                │   │
│  │ ├── HypothesisEngine ← LIVE      │   │  ├── FeedbackLoopBreaker (anti-bias)                   │   │
│  │ ├── ScanIntelligence ← LIVE      │   │  ├── ExplorationBiasInjector (anti-overfit)            │   │
│  │ └── GoalPlanner ← LIVE           │   │  ├── PayloadEvolver (GA)                               │   │
│  │                                   │   │  └── ╔══════════════════════╗                          │   │
│  │  No LLM calls (by design)        │   │      ║ NO PSE CONNECTION !! ║                          │   │
│  │  Pure heuristic scoring           │   │      ╚══════════════════════╝                          │   │
│  └───────────────────────────────────┘   │                                                        │   │
│                                          │  Path B: ScanRunner → FindingPipeline                  │   │
│                                          │  ├── PSE feedback via pse_feedback_fn                  │   │
│                                          │  └── ConfidenceCalibration via DecisionOrchestrator    │   │
│                                          │                                                        │   │
│  ┌──────── DORMANT ─────────────────┐   │  Path C: Swarm (NOT WIRED)                             │   │
│  │ swarm/ (10 files)                 │   │  ├── AgentSwarm, SwarmAgent, MessageBus                │   │
│  │ ├── AgentSwarm                    │   │  └── Multi-GPU scheduler, model sharder                │   │
│  │ ├── SharedWeightManager           │   └────────────────────────────────────────────────────────┘   │
│  │ ├── Multi-GPU scheduler           │                                                                │
│  │ └── 0 external callers            │                                                                │
│  └───────────────────────────────────┘                                                                │
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
| `agents/llm_routing.py` | ModelRouter, complexity classification, adaptive routing |
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
| `agents/llm_output_guard.py` | Per-role JSON schema validation |
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
| `agents/llm_adaptive.py` | Intent feedback loop (EMA), adaptive compression, behavior profiles |
| `agents/llm_intelligence.py` | 7 higher-order LLM functions (summaries, remediation, FP analysis) |

### Layer 8: Streaming & Tool Calling — 2 files
| File | Purpose |
|------|---------|
| `agents/streaming_structured.py` | Incremental JSON parser, progressive validation during streaming |
| `agents/native_tool_calling.py` | Native function calling for OpenAI/Anthropic/Ollama |

### Layer 9: RAG & Cognitive — 3 files
| File | Purpose |
|------|---------|
| `agents/rag_context.py` | Hybrid TF-IDF + semantic retrieval, RRF fusion, MMR diversity |
| `agents/cognitive_bridge.py` | Python↔Copilot bidirectional reasoning (MCP) |
| `agents/copilot_reasoning.py` | Copilot-as-Cognitive-Core structured prompts |

### Layer 10: Local Inference Stack — 9 files
| File | Purpose |
|------|---------|
| `inference/engine.py` | InferenceEngine facade, BackendType routing |
| `inference/ollama_backend.py` | Ollama HTTP backend |
| `inference/llama_backend.py` | Direct llama-cpp-python GGUF loading |
| `inference/model_manager.py` | HuggingFace download, validation, benchmarking |
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
| Feedback | `synthesis_feedback.py`, `feedback_learning.py` | Cross-system signal propagation, prompt augmentation |
| Value | `value_scorer.py`, `chain_impact_scorer.py`, `opportunity_scoring.py` | Multi-factor scoring |
| Genetic | `loop/payload_evolution.py` | GA mutation/crossover/selection |
| Decision | `decision_orchestrator.py` | EV scoring: P(success)×impact×affinity−cost×risk |

---

## 3. ML Algorithm Catalog

| # | Algorithm | File | Input | Output | Persistence |
|---|-----------|------|-------|--------|-------------|
| 1 | **Online Ridge Regression** | `weight_tuner.py` | (13 signals, reward) observations | 13 blended weights, CalibrationResult | **None** (memory only) |
| 2 | **Tabular Q-Learning** | `rl_reward_engine.py` | (state, action, reward) tuples | Q-values, ε-greedy policy | **Disk** (via LearningLoopEngine) |
| 3 | **Thompson Sampling (Beta-Binomial)** | `bayesian_prioritizer.py` | (tech_stack, vuln_type, outcome) | Ranked hypotheses | **Disk** (JSON with file locking) |
| 4 | **Thompson Sampling + Bandits** | `adaptive_learning.py` | (scan_outcome, defense_type) | Test selection, WAF bypass strategy | **Disk** (SQLite) |
| 5 | **Bayesian Calibration** | `confidence_calibration.py` | (prediction, ground_truth) | Recalibrated confidence, Brier/ECE scores | **Disk** (DecisionOrchestrator binding) |
| 6 | **Genetic Algorithm** | `loop/payload_evolution.py` | Population of payloads + fitness | Evolved payload population | **None** (per-session) |
| 7 | **EV Scoring** | `decision_orchestrator.py` | P(success), impact, affinity, cost, risk | Ranked decisions | **None** (runtime only) |
| 8 | **Chain Impact Scoring** | `chain_impact_scorer.py` | ExploitGraph transitions + findings | Chain severity rankings | **None** |
| 9 | **TF-IDF + Semantic Retrieval** | `rag_context.py` | Query + document corpus | Top-k context chunks | **Disk** (SQLite cache) |
| 10 | **EMA Intent Learning** | `llm_adaptive.py` | Chat message stream | Intent classification weights | **None** (per-session) |

---

## 4. Wiring Matrix — 10 Critical Integration Points

| # | From → To | Status | Evidence |
|---|-----------|--------|----------|
| 1 | LLMBridge → WeightTuner | **DISCONNECTED** | LLM prompts never read PSE learned weights |
| 2 | DecisionOrchestrator → LLMBridge | **DISCONNECTED** (by design) | Pure heuristic scoring, no LLM calls |
| 3 | LearningLoopEngine → WeightTuner | **DISCONNECTED** | Macro RL and micro PSE are separate universes |
| 4 | FeedbackLearning → prompts | **CONNECTED** | 👎 → `query_similar` → augment → prepend system prompt |
| 5 | RAGContextEngine → pipeline | **PARTIALLY** | Only dashboard chat; not autonomous loop/PSE |
| 6 | Swarm → main pipeline | **DEAD** | Re-exported from `loop/` but never instantiated |
| 7 | AutonomousLoop → PSE | **DISCONNECTED** | Two parallel execution paths, no bridge |
| 8 | WorldModel/MentalModel → prompts | **CONNECTED** | `to_prompt_context()` wired into THINK/ACT + runner |
| 9 | ExploitGraph → WeightTuner | **DISCONNECTED** | Graph findings don't trigger weight learning |
| 10 | ConfidenceCalibration → decision | **CONNECTED** | Actively recalibrates EV scores in DecisionOrchestrator |

---

## 5. Disconnections (4 Critical)

### D-1: Dual Learning Systems Have No Bridge

**Impact: HIGH**

The system has two completely independent learning systems:

| System | Learns | Persists | Scope |
|--------|--------|----------|-------|
| **Macro RL** (LearningLoopEngine) | Which tools to use, which vuln types to explore | Yes (disk) | Cross-session |
| **Micro PSE** (WeightTuner) | How to score/rank payloads using 13 signals | **No** | Per-session only |

**What's missing:** The macro system learns "SQLi on WordPress is high-value" but this insight never flows to the PSE to boost `chain_alignment` or `environment_fit` weights for SQLi payloads against WordPress targets. Conversely, the PSE learns "bypass_score is the most important signal against Cloudflare" but this never flows back to inform macro-level tool selection.

**Consequence:** Both systems re-learn things the other already knows. The PSE restarts from static priors every session, even though the macro system has accumulated cross-session intelligence about which vulnerability types succeed against which targets.

### D-2: Autonomous Loop Bypasses PSE Entirely

**Impact: HIGH**

The `AutonomousLoop` (OODA cycle) dispatches attacks through `AIDirectedExecutor` (tool commands like "run nuclei", "run sqlmap"). It **never instantiates or calls** `PayloadSynthesisEngine`. The PSE's 13-signal scoring, weight learning, genetic evolution, and WAF adaptation are all unused in autonomous mode.

**Consequence:** Autonomous mode uses less sophisticated attack selection — no learned scoring, no signal-based ranking, no adaptive weight tuning. It relies entirely on the macro RL layer (Q-tables + Thompson Sampling) for exploration, missing the fine-grained payload intelligence that PSE provides.

### D-3: ExploitGraph Findings Don't Feed Weight Learning

**Impact: MEDIUM**

When the ExploitGraph discovers chains (via `process_finding_multihop()`), it updates graph topology but never triggers `WeightTuner.observe()`. The learning path is PSE-internal only: `pse.record_feedback()` → `SynthesisFeedbackCollector` → `WeightTuner.observe()`.

**Consequence:** Findings discovered through the ExploitGraph (multi-hop chains) don't contribute to learning which signals predict successful exploits. Only directly synthesized payloads provide learning signal.

### D-4: LLM Prompts Never Read Learned Weights

**Impact: MEDIUM**

The LLM bridge constructs prompts without knowledge of what the PSE's WeightTuner has learned. If the tuner has learned that `detection_risk` is the #1 predictor of success, this insight is invisible to LLM-driven analysis, hypothesis generation, and remediation recommendations.

**Consequence:** LLM outputs (hypotheses, payloads, analysis) don't benefit from ML-learned signal importance. The ML layer and LLM layer operate in parallel rather than synergistically.

---

## 6. Bugs & Defects (12 items)

### Critical (2)

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| B-1 | **WeightTuner has zero persistence** — all 13-signal ridge regression learning lost every session | `weight_tuner.py` (entire class) | Payload scoring restarts from scratch every run; re-learns same lessons |
| B-2 | **60+ silent `except Exception: pass/continue`** in decision-critical paths — hypothesis engine, session intel, campaign tracker, calibration, lookahead learning all fail silently | `decision_orchestrator.py` (10+), `manual_audit_engine.py` (7), `exploit_path_planner.py` (4), `adaptive_chain_engine.py` (4), `decision_benchmark.py` (6) | Subsystem failures are invisible; system appears to work but makes uninformed decisions |

### High (3)

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| B-3 | **ContextBudgetAllocator not wired into main chat paths** — formal slot-based budgeting exists but LLMBridge uses ad-hoc manual budgeting | `reasoning/context_budget.py` vs `agents/llm_bridge.py:2909` | Two independent budgeting systems; formal allocator's priority logic unused |
| B-4 | **Thinking budget injection can exceed context window** — `_inject_thinking_budget()` adds budget to `max_tokens` without validating against `context_window` | `agents/llm_bridge.py:277-286` | Large thinking budget + small model → request exceeds context window → API error |
| B-5 | **RAG only wired to dashboard chat** — autonomous loop, PSE, runner don't use RAG retrieval | `agents/rag_context.py` → only `server.py:6234` and `llm_bridge.py:3069` | Most attack paths lack retrieval-augmented context |

### Medium (4)

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| B-6 | **No model fallback on API rejection** — routing handles missing config but not model-not-found/rate-limit from API | `agents/llm_routing.py:118-130` | Model unavailability → crash instead of graceful downgrade |
| B-7 | **Underdetermined regression at MIN_OBSERVATIONS=3** — 3 observations for 13 signals means regression is noise until observation count grows | `weight_tuner.py:127` | Early calibrations dominated by regularization, not actual learning |
| B-8 | **VRAM tracking stubbed to 0** — `vram_used_mb=0` TODO in model_manager.py | `inference/model_manager.py:624` | GPU memory management decisions are blind |
| B-9 | **Cloud chat and local chat use different budgeting math** — local uses 20% reserve, cloud uses separate formula | `agents/llm_bridge.py:2909` vs `:3034` | Inconsistent behavior between chat modes |

### Low (3)

| # | Bug | Location | Impact |
|---|-----|----------|--------|
| B-10 | **EMA intent weights not persisted** — chat intent classification restarts every session | `agents/llm_adaptive.py` | Minor re-learning overhead |
| B-11 | **Cross-component atomicity gap** — WeightTuner and BayesianPrioritizer can see temporarily inconsistent state | All ML components | Eventually consistent; not crash-inducing |
| B-12 | **Shim chain adds import indirection** — 7 backward-compat shim files create 2-hop imports | Root-level `*.py` shims | Marginal startup overhead, slight confusion |

---

## 7. Dead / Dormant Code

### Confirmed Dead (1 subsystem, ~22 files)

| Subsystem | Files | Status | Evidence |
|-----------|-------|--------|----------|
| **`swarm/`** | `swarm.py`, `agent_roles.py`, `shared_weights.py`, `message_bus.py`, `gpu_governor.py`, `multi_gpu/*.py` (~10 files) | **DEAD** — zero external callers | Re-exported via `loop/__init__.py` but nothing imports from there. Tests exist but no runtime entry point. |

### Partially Dormant (1 module)

| Module | Status | Evidence |
|--------|--------|----------|
| `reasoning/context_budget.py` | **Built but bypassed** — exists as formal allocator but LLMBridge uses manual budgeting | Used only in `reasoning/prompt_chains.py` for chain execution; main chat ignores it |

---

## 8. Improvement Opportunities

### Tier 1: High-Impact Wiring Fixes

#### I-1: WeightTuner Persistence (fixes B-1 + partially D-1)

Add save/load to `WeightTuner` following the same pattern as `QTablePersistence`:
- Persist `_current_weights`, `_signal_trust`, `_observation_count`, `_calibration_count` to `~/.venator/learning/weight_tuner.json`
- Apply concept-drift decay (0.995) on load, matching QTablePersistence behavior
- Use `json_file_lock` for cross-process safety (same as ToolLedger)
- **Impact:** Payload scoring retains learned signal importance across sessions

#### I-2: Macro→Micro RL Bridge (fixes D-1)

Create a `LearningBridge` that propagates macro insights to micro weights:
- When `ToolLedger.record()` shows a vuln_type has high success rate → boost `environment_fit` weight in WeightTuner for that vuln_type
- When `BayesianPrioritizer` posterior for (tech, vuln) is strongly skewed → adjust `hypothesis_boost` prior in WeightTuner
- When Q-table shows an action's Q-value is outlier-high → feed as observation to WeightTuner
- **Impact:** PSE benefits from cross-session intelligence without needing its own persistence

#### I-3: Autonomous Loop → PSE Integration (fixes D-2)

Wire PSE into the autonomous OODA loop as an alternative execution path:
- In `_act()`, when generating exploit payloads, instantiate PSE and use its ranked payloads instead of raw tool commands
- Feed PSE payloads' scores into the loop's evaluation step
- Route positive/negative outcomes back through `pse.record_feedback()`
- **Impact:** Autonomous mode gains 13-signal scoring, adaptive weights, WAF evasion

#### I-4: ExploitGraph → WeightTuner Feedback (fixes D-3)

When `ExploitGraph.process_finding_multihop()` discovers a chain:
- Extract which signals were present on the triggering payloads
- Feed synthetic observations to `WeightTuner.observe()` with positive reward
- **Impact:** Multi-hop chain discoveries contribute to weight learning

### Tier 2: Bug Fixes

#### I-5: Wire ContextBudgetAllocator into LLMBridge (fixes B-3, B-4, B-9)

Replace the ad-hoc manual budgeting in `llm_bridge._build_agent_chat_prompt_local()` with calls to `ContextBudgetAllocator.allocate()`:
- Unifies local chat, cloud chat, and chain execution budgeting
- Prevents thinking budget from exceeding context window (allocator enforces total bounds)
- **Impact:** Consistent, formally correct token management across all paths

#### I-6: Add Observability to Silent Catches (fixes B-2)

In `decision_orchestrator.py` and other files with silent `except Exception: pass`:
- Replace `pass` with `logger.debug("subsystem X failed: %s", exc)` at minimum
- For decision-critical paths (hypothesis engine, calibration), escalate to `logger.warning()`
- Add a circuit-breaker counter: if a subsystem fails >5 times consecutively, log ONCE at WARNING level
- **Impact:** Silent failures become visible without log spam

#### I-7: Model Fallback on API Error (fixes B-6)

In `llm_routing.py`, add a `fallback_model` chain:
- On 404/model-not-found: try next tier down (e.g., gpt-4o → gpt-4o-mini → gpt-3.5-turbo)
- On rate-limit: switch to secondary provider if configured
- **Impact:** Graceful degradation instead of crash

### Tier 3: Enhancement Opportunities

#### I-8: Broaden RAG Integration (fixes B-5)

Wire `RAGContextEngine` into:
- `runner.py` scan pipeline: retrieve relevant prior findings/CVEs for current target tech
- `autonomous_loop._think()`: retrieve past campaign outcomes for similar targets
- `payload_synthesis_engine.py`: retrieve known bypass techniques for detected WAF
- **Impact:** All execution paths benefit from retrieval-augmented intelligence

#### I-9: Learned Weights → LLM Prompts (fixes D-4)

Add a `weight_context_for_prompt()` method to WeightTuner:
- Returns a 3-sentence summary: "Top signals for this target: bypass_score (0.42), detection_risk (0.23)... Learned from N observations with R²=0.87."
- Inject into LLMBridge's system prompt when analyzing findings or generating hypotheses
- **Impact:** LLM reasoning informed by ML-learned signal importance

#### I-10: Activate Swarm for Multi-Target Campaigns

Wire `AgentSwarm` into `runner.py` for multi-target campaigns:
- When `campaign_mode=True` and `len(targets) > 1`, spawn swarm agents per target
- Use `SharedWeightManager` for model weight sharing
- Use `MessageBus` for cross-target intelligence sharing
- **Impact:** Parallel multi-target exploitation with shared learning

#### I-11: Raise MIN_OBSERVATIONS threshold (fixes B-7)

Increase `MIN_OBSERVATIONS_FOR_CALIBRATION` from 3 to at least 13 (matching signal count k):
- Or use progressive regularization that decreases as observation count grows
- **Impact:** Early calibrations become statistically meaningful

---

## 9. Priority Action Plan

### Phase 1: Critical Fixes (estimated: 4 items)

| Priority | Item | Fixes | Risk if Deferred |
|----------|------|-------|-------------------|
| **P0** | I-1: WeightTuner persistence | B-1 | Learning lost every session |
| **P0** | I-6: Silent catch observability | B-2 | Invisible subsystem failures |
| **P1** | I-5: ContextBudgetAllocator wiring | B-3, B-4, B-9 | Context window overflow, inconsistent budgeting |
| **P1** | I-7: Model fallback on API error | B-6 | Crash on model unavailability |

### Phase 2: Strategic Bridges (estimated: 3 items)

| Priority | Item | Fixes |
|----------|------|-------|
| **P2** | I-2: Macro→Micro RL bridge | D-1 |
| **P2** | I-3: AutonomousLoop → PSE | D-2 |
| **P2** | I-4: ExploitGraph → WeightTuner | D-3 |

### Phase 3: Enhancement (estimated: 4 items)

| Priority | Item | Fixes |
|----------|------|-------|
| **P3** | I-8: Broaden RAG | B-5 |
| **P3** | I-9: Learned weights → prompts | D-4 |
| **P3** | I-10: Activate swarm | Dead code |
| **P3** | I-11: Raise MIN_OBSERVATIONS | B-7 |

---

## File Count Summary

| Category | Files | Status |
|----------|-------|--------|
| LLM Bridge + Providers | 5 | All wired |
| Routing + Hardware | 2 | All wired |
| Types + Cache + Cost | 3 | All wired |
| Security + Defense | 4 | All wired |
| Observability + Ops | 5 | All wired |
| Adaptive Intelligence | 2 | All wired |
| Streaming + Tools | 2 | All wired |
| RAG + Cognitive | 3 | Partially wired (RAG only dashboard) |
| Local Inference | 9 | All wired |
| ML / Scoring / Learning | 16+ | All wired but siloed |
| Prompt Pipeline | 8 | All wired |
| Intelligence / Reasoning | 28+ | All wired |
| Graph (LangGraph + Exploit + State) | 52+ | All wired |
| Agent / Orchestration | 12+ | All wired |
| **Swarm** | **10+** | **DEAD** |
| **Total** | **~160+** | **~150 wired, ~10 dead** |
