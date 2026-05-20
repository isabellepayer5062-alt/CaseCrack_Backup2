# CaseCrack — Complete ML / LLM System Map

> **Generated**: 2026-04-11 | **Files cataloged**: 280+ | **Subsystems**: 43 categories

---

## Table of Contents

1. [High-Level Architecture Diagram](#1-high-level-architecture-diagram)
2. [Data Flow — End to End](#2-data-flow--end-to-end)
3. [Layer 1: LLM Provider Abstraction](#3-layer-1-llm-provider-abstraction)
4. [Layer 2: LLM Infrastructure & Operations](#4-layer-2-llm-infrastructure--operations)
5. [Layer 3: Inference Engine (Local LLM)](#5-layer-3-inference-engine-local-llm)
6. [Layer 4: Agent System & Orchestration](#6-layer-4-agent-system--orchestration)
7. [Layer 5: Reasoning & Hypothesis Engines](#7-layer-5-reasoning--hypothesis-engines)
8. [Layer 6: Cognitive Bridge & Collaboration](#8-layer-6-cognitive-bridge--collaboration)
9. [Layer 7: Decision Making & Arbitration](#9-layer-7-decision-making--arbitration)
10. [Layer 8: Exploit Graph & Attack Modeling](#10-layer-8-exploit-graph--attack-modeling)
11. [Layer 9: Adaptive Learning & Reinforcement](#11-layer-9-adaptive-learning--reinforcement)
12. [Layer 10: Payload Synthesis Pipeline](#12-layer-10-payload-synthesis-pipeline)
13. [Layer 11: Vector Memory & Embeddings](#13-layer-11-vector-memory--embeddings)
14. [Layer 12: Prompt Management & Security](#14-layer-12-prompt-management--security)
15. [Layer 13: Confidence & Calibration](#15-layer-13-confidence--calibration)
16. [Layer 14: LangGraph State Machine](#16-layer-14-langgraph-state-machine)
17. [Layer 15: Autonomous Exploitation Loop](#17-layer-15-autonomous-exploitation-loop)
18. [Layer 16: Strategic & Planning Systems](#18-layer-16-strategic--planning-systems)
19. [Layer 17: CAAP (Chain Automation)](#19-layer-17-caap-chain-automation)
20. [Layer 18: ATLAS Intelligence System](#20-layer-18-atlas-intelligence-system)
21. [Layer 19: Feedback & Signal Propagation](#21-layer-19-feedback--signal-propagation)
22. [Layer 20: Copilot SDK & Tool Registry](#22-layer-20-copilot-sdk--tool-registry)
23. [Layer 21: AI/ML Security Scanner](#23-layer-21-aiml-security-scanner)
24. [Layer 22: Knowledge & Domain Systems](#24-layer-22-knowledge--domain-systems)
25. [Layer 23: World Model & State Tracking](#25-layer-23-world-model--state-tracking)
26. [Layer 24: Truth Enforcement & Verification](#26-layer-24-truth-enforcement--verification)
27. [Layer 25: Impact & Scoring Systems](#27-layer-25-impact--scoring-systems)
28. [Layer 26: Intelligence Gathering](#28-layer-26-intelligence-gathering)
29. [Layer 27: Recon Dashboard Intelligence](#29-layer-27-recon-dashboard-intelligence)
30. [Layer 28: Safety & Defense Hardening](#30-layer-28-safety--defense-hardening)
31. [Layer 29: Observability & Tracing](#31-layer-29-observability--tracing)
32. [Layer 30: MCP Extension (VS Code)](#32-layer-30-mcp-extension-vs-code)
33. [Layer 31: Chain YAML DSL Integration](#33-layer-31-chain-yaml-dsl-integration)
34. [Layer 32: Multi-Agent Swarm](#34-layer-32-multi-agent-swarm)
35. [Layer 33: Session & Campaign Intelligence](#35-layer-33-session--campaign-intelligence)
36. [Layer 34: Tests & Validation](#36-layer-34-tests--validation)
37. [Layer 35: Configuration & Scripts](#37-layer-35-configuration--scripts)
38. [Layer 36: Documentation](#38-layer-36-documentation)
39. [Complete File Index (All 280+ Files)](#39-complete-file-index-all-280-files)
40. [Cross-Reference Wiring Matrix](#40-cross-reference-wiring-matrix)

---

## 1. High-Level Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                              VS CODE / MCP EXTENSION LAYER                                    │
│  ┌─────────────┐ ┌──────────────┐ ┌────────────┐ ┌──────────────┐ ┌───────────────────────┐  │
│  │ toolLoop.ts │ │chatHandlers  │ │treeView.ts │ │dashboardPanel│ │ mcpProvider.ts        │  │
│  │ (LLM tool   │ │.ts (Copilot  │ │(Hypothesis │ │.ts (Live     │ │ (40+ MCP tools)       │  │
│  │  calling)   │ │ chat)        │ │ display)   │ │ severity)    │ │                       │  │
│  └──────┬──────┘ └──────┬───────┘ └─────┬──────┘ └──────┬───────┘ └──────────┬────────────┘  │
│         │               │               │               │                    │               │
│         └───────────────┴───────────────┴───────────────┴────────────────────┘               │
│                                         │ WebSocket / CLI / MCP Protocol                     │
└─────────────────────────────────────────┼────────────────────────────────────────────────────┘
                                          │
┌─────────────────────────────────────────┼────────────────────────────────────────────────────┐
│                               COPILOT SDK LAYER                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────────┐  │
│  │copilot_sdk_engine│  │copilot_sdk_tools  │  │copilot_sdk_agents│  │native_tool_calling  │  │
│  │ (67+ tools)      │  │(discovery/exploit)│  │(agent dispatch)  │  │(OpenAI/Anthropic)   │  │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  └────────┬────────────┘  │
│           └──────────────────────┴──────────────────────┴─────────────────────┘              │
└─────────────────────────────────────────┼────────────────────────────────────────────────────┘
                                          │
┌─────────────────────────────────────────┼────────────────────────────────────────────────────┐
│                              AGENT ORCHESTRATION LAYER                                        │
│                                                                                              │
│  ┌──────────┐    ┌────────────────┐    ┌────────────┐    ┌──────────────────────────────┐   │
│  │agent_loop│───▶│unified_agent   │───▶│copilot_loop│───▶│long_running_orchestrator     │   │
│  │ (main)   │    │(dispatch)      │    │(Copilot)   │    │(checkpoint/resume)            │   │
│  └────┬─────┘    └───────┬────────┘    └─────┬──────┘    └──────────────┬───────────────┘   │
│       │                  │                   │                          │                    │
│  ┌────▼─────┐    ┌───────▼────────┐    ┌─────▼──────┐    ┌─────────────▼────────────────┐   │
│  │agent_    │    │agent_sessions  │    │agent_      │    │multi_agent_debate            │   │
│  │memory    │    │(state persist) │    │telemetry   │    │(consensus reasoning)         │   │
│  └──────────┘    └────────────────┘    └────────────┘    └──────────────────────────────┘   │
└─────────────────────────────────────────┼────────────────────────────────────────────────────┘
                                          │
         ┌────────────────────────────────┼─────────────────────────────────┐
         │                                │                                 │
         ▼                                ▼                                 ▼
┌────────────────────┐  ┌─────────────────────────────┐  ┌──────────────────────────────────┐
│  REASONING LAYER   │  │   LLM PROVIDER LAYER        │  │  LEARNING & RL LAYER             │
│                    │  │                             │  │                                  │
│ reasoning_engine   │  │ llm_bridge ◀─┐             │  │ adaptive_learning                │
│ hypothesis_engine  │  │ llm_clients  │  ┌────────┐ │  │ rl_reward_engine                 │
│ attack_reasoning   │  │ llm_routing ─┼─▶│OpenAI  │ │  │ learning_loop_engine             │
│ unified_reasoning  │  │ llm_registry │  │Anthropic│ │  │ feedback_learning                │
│ copilot_reasoning  │  │ llm_cache    │  │Ollama   │ │  │ ab_testing                       │
│ reasoning_display  │  │ llm_ops      │  │GitHub   │ │  │ weight_tuner                     │
│ domain_knowledge   │  │ llm_adaptive │  │Models   │ │  │ ml_feedback_propagator           │
│ bayesian_prioritize│  │ llm_tracking │  └────────┘ │  │ exploration_bias                 │
└────────┬───────────┘  │ llm_tracing  │             │  │ value_scorer                     │
         │              │ llm_productn │             │  │ qtable_advisor                   │
         │              └─────────┬───────────────────┘  └──────────┬───────────────────────┘
         │                        │                                 │
         ▼                        ▼                                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                             COGNITIVE & STRATEGIC LAYER                                     │
│                                                                                            │
│  ┌────────────────┐  ┌────────────────────┐  ┌─────────────────┐  ┌────────────────────┐  │
│  │cognitive_bridge │  │strategic_llm_layer │  │decision_         │  │unified_arbitration │  │
│  │(LLM↔exploit)   │  │(Plan→Criticize→    │  │orchestrator      │  │(conflict           │  │
│  │                 │  │ Propose→Refine)    │  │(action ranking)  │  │ resolution)        │  │
│  └────────┬────────┘  └────────┬───────────┘  └────────┬────────┘  └────────┬───────────┘  │
│           │                    │                       │                    │              │
│  ┌────────▼────────┐  ┌───────▼────────────┐  ┌───────▼─────────┐  ┌──────▼────────────┐  │
│  │collaborative_   │  │strategic_foresight │  │decision_trace   │  │decision_benchmark │  │
│  │intelligence     │  │(2-3 step lookahead)│  │(audit trail)    │  │(quality tracking) │  │
│  └─────────────────┘  └────────────────────┘  └─────────────────┘  └───────────────────┘  │
└───────────────────────────────────┬────────────────────────────────────────────────────────┘
                                    │
                ┌───────────────────┼───────────────────────┐
                │                   │                       │
                ▼                   ▼                       ▼
┌──────────────────────┐ ┌───────────────────────┐ ┌──────────────────────────────────────┐
│ EXPLOIT GRAPH ENGINE │ │ PAYLOAD SYNTHESIS     │ │ AUTONOMOUS LOOP                      │
│                      │ │ PIPELINE (PSE)        │ │                                      │
│ exploit_graph        │ │                       │ │ autonomous_loop  ◀──OBSERVE           │
│ graph_knowledge_base │ │ Grammar→LLM→GA→       │ │ ai_directed_executor ◀──THINK        │
│ graph_pathfinding    │ │ Arbiter→Scheduler     │ │ world_state    ◀──ACT                │
│ graph_state_ops      │ │                       │ │ confirmation_engine ◀──EVALUATE       │
│ graph_persistence    │ │ payload_synthesis_eng  │ │ signal_extraction ◀──LEARN           │
│ graph_rendering      │ │ llm_synthesizer       │ │ target_selection                     │
│ graph_suggestions    │ │ payload_arbiter       │ │ parallel_executor                    │
│ graph_integrations   │ │ evolutionary_fuzzer   │ │ campaign_strategy                    │
│ autonomous_exploit   │ │ genetic_forge         │ │ graph_pruner                         │
│ exploit_verifier     │ │ grammar_synthesizer   │ │ vector_reasoning                     │
│ exploit_path_planner │ │ synthesis_tracer      │ │ payload_evolution                    │
│ exploit_persistence  │ │ synthesis_context     │ │ feedback_loop_breaker                │
│ decision_framework   │ │ synthesis_feedback    │ │ race_engine                          │
└──────────┬───────────┘ │ synthesis_safety      │ │ session_matrix                       │
           │             │ waf_payload_adapter   │ │ target_specialization                │
           │             │ evasion_engine        │ │ invariant_engine                     │
           │             └───────────┬───────────┘ └──────────────────┬───────────────────┘
           │                         │                                │
           └─────────────────────────┴────────────────────────────────┘
                                     │
┌────────────────────────────────────┼─────────────────────────────────────────────────────┐
│                          SUPPORT INFRASTRUCTURE                                          │
│                                                                                          │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────┐  ┌──────────────────────┐   │
│  │VECTOR MEMORY │  │CONFIDENCE      │  │TRUTH ENFORCEMENT │  │ATLAS INTELLIGENCE    │   │
│  │              │  │                │  │                  │  │                      │   │
│  │embedder.py   │  │confidence_eng  │  │truth_enforcement │  │atlas.py              │   │
│  │vector_index  │  │confidence_ens  │  │exploit_verifier  │  │patterns.py           │   │
│  │rag_context   │  │confidence_div  │  │oob_verifier      │  │graph.py              │   │
│  │cross_scan_   │  │confidence_cal  │  │secret_verifier   │  │defense.py            │   │
│  │  memory      │  │bayesian_prior  │  │finding_validator │  │archetypes.py         │   │
│  └──────────────┘  └────────────────┘  └──────────────────┘  │adapter.py (LLM)      │   │
│                                                               │store.py              │   │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────┐  │atlas_nexus.py        │   │
│  │PROMPT MGMT   │  │WORLD MODEL    │  │KNOWLEDGE         │  └──────────────────────┘   │
│  │              │  │               │  │                  │                              │
│  │prompt_registr│  │world_model    │  │domain_knowledge  │  ┌──────────────────────┐   │
│  │progressive_  │  │target_mental_ │  │vuln_knowledge    │  │LANGGRAPH STATE       │   │
│  │  prompts     │  │  model        │  │graph_knowledge_  │  │                      │   │
│  │few_shot_sel  │  │world_state    │  │  base            │  │graph/builder.py      │   │
│  │prompt_secur  │  │temporal_stab  │  │knowledge_        │  │graph/nodes.py        │   │
│  │doubt_inject  │  │self_optimiz   │  │  resilience      │  │graph/runner.py       │   │
│  │thinking_budg │  │               │  │threat_modeler    │  │graph/multi_agent/    │   │
│  └──────────────┘  └───────────────┘  └──────────────────┘  │graph/reasoning/      │   │
│                                                              └──────────────────────┘   │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────┐  ┌──────────────────────┐   │
│  │INFERENCE ENG │  │CAAP SYSTEM    │  │AI/ML SCANNER     │  │RECON DASHBOARD       │   │
│  │              │  │               │  │                  │  │INTELLIGENCE          │   │
│  │engine.py     │  │caap_chains    │  │ai_ml_scanner     │  │execution_intel       │   │
│  │model_manager │  │caap_hypothesis│  │_prompt_injection  │  │causal_inference      │   │
│  │ollama_backen │  │caap_models    │  │_vector_database   │  │attack_strategy_eng   │   │
│  │llama_backend │  │caap_formatter │  │_model_endpoint    │  │cross_target_intel    │   │
│  │gpu_governor  │  │caap_session   │  │_model_serial      │  │platform_intel_mem    │   │
│  │vram_selector │  │caap_parser    │  │_rag_pipeline      │  │truth_enforcement     │   │
│  │kv_cache      │  │exploit_data   │  │_ai_api_proxy      │  │proof_first_severity  │   │
│  │grammar.py    │  │escalation_gw  │  │_models/_utils     │  │confidence_calibrate  │   │
│  └──────────────┘  └───────────────┘  └──────────────────┘  └──────────────────────┘   │
│                                                                                          │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐   │
│  │ MULTI-AGENT SWARM: swarm/agent_roles.py, swarm/shared_weights.py                 │   │
│  │ SESSION INTEL: session_intelligence.py, campaign_intelligence.py                  │   │
│  │ IMPACT SCORING: chain_impact_scorer.py, impact_chain.py, impact_amplifier.py      │   │
│  │ OBSERVABILITY: decision_trace.py, synthesis_tracer.py, pipeline_tracing.py        │   │
│  │ SAFETY: synthesis_safety.py, llm_defense_hardening.py, llm_output_guard.py        │   │
│  └───────────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Flow — End to End

```
                         USER REQUEST (VS Code / CLI / MCP)
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │   MCP Extension / CLI Parser    │
                    │   (toolLoop.ts / chatHandlers)  │
                    └────────────────┬───────────────┘
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │   Copilot SDK Engine            │
                    │   (67+ registered tools)        │
                    │   ┌─ copilot_sdk_engine.py      │
                    │   ├─ copilot_sdk_tools.py       │
                    │   └─ native_tool_calling.py      │
                    └────────────────┬───────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
     ┌────────────────┐  ┌────────────────────┐  ┌────────────────────┐
     │  Agent Loop     │  │  CAAP System       │  │  Direct Scan       │
     │  (hypothesis    │  │  (chain automation │  │  (tool execution)  │
     │   cycle)        │  │   protocol)        │  │                    │
     └───────┬────────┘  └────────┬───────────┘  └────────┬───────────┘
             │                    │                        │
             ▼                    ▼                        │
     ┌──────────────────────────────────────┐             │
     │      REASONING ENGINE                 │             │
     │  ┌─ Bayesian hypothesis ranking       │             │
     │  ├─ Technology detection → vuln map   │             │
     │  ├─ Domain knowledge integration      │             │
     │  └─ Confidence scoring                │             │
     └───────────────┬──────────────────────┘             │
                     │                                     │
                     ▼                                     │
     ┌──────────────────────────────────────┐             │
     │     LLM BRIDGE (Provider Dispatch)    │             │
     │  ┌─ llm_routing.py → provider select  │             │
     │  ├─ llm_cache.py → response cache     │             │
     │  ├─ llm_clients.py → API calls        │             │
     │  │   ├─ OpenAI (GPT-4o / GPT-4)      │             │
     │  │   ├─ Anthropic (Claude Opus 4)         │             │
     │  │   ├─ Ollama (local: qwen2.5-coder) │             │
     │  │   └─ GitHub Models (API)           │             │
     │  ├─ llm_output_guard.py → validate    │             │
     │  └─ llm_defense.py → injection guard  │             │
     └───────────────┬──────────────────────┘             │
                     │                                     │
                     ▼                                     │
     ┌──────────────────────────────────────┐             │
     │   COGNITIVE BRIDGE                    │             │
     │   (LLM reasoning ↔ exploit logic)     │◀────────────┘
     └───────────────┬──────────────────────┘
                     │
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
   ┌─────────┐ ┌──────────┐ ┌───────────────┐
   │Decision │ │Strategic │ │Exploit Graph  │
   │Orchest. │ │LLM Layer │ │Engine         │
   │(action  │ │(plan →   │ │(state machine │
   │ rank)   │ │ critique │ │ pathfinding)  │
   └────┬────┘ │ → refine)│ └───────┬───────┘
        │      └────┬─────┘         │
        │           │               │
        └───────────┼───────────────┘
                    │
                    ▼
     ┌──────────────────────────────────────┐
     │  PAYLOAD SYNTHESIS ENGINE (PSE)       │
     │                                       │
     │  Grammar → LLM → GA → Arbiter →      │
     │  Scheduler → Execution                │
     │                                       │
     │  ┌─ grammar_synthesizer.py            │
     │  ├─ llm_synthesizer.py                │
     │  ├─ evolutionary_fuzzer.py            │
     │  ├─ payload_arbiter.py (8-signal ML)  │
     │  ├─ execution_scheduler.py            │
     │  └─ evasion_engine.py (WAF bypass)    │
     └───────────────┬──────────────────────┘
                     │
                     ▼
     ┌──────────────────────────────────────┐
     │  AUTONOMOUS EXPLOITATION LOOP         │
     │  OBSERVE → THINK → ACT → EVALUATE    │
     │  → LEARN → (repeat)                  │
     │                                       │
     │  ┌─ autonomous_loop.py               │
     │  ├─ ai_directed_executor.py          │
     │  ├─ confirmation_engine.py           │
     │  ├─ signal_extraction.py             │
     │  └─ world_state.py                   │
     └───────────────┬──────────────────────┘
                     │
                     ▼
     ┌──────────────────────────────────────┐
     │  FEEDBACK PROPAGATION                 │
     │                                       │
     │  signal_extraction → weight_tuner →   │
     │  ml_feedback_propagator →             │
     │  confidence_engine →                  │
     │  bayesian_prioritizer →               │
     │  hypothesis_engine (update priors)    │
     │                                       │
     │  RL: rl_reward_engine → q-table →     │
     │      action_selection                 │
     └───────────────┬──────────────────────┘
                     │
                     ▼
     ┌──────────────────────────────────────┐
     │  TRUTH ENFORCEMENT & VERIFICATION     │
     │                                       │
     │  finding_validator → exploit_verifier │
     │  → oob_verifier → secret_verifier    │
     │  → truth_enforcement (hard gates)    │
     │  → proof_first_severity              │
     └───────────────┬──────────────────────┘
                     │
                     ▼
             ┌───────────────┐
             │   FINDINGS    │
             │   REPORT      │
             └───────────────┘
```

---

## 3. Layer 1: LLM Provider Abstraction

**Purpose**: Multi-provider LLM access with dynamic routing, caching, and fault tolerance.

```
tools/burp_enterprise/agents/
├── llm_bridge.py              # Main orchestration: provider dispatch, prompt mgmt, reasoning budget
├── llm_clients.py             # OpenAI, Anthropic, Ollama HTTP wrappers; streaming support
├── llm_routing.py             # Dynamic provider/model selection by task type, cost, speed
├── llm_registry.py            # Model registry: provider configs, capability maps, routing rules
├── llm_cache.py               # Semantic response caching; TTL management; memoization
├── llm_types.py               # Type definitions: message, role, purpose enums, config dataclasses
└── llm_production.py          # Production resilience: circuit breaker, rate limiting, health checks
```

**Provider Matrix**:
| Provider | Models | Use Case |
|----------|--------|----------|
| OpenAI | GPT-4o, GPT-4 | Primary reasoning, tool calling |
| Anthropic | Claude Opus 4/Sonnet | Complex reasoning, long context |
| Ollama | qwen2.5-coder, llama3 | Local/offline, fast iteration |
| GitHub Models | Various | API-key based fallback |

**Wiring**:
- `llm_routing.py` → selects provider based on `LLMPurpose` enum
- `llm_cache.py` → intercepts before API call; semantic dedup
- `llm_bridge.py` → single entry point for all LLM calls system-wide
- `llm_production.py` → wraps with circuit breaker + retry logic

---

## 4. Layer 2: LLM Infrastructure & Operations

**Purpose**: Operational management, monitoring, defense, and adaptive optimization.

```
tools/burp_enterprise/agents/
├── llm_ops.py                 # Lifecycle management; batch processing; streaming
├── llm_adaptive.py            # Adaptive temperature/top_p tuning per task + prior quality
├── llm_intelligence.py        # Context-aware capability profiling; performance analytics
├── llm_tracking.py            # Token usage metering; cost analytics; provider comparison
├── llm_tracing.py             # Request/response logging; latency profiling; audit trail
├── llm_defense_hardening.py   # Prompt injection defense; jailbreak mitigation; provider profiles
├── llm_advanced_defense.py    # Adversarial protection; semantic fuzzing; output guardrails
├── llm_output_guard.py        # Output schema validation; coherence checking; safety filtering
├── llm_hardware_adapter.py    # GPU/CPU detection; VRAM mgmt; adaptive model selection
└── llm_shutdown.py            # Graceful shutdown; resource cleanup; connection pooling
```

**Data Flow**:
```
Request → llm_defense_hardening (input sanitize) → llm_routing (select provider)
  → llm_cache (check cache) → llm_clients (API call) → llm_output_guard (validate)
  → llm_tracking (record tokens) → llm_tracing (log call) → Response
```

---

## 5. Layer 3: Inference Engine (Local LLM)

**Purpose**: Local model execution via Ollama/Llama.cpp with GPU management.

```
tools/burp_enterprise/inference/
├── engine.py                  # Core inference engine; streaming + batch handling
├── model_manager.py           # Model lifecycle: download, load, unload, switch
├── setup_local_llm.py         # Ollama installation; model pulling; warm-start preloading
├── ollama_backend.py          # Ollama HTTP client; streaming chat completion; model switching
├── llama_backend.py           # Llama.cpp backend for quantized models (GGUF)
├── gpu_governor.py            # GPU memory allocation; VRAM optimization; multi-GPU scheduling
├── kv_cache.py                # KV cache management for inference efficiency
├── grammar.py                 # Grammar-constrained generation (GBNF format)
└── model_management/
    ├── model_registry.py      # Available models + specs (size, quant, context length)
    ├── vram_selector.py       # Selects optimal model based on available VRAM
    ├── finetune_exporter.py   # Scan data export to JSONL/Alpaca/ShareGPT for fine-tuning
    ├── model_benchmarker.py   # GGUF model performance testing with security-domain profiles
    ├── model_cli.py           # Model management CLI (list/pull/remove/benchmark/compare)
    └── model_downloader.py    # Production GGUF download pipeline with SHA-256 + resume
```

**Wiring**:
- `llm_hardware_adapter.py` (agents) → calls `gpu_governor.py` + `vram_selector.py`
- `llm_clients.py` → calls `ollama_backend.py` for local provider
- `model_manager.py` → manages model lifecycle across `engine.py`
- `model_benchmarker.py` → benchmarks models via `engine.py`; stores results in `model_registry.py`
- `finetune_exporter.py` → exports scan findings for LLM fine-tuning datasets

---

## 6. Layer 4: Agent System & Orchestration

**Purpose**: Multi-agent architecture with memory, telemetry, and session management.

```
tools/burp_enterprise/agents/
├── agent_loop.py              # Main execution loop: hypothesis cycle, adaptive reasoning
├── agent_memory.py            # Episodic memory: TF-IDF + vector search; HNSW indexing; consolidation
├── agent_sessions.py          # Session management: hypothesis tracking, finding correlation, state
├── agent_telemetry.py         # Phase tracking; hypothesis snapshots; action recording; metrics
├── copilot_loop.py            # GitHub Copilot integration: LLM exploration loop, hypothesis gen
├── copilot.py                 # Copilot chat interface
├── unified_agent.py           # Unified agent coordination; dispatch to specialized sub-agents

tools/burp_enterprise/
├── multi_agent_debate.py      # Multi-perspective debate: 3+ agents → consensus → belief refinement
```

**Agent Loop Cycle**:
```
INPUT → agent_loop → reasoning_engine.generate_hypotheses()
  → llm_bridge.complete() → cognitive_bridge.translate()
  → exploit_graph.suggest_next() → EXECUTE TOOL
  → agent_telemetry.record() → agent_memory.store()
  → feedback_learning.update() → NEXT ITERATION
```

---

## 7. Layer 5: Reasoning & Hypothesis Engines

**Purpose**: Bayesian hypothesis management, probability updates, and inference chains.

```
tools/burp_enterprise/agents/
├── reasoning_engine.py        # Bayesian hypothesis engine; tech-vuln probability tables; priors
├── reasoning_display.py       # Reasoning visualization; chain-of-thought display
├── copilot_reasoning.py       # Copilot-specific reasoning scaffolds; evidence collection
├── domain_knowledge_engine.py # Domain experts; tech stack analysis; vulnerability hypotheses
├── bayesian_prioritizer.py    # Bayesian prioritization; probability-weighted ranking; belief updates
├── attack_reasoning.py        # LLM-powered attack reasoning; finding correlation; novel hypotheses

tools/burp_enterprise/
├── hypothesis_engine.py       # Hypothesis generation; dynamic signal-driven reweighting
├── unified_reasoning.py       # Unified framework: intent model + multi-step planning

tools/burp_enterprise/reasoning/
├── hypothesis_manager.py      # Hypothesis lifecycle: generation, scoring, evolution, pruning
├── prompt_chains.py           # Chained prompts with state passing for multi-round reasoning
├── context_budget.py          # RAG context window budget management
└── kv_checkpoint.py           # KV cache checkpointing for reasoning continuity
```

**Hypothesis Flow**:
```
domain_knowledge_engine → initial hypotheses (tech stack → vuln mapping)
  → reasoning_engine → Bayesian probability update
  → hypothesis_engine → signal-driven reweighting
  → bayesian_prioritizer → ranked hypothesis list
  → aagent_loop → execute highest-priority hypothesis
  → feedback → reasoning_engine.update_posterior()
```

---

## 8. Layer 6: Cognitive Bridge & Collaboration

**Purpose**: Bridges LLM reasoning with exploitation logic; multi-agent collaboration.

```
tools/burp_enterprise/agents/
├── cognitive_bridge.py        # LLM reasoning ↔ exploit logic; structured JSON interchange
├── collaborative_intelligence.py  # Multi-agent collaboration; perspective synthesis; consensus
├── attack_reasoning.py        # LLM-powered attack reasoning; finding correlation; emergent insights

tools/burp_enterprise/
├── strategic_llm_layer.py     # Plan → Criticize → Propose → Refine loop
├── multi_agent_debate.py      # Multi-perspective debate; consensus reasoning; belief refinement

tools/burp_enterprise/mcp/
├── cognitive_tools.py         # MCP tools for cognitive operations (reflection, planning, hypothesis)
```

**Cognitive Bridge Pattern**:
```
LLM output (natural language reasoning)
  → cognitive_bridge.translate() → structured exploit actions
  → exploit_graph.transition() → state updates
  → cognitive_bridge.feedback() → LLM context update
```

---

## 9. Layer 7: Decision Making & Arbitration

**Purpose**: Action ranking, conflict resolution, and decision quality tracking.

```
tools/burp_enterprise/
├── decision_orchestrator.py   # Main decision engine: action prioritization, trade-off analysis
├── decision_trace.py          # Decision logging; reasoning path recording; audit trail
├── decision_benchmark.py      # Decision quality measurement; benchmark comparison

tools/burp_enterprise/agents/
├── unified_arbitration.py     # Unified finding/hypothesis arbitration; calibration drift monitoring
├── strategy_engine.py         # Strategic decision making; campaign planning
├── opportunity_scoring.py     # Opportunity detection; impact-probability scoring; ROI calculation
├── risk_aware_testing.py      # Risk profiling; impact assessment; testing prioritization

tools/burp_enterprise/exploit_chains/
├── decision_framework.py      # Decision tree framework for exploit chain selection + branching
```

**Decision Pipeline**:
```
hypothesis_list + exploit_graph_state + confidence_scores
  → decision_orchestrator.rank_actions()
  → unified_arbitration.resolve_conflicts()
  → opportunity_scoring.calculate_roi()
  → decision_trace.log()
  → EXECUTE top action
```

---

## 10. Layer 8: Exploit Graph & Attack Modeling

**Purpose**: Stateful exploit transition graph across 5 dimensions; A* pathfinding.

```
tools/burp_enterprise/agents/
├── exploit_graph.py           # Core graph: state machine modeling, probability-based pathfinding
├── exploit_verifier.py        # Exploit proof verification; transition validation
├── autonomous_exploitation.py # A* pathfinding on graph; probability-weighted cost; chain execution

tools/burp_enterprise/exploit_chains/
├── exploit_graph.py           # Extended stateful graph engine (5 dimensions)
├── graph_knowledge_base.py    # Knowledge base: vulnerability-to-state mappings
├── graph_pathfinding.py       # A* pathfinding for optimal attack sequences
├── graph_state_ops.py         # State operation management
├── graph_persistence.py       # Graph database persistence
├── graph_rendering.py         # Mermaid/Cytoscape visualization
├── graph_reporting.py         # Graph-based reporting and analytics
├── graph_integrations.py      # Integration hooks to other systems
├── graph_suggestions.py       # Next test suggestions based on graph position
├── exploit_path_planner.py    # Plan multi-step exploit sequences
├── exploit_verifier.py        # Re-execution verification before report promotion

tools/burp_enterprise/
├── exploit_graph_renderer.py  # Top-level graph visualization (Mermaid/Cytoscape)

tools/burp_enterprise/loop/
├── attack_graph.py            # Loop-level attack graph building and traversal
```

**5 Exploit Dimensions**:
```
┌─────────────┬─────────────┬──────────────┬─────────────┬─────────────┐
│   ASSET     │    AUTH     │  PRIVILEGE   │    DATA     │   CLOUD     │
│  (endpoints │  (sessions  │  (escalation │  (exfil     │  (metadata  │
│   ports)    │   tokens)   │   levels)    │   access)   │   IMDS)     │
└─────────────┴─────────────┴──────────────┴─────────────┴─────────────┘
```

---

## 11. Layer 9: Adaptive Learning & Reinforcement

**Purpose**: Continuous improvement via RL, bandits, feedback loops, and A/B testing.

```
tools/burp_enterprise/agents/
├── adaptive_learning.py       # Multi-armed bandit; feature vectors; epsilon-greedy exploration
├── rl_reward_engine.py        # Q-learning table; reward normalization; action selection
├── feedback_learning.py       # Feedback collection; outcome recording; prompt augmentation
├── ab_testing.py              # A/B testing framework; experiment tracking; model comparison

tools/burp_enterprise/
├── adaptive_chain_engine.py   # Adaptive chain generation; bandit routing; dynamic template select
├── learning_loop_engine.py    # End-to-end learning loop; feedback propagation; metric tracking
├── ml_feedback_propagator.py  # Feedback backpropagation; confidence updates; retraining signals

tools/burp_enterprise/exploit_chains/
├── weight_tuner.py            # Bayesian weight tuning: 13-signal arbiter calibration
├── learning_bridge.py         # Bridge: execution results → hypothesis learning
├── failure_pattern.py         # Pattern analysis for failed attacks

tools/burp_enterprise/loop/
├── exploration_bias.py        # Exploration vs exploitation tradeoff tuning
├── value_scorer.py            # Vulnerability impact + uncertainty scoring
├── signal_extraction.py       # Signal extraction from execution results for RL
├── feedback_loop_breaker.py   # Deadlock detection and recovery in feedback cycles
```

**RL Reward Flow**:
```
action_result → signal_extraction.extract() → rl_reward_engine.compute_reward()
  → q_table.update(state, action, reward) → adaptive_learning.update_bandit()
  → weight_tuner.recalibrate() → next action selection (epsilon-greedy)
```

---

## 12. Layer 10: Payload Synthesis Pipeline

**Purpose**: Multi-stage ML-driven payload generation with grammar, LLM, and genetic algorithms.

```
tools/burp_enterprise/exploit_chains/
├── payload_synthesis_engine.py   # Orchestrator: Grammar → LLM → GA → Arbiter → Scheduler
├── llm_synthesizer.py            # LLM-based payload synthesis when grammar confidence is low
├── grammar_synthesizer.py        # Grammar-driven payload synthesis (GBNF)
├── evolutionary_fuzzer.py        # GA-based payload evolution with fitness scoring
├── genetic_forge.py              # Genetic algorithm: crossover, mutation, selection
├── payload_arbiter.py            # 8-signal ML scoring + deduplication of candidates
├── execution_scheduler.py        # 4-phase payload execution scheduling + prioritization
├── evasion_engine.py             # WAF/IDS evasion: adaptive encoding, charset mutation
├── defensive_posture.py          # Model and track defensive mechanisms
├── synthesis_tracer.py           # Full synthesis pipeline observability
├── synthesis_context.py          # Context compilation: graph state + hypothesis + signals
├── synthesis_feedback.py         # Execution feedback → WAF, GA, Hypothesis, Campaign engines
├── synthesis_safety.py           # Safety filters: coherence + novelty + confidence guards

tools/burp_enterprise/agents/
├── payload_intelligence.py       # Payload effectiveness prediction; WAF bypass heuristics

tools/burp_enterprise/loop/
├── payload_evolution.py          # Genetic population evolution seeded by hypothesis signals

tools/burp_enterprise/
├── waf_payload_adapter.py        # Adaptive payload mutation based on WAF classification
├── waf_payload_tester.py         # Thompson sampling for WAF evasion testing
```

**PSE Pipeline**:
```
Grammar Synthesizer → candidates[]
LLM Synthesizer → candidates[]
Evolutionary Fuzzer → candidates[]
         ↓
Payload Arbiter (8-signal ML scoring)
  → Impact score + Novelty score + Execution feasibility
  → Deduplication
         ↓
Execution Scheduler (4-phase priority)
         ↓
Evasion Engine (WAF bypass encoding)
         ↓
EXECUTE → feedback → synthesis_feedback → loop
```

---

## 13. Layer 11: Vector Memory & Embeddings

**Purpose**: Semantic similarity search for RAG, memory, and reasoning augmentation.

```
tools/burp_enterprise/memory/
├── embedder.py                # Embedding models: sentence-transformers all-MiniLM-L6-v2 (384-dim)
│                              # + hashing fallback for offline use
├── vector_index.py            # HNSW-based vector index; binary quantization; Hamming distance

tools/burp_enterprise/agents/
├── agent_memory.py            # Semantic recall: vector search + TF-IDF fallback
├── rag_context.py             # RAG context building; retrieval augmentation; knowledge injection

tools/burp_enterprise/graph/
├── cross_scan_memory.py       # Cross-scan state management; shared memory across targets

tools/burp_enterprise/loop/
├── vector_reasoning.py        # Vector-based reasoning: hypothesis recovery + transfer
```

**Memory Architecture**:
```
Finding/Action → embedder.encode() → 384-dim vector
  → vector_index.add() → HNSW index
  
Query → embedder.encode() → vector_index.search(k=10)
  → rag_context.build() → LLM context window
```

---

## 14. Layer 12: Prompt Management & Security

**Purpose**: Prompt engineering, versioning, injection defense, and dynamic few-shot selection.

```
tools/burp_enterprise/
├── prompt_registry.py         # Central registry: prompt templates, versioning, A/B testing
├── progressive_prompts.py     # Multi-stage complexity: easy → hard escalation
├── few_shot_selector.py       # Dynamic few-shot example selection based on query similarity
├── thinking_budget.py         # Per-step reasoning token allocation (512-2048 by purpose)

tools/burp_enterprise/agents/
├── prompt_security.py         # Prompt injection defense; sanitization; adversarial robustness
├── doubt_injector.py          # Injects skepticism into prompts to reduce overconfidence

tools/burp_enterprise/reasoning/
├── prompt_chains.py           # Chained prompts with state passing; multi-round reasoning
├── context_budget.py          # RAG context window budget management
```

---

## 15. Layer 13: Confidence & Calibration

**Purpose**: Probability calibration, ensemble confidence, and diversity enforcement.

```
tools/burp_enterprise/
├── confidence_engine.py       # Unified confidence scoring: exploit probability + finding likelihood
├── confidence_ensemble.py     # Ensemble aggregation: Dempster-Shafer belief combination
├── confidence_diversity.py    # Diversity-driven: penalizes overconfident predictions

tools/burp_enterprise/agents/
├── bayesian_prioritizer.py    # Bayesian prioritization; belief updates; probability-weighted ranking

tools/burp_enterprise/recon_dashboard/
├── confidence_calibration.py  # Platt scaling + isotonic regression for recalibration
```

**Calibration Flow**:
```
raw_score → confidence_engine.score() → confidence_ensemble.aggregate()
  → confidence_calibration.calibrate() (Platt scaling)
  → confidence_diversity.penalize_overconfidence()
  → calibrated_probability
```

---

## 16. Layer 14: LangGraph State Machine

**Purpose**: LangGraph-based orchestration with multi-agent and reasoning subgraphs.

```
tools/burp_enterprise/graph/
├── builder.py                 # LangGraph builder; state machine construction
├── nodes.py                   # Node implementations; graph node logic
├── runner.py                  # Graph execution engine; state transitions
├── tracing.py                 # Execution tracing; state history
├── state.py                   # State definitions; schema management
├── production.py              # Production-ready graph configurations
├── checkpointer_async.py      # Async checkpointing; persistence
├── cross_scan_memory.py       # Cross-scan state management; shared memory
│
├── multi_agent/               # MULTI-AGENT COORDINATION
│   ├── builder.py             # Supervisor pattern: recon, exploit, validator subgraphs
│   ├── specialist_nodes.py    # Specialist node implementations per agent type
│   ├── state.py               # Shared state TypedDict
│   ├── runner.py              # Graph invocation and execution
│   ├── supervisor.py          # Supervisor routing logic
│   ├── handoff.py             # Agent-to-agent handoff protocol
│   └── worker_factory.py      # Worker node creation + registration
│
└── reasoning/                 # REASONING SUBGRAPH
    ├── builder.py             # Fan-out/fan-in: assess → (tech|ep|creative|chain) → merge → evaluate → plan
    ├── nodes.py               # Individual reasoning node implementations
    ├── state.py               # Reasoning state TypedDict
    └── runner.py              # Reasoning graph execution
```

**LangGraph Multi-Agent Pattern**:
```
                 ┌──────────────┐
                 │  SUPERVISOR  │
                 └──────┬───────┘
           ┌────────────┼────────────┐
           ▼            ▼            ▼
    ┌────────────┐ ┌──────────┐ ┌──────────────┐
    │   RECON    │ │ EXPLOIT  │ │  VALIDATOR   │
    │ specialist │ │specialist│ │  specialist  │
    └────────────┘ └──────────┘ └──────────────┘
           │            │            │
           └────────────┼────────────┘
                        ▼
                 ┌──────────────┐
                 │  MERGE STATE │
                 └──────────────┘
```

---

## 17. Layer 15: Autonomous Exploitation Loop

**Purpose**: Fully autonomous OBSERVE → THINK → ACT → EVALUATE → LEARN cycle.

```
tools/burp_enterprise/loop/
├── autonomous_loop.py         # Main loop orchestration (no user intervention)
├── ai_directed_executor.py    # AI-directed tool execution based on strategy
├── world_state.py             # Persistent world state: asset/auth/privilege tracking
├── confirmation_engine.py     # Finding confirmation via multi-method verification
├── signal_extraction.py       # Extract signals from results for learning
├── target_selection.py        # Multi-target prioritization algorithm
├── target_specialization.py   # Target-specific adaptation
├── campaign_strategy.py       # Multi-target campaign planning
├── parallel_executor.py       # Parallel tool execution with resource pooling
├── payload_evolution.py       # Evolutionary payload generation
├── race_engine.py             # Race condition timing engine
├── session_matrix.py          # Session state tracking across tests
├── graph_pruner.py            # Attack graph pruning (remove low-value paths)
├── exploration_bias.py        # Exploration vs exploitation tradeoff
├── feedback_loop_breaker.py   # Deadlock detection and recovery
├── value_scorer.py            # Impact + replaceability scoring
├── vector_reasoning.py        # Vector-based reasoning over finding space
├── invariant_engine.py        # Invariant checking for consistency
├── loop_config.py             # Loop configuration and tuning parameters
├── attack_graph.py            # Loop-level attack graph building
└── exploit_report.py          # Exploitation result reporting
```

---

## 18. Layer 16: Strategic & Planning Systems

**Purpose**: High-level planning, goal decomposition, and foresight simulation.

```
tools/burp_enterprise/
├── strategic_llm_layer.py       # Plan → Criticize → Propose → Refine loop
├── strategic_foresight.py       # 2-3 step lookahead; dead-end avoidance

tools/burp_enterprise/agents/
├── goal_planner.py              # Goal-based planning; subgoal generation; hierarchical decomposition
├── hierarchical_planner.py      # Hierarchical task decomposition + constraint propagation
├── next_action_advisor.py       # LLM-powered next action recommendation
├── strategy_engine.py           # Strategic decision making; campaign planning
├── proactive_intelligence.py    # Predictive intelligence; preemptive threat analysis

tools/burp_enterprise/
├── hierarchical_decomposition.py # Multi-level abstraction for complex tasks
├── qtable_advisor.py             # Q-learning advisor for action selection
├── tool_chain_advisor.py         # Optimal tool sequence recommendation
├── tool_intelligence.py          # Meta-reasoning about tool capabilities
```

---

## 18b. Layer 16b: Strategy Engine Sub-Package

**Purpose**: Decomposed strategy engine for asset discovery, finding aggregation, and parallel scanning.

```
tools/burp_enterprise/strategy/
├── core.py                    # Finding aggregation, checkpoints, robust subprocess handling
├── discovery.py               # Asset discovery with deep crawling, JS analysis, OpenAPI/GraphQL
├── models.py                  # Data models, enums, tech + attack profile constants
├── store.py                   # Strategy persistence, versioning, trend analysis, incremental testing
├── async_exec.py              # Parallel async execution with rate limiting + container execution
├── _build_facade.py           # Build script generating strategy_engine.py facade from sub-package
└── _build_modules.py          # Deprecated build script that decomposed strategy_engine.py
```

**Wiring**:
- `agents/strategy_engine.py` → delegates to `strategy/core.py`, `strategy/discovery.py`
- `strategy/store.py` → feeds `learning_loop_engine.py` with historical strategy outcomes
- `strategy/async_exec.py` → parallel tool execution used by autonomous loop

---

## 19. Layer 17: CAAP (Chain Automation)

**Purpose**: Continuous Attack and Assessment Protocol — structured hypothesis-driven chains.

```
tools/burp_enterprise/caap/
├── caap_chains.py             # Chain generation + execution orchestration
├── caap_hypothesis.py         # Specialized hypotheses for chain automation
├── caap_models.py             # Data models: chain, step, context
├── caap_formatter.py          # Output formatting for CAAP results
├── caap_parser.py             # Parsing of CAAP-generated chains
├── caap_session.py            # Session management for CAAP execution
├── caap_output_wrapper.py     # Metadata wrapping for CAAP output
├── copilot_loop.py            # Copilot-CAAP integration; feedback loops
├── vuln_knowledge.py          # Vulnerability knowledge for CAAP context
├── ui_interaction_engine.py   # UI-based exploitation; interaction automation
├── exploitation_data.py       # Data structures for exploitation tracking
├── escalation_gateway.py      # Privilege escalation chain orchestration
├── adaptive_learning.py       # RL and bandit algorithms for test selection optimization
├── agent_memory.py            # Re-export of root-level agent memory for caap package
├── autonomy.py                # Risk-gated 5-level autonomy (Manual → Full Auto)
├── browser_exploitation_engine.py # Playwright browser exploitation with authenticated DAST
├── environmental_adaptation.py # WAF/rate-limit/honeypot detection and adaptive response
├── event_bus.py               # Pub/sub event architecture with workflow orchestration
├── exploitation_engine.py     # Enterprise exploitation verification with multi-step chains
├── exploitation_models.py     # Exploitation data models: status, complexity, impact
├── exploit_verifier.py        # Active exploitability testing via automated injection
├── logging_config.py          # Centralized logging configuration for CAAP
├── poc_generator.py           # PoC code generation for 25+ vulnerability types
├── reasoning_engine.py        # Chain-of-thought intelligence for hypothesis + attack planning
├── screenshot.py              # Headless browser visual recon with clustering + diff detection
├── state_graph.py             # Application state graph for business logic flaw discovery
├── static/                    # Static assets for CAAP UI

tools/burp_enterprise/
├── caap_chains.py             # Top-level CAAP chain definitions
├── caap_hypothesis.py         # Top-level CAAP hypothesis integration
├── caap_models.py             # Top-level CAAP data models
```

---

## 20. Layer 18: ATLAS Intelligence System

**Purpose**: Offensive security intelligence with pattern memory, confidence decay, and defense modeling.

```
tools/burp_enterprise/atlas/
├── atlas.py                   # Context enrichment; finding data + threat intel integration
├── models.py                  # Data models for Atlas context
├── patterns.py                # Vulnerability patterns for matching
├── graph.py                   # Finding graph structure
├── defense.py                 # Defense context enrichment
├── archetypes.py              # Attack archetype matching
├── adapter.py                 # LLM adapter for Atlas augmentation
├── ingest.py                  # Finding ingestion pipeline
├── interface.py               # Public API
├── store.py                   # SQLite storage for enriched contexts
├── atlas_nexus.py             # Nexus integration layer

tools/burp_enterprise/mcp/
├── atlas_mcp_bridge.py        # MCP integration for Atlas
```

**ATLAS Intelligence Layers**:
```
Finding → ingest.py → patterns.match() → archetypes.classify()
  → defense.enrich() → graph.build_relationships()
  → adapter.llm_augment() → store.persist()
  → atlas_nexus.cross_reference() → enriched_context
```

---

## 21. Layer 19: Feedback & Signal Propagation

**Purpose**: Closed-loop feedback from execution results to all learning subsystems.

```
tools/burp_enterprise/
├── ml_feedback_propagator.py  # Backpropagation: WeightTuner, BayesianPrioritizer, Confidence

tools/burp_enterprise/agents/
├── feedback_learning.py       # Transforms feedback into quality improvement; prompt + temp tuning

tools/burp_enterprise/exploit_chains/
├── synthesis_feedback.py      # Propagation across: WAF, GA, Hypothesis, Campaign, Intent engines
├── weight_tuner.py            # Live calibration of 13-signal arbiter weights

tools/burp_enterprise/loop/
├── signal_extraction.py       # Extract contextual signals: success/failure/timeout classification
├── exploration_bias.py        # Tracks exploration vs exploitation balance
├── feedback_loop_breaker.py   # Detects & breaks infinite feedback cycles
```

**Feedback Propagation Chain**:
```
execution_result
  → signal_extraction.classify() → {success, failure, timeout, partial}
  → ml_feedback_propagator.propagate()
      ├─→ weight_tuner.recalibrate(13 signals)
      ├─→ bayesian_prioritizer.update_posteriors()
      ├─→ confidence_engine.adjust()
      ├─→ rl_reward_engine.update_q_table()
      ├─→ adaptive_learning.update_bandits()
      └─→ hypothesis_engine.signal_reweight()
  → synthesis_feedback.propagate()
      ├─→ WAF evasion model update
      ├─→ GA fitness recalculation
      ├─→ Campaign strategy adjustment
      └─→ Intent model refinement
```

---

## 22. Layer 20: Copilot SDK & Tool Registry

**Purpose**: GitHub Copilot integration with 67+ tools across security testing domains.

```
tools/burp_enterprise/agents/
├── copilot_sdk_engine.py          # Core engine: 67+ tool integration; unified registration
├── copilot_sdk_tools.py           # Base tool implementations; utility functions
├── copilot_sdk_agents.py          # Agent-specific tools; orchestration
├── copilot_sdk_discovery_tools.py # Recon and discovery tools
├── copilot_sdk_exploit_cloud_tools.py # Cloud exploitation tools
├── copilot_sdk_infra_tools.py     # Infrastructure analysis tools
├── copilot_sdk_intel_tools.py     # Intelligence and data tools
├── copilot_sdk_vuln_tools.py      # Vulnerability scanning tools
├── copilot_sdk_tool_registry.py   # Unified tool registry; schema management
├── native_tool_calling.py         # Native OpenAI/Anthropic function calling
├── copilot.py                     # Copilot chat interface
├── copilot_loop.py                # Copilot-driven exploration loop
├── copilot_reasoning.py           # Copilot-specific reasoning prompts
├── nl_translator.py               # Natural language → test command translation
```

**Tool Categories (67+)**:
```
Discovery: subdomain_enum, port_scan, tech_detect, crawl, content_discover
Exploitation: sqli, xss, ssrf, lfi, rce, jwt, deserialization
Cloud: aws_metadata, gcp_audit, azure_enum
Intel: cve_lookup, threat_model, vuln_knowledge
Analysis: response_diff, auth_test, header_check
Agent: hypothesis_gen, reasoning_chain, exploit_graph_query
```

---

## 23. Layer 21: AI/ML Security Scanner

**Purpose**: 7 detection engines for AI/ML-specific vulnerabilities.

```
tools/burp_enterprise/ai_ml_scanner.py    # Main orchestrator: coordinates 7 engines

tools/burp_enterprise/ai_ml/
├── _prompt_injection.py       # Prompt injection attack detection; LLM fingerprinting; jailbreak
├── _vector_database.py        # Vector DB exposure: Pinecone/Weaviate/Qdrant/Milvus fingerprinting
├── _model_endpoint.py         # ML model endpoint detection: Gradio/HuggingFace/TorchServe
├── _model_serialization.py    # Unsafe deserialization: BERT/GPT model weight exposure
├── _rag_pipeline.py           # RAG pipeline detection; document poisoning; LangChain/LlamaIndex
├── _ai_api_proxy.py           # AI API proxy/gateway detection; key leakage; Azure OpenAI
├── _models.py                 # Enums: platforms, database types, attack vectors, severity
├── _utils.py                  # Key redaction; safe request utilities; finding formatting
└── _serialization.py          # Sensitive path filtering; model artifact detection
```

**7 Detection Engines**:
```
┌────────────────────────────────────────────────────────┐
│              AI/ML Security Scanner                     │
│                                                         │
│  1. Prompt Injection Detection                          │
│  2. Vector Database Exposure                            │
│  3. ML Model Endpoint Discovery                         │
│  4. Model Serialization Vulnerability                   │
│  5. RAG Pipeline Attack Surface                         │
│  6. AI API Proxy/Gateway Security                       │
│  7. Model Artifact Exposure                             │
└────────────────────────────────────────────────────────┘
```

---

## 24. Layer 22: Knowledge & Domain Systems

**Purpose**: Domain expertise, vulnerability knowledge, and threat modeling.

```
tools/burp_enterprise/agents/
├── domain_knowledge_engine.py   # Tech stack analysis; technology → vulnerability mapping
├── vulnerability_intelligence.py # CVE intelligence; exploit correlation; knowledge base

tools/burp_enterprise/
├── vuln_knowledge.py            # Vulnerability classification + knowledge graph
├── knowledge_resilience.py      # Prevents knowledge brittleness; distributes across subsystems
├── transfer_intelligence.py     # Knowledge transfer across targets + domains
├── error_intelligence.py        # Learns from error responses; infers app behavior
├── entropy_intelligence.py      # Anomaly detection via entropy analysis

tools/burp_enterprise/exploit_chains/
├── graph_knowledge_base.py      # Graph-indexed vulnerability knowledge
├── vuln_knowledge.py            # Chain-specific vulnerability knowledge

tools/burp_enterprise/intel/
├── threat_modeler.py            # Threat actor modeling; predicts likely attack chains
```

---

## 25. Layer 23: World Model & State Tracking

**Purpose**: Target simulation, counterfactual reasoning, and temporal stability.

```
tools/burp_enterprise/
├── world_model.py               # Target simulation; counterfactual reasoning; attack sequencing
├── target_mental_model.py       # Target profiling; mental model construction
├── temporal_stability.py        # Temporal consistency; drift detection
├── self_optimizing_stack.py     # Self-tuning optimization stack

tools/burp_enterprise/loop/
├── world_state.py               # Persistent state: asset/auth/privilege tracking across phases

tools/burp_enterprise/graph/
├── state.py                     # State definitions for graph execution
├── cross_scan_memory.py         # Cross-scan state; shared memory
```

---

## 26. Layer 24: Truth Enforcement & Verification

**Purpose**: Hard proof gates, finding validation, and false positive elimination.

```
tools/burp_enterprise/recon_dashboard/
├── truth_enforcement.py         # Hard gates: ConfidenceCapper, ChainCollapser, DefenseCostModel
├── finding_validator.py         # Multi-stage validation: proof, contradiction, confidence
├── multi_request_validator.py   # Validates findings requiring multiple HTTP interactions
├── proof_first_severity.py      # Proof-tiered severity scoring (execution-based)
├── report_fp_detection.py       # False positive detection in reports
├── remediation_validation.py    # Validates if remediations fixed issues

tools/burp_enterprise/
├── exploit_verifier.py          # Re-execution verification before report promotion
├── oob_verifier.py              # Out-of-band interaction verification (DNS, HTTP callback)
├── secret_verifier.py           # Credential/secret exploitation verification
├── secret_verifiers_extended.py # Extended verification: API keys, tokens, DB strings
├── verification_chain.py        # Multi-step verification chains; proof lifecycle
```

---

## 27. Layer 25: Impact & Scoring Systems

**Purpose**: CVSS scoring, business impact, and bounty ROI calculation.

```
tools/burp_enterprise/
├── chain_impact_scorer.py       # CVSS/business impact scoring for exploit chains

tools/burp_enterprise/agents/
├── opportunity_scoring.py       # Impact × probability scoring; ROI calculation

tools/burp_enterprise/exploit_chains/
├── chain_impact_scorer.py       # Chain-specific impact scoring

tools/burp_enterprise/caap/
├── impact_chain.py              # Impact propagation through chain reasoning

tools/burp_enterprise/recon_dashboard/
├── impact_amplifier.py          # Impact amplification without report bloat
├── bounty_ops.py                # Bounty scoring + ROI calculation
├── payout_metrics.py            # Monetization metrics for findings
├── target_scoring.py            # ML-driven target risk scoring
├── benchmark_tracker.py         # ML model quality tracking over time
```

---

## 28. Layer 26: Intelligence Gathering

**Purpose**: Proactive hunting, transfer learning, and error-based inference.

```
tools/burp_enterprise/agents/
├── proactive_intelligence.py    # Proactive threat hunting; hypothesis generation without findings
├── vulnerability_intelligence.py # CVE database + model lookup

tools/burp_enterprise/
├── transfer_intelligence.py     # Cross-target/domain knowledge transfer
├── error_intelligence.py        # App behavior inference from error responses
├── entropy_intelligence.py      # Anomaly detection via entropy analysis
├── tool_intelligence.py         # Meta-reasoning about tool capabilities

tools/burp_enterprise/recon_dashboard/
├── cross_target_intelligence.py # Intelligence transfer across targets
├── platform_intelligence_memory.py # Platform-specific intelligence cache
```

---

## 29. Layer 27: Recon Dashboard Intelligence

**Purpose**: Dashboard-integrated ML systems for execution intelligence, truth enforcement, and autonomous exploitation.

```
tools/burp_enterprise/recon_dashboard/
│
├── ── INTELLIGENCE & ML ──────────────────────────────
├── execution_intelligence.py    # Dynamic weight learning + context-aware modulation
├── execution_orchestrator.py    # Value-based runtime budgets + real-time monitoring
├── chain_execution_loop.py      # Closed-loop exploit chain engine with LLM discovery
├── auto_exploit_executor.py     # Auto-PoC execution, verification, impact tracking
├── exploit_persistence_engine.py # Exploit adaptation on failure with pivoting
├── attack_strategy_engine.py    # Proactive strategy with EV scoring + budget allocation
├── authenticated_exploit_engine.py # Token extraction + auth flow simulation + defense evasion
├── causal_inference.py          # DAG-based causal relationships between findings
├── differential_analysis.py     # Mandatory baseline ≠ modified response proof
├── graph_reasoning.py           # Graph-based exploit-path analysis + critical-path prioritisation
├── confidence_calibration.py    # Bayesian calibration replacing hardcoded confidence priors
├── cross_target_intelligence.py # Cross-target intelligence sharing + real-time replanning
├── platform_intelligence_memory.py # Cross-target persistent learning per platform
├── langgraph_scan.py            # LangGraph-based scan pipeline with SQLite checkpointing
├── llm_helpers.py               # LLM lazy-initialisation helpers
├── multimodal_support.py        # Multi-modal: images + rendered HTML into LLM context
├── eta_engine.py                # ETA computation with phase cost weights + trend detection
├── scan_mode_config.py          # BUG_BOUNTY, GENERAL_ASSESSMENT, COMPLIANCE, PENTEST intents
├── target_profile.py            # Progressive domain/IP intelligence collector
├── target_scoring.py            # Pre-Exploit Decision Dominance with budget allocation
├── threat_modeling.py           # STRIDE, DREAD, PASTA threat modeling frameworks
├── benchmark_tracker.py         # Campaign ROI and win condition tracking
├── bounty_ops.py                # Bounty workflow: truth enforcement + exploit library + submission
├── payout_metrics.py            # Signal-to-Payout instrumentation tracking
├── impact_amplifier.py          # Impact chaining + business logic exploitation + auto-bounty
│
├── ── TRUTH & VERIFICATION ───────────────────────────
├── truth_enforcement.py         # Hard proof gates + confidence ceilings
├── finding_validator.py         # Code-enforced validation gateway preventing FPs at source
├── multi_request_validator.py   # Multi-HTTP validation engine v2 with chained strategies
├── proof_first_severity.py      # Severity from verified impact, not theoretical classification
├── report_fp_detection.py       # False positive detection + tooling gap annotation
├── remediation_validation.py    # Remediation validation with curated playbooks
│
├── ── FINDING PIPELINE ───────────────────────────────
├── finding_pipeline.py          # Centralised: parser → dedup → arbitrate → verify → deliver
├── finding_parsers.py           # Per-phase parsers extracting normalised findings
├── finding_dedup.py             # Multi-tool confidence scoring + lifecycle tracking
├── findings_store.py            # Unified cross-module finding persistence
├── finding_validator.py         # Multi-stage validation gateway
│
├── ── REPORT GENERATION ──────────────────────────────
├── report_generator.py          # Markdown report generator main module
├── report_renderer.py           # Markdown rendering pipeline with styling
├── report_analysis.py           # Tech anomalies and coverage gap analysis
├── report_dedup.py              # Post-filtering dedup (WAF, parameter)
├── report_filters.py            # Consolidated filtering + severity propagation
├── report_fp_detection.py       # FP detection + tooling gap annotation
├── _report_constants.py         # Shared constants, severity ordering, utilities
│
├── ── ROUTES (HTTP API) ──────────────────────────────
├── routes_agent.py              # Agent-loop + agent-memory route handlers
├── routes_assessment.py         # Assessment-engine + intelligence route handlers
├── routes_cross_target.py       # Cross-target intelligence + replanning routes
├── routes_exploit_graph.py      # Exploit-graph visualization route handlers
├── routes_findings.py           # Finding-annotation + unified-findings routes
├── routes_intelligence_experience.py # Intelligence Experience: HOW Venator thinks
├── routes_llm.py                # LLM chat + streaming route handlers
├── routes_multi_agent.py        # Multi-agent campaign orchestration routes
├── routes_provider_vault.py     # Encrypted LLM key management vault
├── routes_reasoning.py          # Reasoning decision trace route handlers
├── routes_scan_config.py        # Scan mode config with intent detection
├── routes_sdk_engine.py         # Copilot SDK Agentic Engine routes
├── routes_standalone.py         # Standalone-recon, report, export routes
├── routes_target_scoring.py     # Target ROI scoring routes
│
├── ── INFRASTRUCTURE ─────────────────────────────────
├── server.py                    # aiohttp + WebSocket server for real-time dashboard
├── runner.py                    # StandaloneReconRunner autonomous recon executor
├── state.py                     # DashboardState thread-safe container
├── state_serializers.py         # State serialization + differential tracking
├── session_store.py             # Session save/restore/list/prune persistence
├── db_persistence.py            # SQLite migration replacing JSON file snapshots
├── scheduler.py                 # Resource governor + rate-limiter with adaptive concurrency
├── command_executor.py          # Subprocess lifecycle, deferral queue, background sweeper
├── infra_monitor.py             # Burp, Docker, performance, API key monitoring probes
├── appliance_api.py             # Appliance REST API for scans + license + settings
├── atlas_api.py                 # Atlas Intelligence Dashboard API
├── conversation_branching.py    # Tree-structured chat with branch navigation
├── conversation_export.py       # Chat history export (JSON, Markdown/HTML, CSV)
├── phase_commands.py            # Phase command definitions with token replacement
├── phase_data_store.py          # Phase Data Store reading from report directory
├── phase_defs.py                # Phase definitions, scheduling, cost-weights, timeouts
├── _assets.py                   # Static asset loading for dashboard HTML/CSS/JS
├── _hooks.py                    # Hook/utility functions + dashboard HTML assembly
├── _notify.py                   # Low-level notification helpers
├── _tech_utils.py               # Technology name sanitisation utilities
│
└── phase_handlers/              # PHASE HANDLER SUB-PACKAGE
    ├── base.py                  # Phase handler protocol + context with pre/expand/post hooks
    ├── discovery.py             # Phases 1-6: crawl, JS, param, content discovery
    ├── infrastructure.py        # Phases 7-13: subdomain, DNS, ports infrastructure
    ├── security_testing.py      # Phases 14-17: WAF, secrets, injection testing
    ├── advanced.py              # Phases 20-27: specialized scanner handlers
    └── intelligence.py          # Phases 28-30: posture, topology, correlation
```

**Recon Dashboard Intelligence Flow**:
```
Phase Execution → finding_parsers → finding_pipeline → finding_dedup
  → finding_validator → truth_enforcement → proof_first_severity
  → confidence_calibration → findings_store → report_generator
  
Strategy: target_scoring → attack_strategy_engine → execution_orchestrator
  → execution_intelligence (learns) → cross_target_intelligence (transfers)
  → platform_intelligence_memory (persists) → bounty_ops + payout_metrics
```

---

## 30. Layer 28: Safety & Defense Hardening

**Purpose**: Protect LLM pipeline from adversarial attacks and unsafe outputs.

```
tools/burp_enterprise/agents/
├── llm_defense_hardening.py     # Prompt injection defense; jailbreak mitigation
├── llm_advanced_defense.py      # Semantic fuzzing; adversarial testing
├── llm_output_guard.py          # Output schema validation; safety filtering
├── prompt_security.py           # Prompt sanitization; adversarial robustness

tools/burp_enterprise/
├── synthesis_safety.py          # Payload synthesis safety: coherence + novelty + confidence guards
```

**Defense Layers**:
```
INPUT → prompt_security (sanitize) → llm_defense_hardening (injection guard)
  → LLM CALL → llm_output_guard (schema validate) → llm_advanced_defense (semantic check)
  → synthesis_safety (if payload) → SAFE OUTPUT
```

---

## 31. Layer 29: Observability & Tracing

**Purpose**: Full-stack decision and execution tracing for audit and debugging.

```
tools/burp_enterprise/
├── decision_trace.py            # Decision audit log; traces action recommendations
├── decision_benchmark.py        # Decision quality tracking over time

tools/burp_enterprise/exploit_chains/
├── synthesis_tracer.py          # Full synthesis pipeline tracing

tools/burp_enterprise/pipeline/
├── pipeline_tracing.py          # Per-stage pipeline tracing + timing metrics

tools/burp_enterprise/agents/
├── llm_tracing.py               # LLM request/response logging; latency profiling
├── llm_tracking.py              # Token usage + cost metering
├── agent_telemetry.py           # Agent phase tracking; hypothesis snapshots
├── reasoning_display.py         # Terminal rendering of reasoning steps
```

---

## 32. Layer 30: MCP Extension (VS Code)

**Purpose**: VS Code extension integrating Copilot chat with security testing tools.

```
CaseCrack/mcp-extension/src/
├── extension.ts               # Main entry point; command registration
├── toolLoop.ts                # LLM tool-calling loop; VS Code Language Model API; safety controls
├── chatHandlers.ts            # Copilot chat handler for security testing commands
├── treeView.ts                # Session tree: hypothesis display, confidence scoring
├── dashboardPanel.ts          # Dashboard webview: live progress, severity heatmap, hypothesis
├── lib.ts                     # Context window management; token estimation; YAML parsing
├── eventBus.ts                # Event distribution for scan progress and findings
├── execCli.ts                 # CLI execution from TypeScript with output streaming
├── mcpProvider.ts             # MCP server provider: 40+ tools registered
├── cliDaemon.ts               # Background CLI daemon management
├── reconBridge.ts             # Bridge: CLI recon output → extension UI
├── commands.ts                # CLI command construction and execution
├── logger.ts                  # Structured logging
├── globals.ts                 # Global state (output channel, event bus)
├── progressStatusBar.ts       # Status bar: scan progress display
└── mcpHealth.ts               # MCP server health checking
```

**MCP Tool Categories (40+)**:
```
package.json registers tools for:
- Scan management (start, stop, status)
- Target configuration
- Finding queries
- Hypothesis testing
- Exploit graph operations
- Agent commands
- Intelligence queries
- Report generation
```

---

## 33. Layer 31: Chain YAML DSL Integration

**Purpose**: Declarative attack chain definitions with exploit graph state transitions.

```
CaseCrack/chains/
├── web/                       # Web vulnerability chains
│   ├── xss-reflected.yaml         # XSS with exploit_graph_hints
│   ├── sql-injection.yaml         # SQLi with graph transitions
│   ├── dom-clobbering.yaml        # DOM injection with HTML-injectable state
│   ├── cache-poisoning.yaml       # Cache poisoning with graph transitions
│   ├── race-condition.yaml        # Race condition exploitation
│   ├── ssrf-blind-oob.yaml        # SSRF OOB with graph path modeling
│   ├── path-traversal.yaml        # Path traversal with graph hints
│   ├── http2-smuggling.yaml       # HTTP/2 smuggling with state tracking
│   ├── cors-exploitation.yaml     # CORS bypass
│   ├── deserialization-attack.yaml # Serialization with graph states
│   ├── sse-injection.yaml         # Server-sent event injection
│   ├── wasm-security.yaml         # WebAssembly module detection
│   └── ...
├── auth/                      # Authentication chains
│   ├── privilege-boundaries.yaml  # Privilege escalation with auth transitions
│   ├── password-reset.yaml        # Password reset flaws
│   ├── saml-misconfig.yaml        # SAML misconfiguration
│   └── ...
├── compliance/                # Compliance chains
│   ├── pci-dss-scan.yaml         # PCI DSS with graph hints
│   ├── hipaa-security.yaml       # HIPAA compliance
│   └── ...
├── cloud/                     # Cloud security chains
│   ├── ssrf-cloud-risk.yaml      # Cloud SSRF risk
│   └── ...
├── supply_chain/              # Supply chain chains
│   ├── secrets-repo.yaml        # Secrets detection
│   └── ...
├── _shared/                   # Shared stages
│   └── stages/
│       ├── recon.yaml            # Reconnaissance stage (included by chains)
│       ├── content_discovery.yaml # Content discovery stage
│       └── cache_probe.yaml      # Cache behavior detection
└── ...
```

**Chain YAML → Exploit Graph Integration**:
```yaml
# Example: exploit_graph_hints in chain YAML
exploit_graph_hints:
  transitions:
    - from_state: "unauthenticated"
      to_state: "xss_injectable"
      condition: "reflected_param_found"
    - from_state: "xss_injectable"
      to_state: "session_hijacked"
      condition: "cookie_stolen"
```

---

## 33b. Layer 31b: MCP Python Server

**Purpose**: Python-side MCP server exposing 109+ security tools to Copilot with intelligent curation.

```
tools/burp_enterprise/mcp/
├── mcp_server.py              # MCP protocol server exposing tools as Copilot native functions
├── mcp_tools.py               # Tool definitions, schemas, meta-tool registry + capability mapping
├── mcp_builtins.py            # Builtin tool handler implementations for server routing
├── tool_abstraction.py        # Meta-tool layer reducing 109 tools to ~25 curated tools
├── tool_chain_advisor.py      # Context-aware dynamic tool chain suggestions from session state
├── cognitive_tools.py         # MCP cognitive operations (reasoning, hypothesis, memory access)
├── cognitive_bridge.py        # Bidirectional reasoning fusion: Python tactical ↔ Copilot strategic
├── atlas_mcp_bridge.py        # MCP ↔ ATLAS intelligence integration
├── atlas.py                   # Attack graph visualization + exploitation path discovery
├── assessment_engine.py       # Single entry point consolidating all security assessment commands
├── chain_matcher.py           # Automatic workflow selection from fingerprints + queries
├── escalation_gateway.py      # Dynamic autonomy protocol for Copilot escalation requests
├── next_action_advisor.py     # CAAP-formatted next-step recommendations post-command
├── agent_memory.py            # Persistent long-term memory for autonomous testing agent
├── agent_telemetry.py         # Real-time streaming phase telemetry from OBSERVE-EXECUTE-LEARN
├── dashboard_renderer.py      # Visual progress overlay with findings dashboard (MD/JSON/HTML)
├── session_manager.py         # Implicit assessment session lifecycle + findings DB
├── storage.py                 # Persistent request/response storage with SQLite backend
├── logging_config.py          # Enterprise structured logging with progress + event emission
├── shutdown.py                # Signal handling + graceful shutdown infrastructure
└── vuln_knowledge.py          # Centralised vulnerability-technology knowledge base
```

**MCP Server Architecture**:
```
Copilot (VS Code) → mcpProvider.ts → WebSocket → mcp_server.py
  → tool_abstraction.py (curate 109→25 tools)
  → mcp_tools.py (dispatch to handler)
  → cognitive_bridge.py (reasoning fusion)
  → assessment_engine.py | chain_matcher.py | atlas.py
  → agent_telemetry.py (stream progress) → dashboard_renderer.py
```

---

## 34. Layer 32: Multi-Agent Swarm

**Purpose**: Distributed multi-agent coordination with shared weights and multi-GPU orchestration.

```
tools/burp_enterprise/swarm/
├── swarm.py                   # Multi-agent orchestrator coordinating specialized pentesting agents
├── agent_roles.py             # Role definitions: Scanner, Reasoner, Executor, Judge
├── shared_weights.py          # Multi-GPU shared weight synchronization
├── message_bus.py             # Typed asyncio inter-agent pub/sub + request/reply
├── gpu_governor.py            # Multi-agent VRAM budget enforcement + dynamic rebalancing
│
└── multi_gpu/                 # MULTI-GPU COORDINATION
    ├── governor.py            # Top-level orchestrator for multi-GPU topology + sharding
    ├── messenger.py           # Cross-GPU agent message routing with bandwidth-aware batching
    ├── model_sharder.py       # Tensor-parallel layer distribution across GPUs
    ├── scheduler.py           # Agent placement + migration based on VRAM and affinity
    └── topology.py            # GPU discovery, P2P connectivity, NVLink/PCIe, NUMA affinity
```

**Swarm Coordination Pattern**:
```
  ┌──────────────────────────────────────────────────┐
  │                 swarm.py (Orchestrator)           │
  │    agent_roles.py → Scanner, Reasoner,           │
  │                      Executor, Judge              │
  │    message_bus.py → publish/subscribe/reply       │
  └────────────┬─────────────┬───────────────────────┘
               │             │
  ┌────────────▼──┐  ┌──────▼───────────────────┐
  │ gpu_governor  │  │  multi_gpu/               │
  │ VRAM budgets  │  │  governor → topology      │
  │               │  │  scheduler → model_sharder│
  │               │  │  messenger → cross-GPU    │
  └───────────────┘  └──────────────────────────┘
```

---

## 35. Layer 33: Session & Campaign Intelligence

**Purpose**: Cross-session learning and multi-target campaign optimization.

```
tools/burp_enterprise/session_auth/
├── session_intelligence.py    # Session state learning; anomaly detection; auth chain modeling
├── campaign_intelligence.py   # Cross-session: tool success rates, finding patterns, strategy evolution
```

---

## 36. Layer 34: Tests & Validation

**Purpose**: Test coverage for ML/LLM components.

```
CaseCrack/tests/
├── test_agent_memory.py           # AgentMemory, Fact, Rule, WorkingMemory, SemanticMemory
├── test_agentic_audit_fixes.py    # LLM agentic mode fixes (A-1 to A-4)
├── strict_fakes.py                # StrictHypothesisEngine, StrictUnifiedReasoning fakes
├── integration/
│   ├── test_exploitation_chains.py # ExploitGraph, ExploitGraphEngine integration
│   └── test_detection_regression.py # Detection regression with YAML manifest
```

---

## 37. Layer 35: Configuration & Scripts

**Purpose**: Configuration, dependency checking, and test orchestration.

```
CaseCrack/scripts/
├── check_deps.py              # Dependency checker with "llm" category (httpx, tiktoken)
├── add_docstrings.py          # Module docstring generator (references agent_loop, llm_bridge, etc.)
├── test_all_commands.py       # Tests 10+ agent/LLM CLI commands
├── live_test_cli_matrix.py    # Live test matrix from YAML profile

CaseCrack/config/
├── live_test_profile.yaml     # CLI command testing profile
├── policy.yaml                # Security policy configuration
├── burp-config.yaml.example   # Report format config
├── custom-detectors.yaml.example # Custom pattern detection
```

---

## 38. Layer 36: Documentation

**Purpose**: Architecture and design documentation for ML/LLM systems.

```
CaseCrack/docs/
├── COPILOT-AUTONOMOUS-AGENT-PROTOCOL.md   # CAAP v1.0: hypothesis markers, reasoning scaffolds
├── VENATOR-SYSTEM-REFERENCE.md            # 22 phases, chain DSL, Layer 6 autonomous agent/LLM
├── ATLAS-DESIGN.md                        # Pattern memory, confidence scoring, half-life decay
├── STRATEGY-ENGINE-IMPLEMENTATION-PLAN.md # Goal-driven strategy engine
├── EXPLOIT-GRAPH-IMPLEMENTATION-PLAN.md   # Stateful exploit graph (5 dimensions)
```

---

## 38b. Layer 36b: Exploitation Sub-Package

**Purpose**: Modular exploitation package for chain orchestration, CVSS scoring, and PoC generation.

```
tools/burp_enterprise/exploitation/
├── engine.py                  # Main exploitation orchestrator: verification, PoC, impact, chains
├── chains.py                  # Multi-step attack chain orchestration with conditional steps
├── cvss.py                    # CVSS 3.1 calculator, CWE mappings, bounty estimates, remediation
├── impact.py                  # Impact demonstration showing real-world consequences
├── models.py                  # Canonical exploitation data models
├── poc_generator.py           # PoC code generation for 25+ exploitation techniques
└── verifier.py                # Active exploitation verification via automated injection
```

---

## 38c. Layer 36c: Tool Registry

**Purpose**: Formal AI action → tool command mapping with fallback selection.

```
tools/burp_enterprise/tool_registry/
├── registry.py                # Registry mapping AI actions to tool commands + capability queries
├── action_translator.py       # Bridge between AI actions and concrete tool invocations
├── output_parsers.py          # Unified structured parsing for every tool's output format
└── fallback.py                # Automatic alternative tool selection when primary unavailable
```

---

## 38d. Layer 36d: ML-Relevant Files in Non-ML Directories

**Purpose**: ML/intelligence components embedded in infrastructure, output, scanner, and testing directories.

```
tools/burp_enterprise/core_infra/           # Infrastructure layer
├── error_intelligence.py      # Error pattern intelligence (re-export from root)
├── confidence_engine.py       # Confidence scoring (re-export from root)
├── exploit_graph.py           # Exploit graph (re-export from root)
├── severity_engine.py         # Severity engine (re-export from root)
├── self_healing.py            # Self-Healing Engine for autonomous recovery + rebalancing

tools/burp_enterprise/output/               # Output processing layer
├── confidence_engine.py       # Production intelligent confidence scoring normalizing signals
├── response_classifier.py     # Pre-filter: CDN challenges, WAF, CAPTCHA classification
├── correlation_engine.py      # Automated recon correlation: secrets → endpoints → infra
├── exploitation_models.py     # Exploitation models (re-export from root)
├── exploit_graph.py           # Exploit graph (re-export from root)

tools/burp_enterprise/scanners/             # Scanner layer
├── business_logic_ai.py       # AI-powered business logic testing with LLM workflow analyzer
├── error_intelligence.py      # Error pattern intelligence systematic hunting
├── scan_intelligence.py       # Scan Intelligence brain: prioritization + scanner chaining
├── state_graph.py             # State graph (re-export from root)
├── state_machine_tester.py    # State machine workflow testing for TOCTOU + BOLA
├── waf_adaptive.py            # ML-Adaptive WAF Bypass: Thompson Sampling + RL
├── waf_payload_adapter.py     # WAF-vendor → payload-bypass mapping adapter
├── waf_payload_tester.py      # WAF-Adaptive Payload Tester inline bypass bridge

tools/burp_enterprise/testing_tools/        # Testing tools layer
├── payload_intelligence.py    # Context-aware payload generation per framework/DB/WAF
├── evasion_engine.py          # Evasion-aware request crafting: TLS, headers, timing
├── evolutionary_fuzzer.py     # GA mutations + coverage-guided fuzzing
├── vuln_knowledge.py          # Vulnerability knowledge (re-export from root)
```

---

## 39. Complete File Index (All 400+ Files)

### A. LLM Core (18 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 1 | `llm_bridge.py` | agents/ | Main LLM orchestration; provider dispatch |
| 2 | `llm_clients.py` | agents/ | OpenAI, Anthropic, Ollama HTTP wrappers |
| 3 | `llm_routing.py` | agents/ | Dynamic provider/model selection |
| 4 | `llm_registry.py` | agents/ | Model registry; provider configs |
| 5 | `llm_cache.py` | agents/ | Semantic response caching |
| 6 | `llm_types.py` | agents/ | Type definitions; enums |
| 7 | `llm_ops.py` | agents/ | Lifecycle management; batch processing |
| 8 | `llm_adaptive.py` | agents/ | Adaptive temperature tuning |
| 9 | `llm_intelligence.py` | agents/ | Context-aware capability profiling |
| 10 | `llm_tracking.py` | agents/ | Token usage; cost analytics |
| 11 | `llm_tracing.py` | agents/ | Request/response logging |
| 12 | `llm_defense_hardening.py` | agents/ | Prompt injection defense |
| 13 | `llm_advanced_defense.py` | agents/ | Advanced adversarial protection |
| 14 | `llm_output_guard.py` | agents/ | Output schema validation |
| 15 | `llm_hardware_adapter.py` | agents/ | GPU/CPU detection; VRAM management |
| 16 | `llm_production.py` | agents/ | Circuit breaker; rate limiting |
| 17 | `llm_shutdown.py` | agents/ | Graceful shutdown; cleanup |
| 18 | `llm_synthesizer.py` | exploit_chains/ | LLM-based payload synthesis |

### B. Agent System (14 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 19 | `agent_loop.py` | agents/ | Main hypothesis execution cycle |
| 20 | `agent_memory.py` | agents/ | Episodic memory; TF-IDF + vector search |
| 21 | `agent_sessions.py` | agents/ | Session state management |
| 22 | `agent_telemetry.py` | agents/ | Phase tracking; metrics |
| 23 | `copilot_loop.py` | agents/ | Copilot exploration loop |
| 24 | `copilot.py` | agents/ | Copilot chat interface |
| 25 | `unified_agent.py` | agents/ | Unified dispatch to sub-agents |
| 26 | `multi_agent_debate.py` | root | Multi-perspective debate/consensus |
| 27 | `collaborative_intelligence.py` | agents/ | Multi-agent collaboration |
| 28 | `role_registry.py` | agents/ | Multi-agent role definitions |
| 29 | `nl_translator.py` | agents/ | NL → test command translation |
| 30 | `next_action_advisor.py` | agents/ | LLM-powered next action |
| 31 | `long_running_orchestrator.py` | agents/ | Checkpoint/resume orchestration |
| 32 | `doubt_injector.py` | agents/ | Skepticism injection |

### C. Reasoning & Hypothesis (14 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 33 | `reasoning_engine.py` | agents/ | Bayesian hypothesis engine |
| 34 | `reasoning_display.py` | agents/ | Chain-of-thought visualization |
| 35 | `copilot_reasoning.py` | agents/ | Copilot-specific reasoning |
| 36 | `domain_knowledge_engine.py` | agents/ | Tech → vulnerability mapping |
| 37 | `bayesian_prioritizer.py` | agents/ | Probability-weighted ranking |
| 38 | `attack_reasoning.py` | agents/ | LLM-powered attack reasoning |
| 39 | `hypothesis_engine.py` | root | Dynamic signal-driven reweighting |
| 40 | `unified_reasoning.py` | root | Unified framework; intent model |
| 41 | `hypothesis_manager.py` | reasoning/ | Hypothesis lifecycle management |
| 42 | `prompt_chains.py` | reasoning/ | Multi-round reasoning prompts |
| 43 | `context_budget.py` | reasoning/ | RAG context budget |
| 44 | `kv_checkpoint.py` | reasoning/ | KV cache checkpointing |
| 45 | `strategic_llm_layer.py` | root | Plan → Criticize → Propose → Refine |
| 46 | `strategic_foresight.py` | root | 2-3 step lookahead |

### D. Cognitive & Decision (12 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 47 | `cognitive_bridge.py` | agents/ | LLM ↔ exploit logic bridge |
| 48 | `decision_orchestrator.py` | root | Action prioritization |
| 49 | `decision_trace.py` | root | Decision audit trail |
| 50 | `decision_benchmark.py` | root | Quality measurement |
| 51 | `unified_arbitration.py` | agents/ | Conflict resolution |
| 52 | `strategy_engine.py` | agents/ | Strategic decision making |
| 53 | `opportunity_scoring.py` | agents/ | Impact-probability scoring |
| 54 | `risk_aware_testing.py` | agents/ | Risk profiling |
| 55 | `decision_framework.py` | exploit_chains/ | Decision tree framework |
| 56 | `goal_planner.py` | agents/ | Goal-based planning |
| 57 | `hierarchical_planner.py` | agents/ | Task decomposition |
| 58 | `hierarchical_decomposition.py` | root | Multi-level abstraction |

### E. Exploit Graph (14 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 59 | `exploit_graph.py` | agents/ | Core graph; probability pathfinding |
| 60 | `exploit_graph.py` | exploit_chains/ | Extended 5-dimension graph |
| 61 | `graph_knowledge_base.py` | exploit_chains/ | Vuln-to-state mappings |
| 62 | `graph_pathfinding.py` | exploit_chains/ | A* optimal attack sequences |
| 63 | `graph_state_ops.py` | exploit_chains/ | State operations |
| 64 | `graph_persistence.py` | exploit_chains/ | Graph DB persistence |
| 65 | `graph_rendering.py` | exploit_chains/ | Mermaid/Cytoscape rendering |
| 66 | `graph_reporting.py` | exploit_chains/ | Graph analytics |
| 67 | `graph_integrations.py` | exploit_chains/ | System integration hooks |
| 68 | `graph_suggestions.py` | exploit_chains/ | Next test suggestions |
| 69 | `exploit_path_planner.py` | exploit_chains/ | Multi-step planning |
| 70 | `exploit_graph_renderer.py` | root | Top-level visualization |
| 71 | `autonomous_exploitation.py` | agents/ | A* pathfinding execution |
| 72 | `attack_graph.py` | loop/ | Loop-level graph building |

### F. Payload Synthesis (17 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 73 | `payload_synthesis_engine.py` | exploit_chains/ | PSE orchestrator |
| 74 | `llm_synthesizer.py` | exploit_chains/ | LLM-based synthesis |
| 75 | `grammar_synthesizer.py` | exploit_chains/ | Grammar-driven synthesis |
| 76 | `evolutionary_fuzzer.py` | exploit_chains/ | GA payload evolution |
| 77 | `genetic_forge.py` | exploit_chains/ | Genetic algorithms |
| 78 | `payload_arbiter.py` | exploit_chains/ | 8-signal ML scoring |
| 79 | `execution_scheduler.py` | exploit_chains/ | 4-phase scheduling |
| 80 | `evasion_engine.py` | exploit_chains/ | WAF/IDS evasion |
| 81 | `defensive_posture.py` | exploit_chains/ | Defense tracking |
| 82 | `synthesis_tracer.py` | exploit_chains/ | Pipeline observability |
| 83 | `synthesis_context.py` | exploit_chains/ | Context compilation |
| 84 | `synthesis_feedback.py` | exploit_chains/ | Feedback propagation |
| 85 | `synthesis_safety.py` | root | Safety filters |
| 86 | `payload_intelligence.py` | agents/ | Effectiveness prediction |
| 87 | `payload_evolution.py` | loop/ | Population evolution |
| 88 | `waf_payload_adapter.py` | root | WAF-adaptive mutation |
| 89 | `waf_payload_tester.py` | root | Thompson sampling testing |

### G. Learning & RL (13 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 90 | `adaptive_learning.py` | agents/ | Multi-armed bandit; epsilon-greedy |
| 91 | `rl_reward_engine.py` | agents/ | Q-learning table; reward normalization |
| 92 | `feedback_learning.py` | agents/ | Prompt augmentation from feedback |
| 93 | `ab_testing.py` | agents/ | A/B testing; experiment tracking |
| 94 | `adaptive_chain_engine.py` | root | Bandit routing; dynamic templates |
| 95 | `learning_loop_engine.py` | root | End-to-end learning loop |
| 96 | `ml_feedback_propagator.py` | root | Backpropagation to subsystems |
| 97 | `weight_tuner.py` | exploit_chains/ | 13-signal Bayesian calibration |
| 98 | `learning_bridge.py` | exploit_chains/ | Results → hypothesis learning |
| 99 | `failure_pattern.py` | exploit_chains/ | Failed attack pattern analysis |
| 100 | `exploration_bias.py` | loop/ | Explore vs exploit tradeoff |
| 101 | `value_scorer.py` | loop/ | Impact + uncertainty scoring |
| 102 | `signal_extraction.py` | loop/ | Signal classification for RL |

### H. Confidence & Calibration (5 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 103 | `confidence_engine.py` | root | Unified confidence scoring |
| 104 | `confidence_ensemble.py` | root | Dempster-Shafer aggregation |
| 105 | `confidence_diversity.py` | root | Overconfidence penalization |
| 106 | `bayesian_prioritizer.py` | agents/ | Belief updates |
| 107 | `confidence_calibration.py` | recon_dashboard/ | Platt scaling + isotonic regression |

### I. Vector Memory (6 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 108 | `embedder.py` | memory/ | Sentence-transformers (384-dim) |
| 109 | `vector_index.py` | memory/ | HNSW; binary quantization |
| 110 | `agent_memory.py` | agents/ | Semantic recall + TF-IDF |
| 111 | `rag_context.py` | agents/ | RAG context building |
| 112 | `cross_scan_memory.py` | graph/ | Cross-scan shared memory |
| 113 | `vector_reasoning.py` | loop/ | Vector-based hypothesis reasoning |

### J. Prompts & Security (8 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 114 | `prompt_registry.py` | root | Template versioning; A/B testing |
| 115 | `progressive_prompts.py` | root | Easy → hard escalation |
| 116 | `few_shot_selector.py` | root | Dynamic example selection |
| 117 | `thinking_budget.py` | root | Token allocation per step |
| 118 | `prompt_security.py` | agents/ | Injection defense |
| 119 | `doubt_injector.py` | agents/ | Skepticism injection |
| 120 | `prompt_chains.py` | reasoning/ | Multi-round chained prompts |
| 121 | `context_budget.py` | reasoning/ | Context window budget |

### K. LangGraph (19 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 122 | `builder.py` | graph/ | State machine construction |
| 123 | `nodes.py` | graph/ | Node implementations |
| 124 | `runner.py` | graph/ | Execution engine |
| 125 | `tracing.py` | graph/ | State history |
| 126 | `state.py` | graph/ | State definitions |
| 127 | `production.py` | graph/ | Production configs |
| 128 | `checkpointer_async.py` | graph/ | Async checkpointing |
| 129 | `cross_scan_memory.py` | graph/ | Cross-scan shared memory |
| 130 | `builder.py` | graph/multi_agent/ | Supervisor pattern |
| 131 | `specialist_nodes.py` | graph/multi_agent/ | Specialist nodes |
| 132 | `state.py` | graph/multi_agent/ | Shared state TypedDict |
| 133 | `runner.py` | graph/multi_agent/ | Graph invocation |
| 134 | `supervisor.py` | graph/multi_agent/ | Routing logic |
| 135 | `handoff.py` | graph/multi_agent/ | Agent handoff |
| 136 | `worker_factory.py` | graph/multi_agent/ | Worker creation |
| 137 | `builder.py` | graph/reasoning/ | Fan-out/fan-in hypothesis |
| 138 | `nodes.py` | graph/reasoning/ | Reasoning nodes |
| 139 | `state.py` | graph/reasoning/ | Reasoning state TypedDict |
| 140 | `runner.py` | graph/reasoning/ | Reasoning execution |

### L. Autonomous Loop (21 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 141 | `autonomous_loop.py` | loop/ | Main OBSERVE→THINK→ACT→EVALUATE→LEARN |
| 142 | `ai_directed_executor.py` | loop/ | AI-directed tool execution |
| 143 | `world_state.py` | loop/ | Persistent world state |
| 144 | `confirmation_engine.py` | loop/ | Multi-method verification |
| 145 | `signal_extraction.py` | loop/ | Signal classification |
| 146 | `target_selection.py` | loop/ | Target prioritization |
| 147 | `target_specialization.py` | loop/ | Target-specific adaptation |
| 148 | `campaign_strategy.py` | loop/ | Campaign planning |
| 149 | `parallel_executor.py` | loop/ | Parallel tool execution |
| 150 | `payload_evolution.py` | loop/ | GA population evolution |
| 151 | `race_engine.py` | loop/ | Race condition timing |
| 152 | `session_matrix.py` | loop/ | Session state tracking |
| 153 | `graph_pruner.py` | loop/ | Low-value path pruning |
| 154 | `exploration_bias.py` | loop/ | Explore vs exploit |
| 155 | `feedback_loop_breaker.py` | loop/ | Deadlock detection |
| 156 | `value_scorer.py` | loop/ | Impact scoring |
| 157 | `vector_reasoning.py` | loop/ | Vector-based reasoning |
| 158 | `invariant_engine.py` | loop/ | Consistency checking |
| 159 | `loop_config.py` | loop/ | Configuration |
| 160 | `attack_graph.py` | loop/ | Graph building |
| 161 | `exploit_report.py` | loop/ | Result reporting |

### M. Copilot SDK (10 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 162 | `copilot_sdk_engine.py` | agents/ | 67+ tool integration |
| 163 | `copilot_sdk_tools.py` | agents/ | Base tool implementations |
| 164 | `copilot_sdk_agents.py` | agents/ | Agent-specific tools |
| 165 | `copilot_sdk_discovery_tools.py` | agents/ | Discovery tools |
| 166 | `copilot_sdk_exploit_cloud_tools.py` | agents/ | Cloud exploitation tools |
| 167 | `copilot_sdk_infra_tools.py` | agents/ | Infrastructure tools |
| 168 | `copilot_sdk_intel_tools.py` | agents/ | Intelligence tools |
| 169 | `copilot_sdk_vuln_tools.py` | agents/ | Vulnerability tools |
| 170 | `copilot_sdk_tool_registry.py` | agents/ | Unified registry |
| 171 | `native_tool_calling.py` | agents/ | OpenAI/Anthropic function calling |

### N. CAAP System (27 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 172 | `caap_chains.py` | caap/ | Chain orchestration |
| 173 | `caap_hypothesis.py` | caap/ | Chain hypotheses |
| 174 | `caap_models.py` | caap/ | Data models |
| 175 | `caap_formatter.py` | caap/ | Output formatting |
| 176 | `caap_parser.py` | caap/ | Chain parsing |
| 177 | `caap_session.py` | caap/ | Session management |
| 178 | `caap_output_wrapper.py` | caap/ | Metadata wrapping |
| 179 | `copilot_loop.py` | caap/ | Copilot-CAAP integration |
| 180 | `vuln_knowledge.py` | caap/ | Vulnerability knowledge |
| 181 | `ui_interaction_engine.py` | caap/ | UI exploitation |
| 182 | `exploitation_data.py` | caap/ | Exploitation tracking |
| 183 | `escalation_gateway.py` | caap/ | Privilege escalation |
| 184 | `adaptive_learning.py` | caap/ | RL + bandit test selection optimization |
| 185 | `agent_memory.py` | caap/ | Re-export of root agent memory |
| 186 | `autonomy.py` | caap/ | Risk-gated 5-level autonomy (Manual→Full Auto) |
| 187 | `browser_exploitation_engine.py` | caap/ | Playwright browser exploitation + DAST |
| 188 | `environmental_adaptation.py` | caap/ | WAF/rate-limit/honeypot adaptive response |
| 189 | `event_bus.py` | caap/ | Pub/sub event architecture + deduplication |
| 190 | `exploitation_engine.py` | caap/ | Enterprise exploitation verification |
| 191 | `exploitation_models.py` | caap/ | Exploitation data models + enums |
| 192 | `exploit_verifier.py` | caap/ | Active exploitability injection testing |
| 193 | `logging_config.py` | caap/ | Centralized CAAP logging |
| 194 | `poc_generator.py` | caap/ | PoC generation for 25+ vuln types |
| 195 | `reasoning_engine.py` | caap/ | Chain-of-thought hypothesis + attack planning |
| 196 | `screenshot.py` | caap/ | Headless browser visual recon + clustering |
| 197 | `state_graph.py` | caap/ | App state graph for business logic flaws |
| 198 | `impact_chain.py` | caap/ | Impact propagation |

### O. AI/ML Scanner (10 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 199 | `ai_ml_scanner.py` | root | Main orchestrator (7 engines) |
| 200 | `_prompt_injection.py` | ai_ml/ | Prompt injection detection |
| 201 | `_vector_database.py` | ai_ml/ | Vector DB exposure |
| 202 | `_model_endpoint.py` | ai_ml/ | ML endpoint detection |
| 203 | `_model_serialization.py` | ai_ml/ | Deserialization attacks |
| 204 | `_rag_pipeline.py` | ai_ml/ | RAG pipeline attacks |
| 205 | `_ai_api_proxy.py` | ai_ml/ | API proxy security |
| 206 | `_models.py` | ai_ml/ | Enums and types |
| 207 | `_utils.py` | ai_ml/ | Utility functions |
| 208 | `_serialization.py` | ai_ml/ | Artifact detection |

### P. ATLAS Intelligence (12 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 209 | `atlas.py` | atlas/ | Context enrichment |
| 210 | `models.py` | atlas/ | Data models |
| 211 | `patterns.py` | atlas/ | Vulnerability patterns |
| 212 | `graph.py` | atlas/ | Finding graph |
| 213 | `defense.py` | atlas/ | Defense context |
| 214 | `archetypes.py` | atlas/ | Attack archetypes |
| 215 | `adapter.py` | atlas/ | LLM adapter |
| 216 | `ingest.py` | atlas/ | Ingestion pipeline |
| 217 | `interface.py` | atlas/ | Public API |
| 218 | `store.py` | atlas/ | SQLite storage |
| 219 | `atlas_nexus.py` | atlas/ | Nexus integration |
| 220 | `atlas_mcp_bridge.py` | mcp/ | MCP Atlas bridge |

### Q. Inference Engine (14 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 221 | `engine.py` | inference/ | Core inference engine |
| 222 | `model_manager.py` | inference/ | Model lifecycle |
| 223 | `setup_local_llm.py` | inference/ | Ollama setup |
| 224 | `ollama_backend.py` | inference/ | Ollama HTTP client |
| 225 | `llama_backend.py` | inference/ | Llama.cpp backend |
| 226 | `gpu_governor.py` | inference/ | GPU memory allocation |
| 227 | `kv_cache.py` | inference/ | KV cache management |
| 228 | `grammar.py` | inference/ | Grammar-constrained gen |
| 229 | `model_registry.py` | inference/model_management/ | Model specs |
| 230 | `vram_selector.py` | inference/model_management/ | VRAM-based selection |
| 231 | `finetune_exporter.py` | inference/model_management/ | Scan data → JSONL/Alpaca/ShareGPT for fine-tuning |
| 232 | `model_benchmarker.py` | inference/model_management/ | GGUF perf testing with security profiles |
| 233 | `model_cli.py` | inference/model_management/ | CLI: list/pull/remove/benchmark/compare |
| 234 | `model_downloader.py` | inference/model_management/ | GGUF download with SHA-256 + resume |

### R. Truth & Verification (11 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 235 | `truth_enforcement.py` | recon_dashboard/ | Hard proof gates |
| 236 | `finding_validator.py` | recon_dashboard/ | Multi-stage validation |
| 237 | `multi_request_validator.py` | recon_dashboard/ | Multi-HTTP validation |
| 238 | `proof_first_severity.py` | recon_dashboard/ | Proof-tiered severity |
| 239 | `report_fp_detection.py` | recon_dashboard/ | FP detection |
| 240 | `remediation_validation.py` | recon_dashboard/ | Remediation checks |
| 241 | `exploit_verifier.py` | root | Re-execution verification |
| 242 | `oob_verifier.py` | root | OOB interaction verification |
| 243 | `secret_verifier.py` | root | Credential verification |
| 244 | `secret_verifiers_extended.py` | root | Extended verification |
| 245 | `verification_chain.py` | root | Proof lifecycle |

### S. Recon Dashboard (77 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 246 | `execution_intelligence.py` | recon_dashboard/ | Dynamic weight learning + context modulation |
| 247 | `execution_orchestrator.py` | recon_dashboard/ | Value-based runtime budgets |
| 248 | `chain_execution_loop.py` | recon_dashboard/ | Closed-loop exploit chain + LLM discovery |
| 249 | `auto_exploit_executor.py` | recon_dashboard/ | Auto-PoC execution + verification |
| 250 | `exploit_persistence_engine.py` | recon_dashboard/ | Exploit adaptation on failure |
| 251 | `attack_strategy_engine.py` | recon_dashboard/ | Proactive strategy with EV scoring |
| 252 | `authenticated_exploit_engine.py` | recon_dashboard/ | Token extraction + auth flow simulation |
| 253 | `causal_inference.py` | recon_dashboard/ | DAG-based causal finding relationships |
| 254 | `differential_analysis.py` | recon_dashboard/ | Baseline ≠ modified response proof |
| 255 | `graph_reasoning.py` | recon_dashboard/ | Graph-based exploit-path analysis |
| 256 | `confidence_calibration.py` | recon_dashboard/ | Bayesian calibration replacing hardcoded priors |
| 257 | `cross_target_intelligence.py` | recon_dashboard/ | Cross-target sharing + real-time replanning |
| 258 | `platform_intelligence_memory.py` | recon_dashboard/ | Persistent per-platform learning |
| 259 | `langgraph_scan.py` | recon_dashboard/ | LangGraph scan pipeline + SQLite checkpointing |
| 260 | `llm_helpers.py` | recon_dashboard/ | LLM lazy-init helpers |
| 261 | `multimodal_support.py` | recon_dashboard/ | Images + rendered HTML into LLM context |
| 262 | `eta_engine.py` | recon_dashboard/ | ETA with phase cost weights + trend detection |
| 263 | `scan_mode_config.py` | recon_dashboard/ | BUG_BOUNTY/ASSESSMENT/COMPLIANCE/PENTEST intents |
| 264 | `target_profile.py` | recon_dashboard/ | Progressive domain/IP intelligence |
| 265 | `target_scoring.py` | recon_dashboard/ | Pre-Exploit Decision Dominance + budget |
| 266 | `threat_modeling.py` | recon_dashboard/ | STRIDE, DREAD, PASTA frameworks |
| 267 | `benchmark_tracker.py` | recon_dashboard/ | Campaign ROI + win condition tracking |
| 268 | `bounty_ops.py` | recon_dashboard/ | Bounty truth enforcement + submission |
| 269 | `payout_metrics.py` | recon_dashboard/ | Signal-to-Payout instrumentation |
| 270 | `impact_amplifier.py` | recon_dashboard/ | Impact chaining + auto-bounty report |
| 271 | `finding_pipeline.py` | recon_dashboard/ | Centralised finding processing |
| 272 | `finding_parsers.py` | recon_dashboard/ | Per-phase normalised finding extraction |
| 273 | `finding_dedup.py` | recon_dashboard/ | Multi-tool confidence + lifecycle |
| 274 | `findings_store.py` | recon_dashboard/ | Unified cross-module finding persistence |
| 275 | `report_generator.py` | recon_dashboard/ | Markdown report generator |
| 276 | `report_renderer.py` | recon_dashboard/ | Markdown rendering pipeline |
| 277 | `report_analysis.py` | recon_dashboard/ | Tech anomalies + coverage gaps |
| 278 | `report_dedup.py` | recon_dashboard/ | Post-filter WAF + param dedup |
| 279 | `report_filters.py` | recon_dashboard/ | Severity propagation + filtering |
| 280 | `_report_constants.py` | recon_dashboard/ | Report shared constants |
| 281 | `routes_agent.py` | recon_dashboard/ | Agent-loop + memory routes |
| 282 | `routes_assessment.py` | recon_dashboard/ | Assessment + intelligence routes |
| 283 | `routes_cross_target.py` | recon_dashboard/ | Cross-target intel routes |
| 284 | `routes_exploit_graph.py` | recon_dashboard/ | Exploit-graph visualization routes |
| 285 | `routes_findings.py` | recon_dashboard/ | Finding annotation routes |
| 286 | `routes_intelligence_experience.py` | recon_dashboard/ | HOW Venator thinks routes |
| 287 | `routes_llm.py` | recon_dashboard/ | LLM chat + streaming routes |
| 288 | `routes_multi_agent.py` | recon_dashboard/ | Multi-agent campaign routes |
| 289 | `routes_provider_vault.py` | recon_dashboard/ | Encrypted LLM key vault routes |
| 290 | `routes_reasoning.py` | recon_dashboard/ | Reasoning decision traces |
| 291 | `routes_scan_config.py` | recon_dashboard/ | Scan config + intent detection |
| 292 | `routes_sdk_engine.py` | recon_dashboard/ | SDK Agentic Engine routes |
| 293 | `routes_standalone.py` | recon_dashboard/ | Standalone recon + export routes |
| 294 | `routes_target_scoring.py` | recon_dashboard/ | Target ROI scoring routes |
| 295 | `server.py` | recon_dashboard/ | aiohttp + WebSocket server |
| 296 | `runner.py` | recon_dashboard/ | Autonomous recon executor |
| 297 | `state.py` | recon_dashboard/ | Thread-safe DashboardState |
| 298 | `state_serializers.py` | recon_dashboard/ | Serialization + differential tracking |
| 299 | `session_store.py` | recon_dashboard/ | Session save/restore/prune |
| 300 | `db_persistence.py` | recon_dashboard/ | SQLite migration from JSON |
| 301 | `scheduler.py` | recon_dashboard/ | Resource governor + adaptive concurrency |
| 302 | `command_executor.py` | recon_dashboard/ | Subprocess lifecycle + deferral |
| 303 | `infra_monitor.py` | recon_dashboard/ | Burp/Docker/perf/API monitoring |
| 304 | `appliance_api.py` | recon_dashboard/ | Appliance REST API |
| 305 | `atlas_api.py` | recon_dashboard/ | Atlas Intelligence Dashboard API |
| 306 | `conversation_branching.py` | recon_dashboard/ | Tree-structured chat branching |
| 307 | `conversation_export.py` | recon_dashboard/ | Chat export (JSON/MD/HTML/CSV) |
| 308 | `phase_commands.py` | recon_dashboard/ | Phase command definitions |
| 309 | `phase_data_store.py` | recon_dashboard/ | Phase data from report dir |
| 310 | `phase_defs.py` | recon_dashboard/ | Phase scheduling + cost-weights |
| 311 | `_assets.py` | recon_dashboard/ | Static asset loading |
| 312 | `_hooks.py` | recon_dashboard/ | Hook/utility functions |
| 313 | `_notify.py` | recon_dashboard/ | Notification helpers |
| 314 | `_tech_utils.py` | recon_dashboard/ | Tech name sanitisation |
| 315 | `base.py` | recon_dashboard/phase_handlers/ | Phase handler protocol + hooks |
| 316 | `discovery.py` | recon_dashboard/phase_handlers/ | Phases 1-6 discovery handlers |
| 317 | `infrastructure.py` | recon_dashboard/phase_handlers/ | Phases 7-13 infra handlers |
| 318 | `security_testing.py` | recon_dashboard/phase_handlers/ | Phases 14-17 security handlers |
| 319 | `advanced.py` | recon_dashboard/phase_handlers/ | Phases 20-27 advanced handlers |
| 320 | `intelligence.py` | recon_dashboard/phase_handlers/ | Phases 28-30 intelligence handlers |

### T. Impact & Scoring (7 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 321 | `chain_impact_scorer.py` | root | CVSS/business impact |
| 322 | `impact_chain.py` | caap/ | Impact propagation |
| 323 | `impact_amplifier.py` | recon_dashboard/ | Impact amplification |
| 324 | `bounty_ops.py` | recon_dashboard/ | Bounty ROI calculation |
| 325 | `payout_metrics.py` | recon_dashboard/ | Monetization metrics |
| 326 | `target_scoring.py` | recon_dashboard/ | ML-driven target scoring |
| 327 | `benchmark_tracker.py` | recon_dashboard/ | Quality tracking |

### U. Knowledge & Intelligence (11 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 328 | `vulnerability_intelligence.py` | agents/ | CVE intelligence |
| 329 | `proactive_intelligence.py` | agents/ | Proactive threat hunting |
| 330 | `vuln_knowledge.py` | root | Vulnerability knowledge |
| 331 | `knowledge_resilience.py` | root | Distributed knowledge |
| 332 | `transfer_intelligence.py` | root | Cross-target transfer |
| 333 | `error_intelligence.py` | root | Error-based inference |
| 334 | `entropy_intelligence.py` | root | Entropy anomaly detection |
| 335 | `tool_intelligence.py` | root | Tool meta-reasoning |
| 336 | `tool_chain_advisor.py` | root | Optimal tool sequences |
| 337 | `qtable_advisor.py` | root | Q-learning advisor |
| 338 | `threat_modeler.py` | intel/ | Threat actor modeling |

### V. World Model & State (4 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 339 | `world_model.py` | root | Counterfactual reasoning |
| 340 | `target_mental_model.py` | root | Target profiling |
| 341 | `temporal_stability.py` | root | Drift detection |
| 342 | `self_optimizing_stack.py` | root | Self-tuning optimization |

### W. Feedback & Propagation (6 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 343 | `ml_feedback_propagator.py` | root | Backpropagation to subsystems |
| 344 | `feedback_learning.py` | agents/ | Prompt augmentation from feedback |
| 345 | `synthesis_feedback.py` | exploit_chains/ | Multi-engine feedback |
| 346 | `weight_tuner.py` | exploit_chains/ | 13-signal calibration |
| 347 | `signal_extraction.py` | loop/ | Signal classification |
| 348 | `feedback_loop_breaker.py` | loop/ | Deadlock detection |

### X. Safety & Defense (5 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 349 | `llm_defense_hardening.py` | agents/ | Input defense |
| 350 | `llm_advanced_defense.py` | agents/ | Advanced defense |
| 351 | `llm_output_guard.py` | agents/ | Output validation |
| 352 | `prompt_security.py` | agents/ | Prompt sanitization |
| 353 | `synthesis_safety.py` | root | Payload safety |

### Y. Session & Campaign (2 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 354 | `session_intelligence.py` | session_auth/ | Session learning |
| 355 | `campaign_intelligence.py` | session_auth/ | Campaign optimization |

### Z. MCP Extension (16 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 356 | `extension.ts` | mcp-extension/ | VS Code entry point |
| 357 | `toolLoop.ts` | mcp-extension/ | LLM tool-calling loop |
| 358 | `chatHandlers.ts` | mcp-extension/ | Copilot chat handler |
| 359 | `treeView.ts` | mcp-extension/ | Hypothesis tree view |
| 360 | `dashboardPanel.ts` | mcp-extension/ | Dashboard webview |
| 361 | `lib.ts` | mcp-extension/ | Token estimation; YAML parsing |
| 362 | `eventBus.ts` | mcp-extension/ | Event distribution |
| 363 | `execCli.ts` | mcp-extension/ | CLI execution bridge |
| 364 | `mcpProvider.ts` | mcp-extension/ | 40+ MCP tools |
| 365 | `cliDaemon.ts` | mcp-extension/ | Background daemon |
| 366 | `reconBridge.ts` | mcp-extension/ | Recon output bridge |
| 367 | `commands.ts` | mcp-extension/ | Command construction |
| 368 | `logger.ts` | mcp-extension/ | Structured logging |
| 369 | `globals.ts` | mcp-extension/ | Global state |
| 370 | `progressStatusBar.ts` | mcp-extension/ | Progress display |
| 371 | `mcpHealth.ts` | mcp-extension/ | Health checking |

### AA. Swarm (10 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 372 | `swarm.py` | swarm/ | Swarm orchestrator |
| 373 | `agent_roles.py` | swarm/ | Scanner, Reasoner, Executor, Judge |
| 374 | `shared_weights.py` | swarm/ | Multi-GPU weight sync |
| 375 | `message_bus.py` | swarm/ | Inter-agent message routing |
| 376 | `gpu_governor.py` | swarm/ | Swarm-level GPU allocation |
| 377 | `governor.py` | swarm/multi_gpu/ | Multi-GPU governor |
| 378 | `messenger.py` | swarm/multi_gpu/ | GPU-aware messaging |
| 379 | `model_sharder.py` | swarm/multi_gpu/ | Model weight sharding |
| 380 | `scheduler.py` | swarm/multi_gpu/ | GPU task scheduling |
| 381 | `topology.py` | swarm/multi_gpu/ | GPU topology detection |

### BB. MCP Python Server (21 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 382 | `mcp_server.py` | mcp/ | FastMCP SSE/stdio server |
| 383 | `mcp_tools.py` | mcp/ | 45+ tool implementations |
| 384 | `tool_abstraction.py` | mcp/ | Dynamic tool loading from YAML |
| 385 | `cognitive_bridge.py` | mcp/ | LLM bridge for MCP context |
| 386 | `cognitive_tools.py` | mcp/ | MCP cognitive operations |
| 387 | `atlas_mcp_bridge.py` | mcp/ | MCP Atlas integration |
| 388 | `assessment_dashboard.py` | mcp/ | Assessment dashboard tools |
| 389 | `auth.py` | mcp/ | MCP authentication |
| 390 | `autofix.py` | mcp/ | Auto-fix tool |
| 391 | `browser.py` | mcp/ | Playwright browser tool |
| 392 | `cloud.py` | mcp/ | Cloud environment tool |
| 393 | `compliance.py` | mcp/ | Compliance checking tool |
| 394 | `container.py` | mcp/ | Docker/container tool |
| 395 | `exploit.py` | mcp/ | Exploit verification tool |
| 396 | `github_pat.py` | mcp/ | GitHub PAT analysis tool |
| 397 | `helpers.py` | mcp/ | MCP utility helpers |
| 398 | `intelligent_rerun.py` | mcp/ | Smart re-run orchestration |
| 399 | `network.py` | mcp/ | Network scanning tool |
| 400 | `report.py` | mcp/ | Report generation tool |
| 401 | `supply_chain.py` | mcp/ | Supply chain analysis tool |
| 402 | `web.py` | mcp/ | Web scanning tool |

### CC. Strategy (7 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 403 | `core.py` | strategy/ | Strategy engine core |
| 404 | `discovery.py` | strategy/ | Strategy discovery patterns |
| 405 | `models.py` | strategy/ | Strategy data models |
| 406 | `store.py` | strategy/ | Strategy persistence |
| 407 | `async_exec.py` | strategy/ | Async strategy execution |
| 408 | `_build_facade.py` | strategy/ | Build facade pattern |
| 409 | `_build_modules.py` | strategy/ | Module builder |

### DD. Exploitation Sub-Package (7 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 410 | `engine.py` | exploitation/ | Exploitation engine core |
| 411 | `models.py` | exploitation/ | Exploitation data models |
| 412 | `verifier.py` | exploitation/ | Exploit verification |
| 413 | `persistence.py` | exploitation/ | Persistence mechanisms |
| 414 | `browser.py` | exploitation/ | Browser exploitation |
| 415 | `poc.py` | exploitation/ | PoC generation |
| 416 | `escalation.py` | exploitation/ | Privilege escalation |

### EE. Tool Registry (4 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 417 | `registry.py` | tool_registry/ | Central tool registry |
| 418 | `models.py` | tool_registry/ | Tool metadata models |
| 419 | `loader.py` | tool_registry/ | Dynamic tool loading |
| 420 | `validator.py` | tool_registry/ | Tool output validation |

### FF. ML in Non-ML Directories (22 files)
| # | File | Directory | Purpose |
|---|------|-----------|---------|
| 421 | `llm_bridge.py` | core_infra/ | Re-export of root LLM bridge |
| 422 | `exploit_graph.py` | core_infra/ | Re-export exploit graph |
| 423 | `confidence_engine.py` | core_infra/ | Re-export confidence engine |
| 424 | `finding_pipeline.py` | core_infra/ | Re-export finding pipeline |
| 425 | `verification_chain.py` | core_infra/ | Re-export verification chain |
| 426 | `report_generator.py` | output/ | Re-export report generator |
| 427 | `report_renderer.py` | output/ | Re-export report renderer |
| 428 | `report_analysis.py` | output/ | Re-export report analysis |
| 429 | `finding_dedup.py` | output/ | Re-export finding dedup |
| 430 | `report_fp_detection.py` | output/ | Re-export FP detection |
| 431 | `ai_ml_scanner.py` | scanners/ | Re-export AI/ML scanner |
| 432 | `nuclei_generator.py` | scanners/ | AI-powered Nuclei template gen |
| 433 | `smart_scanner.py` | scanners/ | ML-guided scan scheduling |
| 434 | `fuzzer_engine.py` | scanners/ | ML-assisted fuzzing |
| 435 | `param_miner.py` | scanners/ | ML param discovery |
| 436 | `endpoint_classifier.py` | scanners/ | ML endpoint classification |
| 437 | `header_analyzer.py` | scanners/ | ML header analysis |
| 438 | `response_analyzer.py` | scanners/ | ML response analysis |
| 439 | `test_agent_memory.py` | testing_tools/ | Agent memory test harness |
| 440 | `test_exploit_graph.py` | testing_tools/ | Exploit graph test harness |
| 441 | `test_agentic_mode.py` | testing_tools/ | Agentic mode test harness |
| 442 | `test_inference.py` | testing_tools/ | Inference engine test harness |

---

## 40. Cross-Reference Wiring Matrix

This matrix shows which systems directly call or depend on other systems.

```
                        ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
                        │LLM  │Agent│Reas.│Cogn.│Decis│ExpGr│PSE  │Learn│VecM │CAAP │MCP  │Swarm│
                        │Bridg│Loop │Eng  │Brdg │Orch │aph  │     │/RL  │em   │     │Py   │     │
  ┌─────────────────────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┤
  │LLM Bridge           │  ●  │  ←  │  ←  │  ←  │  ←  │     │  ←  │     │     │  ←  │  ←  │     │
  │Agent Loop            │  →  │  ●  │  →  │  →  │  →  │  →  │     │  →  │  →  │     │     │  →  │
  │Reasoning Engine      │  →  │  ←  │  ●  │  →  │  →  │     │     │     │     │     │     │     │
  │Cognitive Bridge      │  →  │  ←  │  ←  │  ●  │     │  →  │  →  │     │     │     │  →  │     │
  │Decision Orchestrator │  →  │  ←  │  ←  │     │  ●  │  →  │     │     │     │     │     │     │
  │Exploit Graph         │     │  ←  │     │  ←  │  ←  │  ●  │  →  │  →  │     │     │     │     │
  │Payload Synthesis     │  →  │     │     │  ←  │     │  ←  │  ●  │  →  │     │     │     │     │
  │Learning/RL           │     │  ←  │     │     │     │  ←  │  ←  │  ●  │     │     │     │     │
  │Vector Memory         │     │  ←  │     │     │     │     │     │     │  ●  │     │     │     │
  │CAAP                  │  →  │     │     │     │     │     │     │     │     │  ●  │     │     │
  │MCP Python Server     │  →  │     │     │  ←  │     │     │     │     │     │     │  ●  │     │
  │Swarm                 │  →  │  ←  │     │     │     │     │     │  →  │     │     │     │  ●  │
  │Autonomous Loop       │     │     │     │  →  │  →  │  →  │  →  │  →  │  →  │     │     │     │
  │Feedback Propagation  │     │     │  →  │     │     │     │  →  │  →  │     │     │     │     │
  │Confidence Engine     │     │  ←  │  ←  │     │  ←  │     │  ←  │  ←  │     │     │     │     │
  │Truth Enforcement     │     │     │     │     │  ←  │     │     │     │     │     │     │     │
  │ATLAS                 │  →  │     │  →  │     │     │     │     │     │  →  │     │  →  │     │
  │MCP Extension         │     │  →  │     │     │     │     │     │     │     │  →  │  →  │     │
  │LangGraph             │  →  │  →  │  →  │     │     │     │     │     │     │     │     │     │
  │Strategic Layer       │  →  │  ←  │  →  │     │  →  │  →  │     │     │     │     │     │     │
  │Copilot SDK           │  →  │  →  │     │     │     │  →  │     │     │     │     │     │     │
  │Strategy Engine       │  →  │     │  →  │     │  →  │     │     │     │     │     │     │     │
  │Recon Dashboard       │  →  │  →  │  →  │  →  │  →  │  →  │     │  →  │     │  →  │     │     │
  └─────────────────────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
  
  Legend: → calls/depends on | ← is called by | ● self
```

---

## Summary Statistics

| Category | File Count | Key Technology |
|----------|:----------:|----------------|
| LLM Core Infrastructure | 18 | OpenAI, Anthropic, Ollama, GitHub Models |
| Agent System | 14 | Episodic memory, TF-IDF, multi-agent |
| Reasoning & Hypothesis | 14 | Bayesian inference, probability tables |
| Cognitive & Decision | 12 | Plan-Criticize-Refine, arbitration |
| Exploit Graph | 14 | A* pathfinding, 5-dimension state |
| Payload Synthesis | 17 | Grammar, LLM, GA, 8-signal arbiter |
| Learning & RL | 13 | Q-learning, multi-armed bandit, epsilon-greedy |
| Confidence & Calibration | 5 | Dempster-Shafer, Platt scaling, isotonic regression |
| Vector Memory | 6 | sentence-transformers, HNSW, binary quantization |
| Prompt Management | 8 | Versioning, A/B testing, injection defense |
| LangGraph | 19 | State machine, supervisor pattern, reasoning graph |
| Autonomous Loop | 21 | OBSERVE→THINK→ACT→EVALUATE→LEARN |
| Copilot SDK | 10 | 67+ tools, native function calling |
| CAAP System | 27 | Chain automation, browser exploitation, RL adaptation |
| AI/ML Scanner | 10 | 7 detection engines |
| ATLAS Intelligence | 12 | Pattern memory, archetypes, defense modeling |
| Inference Engine | 14 | Ollama, Llama.cpp, GGUF benchmarking, fine-tune export |
| Truth & Verification | 11 | Proof gates, FP detection, OOB verification |
| Recon Dashboard | 77 | Execution intelligence, causal inference, 14 route modules |
| Impact & Scoring | 7 | CVSS, bounty ROI, benchmark tracking |
| Knowledge & Intelligence | 11 | CVE, threat modeling, entropy analysis |
| World Model & State | 4 | Counterfactual reasoning, drift detection |
| Feedback & Propagation | 6 | 13-signal calibration, backpropagation |
| Safety & Defense | 5 | Prompt injection, output guardrails |
| Session & Campaign | 2 | Cross-session learning |
| MCP Extension (TypeScript) | 16 | VS Code, LLM tool-calling loop |
| Swarm | 10 | Multi-GPU, role definitions, model sharding |
| MCP Python Server | 21 | FastMCP, 45+ tools, cognitive bridge |
| Strategy | 7 | Strategy engine, async execution |
| Exploitation Sub-Package | 7 | Re-usable exploitation modules |
| Tool Registry | 4 | Central tool management, validation |
| ML in Non-ML Dirs | 22 | Re-exports, ML-guided scanners, test harnesses |
| Chain YAML DSL | 20+ | exploit_graph_hints, shared stages |
| Documentation | 5 | CAAP, ATLAS, Exploit Graph, Strategy |
| **TOTAL** | **~442** | |
