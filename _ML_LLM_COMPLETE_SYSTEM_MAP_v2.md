# CaseCrack — Complete ML / LLM System Map v2

> **Generated**: 2026-04-11 | **Files cataloged**: 442+ | **Total ML/LLM Lines**: ~185,000+ | **Subsystems**: 35 categories

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
11. [Layer 9: Adaptive Learning & RL](#11-layer-9-adaptive-learning--rl)
12. [Layer 10: Payload Synthesis Pipeline](#12-layer-10-payload-synthesis-pipeline)
13. [Layer 11: Vector Memory & Embeddings](#13-layer-11-vector-memory--embeddings)
14. [Layer 12: Prompt Management & Security](#14-layer-12-prompt-management--security)
15. [Layer 13: Confidence & Calibration](#15-layer-13-confidence--calibration)
16. [Layer 14: LangGraph State Machine](#16-layer-14-langgraph-state-machine)
17. [Layer 15: Autonomous Exploitation Loop](#17-layer-15-autonomous-exploitation-loop)
18. [Layer 16: Strategic & Planning Systems](#18-layer-16-strategic--planning-systems)
19. [Layer 16b: Strategy Engine](#19-layer-16b-strategy-engine)
20. [Layer 17: CAAP System](#20-layer-17-caap-system)
21. [Layer 18: ATLAS Intelligence](#21-layer-18-atlas-intelligence)
22. [Layer 19: Feedback & Signal Propagation](#22-layer-19-feedback--signal-propagation)
23. [Layer 20: Copilot SDK & Tool Registry](#23-layer-20-copilot-sdk--tool-registry)
24. [Layer 21: AI/ML Security Scanner](#24-layer-21-aiml-security-scanner)
25. [Layer 22: Knowledge & Domain Systems](#25-layer-22-knowledge--domain-systems)
26. [Layer 23: World Model & State](#26-layer-23-world-model--state)
27. [Layer 24: Truth Enforcement & Verification](#27-layer-24-truth-enforcement--verification)
28. [Layer 25: Impact & Scoring](#28-layer-25-impact--scoring)
29. [Layer 27: Recon Dashboard](#29-layer-27-recon-dashboard)
30. [Layer 28: Safety & Defense](#30-layer-28-safety--defense)
31. [Layer 30: MCP Extension (VS Code)](#31-layer-30-mcp-extension-vs-code)
32. [Layer 31: MCP Python Server](#32-layer-31-mcp-python-server)
33. [Layer 32: Multi-Agent Swarm](#33-layer-32-multi-agent-swarm)
34. [Layer 33: Exploitation Sub-Package](#34-layer-33-exploitation-sub-package)
35. [Layer 34: Tool Registry](#35-layer-34-tool-registry)
36. [Complete File Index with Line Counts](#36-complete-file-index-with-line-counts)
37. [Complete Wiring Map (All Imports)](#37-complete-wiring-map-all-imports)
38. [Cross-Reference Dependency Matrix](#38-cross-reference-dependency-matrix)
39. [Summary Statistics](#39-summary-statistics)

---

## 1. High-Level Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                              VS CODE / MCP EXTENSION LAYER  (16 files, ~3,200 LoC)           │
│  ┌─────────────┐ ┌──────────────┐ ┌────────────┐ ┌──────────────┐ ┌───────────────────────┐  │
│  │ toolLoop.ts │ │chatHandlers  │ │treeView.ts │ │dashboardPanel│ │ mcpProvider.ts        │  │
│  │ (LLM tool   │ │.ts (Copilot  │ │(Hypothesis │ │.ts (Live     │ │ (40+ MCP tools)       │  │
│  │  calling)   │ │ chat)        │ │ display)   │ │ severity)    │ │                       │  │
│  └──────┬──────┘ └──────┬───────┘ └─────┬──────┘ └──────┬───────┘ └──────────┬────────────┘  │
│         └───────────────┴───────────────┴───────────────┴────────────────────┘               │
│                                         │ WebSocket / CLI / MCP Protocol                     │
└─────────────────────────────────────────┼────────────────────────────────────────────────────┘
                                          │
┌─────────────────────────────────────────┼────────────────────────────────────────────────────┐
│                           MCP PYTHON SERVER  (21 files, ~4,300 LoC)                          │
│  ┌────────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐  │
│  │ mcp_server.py  │ │ mcp_tools.py │ │mcp_builtins  │ │cognitive_    │ │atlas_mcp_bridge  │  │
│  │ (837 lines)    │ │ (106 lines)  │ │(1,050 lines) │ │bridge (841)  │ │(931 lines)       │  │
│  └────────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────────┘  │
└───────────┼────────────────┼────────────────┼────────────────┼────────────────┼──────────────┘
            │                │                │                │                │
┌───────────┼────────────────┼────────────────┼────────────────┼────────────────┼──────────────┐
│           ▼                ▼                ▼                ▼                ▼               │
│                         COPILOT SDK LAYER  (10 files, ~7,000 LoC)                            │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────────┐  │
│  │copilot_sdk_engine│  │copilot_sdk_tools  │  │copilot_sdk_agents│  │native_tool_calling  │  │
│  │(1,512 lines)     │  │(736 lines)        │  │(1,101 lines)     │  │(924 lines)          │  │
│  └────────┬─────────┘  └────────┬──────────┘  └────────┬─────────┘  └─────────┬───────────┘  │
└───────────┼─────────────────────┼───────────────────────┼──────────────────────┼─────────────┘
            │                     │                       │                      │
┌───────────▼─────────────────────▼───────────────────────▼──────────────────────▼─────────────┐
│                          AGENT CORE  (39 real-code files, ~55,000 LoC)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ llm_bridge   │  │ agent_loop   │  │agent_memory  │  │reasoning_eng │  │cognitive_brdg│  │
│  │ (4,100 lines)│  │ (2,656 lines)│  │(2,605 lines) │  │(2,942 lines) │  │(1,069 lines) │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │     15 internal imports    │              │              │              │          │
│         └────────────────────────────┴──────────────┴──────────────┴──────────────┘          │
└─────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                          │
          ┌───────────────────────────────┼──────────────────────────────────────┐
          │                               │                                      │
┌─────────▼─────────┐  ┌─────────────────▼──────────────────┐  ┌────────────────▼─────────────┐
│  LANGGRAPH        │  │  AUTONOMOUS LOOP                    │  │  DECISION & STRATEGY         │
│  (19 files)       │  │  (21 files, ~8,500 LoC)             │  │  (12 files, ~13,000 LoC)     │
│  ~8,800 LoC       │  │  ┌──────────────────────────────┐   │  │  ┌────────────────────────┐  │
│  state→nodes→     │  │  │ autonomous_loop.py (2,513)   │   │  │  │decision_orchestrator   │  │
│  builder→runner   │  │  │ invariant_engine.py (713)    │   │  │  │(3,264 lines) ← hub     │  │
│                   │  │  │ ai_directed_executor.py (629)│   │  │  │13 internal imports      │  │
│  graph/ (4,720)   │  │  └──────────────────────────────┘   │  │  └────────────────────────┘  │
│  multi_agent/     │  │  2 files with internal imports      │  │  strategy/ (9,000 LoC)       │
│   (3,123)         │  │  19 self-contained modules          │  │  strategic_foresight (767)   │
│  reasoning/       │  │                                     │  │  strategic_llm_layer (1,097) │
│   (1,711)         │  │                                     │  │                              │
└───────────────────┘  └─────────────────────────────────────┘  └──────────────────────────────┘
          │                               │                                      │
          └───────────────────────────────┼──────────────────────────────────────┘
                                          │
┌─────────────────────────────────────────▼────────────────────────────────────────────────────┐
│                    EXPLOIT GRAPH + PAYLOAD SYNTHESIS  (31 files, ~22,000 LoC)                │
│  ┌─────────────────────┐  ┌──────────────────────┐  ┌──────────────────────────────────────┐│
│  │ exploit_graph.py     │  │payload_synthesis_eng │  │ weight_tuner.py (1,640)             ││
│  │ (1,904 lines)        │  │(890 lines)           │  │ payload_arbiter.py (1,701)          ││
│  │ unified_attack_graph │  │grammar_synth (1,185) │  │ learning_bridge.py (515)            ││
│  │ (1,830 lines)        │  │evolutionary_fuzz(779)│  │ synthesis_feedback (569)            ││
│  └──────────────────────┘  └──────────────────────┘  └──────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────────────────────────────┘
                                          │
┌─────────────────────────────────────────▼────────────────────────────────────────────────────┐
│                    RECON DASHBOARD  (77 files, ~73,000 LoC)  ← LARGEST SUBSYSTEM            │
│  Intelligence (26 files)  │  Truth (6)  │  Finding Pipeline (5)  │  Reports (7)             │
│  Routes (14 files)        │  Infrastructure (19)  │  Phase Handlers (6)                     │
│  ┌─────────────────────┐  ┌──────────────────────┐  ┌──────────────────────────────────┐    │
│  │ server.py (9,089)   │  │ runner.py (7,871)    │  │ finding_parsers.py (3,390)      │    │
│  │ state.py (2,460)    │  │ multi_request_val    │  │ phase_commands.py (2,595)        │    │
│  │ bounty_ops (2,421)  │  │ (3,346 lines)        │  │ report_renderer.py (1,809)       │    │
│  └─────────────────────┘  └──────────────────────┘  └──────────────────────────────────┘    │
│  runner.py has 11 internal imports — most connected dashboard file                           │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Flow — End to End

```
User Input (VS Code / CLI / WebSocket)
    │
    ├─→ MCP Extension (TypeScript, 16 files)  ──→  MCP Python Server (21 files)
    │                                                    │
    ├─→ Copilot SDK Engine (10 files) ─────────────────→─┤
    │                                                    │
    ▼                                                    ▼
Agent Core (llm_bridge.py → 4,100 lines, 15 internal imports)
    │
    ├─→ LLM Providers (OpenAI, Anthropic, Ollama, GitHub Models)
    │       via llm_clients.py (1,979 lines)
    │       via llm_routing.py (861 lines)  
    │       via inference/engine.py (659 lines) for local models
    │
    ├─→ Reasoning Engine (2,942 lines) ──→ Hypothesis Engine (1,202 lines)
    │       │
    │       └─→ LangGraph (19 files, 8,800 LoC)
    │               state.py → nodes.py → builder.py → runner.py
    │
    ├─→ Decision Orchestrator (3,264 lines, 13 internal imports)
    │       Imports: decision_benchmark, decision_trace, event_bus,
    │                confidence_calibration, finding_validator,
    │                self_optimizing_stack, stealth_orchestrator,
    │                strategic_foresight, strategic_llm_layer,
    │                target_mental_model, reasoning_engine
    │
    ├─→ Autonomous Loop (2,513 lines)
    │       Imports: ai_directed_executor, loop_config, world_state
    │       21 self-contained modules for signal/target/campaign/etc
    │
    ├─→ Exploit Graph (1,904 lines) → Payload Synthesis (890 lines)
    │       │
    │       └─→ Weight Tuner (1,640 lines) ← 13-signal Bayesian calibration
    │
    ├─→ CAAP (27 files) → Browser Exploitation Engine (1,823 lines)
    │       Exploitation Engine → PoC Generator → Exploit Verifier → Impact Chain
    │
    └─→ Recon Dashboard (77 files, runner.py = 7,871 lines)
            └─→ Finding Pipeline → Finding Parsers (3,390 lines)
            └─→ Server (9,089 lines) → All Routes (14 modules)
```

---

## 3. Layer 1: LLM Provider Abstraction

**Total: 4 files, ~8,500 LoC** | **Location**: `agents/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `llm_bridge.py` | 4,100 | `db_registry`, `exceptions`, `llm_types`, `llm_cache`, `llm_clients`, `llm_routing`, `llm_hardware_adapter`, `llm_tracking`, `feedback_learning`, `streaming_structured`, `llm_adaptive`, `llm_production`, `llm_ops`, `ab_testing`, `llm_tracing` (15 imports) | Central LLM gateway — routes all requests, caches, tracks, streams |
| `llm_clients.py` | 1,979 | `exceptions`, `llm_types` | OpenAI, Anthropic, Ollama, GitHub Models HTTP clients |
| `llm_routing.py` | 861 | `llm_types`, `llm_clients`, `llm_hardware_adapter` | Model selection + fallback routing |
| `llm_types.py` | 1,420 | *(none)* | Shared types: `LLMResponse`, `CacheStrategy`, `PROMPT_TEMPLATES` |

**Wiring pattern**: `llm_bridge.py` is the **#1 most-imported module** in the entire system — nearly every subsystem depends on it.

---

## 4. Layer 2: LLM Infrastructure & Operations

**Total: 10 files, ~7,400 LoC** | **Location**: `agents/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `llm_cache.py` | 471 | `db_registry`, `llm_types` | Semantic + exact cache with TTL |
| `llm_tracking.py` | 796 | `db_registry`, `exceptions`, `llm_types` | Token accounting, cost tracking |
| `llm_production.py` | 1,695 | `db_registry` | Production hardening: circuit breakers, rate-limits |
| `llm_ops.py` | 1,173 | *(self-contained)* | Operational monitoring, health checks |
| `llm_adaptive.py` | 763 | `db_registry` | Dynamic temperature, top-p tuning |
| `llm_tracing.py` | 520 | *(self-contained)* | OpenTelemetry span instrumentation |
| `llm_hardware_adapter.py` | 435 | *(self-contained)* | GPU/CPU detection + model sizing |
| `streaming_structured.py` | 593 | *(self-contained)* | Structured JSON streaming parser |
| `llm_intelligence.py` | 414 | `prompt_security` | Meta-reasoning about LLM capabilities |
| `llm_registry.py` | 157 | *(self-contained)* | Model capability registry |

---

## 5. Layer 3: Inference Engine (Local LLM)

**Total: 14 files, ~6,600 LoC** | **Location**: `inference/`, `inference/model_management/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `engine.py` | 659 | *(self-contained)* | Core inference: batch, stream, grammar-constrained |
| `model_manager.py` | 635 | *(self-contained)* | Model lifecycle: load, unload, swap |
| `gpu_governor.py` | 1,194 | *(self-contained)* | GPU memory allocation + VRAM budgeting |
| `ollama_backend.py` | 515 | *(self-contained)* | Ollama HTTP client |
| `llama_backend.py` | 392 | *(self-contained)* | Llama.cpp ctypes backend |
| `setup_local_llm.py` | 569 | *(self-contained)* | Ollama auto-install + model pull |
| `kv_cache.py` | 306 | *(self-contained)* | KV cache management |
| `grammar.py` | 343 | *(self-contained)* | Grammar-constrained generation |
| `model_registry.py` | 543 | *(self-contained)* | Model specs + capability matrix |
| `vram_selector.py` | 404 | *(self-contained)* | VRAM-based model selection |
| `finetune_exporter.py` | 457 | *(self-contained)* | Scan data → JSONL/Alpaca/ShareGPT |
| `model_benchmarker.py` | 514 | *(self-contained)* | GGUF perf testing + security profiles |
| `model_cli.py` | 406 | *(self-contained)* | CLI: list/pull/remove/benchmark/compare |
| `model_downloader.py` | 435 | *(self-contained)* | GGUF download with SHA-256 + resume |

**Architecture note**: All 14 files are **self-contained** — zero internal imports. Clean layered design.

---

## 6. Layer 4: Agent System & Orchestration

**Total: 14 core files, ~22,000 LoC** | **Location**: `agents/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `agent_loop.py` | 2,656 | `db_manager`, `db_registry` | Main OBSERVE→REASON→ACT→LEARN loop |
| `agent_memory.py` | 2,605 | `db_registry` | Episodic memory + TF-IDF + semantic recall |
| `unified_agent.py` | 2,102 | `db_registry` | Unified agent facade |
| `copilot_loop.py` | 2,349 | `autonomy`, `platforms`, `reasoning_display`, `reasoning_engine`, `strategy_engine`, `telemetry` | Copilot integration loop |
| `goal_planner.py` | 2,096 | `db_registry` | Hierarchical goal decomposition |
| `hierarchical_planner.py` | 1,991 | `db_registry` | Sub-goal planning + task scheduling |
| `risk_aware_testing.py` | 1,904 | `db_registry` | Risk-weighted test prioritization |
| `agent_sessions.py` | 1,456 | `logging_config` | Session persistence + replay |
| `attack_reasoning.py` | 1,594 | *(self-contained)* | Attack strategy reasoning |
| `collaborative_intelligence.py` | 2,297 | `db_registry` | Multi-agent collaboration |
| `unified_arbitration.py` | 1,095 | *(self-contained)* | Finding arbitration |
| `planner_bridge.py` | 1,038 | *(self-contained)* | Planner ↔ executor bridge |
| `autonomous_exploitation.py` | 984 | *(self-contained)* | A* pathfinding exploitation |
| `bayesian_prioritizer.py` | 569 | `logging_config`, `_safe_parse` | Bayesian belief updates |

---

## 7. Layer 5: Reasoning & Hypothesis Engines

**Total: 6 files, ~7,700 LoC** | **Location**: `agents/`, `reasoning/`, root

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `reasoning_engine.py` | 2,942 | `db_registry` | Bayesian probability tables, multi-hypothesis tracking |
| `hypothesis_engine.py` | 1,202 | *(self-contained)* | Hypothesis generation + pruning |
| `prompt_chains.py` | 1,446 | *(self-contained)* | Multi-round chained prompts |
| `context_budget.py` | 487 | *(self-contained)* | Token budget allocation |
| `hypothesis_manager.py` | 575 | *(self-contained)* | Hypothesis lifecycle management |
| `hierarchical_decomposition.py` | 1,113 | *(self-contained)* | Task decomposition into sub-hypotheses |

---

## 8. Layer 6: Cognitive Bridge & Collaboration

**Total: 3 files, ~4,200 LoC** | **Location**: `agents/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `cognitive_bridge.py` | 1,069 | `db_registry` | LLM → PSE → Exploit Graph bridge |
| `collaborative_intelligence.py` | 2,297 | `db_registry` | Multi-agent collaboration |
| `multi_agent_debate.py` | 1,439 | *(self-contained)* | Multi-perspective debate engine |

---

## 9. Layer 7: Decision Making & Arbitration

**Total: 3 files, ~4,900 LoC** | **Location**: root

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `decision_orchestrator.py` | 3,264 | `decision_benchmark`, `decision_trace`, `event_bus`, `recon_dashboard.confidence_calibration`, `recon_dashboard.finding_validator`, `self_optimizing_stack`, `stealth_orchestrator`, `strategic_foresight`, `strategic_llm_layer`, `target_mental_model`, `agents.reasoning_engine` **(13 imports — highest in system)** | Central decision hub |
| `decision_benchmark.py` | 833 | *(self-contained)* | Decision quality benchmarking |
| `decision_trace.py` | 846 | *(self-contained)* | Decision audit trail + SignalType enum |

**`decision_orchestrator.py` is the most connected file in the entire codebase** — it imports from 13 different internal modules spanning 5 different directories.

---

## 10. Layer 8: Exploit Graph & Attack Modeling

**Total: 14 files, ~9,300 LoC** | **Location**: `exploit_chains/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `exploit_graph.py` | 1,904 | *(self-contained)* | Core graph: 5-dimension state space |
| `exploit_path_planner.py` | 642 | *(self-contained)* | Multi-step A* pathfinding |
| `graph_knowledge_base.py` | 852 | *(self-contained)* | Attack pattern knowledge base |
| `graph_persistence.py` | 307 | *(self-contained)* | SQLite graph persistence |
| `graph_rendering.py` | 303 | *(self-contained)* | D3.js graph visualization data |
| `graph_reporting.py` | 186 | *(self-contained)* | Graph summary reporting |
| `graph_state_ops.py` | 186 | *(self-contained)* | State manipulation operations |
| `graph_suggestions.py` | 106 | *(self-contained)* | Next-test suggestions |
| `graph_pathfinding.py` | 229 | *(self-contained)* | Pathfinding algorithms |
| `graph_integrations.py` | 258 | `exploit_graph` | System integration hooks |
| `exploit_graph_renderer.py` | 386 | *(self-contained)* | Top-level visualization |
| `state_graph.py` | 1,141 | *(self-contained)* | State transition graph |
| `decision_framework.py` | 802 | *(self-contained)* | Attack decision framework |
| `unified_attack_graph.py` | 1,830 | *(self-contained)* | Unified graph (root-level) |

**Architecture note**: 13 of 14 files are self-contained. Only `graph_integrations.py` imports from `exploit_graph`.

---

## 11. Layer 9: Adaptive Learning & RL

**Total: 13 files, ~9,100 LoC** | **Location**: `agents/`, `exploit_chains/`, `loop/`, root

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `adaptive_learning.py` (agents) | 1,983 | `db_registry` | Multi-armed bandit, epsilon-greedy |
| `rl_reward_engine.py` | 692 | *(self-contained)* | Q-learning table, reward normalization |
| `feedback_learning.py` | 755 | *(self-contained)* | Prompt augmentation from feedback |
| `ab_testing.py` | 931 | *(self-contained)* | A/B testing experiment tracking |
| `adaptive_chain_engine.py` | 1,441 | `config.scan_config`, `decision_trace`, `exploit_chains.dynamic_chain` | Bandit routing, dynamic templates |
| `learning_loop_engine.py` | 1,704 | `atlas.models`, `agents.llm_bridge`, `confidence_ensemble`, `decision_orchestrator`, `exploit_chains.learning_bridge`, `json_file_lock`, `transfer_intelligence` **(7 imports)** | End-to-end learning loop |
| `weight_tuner.py` | 1,640 | *(self-contained)* | 13-signal Bayesian calibration |
| `learning_bridge.py` | 515 | *(self-contained)* | Results → hypothesis learning |
| `failure_pattern.py` | 450 | *(self-contained)* | Failed attack pattern analysis |
| `exploration_bias.py` | 250 | *(self-contained)* | Explore vs exploit tradeoff |
| `value_scorer.py` | 350 | *(self-contained)* | Impact + uncertainty scoring |
| `signal_extraction.py` | 495 | *(self-contained)* | Signal classification for RL |
| `ml_feedback_propagator.py` | 536 | `agents.bayesian_prioritizer`, `agents.feedback_learning`, `exploit_chains.exploit_verifier`, `exploit_chains.weight_tuner`, `hypothesis_engine`, `recon_dashboard.confidence_calibration`, `recon_dashboard.findings_store` **(7 imports)** | Backpropagation to subsystems |

---

## 12. Layer 10: Payload Synthesis Pipeline

**Total: 12 files, ~8,900 LoC** | **Location**: `exploit_chains/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `payload_synthesis_engine.py` | 890 | *(self-contained)* | PSE orchestrator |
| `payload_arbiter.py` | 1,701 | *(self-contained)* | 8-signal ML scoring |
| `llm_synthesizer.py` | 472 | *(self-contained)* | LLM-based payload synthesis |
| `grammar_synthesizer.py` | 1,185 | *(self-contained)* | Grammar-driven synthesis |
| `evolutionary_fuzzer.py` | 779 | *(self-contained)* | (in exploit_chains — shim to testing_tools) |
| `genetic_forge.py` | 779 | *(self-contained)* | Genetic algorithm engine |
| `execution_scheduler.py` | 418 | *(self-contained)* | 4-phase scheduling |
| `evasion_engine.py` | (shim) | *(testing_tools)* | WAF/IDS evasion |
| `synthesis_tracer.py` | 700 | *(self-contained)* | Pipeline observability |
| `synthesis_context.py` | 963 | *(self-contained)* | Context compilation |
| `synthesis_feedback.py` | 569 | *(self-contained)* | Feedback propagation |
| `synthesis_safety.py` | 739 | *(self-contained)* | Payload safety filters |

**Architecture note**: All PSE files are self-contained — zero internal imports. Designed as independent engines.

---

## 13. Layer 11: Vector Memory & Embeddings

**Total: 6 files, ~5,500 LoC** | **Location**: `memory/`, `agents/`, `graph/`, `loop/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `embedder.py` | 262 | *(self-contained)* | sentence-transformers (384-dim) |
| `vector_index.py` | 511 | *(self-contained)* | HNSW + binary quantization |
| `agent_memory.py` | 2,605 | `db_registry` | Semantic recall + TF-IDF |
| `rag_context.py` | 974 | *(self-contained)* | RAG context building |
| `cross_scan_memory.py` | 765 | *(self-contained)* | Cross-scan shared memory |
| `vector_reasoning.py` | 400 | *(self-contained)* | Vector-based hypothesis reasoning |

---

## 14. Layer 12: Prompt Management & Security

**Total: 8 files, ~5,600 LoC** | **Location**: root, `agents/`, `reasoning/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `prompt_registry.py` | 944 | `agents.llm_types` | Template versioning + A/B testing |
| `progressive_prompts.py` | 499 | *(self-contained)* | Easy → hard escalation |
| `few_shot_selector.py` | 694 | `agents.agent_memory`, `reasoning.context_budget`, `transfer_intelligence` | Dynamic example selection |
| `thinking_budget.py` | 336 | *(self-contained)* | Token allocation per reasoning step |
| `prompt_security.py` | 912 | *(self-contained)* | Input sanitization + injection defense |
| `doubt_injector.py` | 847 | *(self-contained)* | Skepticism injection for over-confidence |
| `prompt_chains.py` | 1,446 | *(self-contained)* | Multi-round chained prompts |
| `context_budget.py` | 487 | *(self-contained)* | Context window budget management |

---

## 15. Layer 13: Confidence & Calibration

**Total: 5 files, ~4,000 LoC** | **Location**: root, `agents/`, `recon_dashboard/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `confidence_ensemble.py` | 1,463 | `confidence_diversity` | Dempster-Shafer aggregation |
| `confidence_diversity.py` | 802 | *(self-contained)* | Overconfidence penalization |
| `confidence_calibration.py` (dashboard) | 766 | *(self-contained)* | Platt scaling + isotonic regression |
| `bayesian_prioritizer.py` | 569 | `logging_config`, `_safe_parse` | Bayesian belief updates |
| `persona_engine.py` | 1,155 | *(self-contained)* | Persona-based confidence modulation |

---

## 16. Layer 14: LangGraph State Machine

**Total: 19 files, ~8,800 LoC** | **Location**: `graph/`, `graph/multi_agent/`, `graph/reasoning/`

### graph/ (core) — 4,720 LoC
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `state.py` | 221 | *(self-contained)* | `AgentGraphState` TypedDict |
| `nodes.py` | 1,224 | `state` | Node implementations (think, act, reflect) |
| `builder.py` | 183 | `nodes`, `state` | State machine graph construction |
| `runner.py` | 590 | `builder`, `state` | Graph invocation + execution |
| `tracing.py` | 498 | *(self-contained)* | State history tracking |
| `production.py` | 634 | *(self-contained)* | Production config + error handling |
| `checkpointer_async.py` | 477 | *(self-contained)* | Async SQLite checkpointing |
| `cross_scan_memory.py` | 765 | *(self-contained)* | Cross-scan shared memory |

### graph/multi_agent/ — 3,123 LoC
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `state.py` | 236 | *(self-contained)* | `MultiAgentState`, `AgentHandoff` |
| `specialist_nodes.py` | 1,122 | `state`, `worker_factory` | Scanner/Reasoner/Executor/Judge nodes |
| `builder.py` | 334 | `specialist_nodes`, `state`, `supervisor` | Supervisor pattern graph |
| `runner.py` | 349 | `builder`, `state` | Multi-agent invocation |
| `supervisor.py` | 640 | `state` | Routing logic |
| `handoff.py` | 220 | *(self-contained)* | Agent handoff protocol |
| `worker_factory.py` | 139 | *(self-contained)* | Worker creation |

### graph/reasoning/ — 1,711 LoC
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `state.py` | 189 | *(self-contained)* | Reasoning state TypedDict |
| `nodes.py` | 1,004 | `state` | Reasoning nodes (hypothesize, evaluate) |
| `builder.py` | 160 | `nodes`, `state` | Fan-out/fan-in hypothesis graph |
| `runner.py` | 309 | `builder`, `state` | Reasoning execution |

**Wiring pattern**: Clean layered `state → nodes → builder → runner` in all 3 sub-packages.

---

## 17. Layer 15: Autonomous Exploitation Loop

**Total: 21 files, ~8,500 LoC** | **Location**: `loop/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `autonomous_loop.py` | 2,513 | `ai_directed_executor`, `loop_config`, `world_state` | Main OBSERVE→THINK→ACT→EVALUATE→LEARN |
| `ai_directed_executor.py` | 629 | *(self-contained)* | AI-directed tool execution |
| `invariant_engine.py` | 713 | *(self-contained)* | Consistency checking + violation detection |
| `target_selection.py` | 521 | *(self-contained)* | Target prioritization |
| `payload_evolution.py` | 512 | *(self-contained)* | GA population evolution |
| `exploit_report.py` | 510 | *(self-contained)* | Result reporting |
| `confirmation_engine.py` | 499 | *(self-contained)* | Multi-method verification |
| `signal_extraction.py` | 495 | *(self-contained)* | Signal classification |
| `session_matrix.py` | 458 | *(self-contained)* | Session state tracking |
| `attack_graph.py` | 431 | *(self-contained)* | Loop-level graph building |
| `campaign_strategy.py` | 417 | *(self-contained)* | Campaign planning |
| `race_engine.py` | 412 | *(self-contained)* | Race condition timing |
| `vector_reasoning.py` | 400 | *(self-contained)* | Vector-based reasoning |
| `value_scorer.py` | 350 | *(self-contained)* | Impact scoring |
| `target_specialization.py` | 342 | *(self-contained)* | Target-specific adaptation |
| `parallel_executor.py` | 305 | *(self-contained)* | Parallel tool execution |
| `graph_pruner.py` | 255 | *(self-contained)* | Low-value path pruning |
| `exploration_bias.py` | 250 | *(self-contained)* | Explore vs exploit |
| `world_state.py` | 177 | *(self-contained)* | Persistent world state |
| `loop_config.py` | 124 | *(self-contained)* | Configuration |
| `feedback_loop_breaker.py` | 590 | *(self-contained)* | Deadlock detection |

**Architecture note**: Only `autonomous_loop.py` has internal imports (3). All other 20 files are **completely self-contained**. This is the most modular subsystem.

---

## 18. Layer 16: Strategic & Planning Systems

**Total: 4 files, ~3,700 LoC** | **Location**: root

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `stealth_orchestrator.py` | 1,430 | *(self-contained)* | Stealth operation timing + detection avoidance |
| `strategic_llm_layer.py` | 1,097 | *(self-contained)* | Strategic LLM prompting layer |
| `strategic_foresight.py` | 767 | *(self-contained)* | Proactive strategy planning |
| `lookahead_engine.py` | 1,393 | *(self-contained)* | 2-step lookahead decision engine |

---

## 19. Layer 16b: Strategy Engine

**Total: 7 files, ~9,000 LoC** | **Location**: `strategy/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `discovery.py` | 2,217 | `http_client`, `models` | Strategy discovery patterns |
| `core.py` | 1,957 | `http_client`, `models` | Strategy engine core |
| `models.py` | 1,930 | *(self-contained)* | Strategy data models |
| `store.py` | 1,636 | `db_registry`, `core`, `models` | Strategy persistence |
| `async_exec.py` | 1,060 | `core`, `models` | Async strategy execution |
| `_build_modules.py` | 191 | `db_registry`, `http_client`, `models`, `core` | Module builder |
| `_build_facade.py` | 37 | *(re-export)* | Facade pattern |

**Wiring pattern**: `models` → `core`/`discovery` → `store` → `async_exec`. Clean dependency chain.

---

## 20. Layer 17: CAAP System

**Total: 27 files, ~7,300 LoC** | **Location**: `caap/`

### Core CAAP (real code — 7 files, ~4,900 LoC)
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `caap_hypothesis.py` | 1,160 | `logging_config`, `vuln_knowledge`, `caap_models` | Chain hypotheses |
| `caap_formatter.py` | 960 | `logging_config`, `caap_models`, `caap_session`, `caap_hypothesis`, `caap_chains`, `caap_parser`, `vuln_knowledge` **(7 imports)** | Output formatting |
| `caap_parser.py` | 889 | `logging_config`, `caap_models` | Chain parsing |
| `caap_models.py` | 339 | `logging_config` | Data models |
| `caap_session.py` | 322 | `logging_config`, `caap_models` | Session management |
| `caap_chains.py` | 298 | `logging_config`, `caap_models` | Chain orchestration |
| `caap_output_wrapper.py` | 279 | *(self-contained)* | Metadata wrapping |

### CAAP Exploitation (real code — 4 files, ~3,300 LoC)
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `browser_exploitation_engine.py` | 1,823 | `event_bus`, `logging_config` | Playwright browser exploitation + DAST |
| `escalation_gateway.py` | 1,207 | *(self-contained)* | Privilege escalation |
| `ui_interaction_engine.py` | 655 | *(self-contained)* | UI exploitation |
| `exploitation_engine.py` | 634 | `exploitation_models`, `exploitation_data`, `poc_generator`, `exploit_verifier`, `impact_chain`, `logging_config` **(6 imports)** | Enterprise exploitation verification |

### CAAP Data & Models (3 files, ~1,100 LoC)
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `exploitation_models.py` | 469 | *(self-contained)* | Exploitation enums + models |
| `exploitation_data.py` | 302 | `exploitation_models`, `logging_config` | Exploitation tracking data |
| `vuln_knowledge.py` | (shim/8) | *(re-export)* | Vulnerability knowledge re-export |

### CAAP Shims (13 files, 8 lines each — re-export from root)
`adaptive_learning.py`, `agent_memory.py`, `autonomy.py`, `copilot_loop.py`, `environmental_adaptation.py`, `event_bus.py`, `exploit_verifier.py`, `impact_chain.py`, `logging_config.py`, `poc_generator.py`, `reasoning_engine.py`, `screenshot.py`, `state_graph.py`

---

## 21. Layer 18: ATLAS Intelligence

**Total: 12 files, ~6,300 LoC** | **Location**: `atlas/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `store.py` | 954 | *(self-contained)* | SQLite persistence |
| `models.py` | 949 | *(self-contained)* | Data models |
| `adapter.py` | 820 | *(self-contained)* | LLM adapter |
| `interface.py` | 700 | *(self-contained)* | Public API |
| `atlas_nexus.py` | 654 | *(self-contained)* | Nexus integration |
| `advisory.py` | 404 | *(self-contained)* | Security advisories |
| `ingest.py` | 384 | *(self-contained)* | Ingestion pipeline |
| `patterns.py` | 355 | *(self-contained)* | Vulnerability patterns |
| `graph.py` | 291 | *(self-contained)* | Finding graph |
| `bootstrap.py` | 253 | *(self-contained)* | Bootstrap setup |
| `archetypes.py` | 244 | *(self-contained)* | Attack archetypes |
| `defense.py` | 242 | *(self-contained)* | Defense context |

**Architecture note**: All 12 files are **completely self-contained**. Zero internal imports.

---

## 22. Layer 19: Feedback & Signal Propagation

**Total: 6 files, ~3,400 LoC** | **Location**: root, `agents/`, `exploit_chains/`, `loop/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `ml_feedback_propagator.py` | 536 | `agents.bayesian_prioritizer`, `agents.feedback_learning`, `exploit_chains.exploit_verifier`, `exploit_chains.weight_tuner`, `hypothesis_engine`, `recon_dashboard.confidence_calibration`, `recon_dashboard.findings_store` **(7 imports)** | Central backpropagation hub |
| `feedback_learning.py` | 755 | *(self-contained)* | Prompt augmentation |
| `synthesis_feedback.py` | 569 | *(self-contained)* | Multi-engine feedback |
| `weight_tuner.py` | 1,640 | *(self-contained)* | 13-signal Bayesian calibration |
| `signal_extraction.py` | 495 | *(self-contained)* | Signal classification |
| `feedback_loop_breaker.py` | 590 | *(self-contained)* | Deadlock detection |

---

## 23. Layer 20: Copilot SDK & Tool Registry

**Total: 10 files, ~7,000 LoC** | **Location**: `agents/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `copilot_sdk_engine.py` | 1,512 | *(self-contained)* | 67+ tool integration |
| `copilot_sdk_vuln_tools.py` | 1,119 | `copilot_sdk_tools` | Vulnerability tools |
| `copilot_sdk_agents.py` | 1,101 | *(self-contained)* | Agent-specific tools |
| `native_tool_calling.py` | 924 | *(self-contained)* | OpenAI/Anthropic function calling |
| `copilot_sdk_tools.py` | 736 | *(self-contained)* | Base tool implementations |
| `copilot_sdk_discovery_tools.py` | 628 | `copilot_sdk_tools` | Discovery tools |
| `copilot_sdk_infra_tools.py` | 354 | `copilot_sdk_tools` | Infrastructure tools |
| `copilot_sdk_intel_tools.py` | 276 | `copilot_sdk_tools` | Intelligence tools |
| `copilot_sdk_exploit_cloud_tools.py` | 252 | `copilot_sdk_tools` | Cloud exploitation tools |
| `copilot_sdk_tool_registry.py` | 164 | *(self-contained)* | Unified registry |

**Wiring pattern**: `copilot_sdk_tools.py` is the base — 5 tool modules import `HAS_COPILOT_SDK`, `_enum_val`, `_json_result`, `_run_sync` from it.

---

## 24. Layer 21: AI/ML Security Scanner

**Total: 10 files** | **Location**: `ai_ml/`, root

(Shim-based: `ai_ml_scanner.py` at root [29 lines] imports from `ai_ml/` sub-package)

| File | Purpose |
|------|---------|
| `_prompt_injection.py` | Prompt injection detection |
| `_vector_database.py` | Vector DB exposure |
| `_model_endpoint.py` | ML endpoint detection |
| `_model_serialization.py` | Deserialization attacks |
| `_rag_pipeline.py` | RAG pipeline attacks |
| `_ai_api_proxy.py` | API proxy security |
| `_models.py` | Enums and types |
| `_utils.py` | Utility functions |
| `_serialization.py` | Artifact detection |

---

## 25. Layer 22: Knowledge & Domain Systems

**Total: 11 files, ~7,500 LoC** | **Location**: root, `agents/`, `intel/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `knowledge_resilience.py` | 1,229 | *(self-contained)* | Distributed knowledge |
| `tool_intelligence.py` | 1,012 | `learning_loop_engine` | Tool meta-reasoning |
| `transfer_intelligence.py` | 571 | *(self-contained)* | Cross-target transfer |
| `proactive_intelligence.py` | 727 | *(self-contained)* | Proactive threat hunting |
| `domain_knowledge_engine.py` | 624 | *(self-contained)* | Domain-specific knowledge |
| `creative_exploit_heuristics.py` | 608 | *(self-contained)* | Creative exploit generation |
| `vulnerability_intelligence.py` | (shim) | *(re-export)* | CVE intelligence |
| `qtable_advisor.py` | 372 | *(self-contained)* | Q-learning advisor |
| `next_action_advisor.py` | 757 | *(self-contained)* | Next action recommendation |
| `copilot_reasoning.py` | 707 | `vuln_knowledge` | Copilot reasoning + knowledge |

---

## 26. Layer 23: World Model & State

**Total: 4 files, ~5,800 LoC** | **Location**: root

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `self_optimizing_stack.py` | 2,300 | *(self-contained)* | Self-tuning optimization |
| `world_model.py` | 1,644 | *(self-contained)* | Counterfactual reasoning |
| `target_mental_model.py` | 997 | *(self-contained)* | Target profiling |
| `temporal_stability.py` | 818 | *(self-contained)* | Drift detection |

---

## 27. Layer 24: Truth Enforcement & Verification

**Total: 11 files, ~10,700 LoC** | **Location**: `recon_dashboard/`, root

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `truth_enforcement.py` | 1,953 | *(self-contained)* | Hard proof gates + confidence ceilings |
| `remediation_validation.py` | 1,345 | *(self-contained)* | Remediation playbooks + test cases |
| `multi_request_validator.py` | 3,346 | *(self-contained)* | Multi-HTTP validation v2 |
| `oob_verifier.py` | 416 | `oob_interaction` | OOB interaction verification |
| `verification_chain.py` | 954 | `agents.doubt_injector`, `agents.unified_arbitration`, `tool_registry.registry` | Proof lifecycle |
| `finding_validator.py` | 563 | *(self-contained)* | Validation gateway |
| `report_fp_detection.py` | 407 | *(self-contained)* | FP detection |
| `proof_first_severity.py` | 274 | *(self-contained)* | Severity from verified impact |
| `exploit_verifier.py` (chains) | 1,096 | *(self-contained)* | Re-execution verification |
| `secret_verifier.py` | (shim) | → `secrets.secret_verifier` | Credential verification |
| `secret_verifiers_extended.py` | (shim) | *(re-export)* | Extended verification |

---

## 28. Layer 25: Impact & Scoring

**Total: 7 files, ~6,900 LoC** | **Location**: `recon_dashboard/`, `exploit_chains/`, root

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `bounty_ops.py` | 2,421 | *(self-contained)* | Bounty truth enforcement + submission |
| `impact_amplifier.py` | 1,602 | *(self-contained)* | Impact chaining + auto-bounty report |
| `benchmark_tracker.py` | 1,085 | *(self-contained)* | Campaign ROI + win condition tracking |
| `impact_chain.py` | 873 | *(self-contained)* | Impact propagation |
| `target_scoring.py` | 773 | *(self-contained)* | Pre-Exploit Decision Dominance + budget |
| `chain_impact_scorer.py` | 487 | *(self-contained)* | CVSS/business impact scoring |
| `payout_metrics.py` | 479 | *(self-contained)* | Signal-to-Payout instrumentation |

---

## 29. Layer 27: Recon Dashboard

**Total: 77 files, ~73,000 LoC** | **Location**: `recon_dashboard/`, `recon_dashboard/phase_handlers/`

### Core Infrastructure (top 10 by line count)
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `server.py` | 9,089 | `_assets`, `event_bridge`, `infra_monitor`, `llm_helpers`, `session_store`, `state` **(6 imports)** | aiohttp + WebSocket server |
| `runner.py` | 7,871 | `response_classifier`, `canonical_finding`, `phase_health`, `scheduler`, `state`, `command_executor`, `finding_pipeline`, `phase_data_store`, `phase_commands`, `finding_parsers`, `phase_handlers` **(11 imports — most connected dashboard file)** | Autonomous recon executor |
| `finding_parsers.py` | 3,390 | `response_classifier` | Per-phase normalised finding extraction |
| `multi_request_validator.py` | 3,346 | *(self-contained)* | Multi-HTTP validation v2 |
| `phase_commands.py` | 2,595 | *(self-contained)* | Phase command definitions |
| `state.py` | 2,460 | `_tech_utils`, `target_profile`, `phase_defs` | Thread-safe DashboardState |
| `bounty_ops.py` | 2,421 | *(self-contained)* | Bounty truth enforcement |
| `authenticated_exploit_engine.py` | 2,110 | *(self-contained)* | Token extraction + auth flow simulation |
| `truth_enforcement.py` | 1,953 | *(self-contained)* | Hard proof gates |
| `report_renderer.py` | 1,809 | `_report_constants` | Markdown rendering pipeline |

### Intelligence & ML (26 files)
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `execution_intelligence.py` | 1,696 | *(self-contained)* | Dynamic weight learning + context modulation |
| `exploit_persistence_engine.py` | 1,192 | *(self-contained)* | Exploit adaptation on failure |
| `execution_orchestrator.py` | 1,181 | *(self-contained)* | Value-based runtime budgets |
| `scan_mode_config.py` | 1,002 | *(self-contained)* | BUG_BOUNTY/ASSESSMENT/COMPLIANCE/PENTEST |
| `auto_exploit_executor.py` | 831 | *(self-contained)* | Auto-PoC execution + verification |
| `multimodal_support.py` | 827 | *(self-contained)* | Images + rendered HTML into LLM context |
| `threat_modeling.py` | 823 | *(self-contained)* | STRIDE, DREAD, PASTA frameworks |
| `finding_pipeline.py` | 822 | `canonical_finding` | Centralised finding processing |
| `causal_inference.py` | 780 | *(self-contained)* | DAG-based causal finding relationships |
| `confidence_calibration.py` | 766 | *(self-contained)* | Bayesian calibration |
| `graph_reasoning.py` | 697 | *(self-contained)* | Graph-based exploit-path analysis |
| `cross_target_intelligence.py` | 666 | *(self-contained)* | Cross-target sharing + replanning |
| `target_profile.py` | 657 | *(self-contained)* | Progressive domain/IP intelligence |
| `chain_execution_loop.py` | 642 | *(self-contained)* | Closed-loop exploit chain + LLM discovery |
| `eta_engine.py` | 564 | `phase_defs` | ETA with phase cost weights |
| `attack_strategy_engine.py` | 525 | *(self-contained)* | Proactive strategy with EV scoring |
| `platform_intelligence_memory.py` | 492 | *(self-contained)* | Persistent per-platform learning |
| `langgraph_scan.py` | 340 | `phase_defs` | LangGraph scan pipeline |
| `differential_analysis.py` | 233 | *(self-contained)* | Baseline ≠ modified response proof |
| `target_scoring.py` | 773 | *(self-contained)* | Pre-Exploit Decision Dominance |
| `llm_helpers.py` | 124 | *(self-contained)* | LLM lazy-init helpers |

### Routes (14 files, ~5,800 LoC)
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `routes_llm.py` | 1,034 | *(self-contained)* | LLM chat + streaming routes |
| `routes_sdk_engine.py` | 689 | *(self-contained)* | SDK Agentic Engine routes |
| `routes_standalone.py` | 594 | *(self-contained)* | Standalone recon + export routes |
| `routes_provider_vault.py` | 543 | *(self-contained)* | Encrypted LLM key vault routes |
| `routes_multi_agent.py` | 508 | *(self-contained)* | Multi-agent campaign routes |
| `routes_agent.py` | 382 | *(self-contained)* | Agent-loop + memory routes |
| `routes_cross_target.py` | 352 | `cross_target_intelligence` | Cross-target intel routes |
| `routes_intelligence_experience.py` | 350 | *(self-contained)* | HOW Venator thinks routes |
| `routes_scan_config.py` | 283 | `scan_mode_config` | Scan config + intent detection |
| `routes_exploit_graph.py` | 264 | *(self-contained)* | Exploit-graph visualization routes |
| `routes_target_scoring.py` | 255 | `target_scoring` | Target ROI scoring routes |
| `routes_assessment.py` | 223 | *(self-contained)* | Assessment + intelligence routes |
| `routes_reasoning.py` | 198 | *(self-contained)* | Reasoning decision traces |
| `routes_findings.py` | 159 | *(self-contained)* | Finding annotation routes |

### Reports (7 files, ~5,500 LoC)
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `report_renderer.py` | 1,809 | `_report_constants` | Markdown rendering pipeline |
| `remediation_validation.py` | 1,345 | *(self-contained)* | Remediation playbooks |
| `report_analysis.py` | 1,229 | *(self-contained)* | Tech anomalies + coverage gaps |
| `report_dedup.py` | 1,145 | *(self-contained)* | Post-filter WAF + param dedup |
| `report_filters.py` | 882 | *(self-contained)* | Severity propagation + filtering |
| `report_generator.py` | 542 | `_report_constants`, `_tech_utils` | Markdown report generator |
| `report_fp_detection.py` | 407 | *(self-contained)* | FP detection |

### Infrastructure (remaining files)
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `command_executor.py` | 1,370 | *(self-contained)* | Subprocess lifecycle + deferral |
| `_hooks.py` | 1,482 | `_assets`, `_notify`, `server`, `state` | Hook/utility functions |
| `benchmark_tracker.py` | 1,085 | *(self-contained)* | Campaign ROI tracking |
| `phase_data_store.py` | 939 | *(self-contained)* | Phase data from report dir |
| `db_persistence.py` | 849 | `db_registry` (parent) | SQLite migration |
| `state_serializers.py` | 758 | *(self-contained)* | Serialization + diff tracking |
| `scheduler.py` | 739 | `state` | Resource governor |
| `conversation_branching.py` | 663 | *(self-contained)* | Tree-structured chat branching |
| `appliance_api.py` | 603 | *(self-contained)* | Appliance REST API |
| `findings_store.py` | 578 | *(self-contained)* | Unified finding persistence |
| `finding_dedup.py` | 150 | *(self-contained)* | Multi-tool confidence |
| `finding_validator.py` | 563 | *(self-contained)* | Validation gateway |
| `payout_metrics.py` | 479 | *(self-contained)* | Signal-to-Payout |
| `infra_monitor.py` | 420 | *(self-contained)* | Burp/Docker/perf monitoring |
| `conversation_export.py` | 381 | *(self-contained)* | Chat export (JSON/MD/HTML/CSV) |
| `phase_defs.py` | 325 | `_tech_utils` | Phase scheduling + cost-weights |
| `_report_constants.py` | 283 | *(self-contained)* | Report shared constants |
| `session_store.py` | 245 | *(self-contained)* | Session save/restore/prune |
| `_assets.py` | 204 | *(self-contained)* | Static asset loading |
| `event_bridge.py` | 183 | *(self-contained)* | Event bridge |
| `_notify.py` | 149 | `state` | Notification helpers |
| `atlas_api.py` | 1,410 | *(self-contained)* | Atlas Intelligence Dashboard API |
| `impact_amplifier.py` | 1,602 | *(self-contained)* | Impact amplification |
| `_tech_utils.py` | 54 | *(self-contained)* | Tech name sanitisation |

### Phase Handlers (6 files, ~5,100 LoC)
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `security_testing.py` | 1,394 | `base.PhaseContext` | Phases 14-17 security handlers |
| `advanced.py` | 1,382 | `base.PhaseContext` | Phases 20-27 advanced handlers |
| `infrastructure.py` | 806 | `base.PhaseContext` | Phases 7-13 infra handlers |
| `discovery.py` | 689 | `base.PhaseContext` | Phases 1-6 discovery handlers |
| `intelligence.py` | 588 | `base.PhaseContext` | Phases 28-30 intelligence handlers |
| `base.py` | 69 | *(self-contained)* | Phase handler protocol + hooks |

---

## 30. Layer 28: Safety & Defense

**Total: 5 files, ~4,400 LoC** | **Location**: `agents/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `llm_advanced_defense.py` | 1,261 | *(self-contained)* | Advanced defense techniques |
| `llm_output_guard.py` | 814 | *(self-contained)* | Output validation + schema enforcement |
| `prompt_security.py` | 912 | *(self-contained)* | Input sanitization |
| `llm_defense_hardening.py` | 641 | *(self-contained)* | Input defense hardening |
| `synthesis_safety.py` | 739 | *(self-contained)* | Payload safety filters |

---

## 31. Layer 30: MCP Extension (VS Code)

**Total: 16 TypeScript files** | **Location**: `mcp-extension/src/`

| File | Purpose |
|------|---------|
| `extension.ts` | VS Code entry point |
| `toolLoop.ts` | LLM tool-calling loop |
| `chatHandlers.ts` | Copilot chat handler |
| `treeView.ts` | Hypothesis tree view |
| `dashboardPanel.ts` | Dashboard webview |
| `lib.ts` | Token estimation; YAML parsing |
| `eventBus.ts` | Event distribution |
| `execCli.ts` | CLI execution bridge |
| `mcpProvider.ts` | 40+ MCP tools |
| `cliDaemon.ts` | Background daemon |
| `reconBridge.ts` | Recon output bridge |
| `commands.ts` | Command construction |
| `logger.ts` | Structured logging |
| `globals.ts` | Global state |
| `progressStatusBar.ts` | Progress display |
| `mcpHealth.ts` | Health checking |

---

## 32. Layer 31: MCP Python Server

**Total: 21 files, ~4,300 LoC** | **Location**: `mcp/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `mcp_builtins.py` | 1,050 | `logging_config`, `mcp_tools` | Built-in MCP operations |
| `atlas_mcp_bridge.py` | 931 | *(self-contained)* | MCP ↔ Atlas integration |
| `cognitive_bridge.py` | 841 | *(self-contained)* | LLM bridge for MCP context |
| `mcp_server.py` | 837 | `logging_config`, `mcp_tools`, `mcp_builtins`, `cognitive_tools` **(4 imports)** | FastMCP SSE/stdio server |
| `cognitive_tools.py` | 485 | *(self-contained)* | MCP cognitive operations |
| `mcp_tools.py` | 106 | `tool_abstraction`, `tool_chain_advisor` | Tool dispatch layer |

### MCP Shims (15 files, 8 lines each — re-export from root)
`agent_memory.py`, `agent_telemetry.py`, `assessment_engine.py`, `atlas.py`, `chain_matcher.py`, `dashboard_renderer.py`, `escalation_gateway.py`, `logging_config.py`, `next_action_advisor.py`, `session_manager.py`, `shutdown.py`, `storage.py`, `tool_abstraction.py`, `tool_chain_advisor.py`, `vuln_knowledge.py`

**Wiring pattern**: `mcp_server.py` → `mcp_builtins.py` → `mcp_tools.py` → `tool_abstraction.py`

---

## 33. Layer 32: Multi-Agent Swarm

**Total: 10 files, ~5,800 LoC** | **Location**: `swarm/`, `swarm/multi_gpu/`

### swarm/ (core) — 2,641 LoC
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `agent_roles.py` | 804 | *(self-contained)* | Scanner, Reasoner, Executor, Judge roles |
| `swarm.py` | 607 | `agent_roles`, `gpu_governor`, `message_bus`, `shared_weights` **(4 imports)** | Swarm orchestrator |
| `message_bus.py` | 434 | *(self-contained)* | Inter-agent message routing |
| `shared_weights.py` | 430 | *(self-contained)* | Multi-GPU weight sync |
| `gpu_governor.py` | 366 | *(self-contained)* | Swarm-level GPU allocation |

### swarm/multi_gpu/ — 2,943 LoC
| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `topology.py` | 743 | *(self-contained)* | GPU topology detection + interconnect mapping |
| `scheduler.py` | 615 | `topology` | GPU task scheduling |
| `messenger.py` | 565 | `topology` | GPU-aware messaging |
| `model_sharder.py` | 521 | `topology` | Model weight sharding |
| `governor.py` | 499 | `topology`, `model_sharder`, `scheduler`, `messenger` **(4 imports)** | Multi-GPU governor |

**Wiring pattern**: `topology.py` is the foundation — all other multi_gpu files depend on it. `governor.py` is the hub that imports all 4 peers.

---

## 34. Layer 33: Exploitation Sub-Package

**Total: 7 files, ~6,300 LoC** | **Location**: `exploitation/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `poc_generator.py` | 3,194 | `logging_config`, `cvss`, `models` | PoC generation for 25+ vuln types |
| `verifier.py` | 1,274 | `logging_config`, `models` | Exploit verification |
| `engine.py` | 609 | `logging_config`, `telemetry`, `chains`, `cvss`, `impact`, `models`, `poc_generator`, `verifier` **(8 imports — most connected in package)** | Exploitation engine core |
| `impact.py` | 568 | `models` | Impact demonstration |
| `chains.py` | 342 | `models`, `verifier`, `logging_config` | Attack chain execution |
| `cvss.py` | 305 | `logging_config`, `models` | CVSS calculation + bounty estimates |
| `models.py` | 36 | `exploitation_models` (parent) | Data model re-export |

**Wiring pattern**: `models.py` → `cvss`/`impact`/`verifier` → `chains` → `engine` (hub)

---

## 35. Layer 34: Tool Registry

**Total: 4 files, ~2,900 LoC** | **Location**: `tool_registry/`

| File | Lines | Wires To | Purpose |
|------|------:|----------|---------|
| `output_parsers.py` | 1,050 | *(self-contained)* | Tool output parsing + normalization |
| `registry.py` | 961 | *(self-contained)* | Central tool registry |
| `fallback.py` | 452 | `registry` | Smart fallback when tools fail |
| `action_translator.py` | 394 | `registry`, `fallback`, `output_parsers` | NL → tool action translation |

**Wiring pattern**: `registry` + `output_parsers` (self-contained) → `fallback` → `action_translator` (imports all 3)

---

## 36. Complete File Index with Line Counts

### A. LLM Core (4 files — 8,360 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 1 | `llm_bridge.py` | agents/ | 4,100 | Central LLM gateway |
| 2 | `llm_clients.py` | agents/ | 1,979 | Provider HTTP clients |
| 3 | `llm_types.py` | agents/ | 1,420 | Shared types |
| 4 | `llm_routing.py` | agents/ | 861 | Model selection + fallback |

### B. LLM Infrastructure (10 files — 7,017 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 5 | `llm_production.py` | agents/ | 1,695 | Production hardening |
| 6 | `llm_ops.py` | agents/ | 1,173 | Operational monitoring |
| 7 | `llm_adaptive.py` | agents/ | 763 | Dynamic temperature tuning |
| 8 | `llm_tracking.py` | agents/ | 796 | Token accounting |
| 9 | `streaming_structured.py` | agents/ | 593 | Structured JSON streaming |
| 10 | `llm_tracing.py` | agents/ | 520 | OpenTelemetry instrumentation |
| 11 | `llm_cache.py` | agents/ | 471 | Semantic + exact cache |
| 12 | `llm_hardware_adapter.py` | agents/ | 435 | GPU/CPU detection |
| 13 | `llm_intelligence.py` | agents/ | 414 | Meta-reasoning |
| 14 | `llm_registry.py` | agents/ | 157 | Model capability registry |

### C. Agent System (14 files — 22,141 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 15 | `agent_loop.py` | agents/ | 2,656 | Main agent loop |
| 16 | `agent_memory.py` | agents/ | 2,605 | Episodic memory + TF-IDF |
| 17 | `copilot_loop.py` | agents/ | 2,349 | Copilot integration |
| 18 | `collaborative_intelligence.py` | agents/ | 2,297 | Multi-agent collaboration |
| 19 | `unified_agent.py` | agents/ | 2,102 | Unified agent facade |
| 20 | `goal_planner.py` | agents/ | 2,096 | Goal decomposition |
| 21 | `hierarchical_planner.py` | agents/ | 1,991 | Sub-goal planning |
| 22 | `risk_aware_testing.py` | agents/ | 1,904 | Risk-weighted prioritization |
| 23 | `attack_reasoning.py` | agents/ | 1,594 | Attack strategy reasoning |
| 24 | `agent_sessions.py` | agents/ | 1,456 | Session persistence |
| 25 | `unified_arbitration.py` | agents/ | 1,095 | Finding arbitration |
| 26 | `planner_bridge.py` | agents/ | 1,038 | Planner ↔ executor bridge |
| 27 | `autonomous_exploitation.py` | agents/ | 984 | A* pathfinding execution |
| 28 | `bayesian_prioritizer.py` | agents/ | 569 | Bayesian belief updates |

### D. Reasoning & Hypothesis (6 files — 7,765 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 29 | `reasoning_engine.py` | agents/ | 2,942 | Bayesian probability tables |
| 30 | `prompt_chains.py` | reasoning/ | 1,446 | Multi-round chained prompts |
| 31 | `hypothesis_engine.py` | root | 1,202 | Hypothesis generation |
| 32 | `hierarchical_decomposition.py` | root | 1,113 | Task decomposition |
| 33 | `hypothesis_manager.py` | reasoning/ | 575 | Hypothesis lifecycle |
| 34 | `context_budget.py` | reasoning/ | 487 | Token budget allocation |

### E. Exploit Graph (14 files — 9,316 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 35 | `exploit_graph.py` | exploit_chains/ | 1,904 | Core 5-dimension graph |
| 36 | `unified_attack_graph.py` | root | 1,830 | Unified graph |
| 37 | `state_graph.py` | exploit_chains/ | 1,141 | State transition graph |
| 38 | `graph_knowledge_base.py` | exploit_chains/ | 852 | Attack pattern KB |
| 39 | `decision_framework.py` | exploit_chains/ | 802 | Attack decision framework |
| 40 | `exploit_path_planner.py` | exploit_chains/ | 642 | A* pathfinding |
| 41 | `exploit_graph_renderer.py` | exploit_chains/ | 386 | D3.js visualization |
| 42 | `graph_persistence.py` | exploit_chains/ | 307 | SQLite persistence |
| 43 | `graph_rendering.py` | exploit_chains/ | 303 | Rendering data |
| 44 | `graph_integrations.py` | exploit_chains/ | 258 | System integration hooks |
| 45 | `graph_pathfinding.py` | exploit_chains/ | 229 | Algorithms |
| 46 | `graph_reporting.py` | exploit_chains/ | 186 | Summary reporting |
| 47 | `graph_state_ops.py` | exploit_chains/ | 186 | State operations |
| 48 | `graph_suggestions.py` | exploit_chains/ | 106 | Next-test suggestions |

### F. Payload Synthesis (12 files — 8,915 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 49 | `payload_arbiter.py` | exploit_chains/ | 1,701 | 8-signal ML scoring |
| 50 | `grammar_synthesizer.py` | exploit_chains/ | 1,185 | Grammar-driven synthesis |
| 51 | `synthesis_context.py` | exploit_chains/ | 963 | Context compilation |
| 52 | `payload_synthesis_engine.py` | exploit_chains/ | 890 | PSE orchestrator |
| 53 | `genetic_forge.py` | exploit_chains/ | 779 | Genetic algorithms |
| 54 | `synthesis_safety.py` | root | 739 | Safety filters |
| 55 | `synthesis_tracer.py` | exploit_chains/ | 700 | Pipeline observability |
| 56 | `synthesis_feedback.py` | exploit_chains/ | 569 | Feedback propagation |
| 57 | `llm_synthesizer.py` | exploit_chains/ | 472 | LLM-based synthesis |
| 58 | `execution_scheduler.py` | exploit_chains/ | 418 | 4-phase scheduling |

### G. LangGraph (19 files — 8,846 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 59 | `nodes.py` | graph/ | 1,224 | Node implementations |
| 60 | `specialist_nodes.py` | graph/multi_agent/ | 1,122 | Specialist nodes |
| 61 | `nodes.py` | graph/reasoning/ | 1,004 | Reasoning nodes |
| 62 | `cross_scan_memory.py` | graph/ | 765 | Cross-scan memory |
| 63 | `supervisor.py` | graph/multi_agent/ | 640 | Routing logic |
| 64 | `production.py` | graph/ | 634 | Production configs |
| 65 | `runner.py` | graph/ | 590 | Graph execution |
| 66 | `tracing.py` | graph/ | 498 | State history |
| 67 | `checkpointer_async.py` | graph/ | 477 | Async checkpointing |
| 68 | `runner.py` | graph/multi_agent/ | 349 | Multi-agent execution |
| 69 | `builder.py` | graph/multi_agent/ | 334 | Supervisor graph |
| 70 | `runner.py` | graph/reasoning/ | 309 | Reasoning execution |
| 71 | `state.py` | graph/multi_agent/ | 236 | MultiAgentState |
| 72 | `handoff.py` | graph/multi_agent/ | 220 | Agent handoff |
| 73 | `state.py` | graph/ | 221 | AgentGraphState |
| 74 | `state.py` | graph/reasoning/ | 189 | Reasoning state |
| 75 | `builder.py` | graph/ | 183 | Graph construction |
| 76 | `builder.py` | graph/reasoning/ | 160 | Reasoning graph |
| 77 | `worker_factory.py` | graph/multi_agent/ | 139 | Worker creation |

### H. Autonomous Loop (21 files — 8,586 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 78 | `autonomous_loop.py` | loop/ | 2,513 | Main loop |
| 79 | `invariant_engine.py` | loop/ | 713 | Consistency checking |
| 80 | `ai_directed_executor.py` | loop/ | 629 | AI-directed execution |
| 81 | `feedback_loop_breaker.py` | loop/ | 590 | Deadlock detection |
| 82 | `target_selection.py` | loop/ | 521 | Target prioritization |
| 83 | `payload_evolution.py` | loop/ | 512 | GA population |
| 84 | `exploit_report.py` | loop/ | 510 | Result reporting |
| 85 | `confirmation_engine.py` | loop/ | 499 | Multi-method verification |
| 86 | `signal_extraction.py` | loop/ | 495 | Signal classification |
| 87 | `session_matrix.py` | loop/ | 458 | Session state |
| 88 | `attack_graph.py` | loop/ | 431 | Graph building |
| 89 | `campaign_strategy.py` | loop/ | 417 | Campaign planning |
| 90 | `race_engine.py` | loop/ | 412 | Race condition timing |
| 91 | `vector_reasoning.py` | loop/ | 400 | Vector-based reasoning |
| 92 | `value_scorer.py` | loop/ | 350 | Impact scoring |
| 93 | `target_specialization.py` | loop/ | 342 | Target adaptation |
| 94 | `parallel_executor.py` | loop/ | 305 | Parallel execution |
| 95 | `graph_pruner.py` | loop/ | 255 | Path pruning |
| 96 | `exploration_bias.py` | loop/ | 250 | Explore vs exploit |
| 97 | `world_state.py` | loop/ | 177 | World state |
| 98 | `loop_config.py` | loop/ | 124 | Configuration |

### I. Decision & Strategy (11 files — 16,500 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 99 | `decision_orchestrator.py` | root | 3,264 | Central decision hub |
| 100 | `discovery.py` | strategy/ | 2,217 | Strategy discovery |
| 101 | `core.py` | strategy/ | 1,957 | Strategy engine core |
| 102 | `models.py` | strategy/ | 1,930 | Strategy models |
| 103 | `store.py` | strategy/ | 1,636 | Strategy persistence |
| 104 | `stealth_orchestrator.py` | root | 1,430 | Stealth operations |
| 105 | `lookahead_engine.py` | root | 1,393 | 2-step lookahead |
| 106 | `strategic_llm_layer.py` | root | 1,097 | Strategic LLM |
| 107 | `async_exec.py` | strategy/ | 1,060 | Async execution |
| 108 | `decision_trace.py` | root | 846 | Decision audit trail |
| 109 | `decision_benchmark.py` | root | 833 | Decision benchmarking |

### J. Inference Engine (14 files — 6,574 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 110 | `gpu_governor.py` | inference/ | 1,194 | GPU memory allocation |
| 111 | `engine.py` | inference/ | 659 | Core inference |
| 112 | `model_manager.py` | inference/ | 635 | Model lifecycle |
| 113 | `setup_local_llm.py` | inference/ | 569 | Ollama auto-setup |
| 114 | `model_registry.py` | inference/model_management/ | 543 | Model specs |
| 115 | `ollama_backend.py` | inference/ | 515 | Ollama client |
| 116 | `model_benchmarker.py` | inference/model_management/ | 514 | GGUF perf testing |
| 117 | `finetune_exporter.py` | inference/model_management/ | 457 | Fine-tune export |
| 118 | `model_downloader.py` | inference/model_management/ | 435 | GGUF download |
| 119 | `model_cli.py` | inference/model_management/ | 406 | CLI interface |
| 120 | `vram_selector.py` | inference/model_management/ | 404 | VRAM-based selection |
| 121 | `llama_backend.py` | inference/ | 392 | Llama.cpp backend |
| 122 | `grammar.py` | inference/ | 343 | Grammar-constrained gen |
| 123 | `kv_cache.py` | inference/ | 306 | KV cache |

### K. ATLAS (12 files — 6,314 LoC)
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 124 | `store.py` | atlas/ | 954 | SQLite persistence |
| 125 | `models.py` | atlas/ | 949 | Data models |
| 126 | `adapter.py` | atlas/ | 820 | LLM adapter |
| 127 | `interface.py` | atlas/ | 700 | Public API |
| 128 | `atlas_nexus.py` | atlas/ | 654 | Nexus integration |
| 129 | `advisory.py` | atlas/ | 404 | Security advisories |
| 130 | `ingest.py` | atlas/ | 384 | Ingestion pipeline |
| 131 | `patterns.py` | atlas/ | 355 | Vulnerability patterns |
| 132 | `graph.py` | atlas/ | 291 | Finding graph |
| 133 | `bootstrap.py` | atlas/ | 253 | Bootstrap setup |
| 134 | `archetypes.py` | atlas/ | 244 | Attack archetypes |
| 135 | `defense.py` | atlas/ | 242 | Defense context |

### L. Recon Dashboard (77 files — ~73,000 LoC)
*(See Layer 27 above for full breakdown with line counts)*

### M. CAAP (27 files — ~7,300 LoC)
*(See Layer 17 above for full breakdown with line counts)*

### N. MCP Python Server (21 files — ~4,300 LoC)
*(See Layer 31 above for full breakdown)*

### O. Swarm (10 files — 5,818 LoC)
*(See Layer 32 above for full breakdown)*

### P. Exploitation (7 files — 6,328 LoC)
*(See Layer 33 above for full breakdown)*

### Q. Tool Registry (4 files — 2,857 LoC)
*(See Layer 34 above for full breakdown)*

### R. Safety & Defense (5 files — 4,367 LoC)
*(See Layer 28 above for full breakdown)*

### S. Confidence & Calibration (5 files — 4,755 LoC)
*(See Layer 13 above for full breakdown)*

### T. Additional Root Systems
| # | File | Directory | Lines | Purpose |
|---|------|-----------|------:|---------|
| 300 | `event_bus.py` | root | 1,975 | Pub/sub event architecture |
| 301 | `learning_loop_engine.py` | root | 1,704 | End-to-end learning loop |
| 302 | `adaptive_chain_engine.py` | root | 1,441 | Bandit routing + dynamic templates |
| 303 | `multi_agent_debate.py` | root | 1,439 | Multi-perspective debate |
| 304 | `knowledge_resilience.py` | root | 1,229 | Distributed knowledge |
| 305 | `oob_interaction.py` | root | 1,366 | OOB interaction server |
| 306 | `persona_engine.py` | root | 1,155 | Persona-based modulation |
| 307 | `tool_intelligence.py` | root | 1,012 | Tool meta-reasoning |
| 308 | `verification_chain.py` | root | 954 | Proof lifecycle |
| 309 | `symbolic_fallback.py` | root | 937 | Symbolic reasoning fallback |
| 310 | `self_optimizing_stack.py` | root | 2,300 | Self-tuning optimization |
| 311 | `world_model.py` | root | 1,644 | Counterfactual reasoning |
| 312 | `target_mental_model.py` | root | 997 | Target profiling |
| 313 | `temporal_stability.py` | root | 818 | Drift detection |
| 314 | `transfer_intelligence.py` | root | 571 | Cross-target transfer |
| 315 | `ml_feedback_propagator.py` | root | 536 | Backpropagation hub |
| 316 | `unified_reasoning.py` | root | 610 | Unified reasoning layer |

---

## 37. Complete Wiring Map (All Imports)

### Tier 1: Hub Files (7+ internal imports)

```
decision_orchestrator.py (3,264 LoC) ─── 13 IMPORTS ─── MOST CONNECTED FILE
├── decision_benchmark             (decision quality)
├── decision_trace                 (audit trail)
├── event_bus                      (pub/sub)
├── recon_dashboard.confidence_calibration  (cross-pkg)
├── recon_dashboard.finding_validator       (cross-pkg)
├── self_optimizing_stack          (self-tuning)
├── stealth_orchestrator           (stealth ops)
├── strategic_foresight            (proactive strategy)
├── strategic_llm_layer            (strategic LLM)
├── target_mental_model            (target profiling)
├── agents.reasoning_engine        (cross-pkg)
└── (StrategyType, ToolTier, SignalType, etc.)

runner.py [dashboard] (7,871 LoC) ─── 11 IMPORTS ─── MOST CONNECTED DASHBOARD FILE
├── response_classifier            (parent pkg)
├── canonical_finding              (parent pkg)
├── phase_health                   (parent pkg)
├── scheduler                      (sibling)
├── state                          (sibling)
├── command_executor               (sibling)
├── finding_pipeline               (sibling)
├── phase_data_store               (sibling)
├── phase_commands                 (sibling)
├── finding_parsers                (sibling)
└── phase_handlers                 (sibling)

llm_bridge.py [agents] (4,100 LoC) ─── 15 IMPORTS ─── MOST CONNECTED AGENT FILE
├── db_registry                    ├── llm_clients
├── exceptions                     ├── llm_routing
├── llm_types                      ├── llm_hardware_adapter
├── llm_cache                      ├── llm_tracking
├── feedback_learning              ├── streaming_structured
├── llm_adaptive                   ├── llm_production
├── llm_ops                        ├── ab_testing
└── llm_tracing

caap_formatter.py (960 LoC) ─── 7 IMPORTS
├── logging_config                 ├── caap_session
├── caap_models                    ├── caap_hypothesis
├── caap_chains                    ├── caap_parser
└── vuln_knowledge

ml_feedback_propagator.py (536 LoC) ─── 7 IMPORTS (cross-package)
├── agents.bayesian_prioritizer
├── agents.feedback_learning
├── exploit_chains.exploit_verifier
├── exploit_chains.weight_tuner
├── hypothesis_engine
├── recon_dashboard.confidence_calibration
└── recon_dashboard.findings_store

learning_loop_engine.py (1,704 LoC) ─── 7 IMPORTS (cross-package)
├── atlas.models
├── agents.llm_bridge
├── confidence_ensemble
├── decision_orchestrator
├── exploit_chains.learning_bridge
├── json_file_lock
└── transfer_intelligence

server.py [dashboard] (9,089 LoC) ─── 6 IMPORTS
├── _assets                        ├── llm_helpers
├── event_bridge                   ├── session_store
├── infra_monitor                  └── state

copilot_loop.py [agents] (2,349 LoC) ─── 6 IMPORTS
├── autonomy                       ├── reasoning_engine
├── platforms                      ├── strategy_engine
├── reasoning_display              └── telemetry

exploitation/engine.py (609 LoC) ─── 8 IMPORTS
├── logging_config                 ├── cvss
├── telemetry                      ├── impact
├── chains                         ├── models
├── poc_generator                  └── verifier
```

### Tier 2: Medium Connectivity (3-6 imports)

```
verification_chain.py (954) ── 3 imports: doubt_injector, unified_arbitration, tool_registry.registry
adaptive_chain_engine.py (1,441) ── 3 imports: config.scan_config, decision_trace, dynamic_chain
few_shot_selector.py (694) ── 3 imports: agent_memory, context_budget, transfer_intelligence
confidence_ensemble.py (1,463) ── 1 import: confidence_diversity
prompt_registry.py (944) ── 1 import: agents.llm_types
oob_verifier.py (416) ── 1 import: oob_interaction
tool_intelligence.py (1,012) ── 1 import: learning_loop_engine
swarm.py (607) ── 4 imports: agent_roles, gpu_governor, message_bus, shared_weights
governor.py [multi_gpu] (499) ── 4 imports: topology, model_sharder, scheduler, messenger
store.py [strategy] (1,636) ── 3 imports: db_registry, core, models
_hooks.py [dashboard] (1,482) ── 4 imports: _assets, _notify, server, state
state.py [dashboard] (2,460) ── 3 imports: _tech_utils, target_profile, phase_defs
mcp_server.py (837) ── 4 imports: logging_config, mcp_tools, mcp_builtins, cognitive_tools
caap exploitation_engine.py (634) ── 6 imports: exploitation_models, exploitation_data, poc_gen, etc.
action_translator.py (394) ── 3 imports: registry, fallback, output_parsers
```

### Tier 3: Leaf Nodes (0-1 imports)

**Self-contained files (0 internal imports)**: 267 files
These are the foundation layer — they can be tested, moved, or replaced independently.

Notable fully self-contained large files:
- `self_optimizing_stack.py` (2,300 lines)
- `world_model.py` (1,644 lines)
- `multi_agent_debate.py` (1,439 lines)
- `knowledge_resilience.py` (1,229 lines)
- `hypothesis_engine.py` (1,202 lines)
- `persona_engine.py` (1,155 lines)
- All 14 inference engine files
- All 12 ATLAS files
- All 20 loop/ modules (except autonomous_loop.py)
- All 12 PSE files
- All 5 safety/defense files

---

## 38. Cross-Reference Dependency Matrix

```
                        ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
                        │LLM  │Agent│Reas.│Decis│ExpGr│PSE  │Learn│LG   │Loop │CAAP │RDash│MCP  │Swarm│
                        │Bridg│Core │Eng  │Orch │aph  │     │/RL  │raph │     │     │     │Py   │     │
  ┌─────────────────────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┤
  │LLM Bridge (4,100)   │  ●  │  ←  │  ←  │  ←  │     │  ←  │  ←  │     │     │  ←  │  ←  │  ←  │     │
  │Agent Core (22K)      │  →  │  ●  │  →  │  →  │  →  │     │  →  │     │     │     │     │     │  →  │
  │Reasoning Eng (2,942) │  →  │  ←  │  ●  │  ←  │     │     │     │     │     │     │     │     │     │
  │Decision Orch (3,264) │  →  │  ←  │  →  │  ●  │     │     │     │     │     │     │  →  │     │     │
  │Exploit Graph (9K)    │     │  ←  │     │     │  ●  │  →  │  →  │     │     │     │     │     │     │
  │PSE (9K)              │  →  │     │     │     │  ←  │  ●  │  →  │     │     │     │     │     │     │
  │Learning/RL (9K)      │  →  │  ←  │     │  →  │  ←  │  ←  │  ●  │     │     │     │  →  │     │     │
  │LangGraph (8.8K)      │     │     │     │     │     │     │     │  ●  │     │     │     │     │     │
  │Autonomous Loop (8.5K)│     │     │     │     │     │     │     │     │  ●  │     │     │     │     │
  │CAAP (7.3K)           │  →  │     │     │     │     │     │     │     │     │  ●  │     │     │     │
  │Recon Dashboard (73K) │  →  │  →  │  →  │  →  │  →  │     │  →  │     │     │  →  │  ●  │     │     │
  │MCP Python (4.3K)     │  →  │     │     │     │     │     │     │     │     │     │     │  ●  │     │
  │Swarm (5.8K)          │     │  ←  │     │     │     │     │     │     │     │     │     │     │  ●  │
  │Confidence (4.8K)     │     │  ←  │  ←  │  ←  │     │  ←  │  ←  │     │     │     │     │     │     │
  │Truth Enforce (10.7K) │     │     │     │  ←  │     │     │     │     │     │     │  ←  │     │     │
  │ATLAS (6.3K)          │  →  │     │  →  │     │     │     │     │     │     │     │     │  →  │     │
  │Strategy (9K)         │  →  │     │  →  │  →  │     │     │     │     │     │     │     │     │     │
  │Feedback (3.4K)       │     │  →  │     │  →  │  →  │  →  │  →  │     │     │     │  →  │     │     │
  │Safety (4.4K)         │     │     │     │     │     │     │     │     │     │     │     │     │     │
  │Vector Memory (5.5K)  │     │  ←  │     │     │     │     │     │     │     │     │     │     │     │
  │Exploit Pkg (6.3K)    │  →  │     │     │     │     │     │     │     │     │     │     │     │     │
  │Tool Registry (2.9K)  │     │     │     │     │     │     │     │     │     │     │     │     │     │
  └─────────────────────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
  
  Legend: → calls/depends on | ← is called by | ● self | LoC in parentheses
```

### Key Architectural Insights

1. **Most connected file**: `decision_orchestrator.py` (3,264 LoC, 13 imports) — the central nervous system
2. **Most connected dashboard file**: `runner.py` (7,871 LoC, 11 imports)
3. **Most connected agent file**: `llm_bridge.py` (4,100 LoC, 15 imports)
4. **Largest single file**: `server.py` (9,089 LoC) — the dashboard HTTP server
5. **Largest subsystem**: Recon Dashboard (77 files, ~73,000 LoC)
6. **Most self-contained subsystem**: Autonomous Loop (20/21 files have zero imports)
7. **Most self-contained package**: ATLAS (12/12 files have zero internal imports)
8. **Total shim/re-export files**: ~50+ (13 lines each) — re-export pattern for backward compatibility

---

## 39. Summary Statistics

| Category | Files | Lines of Code | Self-Contained | Key Technology |
|----------|------:|-------------:|:--------------:|----------------|
| LLM Core | 4 | 8,360 | 1/4 | OpenAI, Anthropic, Ollama, GitHub Models |
| LLM Infrastructure | 10 | 7,017 | 6/10 | Circuit breakers, caching, tracing |
| Agent System | 14 | 22,141 | 5/14 | Episodic memory, TF-IDF, multi-agent |
| Reasoning & Hypothesis | 6 | 7,765 | 5/6 | Bayesian inference, probability tables |
| Exploit Graph | 14 | 9,316 | 13/14 | A* pathfinding, 5-dimension state |
| Payload Synthesis | 12 | 8,915 | 12/12 | Grammar, LLM, GA, 8-signal arbiter |
| LangGraph | 19 | 8,846 | 7/19 | State machine, supervisor, reasoning graph |
| Autonomous Loop | 21 | 8,586 | 20/21 | OBSERVE→THINK→ACT→EVALUATE→LEARN |
| Decision & Strategy | 11 | 16,500 | 7/11 | Decision orchestrator, 2-step lookahead |
| Confidence & Calibration | 5 | 4,755 | 3/5 | Dempster-Shafer, Platt, isotonic |
| Vector Memory | 6 | 5,517 | 5/6 | sentence-transformers, HNSW |
| Prompt Management | 8 | 5,565 | 5/8 | Versioning, A/B testing, security |
| Inference Engine | 14 | 6,574 | 14/14 | Ollama, Llama.cpp, GGUF |
| ATLAS Intelligence | 12 | 6,314 | 12/12 | Pattern memory, archetypes |
| CAAP System | 27 | ~7,300 | 13 shims | Chain automation, browser exploitation |
| Recon Dashboard | 77 | ~73,000 | ~55/77 | Execution intelligence, 14 route modules |
| MCP Python Server | 21 | ~4,300 | 15 shims | FastMCP, 45+ tools |
| Copilot SDK | 10 | 7,066 | 5/10 | 67+ tools, native function calling |
| Swarm | 10 | 5,818 | 5/10 | Multi-GPU, model sharding, topology |
| Exploitation | 7 | 6,328 | 0/7 | PoC generation, CVSS, verification |
| Tool Registry | 4 | 2,857 | 2/4 | Central registry, output parsing |
| Safety & Defense | 5 | 4,367 | 5/5 | Prompt injection, output guardrails |
| Knowledge Systems | 11 | ~7,500 | 9/11 | CVE, threat modeling, entropy |
| World Model | 4 | 5,759 | 4/4 | Counterfactual, drift detection |
| Truth & Verification | 11 | ~10,700 | 8/11 | Proof gates, FP detection |
| Impact & Scoring | 7 | ~6,900 | 7/7 | CVSS, bounty ROI, benchmark |
| Feedback & Propagation | 6 | 3,400 | 4/6 | 13-signal calibration |
| MCP Extension (TS) | 16 | ~3,200 | n/a | VS Code, LLM tool-calling |
| **TOTAL** | **~442** | **~185,000+** | **~267** | |
