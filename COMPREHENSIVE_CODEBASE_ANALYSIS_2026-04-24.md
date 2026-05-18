# Venator Security v2.27.0 — Comprehensive Codebase Analysis

**Date:** 2026-04-24  
**Analyst:** Cline (AI Systems Architect)  
**Scope:** Full-stack analysis across 10 dimensions  
**Codebase:** `CaseCrack/tools/burp_enterprise/` (1,833 Python files)  

---

## Executive Scorecard

| Dimension | Grade | Status | Blockers |
|-----------|-------|--------|----------|
| A. Recovery Health | B+ | 91.5% recovered | 17 modules missing, 38 need manual merge |
| B. Module Reachability | B | 721→770 target | 50 reconnect tasks pending |
| C. ML/LLM Wiring | C+ | 4 critical disconnections | D1–D4 unbridged; 12 bugs active |
| D. Code Quality | B | 80% coverage gate, mypy strict | Global mypy defaults lax; ruff ignores security |
| E. Test Suite | C+ | 36,117 tests collected | Many failures; timeout crashes; swarm tests failing |
| F. Security Posture | A- | Multi-layer defense-in-depth | 60+ silent excepts; EventBus contract informal |
| G. Dashboard & Frontend | B | 22-phase real-time system | Workspace redesign pending (Venator spec) |
| H. Dependencies | A- | CVE-pinned, SBOM-ready | 35 Docker images must be pre-built |
| I. Data Flow | B+ | EventBus + correlation engine | RAG only wired to chat; PSE disconnected |
| J. Operational Risks | B | Docker-first, MCP exposed | LLM costs; Windows path issues; gRPC reflection req |

**Overall Grade: B** — Production-viable with significant technical debt in ML integration and test stability.

---

## DIMENSION A: Recovery Health

### Recovery Metrics

| Metric | Before | After | Status |
|--------|--------|-------|--------|
| Permanently lost modules | 201 | **17 genuinely absent** | ✅ 91.5% substantively recovered |
| Pure regressions restored | 0 | **8** | ✅ Auto-restored with `.preregression.bak` |
| REFACTORED files (manual merge) | 0 | **38** | ⚠️ Pending manual review |
| MINOR diffs (left alone) | 0 | **3** | ✅ Intentional |
| BOM-corrupted files | 3 | **0** | ✅ All stripped |
| Dangling absolute imports | 382 | **0** | ✅ 100% resolved |
| Relay shims created | 0 | **75** | ✅ Active forwarders |
| New subsystem modules (≥500 LOC) | 0 | **27** | ✅ Production-ready |

### 17 Genuinely Missing Modules (Highest Impact)

| Module | Expected LOC | Score | Subsystem |
|--------|-------------|-------|-----------|
| `validation_fleet` | 2,578 | 45 | agents (root-level) |
| `exploit_chains/manual_audit_engine` | 1,640 | 72 | exploit_chains |
| `adversarial_validation_agent` | 1,137 | 45 | agents (root-level) |
| `recon_dashboard/routes_persistent_agent` | 1,147 | 65 | recon_dashboard |
| `recon_dashboard/cross_target_intelligence` | 627 | 85 | recon_dashboard |
| `recon_dashboard/target_scoring` | 691 | 65 | recon_dashboard |
| `recon_dashboard/routes_multi_agent` | 493 | 55 | recon_dashboard |
| `recon_dashboard/routes_cross_target` | 335 | 50 | recon_dashboard |
| `recon_dashboard/routes_target_scoring` | 249 | 50 | recon_dashboard |
| `recon_dashboard/routes_operator` | 238 | 40 | recon_dashboard |
| `swarm/multi_gpu/messenger` | 534 | 62 | swarm |
| `swarm/multi_gpu/model_sharder` | 499 | 62 | swarm |
| `swarm/multi_gpu/scheduler` | 584 | 62 | swarm |
| `swarm/multi_gpu/topology` | 710 | 62 | swarm |
| `swarm/multi_gpu/governor` | 466 | 57 | swarm |
| `graph/production` | 573 | 60 | graph |
| `strategy_horizon_optimizer` | 618 | 45 | strategy |

**Total LOC gap:** ~13,787 lines across Phase 1 reconnect tasks.

### 38 REFACTORED Files Needing Manual Merge

These files were reimplemented during recovery sprints and now have **unique disk symbols** that would be lost if overwritten by history. They require careful manual merging.

| File | Disk Size | History Size | Unique Disk Symbols | Risk |
|------|-----------|--------------|---------------------|------|
| `agents/llm_bridge.py` | 73 KB | 258 KB | AnthropicClient, Analysis | **HIGH** — 48 history-only symbols missing |
| `exploit_chains/payload_arbiter.py` | 21 KB | 82 KB | _DESTRUCTIVE_PATTERNS, _LOCAL_HOSTS | **HIGH** — 57 history-only symbols |
| `exploit_chains/weight_tuner.py` | 15 KB | 79 KB | _extract_observation, _POSITIVE_SIGNALS | **HIGH** — 27 history-only symbols |
| `agents/advanced_agent_patterns.py` | 54 KB | 68 KB | AgentConfigValidator, AgentMemoryCompactor | **MEDIUM** — 28 history-only symbols |
| `hypothesis_engine.py` | 37 KB | 70 KB | _amplification_for, _prune_expired_boosts | **MEDIUM** — 18 history-only symbols |
| `learning_loop_engine.py` | 69 KB | 100 KB | StrategyEvolver.evolve_exploitation_paths | **MEDIUM** — 17 history-only symbols |
| `exploit_chains/genetic_forge.py` | 26 KB | 37 KB | ForgeChromosome, ForgeFitnessEvaluator | **MEDIUM** — 27 history-only symbols |
| `exploit_chains/synthesis_feedback.py` | 15 KB | 28 KB | _propagate_to_campaign, _propagate_to_forge | **MEDIUM** — 17 history-only symbols |
| `exploit_chains/synthesis_context.py` | 23 KB | 42 KB | ProbeResult, RankedPayload | **MEDIUM** — 15 history-only symbols |
| `exploit_chains/grammar_synthesizer.py` | 30 KB | 53 KB | SQLiGrammar, XSSGrammar | **MEDIUM** — 35 history-only symbols |

*(Full list in `_final_audit_coverage_tight.tsv`)*

### Recovery Protocol Used

1. **BOM stripping** — 3 files cleaned
2. **Relay shim creation** — 75 cross-path forwarders (8 LOC each)
3. **Pure regression restoration** — 8 files auto-restored from valid history snapshots
4. **AST-validity filtering** — Rejects concatenated snapshots (>1 `from __future__`)
5. **Backup preservation** — All overwrites saved as `<path>.preregression.bak`

---

## DIMENSION B: Module Reachability

### Entrypoint Inventory

| Entrypoint | Status | Reachable Modules |
|------------|--------|-------------------|
| `cli.main:main` | ✅ Active | 19 canonical entrypoints |
| `recon_dashboard.py` | ✅ Active | HTTP :8770, WS :8771 |
| `mcp_server.py` | ✅ Active | 40+ MCP tools |
| `chain.py` | ✅ Active | 80+ YAML workflows |

### Reachability Metrics

| Metric | Value | Target |
|--------|-------|--------|
| Total Python modules | 1,833 | — |
| Active modules (post-recovery) | 1,174 | — |
| Currently reachable | 721 | **≥ 770** |
| Reconnect tasks (Phase 1) | 50 | 0 |
| Conditionally-reachable (CR) | 130 | Documented |
| Runtime-reachable (RR) | 141 | Verified |
| Reimplementation tasks (Phase 3) | 201 | 0 |

### Phase 1 Reconnect Status (Top 10 by Score)

| Score | Module | Actual LOC | Expected | % | Status |
|-------|--------|-----------|----------|---|--------|
| 85 | `agents/advanced_agent_patterns` | 1,292 | 1,321 | 97% | ✅ |
| 85 | `recon_dashboard/cross_target_intelligence` | 0 | 627 | 0% | ❌ Missing |
| 75 | `recon_dashboard/phase_handlers/intelligence` | 522 | 522 | 100% | ✅ |
| 72 | `exploit_chains/manual_audit_engine` | 0 | 1,640 | 0% | ❌ Missing |
| 70 | `agents/advanced_orchestration` | 1,355 | 1,127 | 120% | ✅ |
| 70 | `agents/deterministic_replay` | 792 | 606 | 130% | ✅ |
| 65 | `database/data_migration` | 260 | 559 | 46% | ⚠️ Below threshold |
| 65 | `graph/multi_agent/tests/test_multi_agent` | 431 | 431 | 100% | ✅ |
| 65 | `recon_dashboard/routes_intelligence_experience` | 320 | 335 | 95% | ✅ |
| 65 | `recon_dashboard/routes_persistent_agent` | 0 | 1,147 | 0% | ❌ Missing |

**Phase 1 Summary:** 30 ✅ at target · 3 ⚠️ below threshold · **17 ❌ missing**

### Dangling Imports

- **Before recovery:** 382 dangling absolute imports
- **After recovery:** **0 remaining** ✅
- All resolved via relay shims, reimplementation, or removal of orphaned references

---

## DIMENSION C: ML/LLM Wiring Integrity

### The 4 Critical Disconnections

#### D-1: Dual Learning Systems Have No Bridge ⚠️ HIGH

| System | Learns | Persists | Scope |
|--------|--------|----------|-------|
| **Macro RL** (LearningLoopEngine) | Tool selection, vuln exploration | Yes (disk, JSON/SQLite) | Cross-session |
| **Micro PSE** (WeightTuner) | Payload scoring via 13 signals | **NO** | Per-session only |

**Problem:** Macro insights ("SQLi on WordPress is high-value") never flow to PSE weights. PSE signal importance ("bypass_score matters against Cloudflare") never informs macro tool selection.

**Consequence:** Both systems re-learn the same lessons independently. PSE restarts from static priors every session.

**Fix needed:** Bidirectional bridge: `LearningLoopEngine` → `WeightTuner.set_prior_weights()` and `WeightTuner` → `LearningLoopEngine.signal_importance_update()`.

#### D-2: Autonomous Loop Bypasses PSE ⚠️ HIGH

**Problem:** `AutonomousLoop` (OODA cycle) dispatches attacks via `AIDirectedExecutor` (tool commands: "run nuclei", "run sqlmap"). It **never instantiates** `PayloadSynthesisEngine`.

**Consequence:** Autonomous mode uses less sophisticated attack selection — no learned scoring, no genetic evolution, no WAF adaptation.

**Fix needed:** Inject PSE into OODA ACT phase: `autonomous_loop.py` → `payload_synthesis_engine.generate()` for tool parameter optimization.

#### D-3: ExploitGraph Findings Don't Feed Weight Learning ⚠️ MEDIUM

**Problem:** `ExploitGraph.process_finding_multihop()` updates graph topology but never triggers `WeightTuner.observe()`.

**Consequence:** Multi-hop chain findings don't contribute to learning which signals predict successful exploits.

**Fix needed:** Hook `exploit_graph.py:process_finding_multihop()` → `weight_tuner.observe(chain_signals, outcome)`.

#### D-4: LLM Prompts Never Read Learned Weights ⚠️ MEDIUM

**Problem:** `LLMBridge` constructs prompts without knowledge of PSE's learned signal weights.

**Consequence:** LLM outputs (hypotheses, payloads, analysis) don't benefit from ML-learned signal importance.

**Fix needed:** Add `weight_tuner.get_top_signals(n=3)` to `context_builder.py` → inject into system prompts.

### Bug Inventory (12 Items)

| ID | Severity | Bug | File | Status |
|----|----------|-----|------|--------|
| B-1 | **Critical** | WeightTuner has **zero persistence** — all 13-signal ridge regression lost every session | `weight_tuner.py` | **OPEN** |
| B-2 | **Critical** | 60+ silent `except Exception: pass/continue` in decision-critical paths | `decision_orchestrator.py`, `manual_audit_engine.py`, etc. | **OPEN** |
| B-3 | High | ContextBudgetAllocator not wired into main chat paths | `reasoning/context_budget.py` vs `agents/llm_bridge.py` | **OPEN** |
| B-4 | High | Thinking budget injection can exceed context window | `agents/llm_bridge.py:277-286` | **OPEN** |
| B-5 | High | RAG only wired to dashboard chat — autonomous loop/PSE don't use it | `agents/rag_context.py` | **OPEN** |
| B-6 | Medium | No model fallback on API rejection | `agents/llm_routing.py:118-130` | **OPEN** |
| B-7 | Medium | Underdetermined regression at `MIN_OBSERVATIONS=3` | `weight_tuner.py:127` | **OPEN** |
| B-8 | Medium | VRAM tracking stubbed to 0 | `inference/model_manager.py:624` | **OPEN** |
| B-9 | Medium | Cloud chat and local chat use different budgeting math | `agents/llm_bridge.py` | **OPEN** |
| B-10 | Low | Redundant fallback paths in LLMBridge | `agents/llm_bridge.py` | **OPEN** |
| B-11 | Low | Inconsistent error handling in provider clients | `agents/llm_clients.py` | **OPEN** |
| B-12 | Low | Cache key collisions possible | `agents/llm_cache.py` | **OPEN** |

### Dead / Dormant Code

| Subsystem | Files | Status | Evidence |
|-----------|-------|--------|----------|
| **swarm/** | 10+ | **DEAD** | 0 external callers; Multi-GPU scheduler never instantiated |
| **multi_agent_debate.py** | 1 | Dormant | Imported but rarely invoked |
| **loop/vector_reasoning.py** | 1 | Dormant | No production usage |
| **inference/grammar.py** | 1 | Partial | GBNF generation exists but not wired to LLM calls |

### Historical Audit Evolution

- **V2–V10:** 316 findings total → 288 fixed, 28 pending
- **V11:** 14 new bugs confirmed → 11 still present, 3 fixed during audit

---

## DIMENSION D: Code Quality & Type Safety

### mypy Configuration

| Tier | Modules | Settings | Status |
|------|---------|----------|--------|
| **Strict** | 100 (claimed 108) | `check_untyped_defs=true`, `warn_unreachable=true`, `warn_return_any=true` | ✅ Enforced |
| **Relaxed** | 3 | `warn_return_any=false` | `intercept`, `zap_provider`, `mitmproxy_provider` |
| **Deferred** | 0 | — | — |
| **Excluded** | 4 dirs | — | `tests/`, `grpc/`, `scripts/`, `mcp-extension/` |

**Global defaults are surprisingly lax:** `warn_return_any=false`, `check_untyped_defs=false`, `disallow_untyped_defs=false`. Strictness comes entirely from the override block.

### Ruff / Linting

| Setting | Value |
|---------|-------|
| Target Python | 3.10 |
| Line length | 120 |
| Rules | E, F, W, I, B, SIM, RET, UP, C4, RUF, PT, S (security) |
| Security ignores | S101 (assert), S105/106 (passwords), S113 (timeout), S310 (url open), S320 (lxml), S603/607 (subprocess), S608 (SQL) |

**Security lint concern:** S101 (assert) ignored globally. Assertions are used for control flow in production code — risky if run with `-O`.

### Coverage

| Gate | Value | Status |
|------|-------|--------|
| Fail-under | 80% | ✅ Enforced |
| Branch coverage | true | ✅ Enabled |
| Parallel | true | ✅ Enabled |
| Omissions | tests/, chain_templates/, __pycache__/ | — |

### Bandit (Security Linter)

| Skip | Rationale |
|------|-----------|
| B104 | Bind 0.0.0.0 for Docker (MCP/health/gRPC) |
| B108 | `/tmp` usage in path-traversal wordlists |
| B303 | MD5/SHA1 for fingerprinting only |
| B314 | xml.etree for SAML/XXE testing |
| B324 | hashlib for cache keys, dedup |
| B501 | `verify=False` for Burp/mitmproxy tunneling |
| B608 | Hardcoded SQL in internal SQLite (parameterized) |

**Risk:** B501 (no cert validation) and B608 (SQL) are suppressed for testing modules but could mask real issues.

---

## DIMENSION E: Test Suite Health

### Test Metrics

| Metric | Value |
|--------|-------|
| Total tests collected | **36,117** |
| Deselected | 1,725 |
| Skipped | 1 |
| Selected | 34,392 |
| Timeout | 10.0s (thread-based) |

### Failure Patterns (from `test_results.txt`)

| Test File | Failures | Pattern |
|-----------|----------|---------|
| `test_agent_swarm.py` | Many | Swarm subsystem dead — expected |
| `test_agent_sessions.py` | Multiple | Session state issues |
| `test_ai_ml_scanner.py` | Multiple | ML scanner integration |
| `test_autonomous_loop.py` | Multiple | PSE disconnect — expected |
| `test_api_contracts.py` | 1 | API contract violation |
| `test_attack_reasoning.py` | 3 | Reasoning engine |
| `test_caching.py` / `test_caching_comprehensive.py` | Multiple | Cache SWR issues |
| `test_cli_api_extended.py` | **Timeout** | `test_scan_no_findings` hangs on HTTP request |

### Critical Test Failure: Timeout Cascade

```
tests\test_cli_api_extended.py::test_scan_no_findings
  → urllib3 retries with exponential backoff
  → time.sleep(backoff) exceeds 10s timeout
  → pytest-timeout kills thread
```

**Root cause:** `api_security.py:842` makes real HTTP requests in unit tests without mock.

### Mutation Testing (mutmut)

| Target | Modules |
|--------|---------|
| Paths | 9 core files (policy, SARIF, output contract, exploit graph, etc.) |
| Runner | pytest with 10s timeout |
| Coverage | true |

### CI/CD Test Matrix

| Schedule | Command | Scope |
|----------|---------|-------|
| PR smoke | `pytest tests/ -m smoke` | Fast, no Docker |
| Integration | `pytest tests/ -m integration` | Docker required |
| Nightly (Mon–Sat) | Level `standard` scan | External target optional |
| Weekly (Sunday) | Level `aggressive` scan | Full tool suite |

---

## DIMENSION F: Security Posture

### Defense-in-Depth Architecture

```
Request path:
  Tool Wrapper
    └── _policy.py       ← scope check
         └── safety_guardrails.py  ← rate limit + OOB gate
              └── network_safety.py  ← RFC1918 / CIDR blocklist
                   └── audit_trail.py  ← immutable action log
                        └── Docker container  ← isolated execution
```

### Gate Details

#### Gate 1: Network Safety (`network_safety.py`)
- **SSRF Protection:** IP blocklist for RFC 1918, link-local, loopback, cloud metadata
- **DNS Rebinding:** `resolve_and_validate()` — pin resolved IP, prevent TOCTOU
- **ConnectionGuard:** Global semaphore (default 50 concurrent connections)
- **AdaptiveConcurrency:** Auto-tune threads based on 15% error threshold

#### Gate 2: Scope Enforcement (`scope.py` + `safety_guardrails.py`)
- **ScopeManager:** Include/exclude with wildcard subdomain support
- **External scan gate:** `ALLOW_EXTERNAL_SCAN=1` required for non-private hosts

#### Gate 3: Rate Limiting (`rate_limit.py`)
- Token-bucket per-host across all concurrent tools
- **Limitation:** Per-process only — distributed runs can exceed target limits

#### Gate 4: Canary Detection (`canary_detector.py`)
- Honeypot signal detection
- Halts before triggering alerts

#### Gate 5: Audit Trail (`audit_trail.py`)
- Immutable append-only log
- Every action: tool invocation, finding, LLM query

#### Gate 6: Docker Isolation
- All 35 external tools run in separate containers
- No host filesystem access beyond explicit volume mounts

### Safety Gaps

| Gap | Risk | Mitigation |
|-----|------|------------|
| 60+ silent `except Exception: pass` | Subsystem failures invisible | Add logging to all bare excepts |
| Token-bucket per-process only | Distributed scans exceed rate limits | Add distributed rate coordination |
| S101 (assert) ignored in lint | Assertions used for control flow | Replace with proper exceptions |
| EventBus contract informal | Ad-hoc topic naming | Document `EVENTBUS_CONTRACT.md` |

---

## DIMENSION G: Dashboard & Frontend

### Architecture

| Component | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| HTTP Dashboard | **8770** | HTTP (aiohttp) | HTML, REST API, event ingestion |
| WebSocket | **8771** | WS (websockets) | Live push updates |
| Health/Internal | 8080 | HTTP | Container healthcheck |

### Core Files

- **`recon_dashboard.py`** — 1,983 lines. Contains `ReconDashboard` server, `DashboardState`, `StandaloneReconRunner`
- **`recon_dashboard/`** package — Modularized successor with routes, state serializers, confidence calibration, finding validators
- **`dashboard_renderer.py`** — 18-line backward-compat shim

### 22-Phase Recon Engine

| # | Phase | Category | Primary Tools |
|---|-------|----------|---------------|
| 1 | Fingerprinting & Technology | Discovery | httpx, wafw00f, wappalyzer |
| 2 | Endpoint & Asset Discovery | Discovery | katana, ffuf, kiterunner |
| 3 | JS Analysis & Source Maps | Discovery | jsluice, sourcemapper |
| 4 | URL Aggregation & Dorking | Discovery | wayback, gau, google-dorking |
| 5 | Parameter Discovery | Discovery | arjun, x8 |
| 6 | Visual Recon & Screenshots | Discovery | headless browser |
| 7 | Subdomain Discovery | Infrastructure | subfinder, amass, gotator |
| 8 | DNS Resolution & Brute-force | Infrastructure | dnsx, puredns |
| 9 | Virtual Host Discovery | Infrastructure | vhostfinder, ffuf |
| 10 | Network & Port Scanning | Infrastructure | nmap, naabu |
| 11 | TLS & Certificate Analysis | Infrastructure | testssl, tlsx |
| 12 | DNS Security Testing | Security Testing | dnsx, nsec_walker |
| 13 | Cloud Storage Enumeration | Security Testing | cloud_enum |
| 14 | WAF Detection & Fingerprinting | Security Testing | wafw00f |
| 15 | Secrets Scanning | Security Testing | trufflehog, gitleaks, semgrep |
| 16 | CVE Correlation | Security Testing | nuclei, trivy |
| 17 | Active Vulnerability Testing | Security Testing | nomore403, sqlmap, dalfox |
| 18 | OSINT Intelligence | Intelligence | crtsh, rdap, bgpview |
| 19 | Passive Internet Search | Intelligence | shodan, censys, fofa |
| 20 | Source Code & Reverse Analytics | Intelligence | github_deep_recon, semgrep |
| 21 | Unified Crawl + Secrets Pipeline | Synthesis | katana + trufflehog |
| 22 | Attack Surface & Analysis | Synthesis | correlation_engine |

### Workspace Redesign Spec (Venator)

- **19 panels** defined with role taxonomy (primary/secondary/utility)
- **Panel chrome wraps existing containers** — DOM ids preserved
- **No framework** (React/Vue/Angular) — vanilla JS only
- **Agent Chat permanently docked**
- **Focus mode bias system** — expands focused panel, dims others
- **Persistence:** 4 dimensions (Session → Target Override → Named Preset → User Default → Hardcoded)

---

## DIMENSION H: Dependency & Supply Chain

### Core Dependencies (Always Required)

| Package | Version | CVE Justification |
|---------|---------|-------------------|
| requests | ≥2.32.3 | CVE-2024-35195 |
| urllib3 | ≥2.6.3 | CVE-2024-37891, CVE-2025-66418/66471, CVE-2026-21441 |
| pyyaml | ≥6.0.2 | CVE-2024-6156 |

### Optional Extras

| Extra | Packages | Use Case |
|-------|----------|----------|
| `grpc` | grpcio, grpcio-tools, protobuf | gRPC scanning |
| `llm` | httpx, tiktoken, torch | LLM bridge |
| `mcp` | mcp≥1.0.0 | MCP server |
| `recon` | dnspython, Pillow, imagehash, opencv | DNS, image analysis |
| `full` | websockets, aiohttp, mitmproxy, numpy, cryptography | Full feature set |
| `dev` | pytest, ruff, bandit, mypy, mutmut | CI tooling |

### Docker Tool Wrappers (35)

All external tools run in isolated Docker containers. Key providers:

| Provider | Image | Category |
|----------|-------|----------|
| nuclei | venator/nuclei | Template scanning |
| sqlmap | venator/sqlmap | SQL injection |
| dalfox | venator/dalfox | XSS |
| nmap | venator/nmap | Network scanning |
| trufflehog | venator/trufflehog | Secrets in Git |
| amass | venator/amass | Subdomain |
| httpx | venator/httpx | HTTP probing |

**Operational risk:** Docker images must be pre-built or pulled. No auto-pull on first run.

---

## DIMENSION I: Data Flow & Integration

### EventBus Architecture

- **Contract:** `.on(topic, handler)`, `.emit(topic, payload)`, `.off(topic, handler)`
- **Status:** Only sanctioned cross-module wire
- **Gap:** No formal `EVENTBUS_CONTRACT.md` documenting all topics and subscribers

### Finding Lifecycle

```
Tool Wrapper (35 providers)
    ├── _output_contract.py — normalized finding schema
    ├── _policy.py — scope enforcement
    └── _sarif_normalizer.py — SARIF conversion
         │
         ▼
    correlation_engine.py — dedup, cross-phase correlation
         │
         ▼
    db_manager.py — SQLite persistence
         │
         ▼
    reporter.py — Markdown, JSON, HTML, SARIF, CAAP
```

### RAG Context System

- **Implementation:** `agents/rag_context.py` — TF-IDF + semantic retrieval, RRF fusion, MMR diversity
- **Wiring:** Only connected to dashboard chat (`server.py:6234`, `llm_bridge.py:3069`)
- **Gap:** Autonomous loop, PSE, runner do not use RAG retrieval

### Cross-Module Integration Gaps

| Gap | From | To | Impact |
|-----|------|-----|--------|
| No PSE bridge | LearningLoopEngine | WeightTuner | Dual learning systems |
| No PSE in OODA | AutonomousLoop | PayloadSynthesisEngine | Weak autonomous attacks |
| No graph→tuner | ExploitGraph | WeightTuner | Chain findings unused |
| No weight→prompt | WeightTuner | LLMBridge | LLM ignores ML insights |
| RAG chat-only | rag_context.py | Dashboard | Autonomous loop blind |

---

## DIMENSION J: Operational Risks

### Deployment Model

- **Docker-first:** No local binary dependencies
- **Docker Compose:** `docker-compose.yml`, `docker-compose.integration.yml`, `docker-compose.appliance.yml`
- **Appliance mode:** PostgreSQL + Redis backend

### MCP Server Exposure

- **File:** `mcp_server.py` (46 KB restored)
- **Protocol:** Model Context Protocol — exposes all tools as AI tool-use endpoints
- **Risk:** If exposed to network without authentication, provides full offensive capability
- **Mitigation:** Bind to localhost by default; scope enforcement applies

### gRPC Scanning Stack

- **Proto:** `proto/grpc_testserver.proto`
- **Generated stubs:** `grpc/` directory
- **Requirement:** Target must have reflection enabled or manual proto import
- **Status:** Functional but limited adoption

### External API Dependencies

| API | Required For | Graceful Degradation |
|-----|--------------|----------------------|
| OpenAI | LLM agent | ✅ Optional — local Ollama fallback |
| Anthropic | LLM agent | ✅ Optional |
| Shodan | Phase 19 (passive search) | ⚠️ Sparse results without key |
| Censys | Phase 19 | ⚠️ Sparse results |
| GitHub | Phase 20 (source code recon) | ⚠️ Limited without token |

### Known Limitations

| Area | Status |
|------|--------|
| Docker images | Must be pre-built/pulled; no auto-pull |
| LLM cost | Agent mode expensive without local model |
| Windows paths | Dashboard launch requires exact `python.exe` path |
| Burp Suite integration | Requires running Burp Enterprise instance |
| gRPC scanning | Requires reflection or manual proto |
| Rate limiting | Per-process only — distributed runs risky |

---

## Critical Path to Production (v2.28.0)

### Blockers (Must Fix)

1. **[B-1] WeightTuner persistence** — Add SQLite/JSON persistence for 13-signal weights
2. **[B-2] Silent exceptions** — Replace all bare `except: pass` with proper logging
3. **[D-1] Learning bridge** — Connect Macro RL ↔ Micro PSE
4. **[D-2] PSE in autonomous loop** — Inject payload synthesis into OODA ACT phase
5. **17 missing modules** — Reimplement or stub the Phase 1 gap modules

### High Priority

6. **[B-5] RAG expansion** — Wire RAG to autonomous loop and PSE
7. **[D-3] Graph→tuner** — Feed exploit graph findings to weight learning
8. **[D-4] Weight→prompt** — Inject top signals into LLM context
9. **38 REFACTORED files** — Manual merge of history symbols into disk reimplementations
10. **Test timeout fixes** — Mock HTTP in `test_cli_api_extended.py`

### Medium Priority

11. **EventBus contract documentation** — Formalize topic registry
12. **Swarm cleanup** — Remove or reactivate dead swarm subsystem
13. **mypy global strictness** — Remove lax defaults, enforce universally
14. **Coverage ratchet** — Raise from 80% toward 85%

---

## Appendix A: Module Health Matrix (Summary)

| Category | Count | Status |
|----------|-------|--------|
| Total Python files | 1,833 | — |
| Active modules | 1,174 | ✅ |
| Dead modules (classified) | 1,195 | ⚠️ |
| Substantial dead | 525 | Needs triage |
| Medium dead | 97 | Needs triage |
| Stub dead | 573 | Low priority |
| Relay shims | 75 | ✅ Functionally complete |
| Pure regressions restored | 8 | ✅ |
| REFACTORED (manual merge) | 38 | ⚠️ |
| MINOR diffs | 3 | ✅ |
| New modules (recovery) | 27 | ✅ |
| Missing (0 LOC) | 17 | ❌ |

## Appendix B: Subsystem Priority (by Composite Score)

| Rank | Subsystem | Reconnect | Lost | CR Alive | Score | Phase |
|------|-----------|-----------|------|----------|-------|-------|
| 1 | recon_dashboard | 19 | 0 | 3 | 98 | 3a |
| 2 | agents | 7 | 20 | 16 | 91 | 3a |
| 3 | scanners | 0 | 26 | 4 | 56 | 3a |
| 4 | core_infra | 1 | 15 | 11 | 46 | 3a |
| 5 | (root) | 0 | 3 | 31 | 37 | 3a |
| 6 | pipeline | 0 | 15 | 5 | 35 | 3a |
| 7 | recon | 0 | 15 | 4 | 34 | 3a |
| 8 | secrets | 0 | 16 | 1 | 33 | 3a |
| 9 | output | 0 | 14 | 2 | 30 | 3a |
| 10 | swarm | 5 | 1 | 0 | 27 | 3b |

*(Full 25-subsystem ranking in RECONNECTION_ROADMAP.json)*

---

*End of Comprehensive Analysis*
