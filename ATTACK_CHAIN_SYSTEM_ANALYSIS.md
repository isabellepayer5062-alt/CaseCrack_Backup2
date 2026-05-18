# CaseCrack — Attack Chain Identification: Complete System Analysis

**Scope**: End-to-end mapping of how CaseCrack identifies, builds, scores, and surfaces attack chains.  
**Primary files examined**: `output/correlation_engine.py` (3498 lines), `exploit_chains/exploit_graph.py` (2313 lines), `exploit_chains/graph_knowledge_base.py` (891 lines), `recon_dashboard/runner.py`, `recon_dashboard/phase_handlers/advanced.py`, `static/js/recon-dashboard.js`

---

## Architecture Overview

CaseCrack uses **three independent but integrated layers** for attack chain identification. They operate at different speeds and levels of abstraction and are designed to run in parallel:

```
Raw Findings (scan phases 1–45)
        │
        ├──► [Layer 1] QuickCorrelator       ← Runs LIVE during scan. Fast regex+category matching.
        │                                       Emits chain findings via SSE immediately.
        │
        ├──► [Layer 2] CorrelationEngine      ← Runs at scan COMPLETION. Full graph-based BFS.
        │                                       Emits CorrelationReport with AttackChain objects.
        │
        └──► [Layer 3] ExploitGraph           ← Runs continuously. Stateful 5-D attacker model.
                                                Tracks attacker position. Suggests YAML chains.
                        │
                        └──► P36 (phase handler) → emits exploit_chain findings via SSE
```

---

## Layer 1: QuickCorrelator

**File**: `tools/burp_enterprise/output/correlation_engine.py`, class `QuickCorrelator` (line ~3082)

### Purpose
Lightweight, real-time chain detection. Designed to run during a live scan with near-zero latency overhead. Does not build a graph — it pattern-matches findings against 27 predefined rules.

### Algorithm: `_detect_chains()` (lines 3250–3378)

```
Input: List[dict]  (raw finding dicts from all accumulated scan findings)
Output: List[dict]  (chain finding dicts, category='attack_chain')
```

**Step 1 — Pre-filter**: Removes "secure posture" findings (titles matching `no-cors-headers`, `scan-completed-no-results`) that would produce false positive chains.

**Step 2 — Categorize findings**:
- Builds `by_cat` dict: `category → [finding, ...]`
- For each finding, also extracts "virtual keywords" from title+detail text via `_F37_VIRTUAL_KEYWORDS` regex set (enables matching when no formal category is set)

**Step 3 — Rule matching**:
- Iterates all 27 `_QUICK_CHAIN_RULES` (format: `(regex_a, regex_b, chain_name, description)`)
- For each rule, finds all categories matching `pattern_a` and all matching `pattern_b`
- Pairs each matching category_a with each matching category_b (where category_a ≠ category_b)
- Takes the first 5 findings from each side as `findings_a` / `findings_b`

**Step 4 — Severity calculation**:
- `chain_sev` = max severity across all contributing findings (critical → high → medium → low → info)
- **Unverified cap**: If none of the contributing findings have `confirmed`/`verified`/`secret_tier==verified`, severity is capped at MEDIUM
- **Confidence-based cap**: `conf < 50` → MEDIUM max; `conf < 75` → HIGH max; `conf ≥ 75` → CRITICAL allowed

**Step 5 — Confidence scoring**:
```python
score = 20                                    # baseline
score += total_supporting_findings * 10       # each contributing finding adds 10
score += 15  # if unique_phases >= 2          # multi-phase bonus
score += 25  # if has_verified_finding        # verified-evidence bonus
score = min(score, 100)                       # capped
label = "high" if score >= 75 else "medium" if score >= 50 else "low"
```

**Step 6 — Output dict**:
```python
{
    "chain_name": str,
    "description": str,
    "severity": str,
    "confidence": {
        "score": int,       # 0–100
        "label": str,       # low/medium/high
        "has_verified_finding": bool,
        "unique_phases": int
    },
    "findings_a": List[dict],
    "findings_b": List[dict],
    "total_supporting_findings": int,
}
```

### `_QUICK_CHAIN_RULES` — 27 Rules

| # | Pattern A | Pattern B | Chain Name |
|---|-----------|-----------|------------|
| 1 | `credential\|secret\|api.key` | `endpoint\|url\|path` | credential-endpoint-chain |
| 2 | `sqli\|sql.injection` | `endpoint\|url\|path` | sqli-endpoint-chain |
| 3 | `subdomain\|vhost` | `endpoint\|url\|path` | subdomain-endpoint-chain |
| 4 | `xss\|cross.site` | `session\|cookie\|auth` | xss-session-chain |
| 5 | `ssrf` | `cloud\|metadata\|aws\|gcp` | ssrf-cloud-chain |
| 6 | `aspnet\|deserialization` | `rce\|command\|exec` | aspnet-deser-chain |
| 7 | `tech.*vuln\|cve\|outdated` | `rce\|exploit\|attack` | tech-vuln-chain |
| 8 | `tls\|ssl\|cert` | `mitm\|intercept\|downgrade` | tls-misconfig-chain |
| 9 | `subdomain\|dns` | `exposure\|leak\|access` | subdomain-exposure-chain |
| 10 | `http.smuggl` | `cache\|bypass\|poison` | http-smuggling-chain |
| 11 | `editor\|textpad\|vim\|emacs` | `exploit\|rce\|lfi` | editor-exploit-chain |
| 12 | `cors` | `data\|leak\|exfil` | cors-data-leak-chain |
| 13 | `auth\|login\|password` | `credential\|token\|session` | auth-credential-chain |
| 14–20 | 7× SQLi variant chains | Various targets | sqli-chain-1 through sqli-chain-7 |
| 21–27 | Additional FIX-F37 chains | Various | (added in bulk pass) |

### Output Path
QuickCorrelator chains are returned as a list and processed by `runner.py` → merged into `_formatted_chains` → pushed to SSE stream → `recon-all-findings.json`.

---

## Layer 2: CorrelationEngine (Full Graph-Based)

**File**: `tools/burp_enterprise/output/correlation_engine.py`, class `CorrelationEngine` (line ~2155)

### Pipeline (run at scan completion)

```
CorrelationEngine.correlate(findings)
    │
    ├─ 1. FindingNormalizer.normalize()         → List[NormalizedFinding]
    ├─ 2. CorrelationGraph.build_edges()        → CorrelationLink graph (O(n²) pair-check)
    ├─ 3. AttackPathGenerator.generate()        → List[AttackChain]  (BFS)
    ├─ 4. ContextualRiskScorer.score_all()      → Dict[finding_id → RiskContext]
    ├─ 5. ChainSuggester.suggest()              → List[ChainSuggestion]
    ├─ 6. TemporalAnalyzer.compare_snapshots()  → List[TemporalDelta]
    ├─ 7. PriorityScorer.score_all()            → List[PriorityScore]
    └─ Returns CorrelationReport
```

### Step 1: FindingNormalizer

Converts raw dicts to `NormalizedFinding` dataclass:
- Maps `finding_type` → `AttackPhase` via `FINDING_PHASE_MAP` (100+ specific strings)
- Extracts structured `tags` via `_derive_tags()` (vuln_class, tool, target, etc.)
- Normalizes severity strings, timestamps, domain/URL fields

### Step 2: CorrelationGraph — Building Edges

`CorrelationGraph.build_edges()` runs O(n²) over all finding pairs. For each pair (A, B):

`_try_correlate(a, b)` checks:
1. **CORRELATION_RULES**: 40 typed rules as `(src_prefix, tgt_prefix, label, confidence, weight)` tuples
   - Checks if `a.finding_type.startswith(src_prefix)` AND `b.finding_type.startswith(tgt_prefix)`
   - 40 rules covering: Credential→Endpoint, Credential→Cloud, Subdomain→Endpoint, Endpoint→Exploitation, WebSocket, Protocol→Infra, Cloud→Privilege, Supply Chain, GraphQL, Cross-module
2. **PHASE_ADJACENCY**: Even without a direct rule match, two findings may correlate if their `AttackPhase` values are adjacent in the kill chain (directed adjacency graph)
3. Creates `CorrelationLink(source_id, target_id, rule_label, confidence, weight, reason)` for each match

### Step 3: AttackPathGenerator — BFS Chain Discovery

```
_select_seeds()  → top N findings by severity (critical/high only as seeds by default)
_bfs_paths(seed) → BFS traversal of CorrelationLink edges
                   builds paths: [NormalizedFinding, ...]  up to depth 6
_build_chain(path) → AttackChain with:
    steps:       [ChainStep(step_number, finding_id, phase, title, url, severity)]
    total_weight: sum of CorrelationLink.weight across path edges
    confidence:  ChainConfidence (CONFIRMED/HIGH/MEDIUM/LOW/SPECULATIVE)
                 based on link count, verified findings, phase span
    narrative:   _build_narrative()  — human-readable attack story
    impact:      _describe_impact()  — impact description per end state
    remediation: _chain_remediation() — prioritized fix list
```

### AttackPhase Kill Chain (9 Stages)

```
RECONNAISSANCE → CREDENTIAL_ACCESS → INITIAL_ACCESS → EXECUTION
                                                     ↓
                              EXFILTRATION ← LATERAL_MOVEMENT ← PRIVILEGE_ESCALATION ← PERSISTENCE
                                   ↓
                                IMPACT
```

PHASE_ADJACENCY defines which transitions are "adjacent" (used for implicit edge creation).

### Step 4: ContextualRiskScorer

Re-scores findings **by chain context**, not individual severity. A low-severity finding that's part of a confirmed critical chain gets elevated. Output: `RiskContext(finding_id, chain_ids, contextual_severity, risk_multiplier)`.

### Step 5: ChainSuggester

Rule-based: scans all `NormalizedFinding` objects for patterns where a "precursor" finding exists but the "consequence" finding is absent. Produces `ChainSuggestion(precursor, missing_step, chain_type, recommended_test)`.

### Step 6: TemporalAnalyzer

Snapshots the finding set and compares against previous snapshots. Identifies new findings, resolved findings, severity changes. Produces `TemporalDelta` objects for "attack surface is growing" alerts.

### Step 7: PriorityScorer

ML-ready feature vector construction for each finding (severity, phase, chain membership, temporal recency, verified status, blast radius) → `PriorityScore`. Used for finding ranking in UI.

### Learning: PatternMemory + CorrelationRuleSynthesizer

**PatternMemory** (singleton): records confirmed chains and correlation links in-memory. Tracks frequency and confidence of finding-type pairs. `get_high_confidence_pairs()` returns pairs seen ≥N times.

**CorrelationRuleSynthesizer** (singleton): reads from PatternMemory, synthesizes new `CORRELATION_RULES` dynamically. `get_merged_rules()` combines static rules + learned rules for each correlate pass.

### CorrelationReport Output Schema

```python
@dataclass
class CorrelationReport:
    attack_chains:    List[AttackChain]
    correlated_pairs: List[CorrelationLink]
    risk_elevations:  List[RiskContext]
    chain_suggestions: List[ChainSuggestion]
    temporal_deltas:  List[TemporalDelta]
    priority_scores:  List[PriorityScore]
    deduplicated:     List[dict]          # merged/deduped raw findings
    metadata:         dict
```

---

## Layer 3: ExploitGraph (Stateful Attacker Model)

**File**: `tools/burp_enterprise/exploit_chains/exploit_graph.py` (canonical, 2313 lines)  
**Knowledge base**: `tools/burp_enterprise/exploit_chains/graph_knowledge_base.py` (891 lines)

### Conceptual Model

The ExploitGraph models the attacker's real-time position as a **5-dimensional vector**:

| Dimension | States (progression) |
|-----------|---------------------|
| **ASSET** | EXTERNAL_UNKNOWN → SUBDOMAIN_ENUMERATED → ENDPOINT_MAPPED → INTERNAL_NETWORK |
| **AUTH** | UNAUTHENTICATED → SESSION_TOKEN_OBTAINED → USER_SESSION → API_KEY_OBTAINED → SSO_FEDERATED |
| **PRIVILEGE** | NO_PRIVILEGE → STANDARD_USER → ELEVATED_USER → CROSS_ACCOUNT_ACCESS → ADMIN_ACCESS → SUPER_ADMIN |
| **DATA_ACCESS** | PUBLIC_DATA_ONLY → OWN_USER_DATA → OTHER_USER_DATA → SENSITIVE_PII → SOURCE_CODE_ACCESS → BULK_DATA_ACCESS → DATABASE_DUMP |
| **CLOUD** | NO_CLOUD_ACCESS → STORAGE_BUCKET_ACCESS → METADATA_ACCESSIBLE → CLOUD_RESOURCE_ACCESS → IAM_ROLE_ASSUMED → CROSS_ACCOUNT_CLOUD → FULL_CLOUD_ADMIN |

Each dimension advances independently (B7: parallel dimension advancement).

### AttackerPosition Scoring

```python
@property
def risk_score(self) -> float:
    # Sum of _STATE_RISK[current_state] across all 5 dimensions
    # _STATE_RISK maps each AttackerState to a numeric risk (0–100)

@property
def composite_risk_score(self) -> float:
    # Weighted combination: asset+auth+privilege+data+cloud dimensions
    # Used for blast_radius and expected_value calculation
```

### TRANSITION_KNOWLEDGE_BASE (~62 Entries)

Each entry: `{ trigger, from: AttackerState, to: AttackerState, category: StateCategory, probability: float, chain: str (YAML), display: str, description: str, requires_cross_dimension: List[str] }`

**Auth transitions** (13): password_reset_weak, session_fixation, oauth_misconfig, oauth_deep_recon, saml_misconfig, jwt_alg_none, xss_session_steal, xss_blind_oob, csrf_chain, account_enum, logout_bypass, graphql_auth_bypass, secrets_leak→api_key, api_key→session, saml→sso

**Privilege transitions** (9): idor, graphql_idor, mass_assignment, admin_endpoint_exposed (×2), authz_bypass, websocket_privesc, rate_limit_bypass, grpc_bypass, cmdi_pivot→super_admin

**Data access transitions** (10): idor_data (×2), sqli, sqli_blind, path_traversal, xxe_read, ssti_read, secrets_leak→sensitive, open_redirect_phish, graphql_over_fetch, schema_drift

**Cloud transitions** (9): ssrf_metadata, metadata_creds, iam_privesc, iam_attack_path, bucket_public, k8s_exposed, dns_takeover, ssh_db_exposed

**Asset transitions** (9): subdomain_enum, port_scan, endpoint_crawl, subdomain_takeover, ssrf_internal, ssrf_blind, http_smuggling, file_upload_pivot, cmdi_pivot, cdn_waf_bypass

**Cross-dimension bridge transitions** (5): user_auth_established, session_validate, idor_data→bulk, admin_endpoint elevated, secrets_leak→unauthenticated

### Finding → Trigger Resolution (`_resolve_triggers`)

Three lookup mechanisms in priority order:

1. **FINDING_TRIGGER_MAP** (~120 entries): prefix-match on `finding_type` string. More specific prefixes appear first (e.g. `ssrf_cloud` before `ssrf`).

2. **TITLE_KEYWORD_TRIGGERS** (~60 entries): substring match on finding title. Used as fallback when no formal finding_type is set.

3. **CATEGORY_TRIGGER_MAP** (~40 entries): maps scan category (e.g. `secrets`, `graphql`, `websocket`) to a trigger type.

### `process_finding()` Algorithm

```python
1. Extract finding_type, finding_id, severity, evidence
2. Validate inputs (length bounds, type checks)
3. _resolve_triggers(finding_type) → List[trigger_type]
4. severity → sev_weight (_SEVERITY_WEIGHT map: critical=2.0, high=1.5, medium=1.0, etc.)
5. For each trigger:
   - Find all transitions with that trigger_type
   - For each candidate transition:
     a. Get from_node; check current risk ≥ from_state risk (FIX-EG-REACH: 
        reachability check, not exact state match)
     b. Check cross-dimension prerequisites (requires_cross_dimension)
     c. Dedup check: f"{transition.id}:{finding_id}" not in confirmed_triggers
   - Fire all candidate transitions (B7: parallel dimension advancement)
6. For fired transitions:
   - Set is_confirmed=True, record evidence_history entry (B10: append, not overwrite)
   - Emit "graph.position.updated" via EventBus
7. _mark_changed(edge_ids=...) for diff/delta API (B14)
8. Return List[ExploitTransition]
```

### Key Graph Methods

| Method | Purpose |
|--------|---------|
| `build_from_knowledge_base()` | Populates graph from TRANSITION_KNOWLEDGE_BASE; called once on init |
| `process_finding(finding)` | Live state update; fires transitions triggered by a finding |
| `process_findings_batch(findings)` | Batch version; single lock acquisition for efficiency |
| `process_finding_multihop(finding)` | Discovers 2-hop chains (A→B→C) from a single finding |
| `suggest_chains()` | Maps available transitions to executable YAML chain files (delegated to `graph_suggestions.py`) |
| `critical_paths()` | Highest-probability path sequences to critical states |
| `calculate_blast_radius()` | Computes set of reachable states from current position |
| `shortest_path_to(target)` | BFS/A* to reach a specific target state |
| `all_paths_to(target)` | All paths (up to max_paths) to a target state |
| `get_confirmed_transitions()` | All transitions that have been fired (evidence confirmed) |
| `suggest_next_tests()` | Recommends next pentest steps based on current position |
| `generate_attack_narrative()` | Human-readable story of attacker progression (delegated to `graph_rendering.py`) |
| `to_cytoscape()` / `to_cytoscape_diff()` | JSON for Cytoscape.js visualization (cached; diff uses change_seq) |
| `to_d3_force()` | D3 force-directed graph JSON |

### ExploitGraphEngine (Wrapper/Orchestrator)

`ExploitGraphEngine` wraps `ExploitGraph` and adds:
- **EventBus integration**: subscribes to `VULN_*` events (`_on_vuln_event`) and `RECON_*` events (`_on_recon_event`) for live graph updates
- **CorrelationReport ingestion**: `ingest_correlation_report(report)` iterates attack chains and correlation links, calls `_mark_transition_confirmed()` for matching transitions
- **Dynamic transitions**: `register_dynamic_transition()` adds new transitions at runtime based on scan-discovered data
- **Weight tuner binding**: `bind_weight_tuner(tuner)` enables learned probability adjustments
- **Persistence**: `save()`, `load(target)`, `snapshot()` for state persistence across scan phases
- **Singleton pattern**: `get_exploit_graph_engine(target, ...)` returns singleton per target

---

## Data Flow: End-to-End

### Phase 1–45: Scan Running

```
Each scan phase emits findings → runner._push({"type": "finding", ...})
                                        │
                    ┌───────────────────┼──────────────────────┐
                    ▼                   ▼                      ▼
           all_findings list    QuickCorrelator         ExploitGraphEngine
           (accumulated)       .correlate(findings)    ._on_vuln_event(event)
                                        │                      │
                              chain findings emitted     transitions fired
                              immediately via SSE         position updated
```

### Scan Completion (after Phase 45)

```
runner._run_correlation_engine()
    │
    ├── CorrelationEngine.correlate(all_findings) → CorrelationReport
    │       │
    │       ├── report.attack_chains → _chain_to_finding() → SSE push (category=attack_chain)
    │       └── report.deduplicated + chains → recon-all-findings.json
    │
    └── ExploitGraphEngine.ingest_correlation_report(report)
            │
            └── confirmed transitions → position update → graph saved
```

### Phase 36 (Exploit Graph Analysis)

```
phase_handlers/advanced.py P36 post_phase():
    │
    ├── ExploitGraphEngine.suggest_chains() → _p36_suggested_chains
    ├── ExploitGraphEngine.graph.critical_paths() → _p36_critical_paths
    │
    ├── For each suggested_chain (up to 20):
    │       ctx.runner._push({
    │           "type": "finding",
    │           "category": "exploit_chain",
    │           "chain_id", "chain_command", "expected_value",
    │           "probability", "target_risk", "blast_radius",
    │           "risk_score", "composite_risk", "confirmed_transitions",
    │           "chain_steps"
    │       })
    │
    └── For each critical_path (up to 10):
            ctx.runner._push({...same schema...})
```

### Frontend SSE Ingestion

```
SSE event "finding" received
    │
    ├── if category == "exploit_chain" || "attack_chain":
    │       passes through all chain fields:
    │       chain_id, chain_name, chain_command, expected_value, probability,
    │       target_risk, risk_score, composite_risk, blast_radius,
    │       chain_steps, confirmed_transitions, supporting_finding_count,
    │       findings_a, findings_b
    │
    ├── _renderFindingItem(f):
    │       detects fCat == 'exploit_chain' || 'attack_chain'
    │       adds CSS class 'finding-chain-item' (orange left border)
    │       builds chainMetaBar: ⛓️ icon, chain name, step count badge,
    │       EV% badge, blast radius badge
    │
    └── _buildAttackChainCard(f):  (modal detail view)
            metrics grid: EV%, risk score, confirmed transitions, supporting findings
            blast radius callout, chain ID, run command <pre>, step-by-step <ol>,
            correlated findings_a/findings_b lists
```

---

## Scoring Summary

| Layer | Metric | Formula |
|-------|--------|---------|
| QuickCorrelator | Confidence score | `20 + (n×10) + 15[multi-phase] + 25[verified]`, capped 100 |
| QuickCorrelator | Severity | Max of contributing findings; capped MEDIUM if unverified |
| CorrelationEngine | Chain weight | Σ(CorrelationLink.weight) across BFS path edges |
| CorrelationEngine | Chain confidence | `ChainConfidence` enum based on link count, verified count, phase span |
| ExploitGraph | Transition probability | Static KB value × sev_weight, adjusted by context/WeightTuner |
| ExploitGraph | Risk score | Σ(_STATE_RISK[dim_state]) for all 5 dimensions |
| ExploitGraph | Composite risk | Weighted multi-dimensional position score |
| ExploitGraph | Blast radius | Count/set of reachable states from current position |
| P36 output | expected_value | Σ(transition.probability) across critical path |

---

## Output Surfaces

| Surface | Schema | Trigger |
|---------|--------|---------|
| Findings Explorer (SSE) | `{type:"finding", category:"attack_chain"/"exploit_chain", ...}` | Real-time, during scan |
| `recon-all-findings.json` | All findings + formatted chains | Scan completion |
| `/api/exploit-graph/*` | Cytoscape JSON, D3, narrative | On-demand API |
| Report generator | Attack chain sections in HTML/PDF | Report generation |
| CAAP export | `caap_chains.py` / `caap_formatter.py` | CAAP mode |
| Dashboard exploit graph panel | Cytoscape.js visualization | Post-scan |
| Mermaid diagrams | `exploit_graph_renderer.py` | Report rendering |

---

## Key Files Reference

| File | Role |
|------|------|
| `output/correlation_engine.py` | Full CorrelationEngine + QuickCorrelator (3498 lines) |
| `exploit_chains/exploit_graph.py` | Canonical ExploitGraph + ExploitGraphEngine (2313 lines) |
| `exploit_chains/graph_knowledge_base.py` | TRANSITION_KNOWLEDGE_BASE + trigger maps (891 lines) |
| `exploit_chains/graph_suggestions.py` | `suggest_chains()` implementation |
| `exploit_chains/graph_rendering.py` | `generate_attack_narrative()` |
| `exploit_chains/graph_state_ops.py` | `adjust_probabilities()`, `reset()`, state recalculation |
| `exploit_chains/graph_pathfinding.py` | `shortest_path_to()`, `all_paths_to()` |
| `exploit_chains/graph_persistence.py` | Save/load/snapshot |
| `exploit_chains/graph_reporting.py` | Report generation from graph |
| `exploit_chains/graph_integrations.py` | Integration adapters |
| `exploit_chains/attack_path_optimizer.py` | Advanced path optimization |
| `exploit_chains/chain_impact_scorer.py` | Impact scoring for chains |
| `recon_dashboard/runner.py` | `_chain_to_finding()`: chain → SSE finding event |
| `recon_dashboard/phase_handlers/advanced.py` | P36: ExploitGraph → SSE findings |
| `recon_dashboard/routes_exploit_graph.py` | `/api/exploit-graph/*` REST endpoints |
| `tools/burp_enterprise/exploit_graph.py` | **Shim proxy** (18 lines) — imports from exploit_chains |
| `tools/burp_enterprise/output/exploit_graph.py` | **Shim proxy** (12 lines) — same pattern |
| `static/js/recon-dashboard.js` | Frontend SSE ingest + Findings Explorer rendering |
| `static/css/recon-dashboard.css` | Chain finding UI styles |

---

## Identified Gaps & Weaknesses

### G1: Three independent layers, no cross-pollination
QuickCorrelator and CorrelationEngine share no state during a scan run. A QuickCorrelator chain confirmed at phase 20 does not influence CorrelationEngine edge weights at phase 45. ExploitGraph only learns from CorrelationEngine at scan completion.

### G2: Pattern learning is in-memory only
`PatternMemory` and `CorrelationRuleSynthesizer` singletons are in-memory. Unless explicitly serialized via `get_pattern_memory().save()`, patterns learned during one scan are lost when the process restarts. No automatic persistence is wired.

### G3: Static transition probabilities
All 62 `TRANSITION_KNOWLEDGE_BASE` entries have hardcoded probabilities (e.g. `probability: 0.35`). The `WeightTuner` binding exists (`bind_weight_tuner()`) but requires explicit activation — it is not automatically bound at scan start in all code paths.

### G4: No chain deduplication between layers
QuickCorrelator chains (category=`attack_chain`) and ExploitGraph chains (category=`exploit_chain`) can both identify the same underlying attack path (e.g. SSRF→Cloud Metadata). Both are emitted to Findings Explorer and written to `recon-all-findings.json` with no merging.

### G5: Seven exploit_graph.py shim files
The canonical implementation is in `exploit_chains/exploit_graph.py`. All other copies (`tools/burp_enterprise/exploit_graph.py`, `output/exploit_graph.py`, `agents/exploit_graph.py`, `scanners/exploit_graph.py`) are 12–18 line shim proxies using `__getattr__` delegation. This is correct but obscure — imports from the wrong module path silently resolve via the shim.

### G6: QuickCorrelator severity capping logic is order-sensitive
The severity cap applies **after** rule matching. If a finding is categorized as both a rule_a and rule_b category, it may appear in both `findings_a` and `findings_b` for the same chain. The cap logic then sees `has_verified_finding=True` only if the shared finding has a verified tier — but this can result in the same finding "confirming" a chain it is the sole contributor to.

### G7: No temporal correlation in QuickCorrelator
QuickCorrelator has no concept of finding age or scan phase. A credential finding from phase 3 and an endpoint finding from phase 40 produce the same chain as two findings from the same phase. TemporalAnalyzer exists in CorrelationEngine but only runs at scan completion.

---

## Summary Statistics

| Component | Count |
|-----------|-------|
| QuickCorrelator chain rules | 27 |
| CorrelationEngine CORRELATION_RULES | 40 |
| AttackPhase kill-chain stages | 9 |
| FINDING_PHASE_MAP entries | ~100+ |
| ExploitGraph TRANSITION_KNOWLEDGE_BASE entries | ~62 |
| FINDING_TRIGGER_MAP entries | ~120 |
| TITLE_KEYWORD_TRIGGERS entries | ~60 |
| CATEGORY_TRIGGER_MAP entries | ~40 |
| AttackerState values | ~26 |
| StateCategory dimensions | 5 |
| Exploit chain YAML files (casectl chain run) | 40+ |
