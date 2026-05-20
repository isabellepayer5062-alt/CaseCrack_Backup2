# Integration Audit Mode — Comprehensive Implementation Analysis

## Executive Summary

The current audit infrastructure (UU-1 through UU-8 probes, `AuditPyramid`,
`HarnessRunner`, `DifferentialTester`) is entirely **synthetic**: it creates
its own `WeightTuner`, feeds hand-crafted ground-truth weights, and simulates
feedback with scripted `FeedbackType` values.  This has proven invaluable for
isolating edge cases, but it tests the **weight tuner in a vacuum** — divorced
from the 13 real `_compute_*` scoring functions, the actual synthesis engines,
the `PayloadArbiter` composite formula, and — most critically — the production
feedback loop, which **does not exist today**.

### The Showstopper Finding

The real scan pipeline (`Runner → FindingPipeline → PSE.synthesize_payloads()`)
calls `pse.synthesize_payloads(ctx)` when injectable findings arrive, but
**never calls `pse.record_feedback()`**.  There is no production code path that
feeds HTTP execution results back into the WeightTuner / feedback subsystems.
The entire adaptive learning loop is exercised exclusively by the test harness.

This means the Integration Audit Mode has two jobs:
1. **Close the loop** — design the instrumentation that will wire real execution
   feedback into the PSE, even before the production caller is updated.
2. **Verify end-to-end** — prove that signals, weights, feedback, and decisions
   are causally connected when real CaseCrack flows run.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Integration Audit Mode                           │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  TargetStub   │    │  PSE (real)   │    │  IntegrationAuditor  │  │
│  │  (HTTP sim)   │◄───│  + Arbiter    │◄───│  (orchestrator)      │  │
│  │              │────►│  + WeightT.   │────►│                      │  │
│  │  verdict:     │    │  + Feedback   │    │  Signal assertions   │  │
│  │  bypass/block │    │  + all subs   │    │  Weight assertions   │  │
│  │              │    │              │    │  Propagation checks   │  │
│  └──────────────┘    └──────────────┘    │  Causality proofs     │  │
│                                          └──────────────────────┘  │
│                                                                     │
│  Data flow:                                                         │
│  1. Auditor builds SynthesisContext from scenario template           │
│  2. PSE.synthesize_payloads(ctx) — real engines, real scoring        │
│  3. TargetStub evaluates payload → returns verdict (HTTP-like)       │
│  4. Auditor calls PSE.record_feedback() with verdict                 │
│  5. WeightTuner.observe() fires → Ridge regression → Arbiter update  │
│  6. Next synthesis cycle uses updated weights                        │
│  7. Auditor asserts on 4 dimensions after N cycles                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Use real PSE? | Yes | Must test real `_compute_*` functions, grammar, genetic forge |
| Use real HTTP? | No — TargetStub | Deterministic, fast, no external deps |
| Use real WAF? | Stub with configurable rules | Real WAF detection is non-deterministic |
| Use real LLM? | No — mock LLM bridge | Expensive, slow, non-deterministic |
| Extend HarnessRunner? | No — new `IntegrationAuditor` class | HarnessRunner is tied to synthetic GT models; integration mode needs different plumbing |
| Where does it live? | `CaseCrack/tools/burp_enterprise/exploit_chains/integration_audit.py` | Alongside the existing `system_audit_harness.py` and `audit_pyramid.py` |

---

## 2. The Four Audit Dimensions

### 2.1 Signal Presence

**What we verify**: After each `synthesize_payloads()` call, every payload in
the ranked output has all 13 signals populated with meaningful (non-default)
values that reflect the provided context.

**Current gap**: The synthetic harness captures only 8 of 13 signals in
`CycleResult.payloads` (missing: `stealth_score`, `novelty_score`,
`environment_fit`, `temporal_relevance`, `chain_momentum`).

**Implementation**:

```python
@dataclass(frozen=True)
class SignalPresenceReport:
    """Per-cycle signal presence audit."""
    cycle: int
    total_payloads: int
    signals_present: dict[str, int]     # signal_name → count of payloads where != 0.0
    signals_contextual: dict[str, int]  # signal_name → count where value varies across payloads
    zero_signals: list[str]             # signals that were 0.0 on ALL payloads
    invariant_signals: list[str]        # signals identical across all payloads (no differentiation)

    @property
    def presence_rate(self) -> float:
        """Fraction of signal×payload cells that are non-zero."""
        total_cells = self.total_payloads * 13
        present_cells = sum(self.signals_present.values())
        return present_cells / total_cells if total_cells > 0 else 0.0

    @property
    def differentiation_rate(self) -> float:
        """Fraction of signals that vary across payloads (actually discriminate)."""
        return len([s for s in SIGNAL_NAMES if s not in self.invariant_signals]) / 13
```

**Assertions** (per cycle):
- `presence_rate ≥ 0.70` — at least 70% of signal×payload cells non-zero
- `zero_signals` contains at most 2 signals (some signals legitimately zero:
  e.g. `campaign_boost` if no `cross_target_signals`, `chain_alignment` if no
  chain goal)
- `differentiation_rate ≥ 0.50` — at least half the signals actually
  differentiate between payloads (not all identical)

**Context-sensitive assertions**:
- If `ctx.waf_vendor != ""` → `bypass_score` varies across payloads
- If `ctx.chain_goal != ""` → `chain_alignment` varies across payloads  
- If `ctx.hypothesis_multiplier > 1.0` → `hypothesis_boost > 0` on ≥1 payload
- If `ctx.cross_target_signals` non-empty → `campaign_boost > 0` on ≥1 payload

### 2.2 Weight Usage

**What we verify**: The WeightTuner's learned weights are actually used by the
PayloadArbiter to rank payloads, and weight changes cause ranking changes.

**Current gap**: The synthetic probes test the WeightTuner in isolation
(`get_current_weights()`) but never verify that updated weights flow through
to `PayloadArbiter.arbitrate()` and change the composite score formula.

**Implementation**:

```python
@dataclass(frozen=True)
class WeightUsageReport:
    """Verify weights actually influence scoring."""
    cycle: int
    arbiter_weights: dict[str, float]       # snapshotted from arbiter._w_* fields
    tuner_weights: dict[str, float]         # from weight_tuner.get_current_weights()
    weight_arbiter_sync: bool               # arbiter weights == tuner weights (within ε)
    weight_rank_correlation: float          # Spearman ρ between payload signal×weight and actual score
    score_explained_by_weights: float       # R² of score = Σ(signal_i × weight_i)

    # Interventional test results (run once per audit, not per cycle)
    intervention_delta: float | None = None  # score change when weights are manually perturbed
```

**Assertions**:
- `weight_arbiter_sync == True` after every calibration — the tuner and arbiter
  agree on the weights (tests `_push_to_arbiter` wiring)
- `score_explained_by_weights ≥ 0.80` — the composite score is largely
  explained by the linear signal×weight formula (validating no hidden scoring
  path)
- **Interventional test**: Temporarily override `bypass_score` weight to 0.90,
  re-run `arbitrate()` on the same payloads → assert the highest-bypass-score
  payload is now rank-1.  Then restore weights.  This proves **causal** weight
  influence, not just correlation.

**Cross-calibration check**:
- After 25+ feedback events, `tuner_weights ≠ STATIC_PRIORS` — the tuner has
  actually learned something
- `|tuner_weights["bypass_score"] - STATIC_PRIORS["bypass_score"]| > 0.01` —
  the dominant signal has shifted from the prior

### 2.3 Feedback Propagation

**What we verify**: When `pse.record_feedback()` is called with a verdict, the
event reaches all 7 subsystems with the correct reward signal, and the
WeightTuner's internal observation count advances.

**Current gap**: `test_feedback_propagation.py` uses mocks for all 6
non-WeightTuner subsystems.  `test_contract_propagation.py` uses strict fakes.
Neither runs through the **real** PSE where the 5-step propagation chain
(FeedbackCollector → FailureExtractor → ContextCompiler →
TemporalStabilityGuard → SafetyGuard) all fire.

**Implementation**:

```python
@dataclass(frozen=True)
class FeedbackPropagationReport:
    """Verify feedback reaches all subsystems."""
    cycle: int
    events_sent: int                        # FeedbackEvents created this cycle
    tuner_obs_before: int                   # WeightTuner._total_observations before
    tuner_obs_after: int                    # WeightTuner._total_observations after
    tuner_calibrations_before: int          # WeightTuner._total_calibrations before
    tuner_calibrations_after: int           # WeightTuner._total_calibrations after
    reward_values: list[float]              # reward_signal of each event
    feedback_types: list[str]              # FeedbackType of each event
    weights_changed: bool                   # weights different before vs after
    collector_propagation_count: int        # SynthesisFeedbackCollector._propagation_count (if available)
```

**Assertions**:
- `tuner_obs_after == tuner_obs_before + events_sent` — every event reached
  the WeightTuner
- After `events_sent ≥ CALIBRATION_INTERVAL` (5), at least one new calibration
  fired: `tuner_calibrations_after > tuner_calibrations_before`
- `reward_values` matches expected rewards per FeedbackType (±0.30 evidence
  bonus):
  - `EXECUTED_SUCCESSFULLY → 1.0` (or 1.0 with evidence, capped)
  - `BLOCKED_BY_WAF → -0.80`
  - etc.
- `weights_changed == True` after ≥10 events with mixed positive/negative
  feedback

**Subsystem-specific checks** (when subsystems are bound):
- FailureExtractor: after negative feedback, `pse._failure_extractor` has
  recorded the failure (check `len(extractor._failures) > 0`)
- ContextCompiler: after blocked feedback, blocked pattern added to
  `compiler._blocked_cache`
- WeightTuner: `get_signal_correlations()` returns non-zero correlations
  after 10+ events

### 2.4 Decision Causality

**What we verify**: The system's decisions (payload ranking) are **causally**
traceable to the feedback it received, not just correlated with the scenario.

**Current gap**: The `DifferentialTester` ablates context dimensions
(hypothesis, campaign, WAF, chain, prior knowledge) but doesn't test whether
*feedback-driven weight changes* actually cause *different decisions*.

**Implementation — three causal tests**:

#### Test 1: Feedback Direction → Weight Direction → Score Direction

```
Scenario: XSS against Cloudflare

Round A (20 cycles):
  - Payload X has high bypass_score (WAF bypass payloads)
  - Feedback: BYPASSED_WAF → reward +0.70
  → Assert: bypass_score weight increases

Round B (20 cycles):
  - Same payloads X, now feedback: BLOCKED_BY_WAF → reward -0.80
  → Assert: bypass_score weight decreases (or competing signal increases)
  → Assert: composite ranking flips — different payload is now rank-1
```

This is the **minimal causal chain**: positive feedback for a signal-type →
weight increases → payloads with that signal rank higher.

#### Test 2: Counterfactual Intervention

```
After 20 cycles with real feedback:
  1. Snapshot weights W₁ and ranked payloads P₁
  2. Reset WeightTuner to static priors
  3. Re-run arbitrate() on same payloads with static weights → P₂
  4. Assert: P₁ ≠ P₂ (adaptation matters)
  5. Restore W₁

If P₁ == P₂, the weight tuner learned nothing useful, or the weights
are so close to priors that learning made no difference.
```

#### Test 3: Signal Attribution

```
After 20 cycles:
  1. Get weights W
  2. For each signal S:
     a. Set W[S] = 0, normalize remaining
     b. Re-score payloads → rank R_without_S
     c. Compute Kendall τ between R_full and R_without_S
     d. If τ < 0.90 → signal S causally influences ranking
  3. Assert: at least 3 signals have τ < 0.90 (not a single-signal model)
  4. Assert: signal with highest weight has lowest τ (highest influence)
```

---

## 3. TargetStub Design

The existing `GroundTruthModel` is too simple (pattern match → 4 buckets).
For integration mode, we need a **DefenseProfile** that models WAF behavior
realistically enough that the 13 real `_compute_*` functions produce
meaningful signal differentiation.

```python
@dataclass
class DefenseProfile:
    """Simulates target defense posture for integration testing."""
    waf_vendor: str = "cloudflare"
    blocked_patterns: frozenset[str] = frozenset({
        "<script>", "<iframe>", "onerror=", "onload=",
        "union select", "' or 1=1", "../../../",
    })
    bypass_patterns: frozenset[str] = frozenset({
        "<svg/onload=", "<img src=x onerror=",
        "/**/union/**/select",
    })
    true_vuln_type: VulnType = VulnType.XSS
    accepts_encoding: bool = True      # URL-encoded payloads bypass?
    rate_limit_after: int = 50         # requests before rate-limiting kicks in
    connection_flake_rate: float = 0.02  # random RST probability

    def evaluate(self, payload: str, attempt_number: int) -> FeedbackType:
        """Deterministic verdict for a payload string."""
        # Rate limiting
        if attempt_number > self.rate_limit_after:
            if attempt_number % 3 == 0:
                return FeedbackType.RATE_LIMITED

        # Connection flake (deterministic based on hash)
        if hash(payload) % 100 < int(self.connection_flake_rate * 100):
            return FeedbackType.CONNECTION_RESET

        text = payload.lower()

        # Bypass → executed
        for bp in self.bypass_patterns:
            if bp.lower() in text:
                return FeedbackType.EXECUTED_SUCCESSFULLY

        # Blocked
        for blk in self.blocked_patterns:
            if blk.lower() in text:
                return FeedbackType.BLOCKED_BY_WAF

        # Encoding bypass
        if self.accepts_encoding and "%" in payload:
            return FeedbackType.PARTIAL_EXECUTION

        # Default: no effect
        return FeedbackType.NO_EFFECT
```

**Why this matters**: The `_compute_bypass_score()` function checks
`ctx.known_blocked_patterns` and `ctx.known_bypassed_patterns` — the
DefenseProfile feeds these into the context, creating a coherent loop where
signals reflect reality and feedback is consistent with signals.

---

## 4. Integration Scenario Templates

### Scenario 1: XSS Against Cloudflare (Baseline)

**Purpose**: Verify the full loop works on the most common attack surface.

```python
IntegrationScenario(
    name="xss_cloudflare_baseline",
    defense=DefenseProfile(
        waf_vendor="cloudflare",
        blocked_patterns=frozenset({"<script>", "<iframe>", "onerror="}),
        bypass_patterns=frozenset({"<svg/onload=", "<details/open/ontoggle="}),
        true_vuln_type=VulnType.XSS,
    ),
    context_overrides={
        "vuln_type": "xss",
        "waf_vendor": "cloudflare",
        "known_blocked_patterns": frozenset({"<script>"}),
        "target_url": "https://integration.test/search",
        "safety_level": "moderate",
    },
    cycles=40,
    assertions={
        "signal_presence_rate": 0.70,
        "weight_arbiter_sync": True,
        "tuner_learned_vs_prior": True,
        "feedback_causality": True,
    },
)
```

**Expected behavior**:
- Grammar engine produces `<script>alert(1)</script>` (blocked) and
  `<svg/onload=alert(1)>` (bypasses)
- After 10+ cycles, WeightTuner should upweight `bypass_score` and
  `stealth_score` (bypass patterns tend to be stealthier)
- Rank-1 payload should shift from generic `<script>` to WAF-aware payloads

### Scenario 2: SQLi Chain Exploitation

**Purpose**: Test `chain_alignment` and `chain_momentum` signals with a
multi-step exploit chain.

```python
IntegrationScenario(
    name="sqli_chain_escalation",
    defense=DefenseProfile(
        waf_vendor="modsecurity",
        blocked_patterns=frozenset({"union select", "' or 1=1", "sleep("}),
        bypass_patterns=frozenset({"/*!50000union*/select", "' and 1=1--"}),
        true_vuln_type=VulnType.SQLI,
    ),
    context_overrides={
        "vuln_type": "sqli",
        "waf_vendor": "modsecurity",
        "chain_goal": "data_exfiltration",
        "chain_description": "auth_bypass → sqli → data_access",
        "current_chain_step": 1,
    },
    cycles=30,
    chain_progression=[
        {"step": 0, "goal": "auth_bypass"},
        {"step": 1, "goal": "sqli"},
        {"step": 2, "goal": "data_access"},
    ],
)
```

**Expected behavior**:
- `chain_alignment` signal is non-zero and varies by payload
- `chain_momentum` signal reflects success history
- After positive feedback on chain-aligned payloads, their ranking improves

### Scenario 3: Environment Shift (Mid-Scan WAF Change)

**Purpose**: Test adaptation when the defense profile changes mid-scan.

```python
IntegrationScenario(
    name="waf_shift_adaptation",
    defense_phases=[
        (0, 20, DefenseProfile(waf_vendor="", blocked_patterns=frozenset())),  # no WAF
        (20, 40, DefenseProfile(
            waf_vendor="cloudflare",
            blocked_patterns=frozenset({"<script>", "onerror=", "<iframe>"}),
            bypass_patterns=frozenset({"<svg/onload="}),
        )),
    ],
    context_overrides={"vuln_type": "xss"},
    cycles=40,
)
```

**Expected behavior**:
- Cycles 0-19: everything succeeds, weights learn freely
- Cycles 20-39: suddenly blocked → `bypass_score` weight should increase,
  `detection_risk` weight should become more negative
- Score rankings should visibly shift after WAF appears

### Scenario 4: Hypothesis-Driven Exploration

**Purpose**: Test that `hypothesis_boost` signal actually changes decisions.

```python
IntegrationScenario(
    name="hypothesis_driven",
    defense=DefenseProfile(true_vuln_type=VulnType.XSS),
    context_overrides={
        "vuln_type": "xss",
        "hypothesis_multiplier": 2.5,  # strong hypothesis
    },
    cycles=20,
    # Differential: re-run with hypothesis_multiplier=0.0 → rankings must differ
    differential_configs=[
        {"label": "no_hypothesis", "hypothesis_multiplier": 0.0},
    ],
)
```

### Scenario 5: Campaign Cross-Target Intelligence

**Purpose**: Test `campaign_boost` signal from prior target successes.

```python
IntegrationScenario(
    name="cross_target_intel",
    defense=DefenseProfile(true_vuln_type=VulnType.XSS),
    context_overrides={
        "vuln_type": "xss",
        "cross_target_signals": [
            ("xss", "target_a", 0.85),  # high confidence from prior target
            ("xss", "target_b", 0.60),
        ],
    },
    cycles=20,
)
```

---

## 5. Implementation Plan

### File Structure

```
CaseCrack/tools/burp_enterprise/exploit_chains/
  integration_audit.py          # IntegrationAuditor, DefenseProfile, scenarios
  audit_pyramid.py              # (existing) AuditPyramid — unchanged
  system_audit_harness.py       # (existing) HarnessRunner — unchanged

CaseCrack/tests/
  test_integration_audit.py     # Pytest wrapper — runs scenarios, asserts verdicts

Root:
  _run_integration_audit.py     # CLI runner (like the UU probes)
```

### Class Design

```python
class IntegrationAuditor:
    """End-to-end audit of real CaseCrack/Venator flows."""

    def __init__(self, seed: int = 42, deterministic: bool = True):
        self._seed = seed
        self._rng = random.Random(seed)
        self._traces: list[AuditTrace] = []

    def run(self, scenario: IntegrationScenario) -> IntegrationResult:
        """Execute a full integration audit scenario."""
        # 1. Build real PSE (with real Grammar, real Arbiter, real WeightTuner)
        pse = self._build_real_pse()
        ctx = self._build_context(scenario)
        defense = scenario.defense

        signal_reports = []
        weight_reports = []
        feedback_reports = []

        for cycle in range(scenario.cycles):
            # Maybe shift defense profile mid-scan
            defense = self._maybe_shift_defense(scenario, cycle)
            ctx = self._maybe_shift_context(ctx, scenario, cycle, defense)

            # ---- SYNTHESIZE (real engines) ----
            result = pse.synthesize_payloads(ctx)
            payloads = result.payloads or []

            # ---- AUDIT: Signal Presence ----
            signal_reports.append(self._audit_signal_presence(payloads, ctx, cycle))

            # ---- AUDIT: Weight Usage ----
            weight_reports.append(self._audit_weight_usage(pse, payloads, cycle))

            # ---- EXECUTE against TargetStub ----
            for i, p in enumerate(payloads[:5]):
                verdict = defense.evaluate(p.payload, cycle * 5 + i)
                evidence = verdict == FeedbackType.EXECUTED_SUCCESSFULLY

                # ---- FEEDBACK (real propagation) ----
                obs_before = pse._weight_tuner._total_observations
                cal_before = pse._weight_tuner._total_calibrations

                pse.record_feedback(
                    payload=p, context=ctx,
                    feedback_type=verdict.value,
                    response_status=200 if evidence else 403,
                    evidence_found=evidence,
                )

                obs_after = pse._weight_tuner._total_observations
                cal_after = pse._weight_tuner._total_calibrations

                feedback_reports.append(FeedbackPropagationReport(
                    cycle=cycle,
                    events_sent=1,
                    tuner_obs_before=obs_before,
                    tuner_obs_after=obs_after,
                    tuner_calibrations_before=cal_before,
                    tuner_calibrations_after=cal_after,
                    reward_values=[FeedbackEvent._reward_map().get(verdict, 0.0)],
                    feedback_types=[verdict.value],
                    weights_changed=(cal_after > cal_before),
                ))

        # ---- AUDIT: Decision Causality (post-run) ----
        causality = self._audit_causality(pse, ctx, payloads)

        return IntegrationResult(
            scenario=scenario,
            signal_reports=signal_reports,
            weight_reports=weight_reports,
            feedback_reports=feedback_reports,
            causality=causality,
            final_weights=pse._weight_tuner.get_current_weights(),
        )

    def _build_real_pse(self) -> PayloadSynthesisEngine:
        """Create a real PSE with mock-only LLM bridge (expensive/slow)."""
        pse = PayloadSynthesisEngine()
        pse._ensure_initialised()
        # Mock the LLM bridge to avoid network calls
        pse._llm_bridge = _NoOpLLMBridge()
        return pse
```

### The Four Audit Methods (pseudocode)

```python
def _audit_signal_presence(self, payloads, ctx, cycle) -> SignalPresenceReport:
    signals_present = {s: 0 for s in SIGNAL_NAMES}
    signals_values = {s: [] for s in SIGNAL_NAMES}
    for p in payloads:
        for s in SIGNAL_NAMES:
            v = getattr(p, s, 0.0)
            if v != 0.0:
                signals_present[s] += 1
            signals_values[s].append(v)

    invariant = [s for s in SIGNAL_NAMES if len(set(signals_values[s])) <= 1]
    zero = [s for s in SIGNAL_NAMES if signals_present[s] == 0]

    return SignalPresenceReport(
        cycle=cycle, total_payloads=len(payloads),
        signals_present=signals_present,
        signals_contextual={s: len(set(signals_values[s])) for s in SIGNAL_NAMES},
        zero_signals=zero, invariant_signals=invariant,
    )


def _audit_weight_usage(self, pse, payloads, cycle) -> WeightUsageReport:
    tuner_w = pse._weight_tuner.get_current_weights()
    arbiter_w = {s: getattr(pse._arbiter, f"_w_{s.split('_')[0]}", None)
                 for s in SIGNAL_NAMES}  # simplified — real mapping needed

    # Check sync
    sync = all(
        abs(tuner_w.get(s, 0) - arbiter_w.get(s, 0)) < 1e-6
        for s in SIGNAL_NAMES if arbiter_w.get(s) is not None
    )

    # Compute R²: score ≈ Σ(signal_i × weight_i)
    predicted = []
    actual = []
    for p in payloads:
        pred = sum(getattr(p, s, 0) * tuner_w.get(s, 0) for s in SIGNAL_NAMES)
        predicted.append(pred)
        actual.append(p.score)

    r2 = _compute_r_squared_simple(actual, predicted)

    return WeightUsageReport(
        cycle=cycle, arbiter_weights=arbiter_w, tuner_weights=tuner_w,
        weight_arbiter_sync=sync, weight_rank_correlation=0.0,
        score_explained_by_weights=r2,
    )


def _audit_causality(self, pse, ctx, last_payloads) -> CausalityReport:
    # Test 1: Counterfactual — static priors vs learned weights
    learned_w = pse._weight_tuner.get_current_weights()
    rank_learned = [p.score for p in last_payloads]

    pse._arbiter.update_weights(STATIC_PRIORS)
    result_static = pse._arbiter.arbitrate(ctx, ...)  # re-score
    rank_static = [p.score for p in result_static]
    pse._arbiter.update_weights(learned_w)  # restore

    counterfactual_different = (rank_learned != rank_static)

    # Test 2: Signal attribution — ablate each signal
    attribution = {}
    for s in SIGNAL_NAMES:
        ablated = dict(learned_w)
        ablated[s] = 0.0
        total = sum(abs(v) for v in ablated.values())
        ablated = {k: v/total for k, v in ablated.items()} if total > 0 else ablated
        pse._arbiter.update_weights(ablated)
        result_ablated = pse._arbiter.arbitrate(ctx, ...)
        tau = _kendall_tau(rank_learned, [p.score for p in result_ablated])
        attribution[s] = tau
    pse._arbiter.update_weights(learned_w)  # restore

    influential = [s for s, tau in attribution.items() if tau < 0.90]

    return CausalityReport(
        counterfactual_different=counterfactual_different,
        signal_attribution=attribution,
        influential_signals=influential,
    )
```

---

## 6. Critical Gaps to Address Before Implementation

### Gap 1: Feedback Loop Not Closed in Production (BLOCKING)

**File**: `runner.py` — `_synthesize_payloads_for()` at line ~953

The runner calls `pse.synthesize_payloads(ctx)` but never calls
`pse.record_feedback()`.  Each payload is sent to the target by the
`CommandExecutor`, which receives HTTP responses, but there is no bridge from
the CommandExecutor back to the PSE.

**Required wiring**:
```
CommandExecutor.on_tool_complete(result)
  → classify result → FeedbackType
  → Runner._record_pse_feedback(payload, ctx, feedback_type, ...)
    → pse.record_feedback(...)
```

This is a **production code change**, not test infrastructure.  Without it,
the WeightTuner never learns in real scans.  The Integration Audit should
*test* this wiring once implemented.

**Alternate approach for initial auditing**: The Integration Audit Mode can
close the loop itself (as designed above) — it calls `pse.record_feedback()`
directly with TargetStub verdicts.  This validates the PSE internals even
before the production caller is updated.

### Gap 2: Arbiter Weight Field Mapping

The `PayloadArbiter` uses private fields `_w_bypass`, `_w_execute`, etc.
The `WeightTuner` uses dict keys `"bypass_score"`, `"execute_score"`, etc.
The mapping is manually maintained in `update_weights()`.

The Integration Audit should verify the mapping is complete by checking:
```python
for s in SIGNAL_NAMES:
    assert s in arbiter.update_weights.__code__.co_varnames
```

### Gap 3: Non-Determinism from Hash-Based Jitter

The `WeightTuner.observe()` uses Python's `hash()` for payload jitter, which
is randomized per process.  The Integration Audit must either:
- Set `PYTHONHASHSEED=0` for deterministic runs, or
- Run each scenario 3x and assert verdicts are consistent across runs

**Recommendation**: Support both modes — `deterministic=True` sets
`PYTHONHASHSEED=0` via `os.environ` before PSE import; stochastic mode
runs 3x and requires ≥2/3 pass.

### Gap 4: LLM Bridge Dependency

The real PSE calls the LLM bridge for fallback synthesis.  In integration
mode, we need a mock that returns structurally valid payloads without network
calls.  The mock should return payloads that vary in stealth/encoding to ensure
signal differentiation.

```python
class _NoOpLLMBridge:
    """Deterministic LLM stub for integration testing."""
    def generate_payloads(self, context, **kwargs):
        # Return 3 fixed payloads that vary in encoding/stealth
        return [
            "<svg/onload=alert(document.domain)>",
            "%3Csvg%2Fonload%3Dalert(1)%3E",
            "<details open ontoggle=alert(1)>",
        ]
```

### Gap 5: Context Evolution Across Cycles

In real scans, the `SynthesisContext` evolves as findings accumulate:
`known_blocked_patterns` grows, `prior_attempts_on_target` increases,
`success_rate_on_target` changes.  The Integration Audit should mirror this:

```python
def _evolve_context(self, ctx, cycle, feedback_history):
    """Update context based on accumulated feedback."""
    blocked = set(ctx.known_blocked_patterns)
    bypassed = set(ctx.known_bypassed_patterns)
    for fb in feedback_history:
        if fb.feedback_type == FeedbackType.BLOCKED_BY_WAF:
            blocked.add(fb.payload_snippet)
        elif fb.feedback_type in (FeedbackType.BYPASSED_WAF, FeedbackType.EXECUTED_SUCCESSFULLY):
            bypassed.add(fb.payload_snippet)

    return replace(ctx,
        known_blocked_patterns=frozenset(blocked),
        known_bypassed_patterns=frozenset(bypassed),
        prior_attempts_on_target=ctx.prior_attempts_on_target + cycle,
        success_rate_on_target=len([f for f in feedback_history if f.is_positive]) / max(1, len(feedback_history)),
    )
```

---

## 7. Verdict Matrix

Each scenario produces verdicts across all four dimensions:

```
┌──────────────────────┬───────────┬───────────┬───────────┬───────────┐
│ Scenario             │  Signal   │  Weight   │ Feedback  │ Causality │
│                      │ Presence  │  Usage    │  Propag.  │           │
├──────────────────────┼───────────┼───────────┼───────────┼───────────┤
│ xss_cloudflare       │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │
│ sqli_chain           │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │
│ waf_shift            │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │
│ hypothesis_driven    │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │
│ cross_target_intel   │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │ PASS/FAIL │
└──────────────────────┴───────────┴───────────┴───────────┴───────────┘
```

**Overall PASS**: All cells PASS.  
**WARN**: ≤ 2 cells FAIL, no FAIL in "Feedback Propagation" column.  
**FAIL**: Any "Feedback Propagation" FAIL, or > 2 cells FAIL.

---

## 8. Relationship to Existing Infrastructure

```
Existing (synthetic):                    New (integration):
┌──────────────────────┐                ┌──────────────────────┐
│ UU-1..UU-8 Probes    │                │ IntegrationAuditor   │
│ (WeightTuner only)   │                │ (full PSE pipeline)  │
│                      │                │                      │
│ Synthetic GT weights │                │ Real _compute_*()    │
│ Synthetic signals    │                │ Real Grammar/Forge   │
│ Direct observe()     │                │ Real record_feedback │
│ No Arbiter involved  │                │ Real Arbiter scoring │
│                      │                │ TargetStub verdicts  │
│ Tests: weight tuner  │                │ Tests: end-to-end    │
│ learning dynamics    │                │ signal→weight→score  │
└────────┬─────────────┘                └────────┬─────────────┘
         │                                       │
         ▼                                       ▼
┌──────────────────────┐                ┌──────────────────────┐
│ AuditPyramid         │                │ (future)             │
│ Tier1/2/3 + Modes    │                │ Production wiring    │
│ DifferentialTester   │                │ Runner → PSE.record_ │
│ PatternDetector      │                │ feedback() → real    │
│ SystemScorecard      │                │ HTTP response loop   │
└──────────────────────┘                └──────────────────────┘
```

**Key principle**: The integration audit does NOT replace the synthetic probes.
The probes test *internal dynamics* (edge cases, adversarial inputs, decay
behavior).  The integration audit tests *end-to-end wiring* (do real scoring
functions produce meaningful signals? do real weights influence real rankings?
does feedback actually propagate?).

---

## 9. Estimated Scope

| Component | Lines (est.) | Complexity |
|-----------|-------------|------------|
| `DefenseProfile` + `TargetStub` | ~100 | Low — deterministic pattern matching |
| `IntegrationScenario` dataclass | ~50 | Low — config container |
| `IntegrationAuditor` core | ~300 | Medium — orchestration + context evolution |
| Signal presence audit | ~60 | Low — field inspection |
| Weight usage audit | ~80 | Medium — R² computation, sync check |
| Feedback propagation audit | ~60 | Low — counter comparison |
| Decision causality audit | ~120 | High — counterfactual + attribution |
| 5 scenario templates | ~150 | Low — config dicts |
| `_NoOpLLMBridge` | ~30 | Low — fixed responses |
| `test_integration_audit.py` | ~200 | Medium — pytest wrappers |
| **Total** | **~1150** | |

---

## 10. Recommended Implementation Order

1. **DefenseProfile + TargetStub** — the simulated target environment
2. **IntegrationScenario + IntegrationResult** — data structures
3. **IntegrationAuditor.run()** — core loop (synthesis → execute → feedback)
4. **Signal Presence audit** — easiest, validates the pipeline produces data
5. **Feedback Propagation audit** — validates the loop is closed
6. **Weight Usage audit** — validates weights flow to arbiter
7. **Decision Causality audit** — hardest, validates causal chains
8. **5 scenario templates** — exercise different code paths
9. **test_integration_audit.py** — pytest integration
10. **Production wiring (Runner → PSE.record_feedback)** — separate PR, the real fix
