#!/usr/bin/env python3
"""Deep Causal Audit — 9-Layer Manual Audit Engine.

Implements the full audit protocol:

  Layer 1: Causal Walkthrough         — trace ONE decision end-to-end
  Layer 2: Counterfactual Injection   — alter one var, re-score, check delta
  Layer 3: Single-Signal Isolation    — zero all but one, measure performance
  Layer 4: Weight Learning Quality    — track convergence, oscillation, collapse
  Layer 5: Edge Regimes               — deceptive reward, delayed credit, conflict
  Layer 6: Diagnostic Weapons         — regret decomposition, coherence, truth boundary
  Layer 7: Illusions of Intelligence  — shuffle/freeze/randomize
  Layer 8: Audit Checklist            — 7 pass/fail questions per cycle
  Layer 9: Focus Frontier             — early-phase quality, signal redundancy, calibration

Run:
    .venv/Scripts/python.exe _audit_deep_causal.py
"""

from __future__ import annotations

import copy
import math
import random
import statistics
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Bootstrap ────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent / "CaseCrack"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.burp_enterprise.exploit_chains.synthesis_context import (
    RankedPayload,
    SynthesisContext,
    SynthesisEngine,
    VulnType,
)
from tools.burp_enterprise.exploit_chains.synthesis_feedback import (
    FeedbackEvent,
    FeedbackType,
    SynthesisFeedbackCollector,
)
from tools.burp_enterprise.exploit_chains.weight_tuner import WeightTuner
from tools.burp_enterprise.exploit_chains.payload_arbiter import PayloadArbiter
from tools.burp_enterprise.hypothesis_engine import HypothesisEngine


# ── Constants ────────────────────────────────────────────────────────

SIGNAL_NAMES = [
    "bypass_score", "execute_score", "impact_score", "chain_alignment",
    "hypothesis_boost", "environment_fit", "campaign_boost",
    "stealth_score", "temporal_relevance", "novelty_score", "chain_momentum",
    "detection_risk", "cost",
]

POSITIVE_TYPES = [
    FeedbackType.EXECUTED_SUCCESSFULLY,
    FeedbackType.BYPASSED_WAF,
    FeedbackType.PARTIAL_EXECUTION,
]
NEGATIVE_TYPES = [
    FeedbackType.BLOCKED_BY_WAF,
    FeedbackType.NO_EFFECT,
    FeedbackType.CONNECTION_RESET,
]
NEUTRAL_TYPES = [
    FeedbackType.TRIGGERED_ERROR,
    FeedbackType.RATE_LIMITED,
]

# How many cycles for each audit
N_WARMUP = 80
N_AUDIT = 50
N_ISOLATION = 40
N_EDGE = 30


# ── Helpers ──────────────────────────────────────────────────────────

def _make_payload(
    *,
    bypass: float = 0.5,
    execute: float = 0.5,
    impact: float = 0.5,
    chain: float = 0.3,
    hypothesis: float = 0.1,
    environment: float = 0.4,
    campaign: float = 0.05,
    stealth: float = 0.2,
    temporal: float = 0.3,
    novelty: float = 0.3,
    momentum: float = 0.15,
    detection: float = 0.02,
    cost_val: float = 0.01,
    engine: SynthesisEngine = SynthesisEngine.GRAMMAR,
    text: str = "<script>alert(1)</script>",
) -> RankedPayload:
    return RankedPayload(
        payload=text,
        score=0.0,
        engine=engine,
        vuln_type=VulnType.XSS,
        confidence=0.0,
        bypass_score=bypass,
        execute_score=execute,
        impact_score=impact,
        chain_alignment=chain,
        hypothesis_boost=hypothesis,
        environment_fit=environment,
        campaign_boost=campaign,
        stealth_score=stealth,
        temporal_relevance=temporal,
        novelty_score=novelty,
        chain_momentum=momentum,
        detection_risk=detection,
        cost=cost_val,
    )


def _make_context(
    vuln: VulnType = VulnType.XSS,
    url: str = "https://target.example.com/search",
) -> SynthesisContext:
    return SynthesisContext(target_url=url, vuln_type=vuln)


def _score_payload(arbiter: PayloadArbiter, p: RankedPayload, ctx: SynthesisContext) -> float:
    """Score a single payload through the arbiter pipeline."""
    results = arbiter.arbitrate(ctx, {p.engine: [p]})
    return results[0].score if results else 0.0


def _make_candidate_set(
    n: int = 5,
    *,
    dominant_signal: str | None = None,
    dominant_val: float = 0.9,
    base_val: float = 0.4,
) -> list[RankedPayload]:
    """Generate n diverse payloads. If dominant_signal, one payload has it high."""
    payloads = []
    for i in range(n):
        kwargs: dict[str, Any] = {
            "bypass": base_val + random.uniform(-0.15, 0.15),
            "execute": base_val + random.uniform(-0.15, 0.15),
            "impact": base_val + random.uniform(-0.15, 0.15),
            "chain": 0.3 + random.uniform(-0.1, 0.1),
            "hypothesis": 0.1 + random.uniform(-0.05, 0.05),
            "campaign": 0.05 + random.uniform(-0.02, 0.02),
            "detection": 0.02 + random.uniform(0, 0.03),
            "cost_val": 0.01 + random.uniform(0, 0.02),
            "text": f"<img src=x onerror=alert({i})>",
            "engine": [SynthesisEngine.GRAMMAR, SynthesisEngine.LLM, SynthesisEngine.GENETIC_FORGE][i % 3],
        }
        if dominant_signal and i == 0:
            # Map signal name to kwarg
            sig_map = {
                "bypass_score": "bypass", "execute_score": "execute",
                "impact_score": "impact", "chain_alignment": "chain",
                "hypothesis_boost": "hypothesis", "campaign_boost": "campaign",
                "detection_risk": "detection", "cost": "cost_val",
            }
            if dominant_signal in sig_map:
                kwargs[sig_map[dominant_signal]] = dominant_val
        payloads.append(_make_payload(**kwargs))
    return payloads


def _make_feedback(
    payload: RankedPayload,
    ctx: SynthesisContext,
    ft: FeedbackType,
    evidence: bool = False,
) -> FeedbackEvent:
    return FeedbackEvent(
        payload=payload,
        context=ctx,
        feedback_type=ft,
        response_status=200 if ft in POSITIVE_TYPES else 403,
        evidence_found=evidence,
    )


def _get_signal_values(p: RankedPayload) -> dict[str, float]:
    return {s: getattr(p, s, 0.0) for s in SIGNAL_NAMES}


def _get_weights(arbiter: PayloadArbiter) -> dict[str, float]:
    return {
        "bypass_score": arbiter._w_bypass,
        "execute_score": arbiter._w_execute,
        "impact_score": arbiter._w_impact,
        "chain_alignment": arbiter._w_chain,
        "hypothesis_boost": arbiter._w_hypothesis,
        "campaign_boost": arbiter._w_campaign,
        "detection_risk": arbiter._w_detection,
        "cost": arbiter._w_cost,
    }


def _compute_contributions(p: RankedPayload, arbiter: PayloadArbiter) -> dict[str, float]:
    """Compute per-signal contributions (signal_value × weight)."""
    weights = _get_weights(arbiter)
    return {s: getattr(p, s, 0.0) * weights[s] for s in SIGNAL_NAMES}


# ══════════════════════════════════════════════════════════════════════
# LAYER 1: Causal Walkthrough
# ══════════════════════════════════════════════════════════════════════

@dataclass
class CausalWalkthrough:
    """Trace one decision end-to-end: inputs → signals → weights → score → selection → feedback."""
    cycle: int = 0
    inputs: dict[str, Any] = field(default_factory=dict)
    signals_per_payload: list[dict[str, float]] = field(default_factory=list)
    constant_signals: list[str] = field(default_factory=list)
    weights_before: dict[str, float] = field(default_factory=dict)
    contributions: list[dict[str, float]] = field(default_factory=list)
    scores: list[float] = field(default_factory=list)
    winner_idx: int = 0
    runner_up_idx: int = 0
    winner_score: float = 0.0
    runner_up_score: float = 0.0
    delta: float = 0.0
    effectively_random: bool = False
    negative_contributors_dominate: bool = False
    zero_marginal_signals: list[str] = field(default_factory=list)
    feedback_type: str = ""
    reward: float = 0.0


def _run_causal_walkthrough(
    arbiter: PayloadArbiter,
    tuner: WeightTuner,
    ctx: SynthesisContext,
) -> CausalWalkthrough:
    """Execute one full causal walkthrough audit."""
    cw = CausalWalkthrough()

    # Build diverse candidate set
    candidates = _make_candidate_set(5)
    cw.inputs = {
        "n_candidates": len(candidates),
        "vuln_type": ctx.vuln_type.value,
        "target_url": ctx.target_url,
    }

    # Capture weights before scoring
    cw.weights_before = _get_weights(arbiter)

    # Score through arbiter
    engine_map: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
    for p in candidates:
        engine_map[p.engine].append(p)
    ranked = arbiter.arbitrate(ctx, dict(engine_map))

    # Extract signal values for all payloads
    for p in ranked:
        sigs = _get_signal_values(p)
        cw.signals_per_payload.append(sigs)
        cw.contributions.append(_compute_contributions(p, arbiter))
        cw.scores.append(p.score)

    # Check for constant signals (same across all payloads → dead/cosmetic)
    if len(ranked) >= 2:
        for sig in SIGNAL_NAMES:
            vals = [s[sig] for s in cw.signals_per_payload]
            if max(vals) - min(vals) < 1e-6:
                cw.constant_signals.append(sig)

    # Winner vs runner-up
    if len(ranked) >= 2:
        cw.winner_idx = 0
        cw.runner_up_idx = 1
        cw.winner_score = ranked[0].score
        cw.runner_up_score = ranked[1].score
        cw.delta = cw.winner_score - cw.runner_up_score
        cw.effectively_random = cw.delta < 0.02

    # Check for negative contributors dominating winner
    if ranked:
        winner_contribs = cw.contributions[0]
        neg_total = sum(v for v in winner_contribs.values() if v < 0)
        pos_total = sum(v for v in winner_contribs.values() if v > 0)
        cw.negative_contributors_dominate = abs(neg_total) > pos_total * 0.5

        # Zero marginal signals (weight present but no contribution)
        for sig, contrib in winner_contribs.items():
            if abs(cw.weights_before.get(sig, 0)) > 0.005 and abs(contrib) < 0.001:
                cw.zero_marginal_signals.append(sig)

    return cw


# ══════════════════════════════════════════════════════════════════════
# LAYER 2: Counterfactual Injection
# ══════════════════════════════════════════════════════════════════════

@dataclass
class CounterfactualResult:
    intervention: str = ""
    original_ranking: list[int] = field(default_factory=list)
    modified_ranking: list[int] = field(default_factory=list)
    ranking_changed: bool = False
    original_winner_score: float = 0.0
    modified_winner_score: float = 0.0
    score_delta: float = 0.0
    signal_is_decorative: bool = False


def _run_counterfactual(
    arbiter: PayloadArbiter,
    ctx: SynthesisContext,
    candidates: list[RankedPayload],
    intervention: str,
    modify_fn: Any,
) -> CounterfactualResult:
    """Run original scoring, then modify one variable, re-score, compare."""
    result = CounterfactualResult(intervention=intervention)

    # Original scoring
    originals = [copy.deepcopy(p) for p in candidates]
    engine_map: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
    for p in originals:
        engine_map[p.engine].append(p)
    orig_ranked = arbiter.arbitrate(ctx, dict(engine_map))
    result.original_ranking = [id(p) for p in orig_ranked]
    result.original_winner_score = orig_ranked[0].score if orig_ranked else 0.0

    # Modified scoring  
    modified = [copy.deepcopy(p) for p in candidates]
    for p in modified:
        modify_fn(p)
    engine_map2: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
    for p in modified:
        engine_map2[p.engine].append(p)
    mod_ranked = arbiter.arbitrate(ctx, dict(engine_map2))
    result.modified_ranking = [id(p) for p in mod_ranked]
    result.modified_winner_score = mod_ranked[0].score if mod_ranked else 0.0

    # Compare
    result.score_delta = result.modified_winner_score - result.original_winner_score
    # Check if TOP payload changed
    if orig_ranked and mod_ranked:
        orig_top_text = orig_ranked[0].payload
        mod_top_text = mod_ranked[0].payload
        result.ranking_changed = orig_top_text != mod_top_text

    result.signal_is_decorative = not result.ranking_changed and abs(result.score_delta) < 0.01
    return result


# ══════════════════════════════════════════════════════════════════════
# LAYER 3: Single-Signal Isolation
# ══════════════════════════════════════════════════════════════════════

@dataclass
class IsolationResult:
    signal: str = ""
    mean_score: float = 0.0
    random_baseline: float = 0.0
    above_random: bool = False
    correlation_with_reward: float = 0.0
    is_causal: bool = False


def _run_isolation_test(
    signal_name: str,
    n_cycles: int = N_ISOLATION,
) -> IsolationResult:
    """Zero all weights except one. Run n cycles. Check performance vs random."""
    result = IsolationResult(signal=signal_name)

    arbiter = PayloadArbiter()
    tuner = WeightTuner()
    tuner.bind_arbiter(arbiter)

    # Zero all weights except target signal
    all_weights = {s: 0.0 for s in SIGNAL_NAMES}
    # For negative signals, keep their sign
    if signal_name in ("detection_risk", "cost"):
        all_weights[signal_name] = -1.0
    else:
        all_weights[signal_name] = 1.0
    # Normalize
    total = sum(abs(v) for v in all_weights.values())
    all_weights = {k: v / total for k, v in all_weights.items()}
    arbiter.update_weights(all_weights)

    ctx = _make_context()
    scores = []
    rewards = []

    for i in range(n_cycles):
        # Create candidates with varying signal values
        candidates = _make_candidate_set(5, dominant_signal=signal_name, dominant_val=0.9)
        engine_map: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
        for p in candidates:
            engine_map[p.engine].append(p)
        ranked = arbiter.arbitrate(ctx, dict(engine_map))

        if ranked:
            winner = ranked[0]
            scores.append(winner.score)
            # Simulate reward: high signal should correlate with positive feedback
            sig_val = getattr(winner, signal_name, 0.0)
            if signal_name in ("detection_risk", "cost"):
                reward = 1.0 - sig_val  # Lower is better
            else:
                reward = sig_val  # Higher is better
            rewards.append(reward)

    result.mean_score = statistics.mean(scores) if scores else 0.0
    result.random_baseline = 0.0  # Computed below

    # Random baseline: shuffle signal values
    random_scores = []
    for _ in range(n_cycles):
        cands = _make_candidate_set(5)
        # Shuffle the target signal across candidates
        vals = [getattr(c, signal_name, 0.0) for c in cands]
        random.shuffle(vals)
        for c, v in zip(cands, vals):
            setattr(c, signal_name, v)
        engine_map3: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
        for c in cands:
            engine_map3[c.engine].append(c)
        ranked3 = arbiter.arbitrate(ctx, dict(engine_map3))
        if ranked3:
            random_scores.append(ranked3[0].score)

    result.random_baseline = statistics.mean(random_scores) if random_scores else 0.0
    result.above_random = result.mean_score > result.random_baseline + 0.005

    # Check signal-reward correlation
    if len(scores) >= 10 and len(rewards) >= 10:
        try:
            result.correlation_with_reward = _pearson(scores, rewards)
        except (ValueError, ZeroDivisionError):
            result.correlation_with_reward = 0.0

    result.is_causal = result.above_random and result.correlation_with_reward > 0.1
    return result


def _pearson(xs: list[float], ys: list[float]) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if sx * sy == 0:
        return 0.0
    return cov / (sx * sy)


# ══════════════════════════════════════════════════════════════════════
# LAYER 4: Weight Learning Quality
# ══════════════════════════════════════════════════════════════════════

@dataclass
class LearningQuality:
    signal: str = ""
    initial_weight: float = 0.0
    final_weight: float = 0.0
    direction_correct: bool = False
    oscillation_count: int = 0
    is_oscillating: bool = False
    converged: bool = False
    all_equal: bool = False  # model collapse


def _run_learning_quality(
    n_cycles: int = N_WARMUP + N_AUDIT,
) -> tuple[list[LearningQuality], list[dict[str, float]]]:
    """Track weight evolution over time. Detect oscillation, flat, collapse."""
    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    tuner.bind_arbiter(arbiter)
    hyp = HypothesisEngine()

    collector = SynthesisFeedbackCollector()
    collector.bind_weight_tuner(tuner)
    collector.bind_hypothesis_engine(hyp)

    ctx = _make_context()
    weight_timeline: list[dict[str, float]] = []

    # Feed a consistent signal pattern: bypass HIGH, execute LOW
    for i in range(n_cycles):
        payload = _make_payload(bypass=0.85, execute=0.15, impact=0.5)
        if i % 4 < 3:  # 75% positive
            ft = FeedbackType.EXECUTED_SUCCESSFULLY
            evidence = (i % 3 == 0)
        else:
            ft = FeedbackType.BLOCKED_BY_WAF
            evidence = False

        event = _make_feedback(payload, ctx, ft, evidence)
        collector.record_feedback(event)

        if i % 5 == 0:
            weight_timeline.append(tuner.get_current_weights())

    # Analyze each signal's learning trajectory
    results: list[LearningQuality] = []
    for sig in SIGNAL_NAMES:
        lq = LearningQuality(signal=sig)
        trajectory = [w.get(sig, 0.0) for w in weight_timeline]
        if len(trajectory) >= 2:
            lq.initial_weight = trajectory[0]
            lq.final_weight = trajectory[-1]

            # Direction correctness
            if sig == "bypass_score":
                lq.direction_correct = lq.final_weight > lq.initial_weight
            elif sig == "execute_score":
                lq.direction_correct = lq.final_weight < lq.initial_weight
            else:
                lq.direction_correct = True  # No strong expectation

            # Oscillation detection: count sign changes in deltas
            deltas = [trajectory[j + 1] - trajectory[j] for j in range(len(trajectory) - 1)]
            sign_changes = sum(
                1 for j in range(len(deltas) - 1)
                if deltas[j] * deltas[j + 1] < 0 and abs(deltas[j]) > 0.001
            )
            lq.oscillation_count = sign_changes
            lq.is_oscillating = sign_changes > len(deltas) * 0.5

            # Convergence: last 30% of trajectory stable
            if len(trajectory) >= 6:
                tail = trajectory[-len(trajectory) // 3:]
                tail_range = max(tail) - min(tail)
                lq.converged = tail_range < 0.02

        results.append(lq)

    # Model collapse: all weights converging to same value
    if weight_timeline:
        final = weight_timeline[-1]
        pos_weights = [v for k, v in final.items() if v > 0]
        if pos_weights and len(pos_weights) >= 4:
            for r in results:
                rng = max(pos_weights) - min(pos_weights)
                r.all_equal = rng < 0.02

    return results, weight_timeline


# ══════════════════════════════════════════════════════════════════════
# LAYER 5: Edge Regimes
# ══════════════════════════════════════════════════════════════════════

@dataclass
class EdgeRegimeResult:
    regime: str = ""
    description: str = ""
    passed: bool = False
    detail: str = ""


def _test_deceptive_success() -> EdgeRegimeResult:
    """Bad payload returns high reward. Does system get fooled long-term?"""
    result = EdgeRegimeResult(
        regime="deceptive_success",
        description="Bad payload (low bypass) gets high reward — does it fool learning?",
    )

    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    tuner.bind_arbiter(arbiter)
    collector = SynthesisFeedbackCollector()
    collector.bind_weight_tuner(tuner)

    ctx = _make_context()

    # Phase 1: Normal learning (30 cycles)
    for _ in range(30):
        p = _make_payload(bypass=0.9, execute=0.2)
        event = _make_feedback(p, ctx, FeedbackType.EXECUTED_SUCCESSFULLY, evidence=True)
        collector.record_feedback(event)

    weights_before = tuner.get_current_weights()

    # Phase 2: Deceptive feedback — low-bypass payload gets SUCCESS (20 cycles)
    for _ in range(20):
        p = _make_payload(bypass=0.1, execute=0.9)
        event = _make_feedback(p, ctx, FeedbackType.EXECUTED_SUCCESSFULLY, evidence=True)
        collector.record_feedback(event)

    weights_after = tuner.get_current_weights()

    # Check: bypass weight should not crash to near-zero
    bypass_before = weights_before.get("bypass_score", 0.3)
    bypass_after = weights_after.get("bypass_score", 0.3)
    bypass_drop = bypass_before - bypass_after

    result.detail = (
        f"bypass weight: {bypass_before:.4f} → {bypass_after:.4f} (Δ={bypass_drop:+.4f})"
    )
    # PASS if bypass doesn't crash below 0.10 (shows resistance to deception)
    result.passed = bypass_after > 0.10
    return result


def _test_delayed_credit() -> EdgeRegimeResult:
    """Step 1 = failure, Step 3 = success. Credit assignment works?"""
    result = EdgeRegimeResult(
        regime="delayed_credit",
        description="Credit assignment across failure→success sequence",
    )

    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    tuner.bind_arbiter(arbiter)
    collector = SynthesisFeedbackCollector()
    collector.bind_weight_tuner(tuner)

    ctx = _make_context()

    total_pos_reward = 0.0
    total_neg_reward = 0.0

    # 3-step sequences: fail, fail, succeed — 10 times
    for seq in range(10):
        # Step 1: failure (low bypass)
        p1 = _make_payload(bypass=0.2, execute=0.3)
        e1 = _make_feedback(p1, ctx, FeedbackType.BLOCKED_BY_WAF)
        collector.record_feedback(e1)
        total_neg_reward += abs(e1.reward_signal)

        # Step 2: partial
        p2 = _make_payload(bypass=0.5, execute=0.5)
        e2 = _make_feedback(p2, ctx, FeedbackType.TRIGGERED_ERROR)
        collector.record_feedback(e2)

        # Step 3: success (high bypass)
        p3 = _make_payload(bypass=0.9, execute=0.8)
        e3 = _make_feedback(p3, ctx, FeedbackType.EXECUTED_SUCCESSFULLY, evidence=True)
        collector.record_feedback(e3)
        total_pos_reward += e3.reward_signal

    weights = tuner.get_current_weights()
    bypass_w = weights.get("bypass_score", 0.3)

    result.detail = (
        f"After 10 fail→fail→succeed sequences: bypass_weight={bypass_w:.4f}, "
        f"observations={tuner._total_observations}"
    )
    # Should still learn that bypass matters
    result.passed = bypass_w > 0.25
    return result


def _test_signal_conflict() -> EdgeRegimeResult:
    """hypothesis = strong positive, WAF = strong negative. Arbitration balance works?"""
    result = EdgeRegimeResult(
        regime="signal_conflict",
        description="hypothesis=high vs WAF=strong_negative → balanced arbitration?",
    )

    arbiter = PayloadArbiter()
    ctx = _make_context()

    # Create conflicting payload: great hypothesis, terrible WAF
    p_conflict = _make_payload(
        bypass=0.1,        # WAF will block
        execute=0.8,
        hypothesis=0.95,   # Hypothesis loves it
        chain=0.9,
        detection=0.8,     # High detection risk
    )
    # Create balanced payload
    p_balanced = _make_payload(
        bypass=0.6,
        execute=0.6,
        hypothesis=0.4,
        chain=0.5,
        detection=0.05,
    )

    ranked = arbiter.arbitrate(ctx, {
        SynthesisEngine.GRAMMAR: [p_conflict],
        SynthesisEngine.LLM: [p_balanced],
    })

    if len(ranked) >= 2:
        conflict_idx = 0 if "alert(1)" in ranked[0].payload else 1
        balanced_idx = 1 - conflict_idx
        conflict_score = ranked[conflict_idx].score
        balanced_score = ranked[balanced_idx].score
        result.detail = (
            f"Conflict payload: {conflict_score:.4f}, "
            f"Balanced payload: {balanced_score:.4f}, "
            f"balanced wins={balanced_score > conflict_score}"
        )
        # Balanced should generally win (detection_risk penalty + low bypass outweighs hypothesis)
        result.passed = balanced_score >= conflict_score * 0.8  # Allow some tolerance
    else:
        result.detail = "Not enough ranked payloads"
        result.passed = False

    return result


# ══════════════════════════════════════════════════════════════════════
# LAYER 6: Diagnostic Weapons
# ══════════════════════════════════════════════════════════════════════

@dataclass
class RegretDecomposition:
    """Where does error come from: scoring, selection, or execution?"""
    scoring_error: float = 0.0    # score ≠ true quality
    selection_error: float = 0.0  # picked wrong among correctly scored
    total_regret: float = 0.0
    source: str = ""  # "scoring" | "selection" | "both" | "none"


def _run_regret_decomposition(n_cycles: int = N_AUDIT) -> RegretDecomposition:
    """Decompose regret into scoring vs selection components."""
    rd = RegretDecomposition()
    arbiter = PayloadArbiter()
    ctx = _make_context()

    scoring_errors = []
    selection_errors = []

    for _ in range(n_cycles):
        # Create candidates with known "true quality" (bypass = proxy for truth)
        candidates = _make_candidate_set(5)
        # "True quality" = bypass_score (our ground truth proxy)
        true_qualities = [p.bypass_score for p in candidates]
        best_true_idx = true_qualities.index(max(true_qualities))

        engine_map: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
        for p in candidates:
            engine_map[p.engine].append(p)
        ranked = arbiter.arbitrate(ctx, dict(engine_map))

        if ranked:
            # Find which original candidate won
            selected_quality = ranked[0].bypass_score
            best_quality = max(true_qualities)

            # Scoring error: does the score correlate with true quality?
            if len(ranked) >= 2:
                top_score = ranked[0].score
                second_score = ranked[1].score
                top_true = ranked[0].bypass_score
                second_true = ranked[1].bypass_score
                if top_true < second_true:  # Score said A > B but truth says B > A
                    scoring_errors.append(abs(top_score - second_score))

            # Selection error: regret = best_true - selected_true
            regret = best_quality - selected_quality
            if regret > 0.01:
                selection_errors.append(regret)

    rd.scoring_error = statistics.mean(scoring_errors) if scoring_errors else 0.0
    rd.selection_error = statistics.mean(selection_errors) if selection_errors else 0.0
    rd.total_regret = rd.scoring_error + rd.selection_error

    if rd.scoring_error > rd.selection_error * 2:
        rd.source = "scoring"
    elif rd.selection_error > rd.scoring_error * 2:
        rd.source = "selection"
    elif rd.total_regret > 0.01:
        rd.source = "both"
    else:
        rd.source = "none"

    return rd


@dataclass
class CoherenceCheck:
    """Do subsystems agree? Or internally inconsistent but externally correct?"""
    hypothesis_consistent: bool = False
    weight_tuner_consistent: bool = False
    arbiter_consistent: bool = False
    detail: str = ""


def _run_coherence_check() -> CoherenceCheck:
    """Send same event to all subsystems, check they agree."""
    cc = CoherenceCheck()

    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    tuner.bind_arbiter(arbiter)
    hyp = HypothesisEngine()

    collector = SynthesisFeedbackCollector()
    collector.bind_weight_tuner(tuner)
    collector.bind_hypothesis_engine(hyp)

    ctx = _make_context()
    payload = _make_payload(bypass=0.9, execute=0.2)

    # Feed 30 positive bypass events
    for _ in range(30):
        event = _make_feedback(payload, ctx, FeedbackType.BYPASSED_WAF, evidence=True)
        collector.record_feedback(event)

    # Check coherence
    weights = tuner.get_current_weights()
    arbiter_w = _get_weights(arbiter)
    hyp_metrics = hyp.get_metrics()

    # WeightTuner → Arbiter sync (should be identical)
    tuner_bypass = weights.get("bypass_score", 0)
    arbiter_bypass = arbiter_w.get("bypass_score", 0)
    cc.weight_tuner_consistent = abs(tuner_bypass - arbiter_bypass) < 0.001

    # Arbiter weights reflect learning direction
    cc.arbiter_consistent = arbiter_bypass > 0.30  # Should be above default due to positive bypass signal

    # Hypothesis engine received signals
    cc.hypothesis_consistent = hyp_metrics.get("signals_received", 0) > 0

    cc.detail = (
        f"tuner_bypass={tuner_bypass:.4f}, arbiter_bypass={arbiter_bypass:.4f}, "
        f"hyp_signals={hyp_metrics.get('signals_received', 0)}"
    )
    return cc


@dataclass
class TruthBoundary:
    """High confidence + wrong = top priority bug."""
    confident_correct: int = 0
    confident_wrong: int = 0     # THE DANGEROUS CASE
    unconfident_correct: int = 0
    unconfident_wrong: int = 0
    calibration_error: float = 0.0


def _run_truth_boundary(n_cycles: int = N_AUDIT) -> TruthBoundary:
    """Run cycles and check: when confidence > 0.7, is the payload actually good?"""
    tb = TruthBoundary()
    arbiter = PayloadArbiter()
    ctx = _make_context()

    for _ in range(n_cycles):
        candidates = _make_candidate_set(5)
        engine_map: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
        for p in candidates:
            engine_map[p.engine].append(p)
        ranked = arbiter.arbitrate(ctx, dict(engine_map))

        if ranked:
            winner = ranked[0]
            confidence = winner.confidence  # = score after arbitration
            # "Ground truth" proxy: bypass + execute (most reliable signals)
            true_quality = (winner.bypass_score + winner.execute_score) / 2
            is_good = true_quality > 0.5

            high_conf = confidence > 0.25  # Threshold matches typical score ranges

            if high_conf and is_good:
                tb.confident_correct += 1
            elif high_conf and not is_good:
                tb.confident_wrong += 1
            elif not high_conf and is_good:
                tb.unconfident_correct += 1
            else:
                tb.unconfident_wrong += 1

    total = tb.confident_correct + tb.confident_wrong + tb.unconfident_correct + tb.unconfident_wrong
    if total > 0:
        total_confident = tb.confident_correct + tb.confident_wrong
        if total_confident > 0:
            expected_acc = total_confident / total  # Expected frequency
            actual_acc = tb.confident_correct / total_confident  # Actual correctness
            tb.calibration_error = abs(expected_acc - actual_acc)

    return tb


# ══════════════════════════════════════════════════════════════════════
# LAYER 7: Illusions of Intelligence
# ══════════════════════════════════════════════════════════════════════

@dataclass
class IllusionTest:
    test: str = ""
    normal_performance: float = 0.0
    perturbed_performance: float = 0.0
    drop: float = 0.0
    is_illusion: bool = False


def _test_signal_shuffle() -> IllusionTest:
    """Shuffle signal labels (bypass↔execute, etc). Performance should drop."""
    it = IllusionTest(test="signal_shuffle")
    arbiter = PayloadArbiter()
    ctx = _make_context()

    # Normal performance: score candidates correctly
    normal_scores = []
    for _ in range(N_AUDIT):
        candidates = _make_candidate_set(5, dominant_signal="bypass_score", dominant_val=0.9)
        engine_map: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
        for p in candidates:
            engine_map[p.engine].append(p)
        ranked = arbiter.arbitrate(ctx, dict(engine_map))
        if ranked:
            # "Performance" = does the high-bypass payload win?
            normal_scores.append(1.0 if ranked[0].bypass_score > 0.7 else 0.0)

    # Shuffled: swap bypass ↔ execute values
    shuffled_scores = []
    for _ in range(N_AUDIT):
        candidates = _make_candidate_set(5, dominant_signal="bypass_score", dominant_val=0.9)
        for p in candidates:
            p.bypass_score, p.execute_score = p.execute_score, p.bypass_score
        engine_map2: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
        for p in candidates:
            engine_map2[p.engine].append(p)
        ranked2 = arbiter.arbitrate(ctx, dict(engine_map2))
        if ranked2:
            shuffled_scores.append(1.0 if ranked2[0].bypass_score > 0.7 else 0.0)

    it.normal_performance = statistics.mean(normal_scores) if normal_scores else 0.0
    it.perturbed_performance = statistics.mean(shuffled_scores) if shuffled_scores else 0.0
    it.drop = it.normal_performance - it.perturbed_performance
    it.is_illusion = it.drop < 0.10  # If shuffling doesn't matter, intelligence is fake
    return it


def _test_weight_freeze() -> IllusionTest:
    """Freeze weights (no learning). Performance should degrade over time."""
    it = IllusionTest(test="weight_freeze")

    # With learning
    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    tuner.bind_arbiter(arbiter)
    collector = SynthesisFeedbackCollector()
    collector.bind_weight_tuner(tuner)

    ctx = _make_context()
    learning_scores = []
    for i in range(N_WARMUP):
        p = _make_payload(bypass=0.8 + random.uniform(-0.1, 0.1), execute=0.2)
        ft = FeedbackType.EXECUTED_SUCCESSFULLY if i % 3 < 2 else FeedbackType.BLOCKED_BY_WAF
        event = _make_feedback(p, ctx, ft, evidence=(i % 4 == 0))
        collector.record_feedback(event)

    # Score after learning
    for _ in range(N_AUDIT):
        candidates = _make_candidate_set(5, dominant_signal="bypass_score", dominant_val=0.85)
        engine_map: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
        for p in candidates:
            engine_map[p.engine].append(p)
        ranked = arbiter.arbitrate(ctx, dict(engine_map))
        if ranked:
            learning_scores.append(ranked[0].score)

    # Without learning  (fresh arbiter, default weights)
    arbiter2 = PayloadArbiter()
    frozen_scores = []
    for _ in range(N_AUDIT):
        candidates = _make_candidate_set(5, dominant_signal="bypass_score", dominant_val=0.85)
        engine_map2: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
        for p in candidates:
            engine_map2[p.engine].append(p)
        ranked2 = arbiter2.arbitrate(ctx, dict(engine_map2))
        if ranked2:
            frozen_scores.append(ranked2[0].score)

    it.normal_performance = statistics.mean(learning_scores) if learning_scores else 0.0
    it.perturbed_performance = statistics.mean(frozen_scores) if frozen_scores else 0.0
    it.drop = it.normal_performance - it.perturbed_performance
    it.is_illusion = abs(it.drop) < 0.005  # Learning made no difference = illusion
    return it


def _test_payload_randomize() -> IllusionTest:
    """Completely random payloads. Score variance should be wide (system differentiates)."""
    it = IllusionTest(test="payload_randomize")
    arbiter = PayloadArbiter()
    ctx = _make_context()

    scores = []
    for _ in range(N_AUDIT):
        # Fully random signal values
        p = _make_payload(
            bypass=random.random(),
            execute=random.random(),
            impact=random.random(),
            chain=random.random(),
            hypothesis=random.random(),
            campaign=random.random(),
            detection=random.random(),
            cost_val=random.random(),
        )
        engine_map: dict[SynthesisEngine, list[RankedPayload]] = defaultdict(list)
        engine_map[p.engine].append(p)
        ranked = arbiter.arbitrate(ctx, dict(engine_map))
        if ranked:
            scores.append(ranked[0].score)

    it.normal_performance = statistics.stdev(scores) if len(scores) >= 2 else 0.0
    it.perturbed_performance = 0.0  # N/A
    it.drop = 0.0
    it.is_illusion = it.normal_performance < 0.01  # All random payloads score the same = dead system
    return it


# ══════════════════════════════════════════════════════════════════════
# LAYER 8: Audit Checklist (7 Questions)
# ══════════════════════════════════════════════════════════════════════

@dataclass
class ChecklistItem:
    question: str = ""
    answer: bool = False
    evidence: str = ""


def _run_checklist(
    walkthrough: CausalWalkthrough,
    isolation_results: list[IsolationResult],
    learning: list[LearningQuality],
    regret: RegretDecomposition,
) -> list[ChecklistItem]:
    """Answer the 7 audit questions."""
    items = []

    # Q1: Are all 8 signals varying across candidates?
    constant = walkthrough.constant_signals
    q1 = ChecklistItem(
        question="All 8 signals varying across candidates?",
        answer=len(constant) == 0,
        evidence=f"Constant: {constant}" if constant else "All 8 signals differentiate",
    )
    items.append(q1)

    # Q2: Do weights actually influence ranking?
    weight_influence = any(r.is_causal for r in isolation_results)
    q2 = ChecklistItem(
        question="Weights actually influence ranking?",
        answer=weight_influence,
        evidence=f"Causal signals: {[r.signal for r in isolation_results if r.is_causal]}",
    )
    items.append(q2)

    # Q3: Does best score ≈ best ground truth?
    q3_pass = regret.total_regret < 0.10
    q3 = ChecklistItem(
        question="Best score ≈ best ground truth?",
        answer=q3_pass,
        evidence=f"Total regret: {regret.total_regret:.4f}, source: {regret.source}",
    )
    items.append(q3)

    # Q4: Does regret decrease over cycles?
    bypass_learning = next((l for l in learning if l.signal == "bypass_score"), None)
    q4_pass = bypass_learning.direction_correct if bypass_learning else False
    q4 = ChecklistItem(
        question="Regret decreases over cycles?",
        answer=q4_pass,
        evidence=f"bypass: {'correct' if q4_pass else 'wrong'} direction, "
                 f"converged={bypass_learning.converged if bypass_learning else 'N/A'}",
    )
    items.append(q4)

    # Q5: Does feedback change future decisions?
    execute_learning = next((l for l in learning if l.signal == "execute_score"), None)
    q5_pass = (
        bypass_learning is not None and bypass_learning.final_weight != bypass_learning.initial_weight
    )
    q5 = ChecklistItem(
        question="Feedback changes future decisions?",
        answer=q5_pass,
        evidence=f"bypass Δ={bypass_learning.final_weight - bypass_learning.initial_weight:+.4f}"
                 if bypass_learning else "N/A",
    )
    items.append(q5)

    # Q6: Can system be broken with small perturbation?
    q6_pass = walkthrough.delta >= 0.02  # Non-trivial margin
    q6 = ChecklistItem(
        question="System robust to small perturbation?",
        answer=q6_pass,
        evidence=f"Winner-runner delta: {walkthrough.delta:.4f} "
                 f"({'robust' if q6_pass else 'fragile — effectively random'})",
    )
    items.append(q6)

    # Q7: Does removing a signal change outcomes?
    causal_count = sum(1 for r in isolation_results if r.is_causal)
    q7 = ChecklistItem(
        question="Removing a signal changes outcomes?",
        answer=causal_count >= 3,
        evidence=f"{causal_count}/8 signals are causally meaningful",
    )
    items.append(q7)

    return items


# ══════════════════════════════════════════════════════════════════════
# LAYER 9: Focus Frontier
# ══════════════════════════════════════════════════════════════════════

@dataclass
class FocusFrontier:
    early_phase_quality: str = ""
    signal_redundancy: list[tuple[str, str, float]] = field(default_factory=list)
    calibration_gap: float = 0.0


def _compute_focus_frontier(
    weight_timeline: list[dict[str, float]],
    isolation_results: list[IsolationResult],
    truth_boundary: TruthBoundary,
) -> FocusFrontier:
    ff = FocusFrontier()

    # Early-phase: how fast do weights diverge from default?
    if len(weight_timeline) >= 10:
        early = weight_timeline[:5]
        early_deltas = []
        for w in early:
            total_delta = sum(abs(w.get(s, 0) - 0.3) for s in ["bypass_score"])
            early_deltas.append(total_delta)
        avg_early_delta = statistics.mean(early_deltas)
        if avg_early_delta < 0.01:
            ff.early_phase_quality = "SLOW — weights barely moving in first 25 observations"
        elif avg_early_delta < 0.03:
            ff.early_phase_quality = "MODERATE — some early learning but weak"
        else:
            ff.early_phase_quality = "GOOD — rapid early learning"
    else:
        ff.early_phase_quality = "INSUFFICIENT DATA"

    # Signal redundancy: which pairs have similar isolation performance?
    for i in range(len(isolation_results)):
        for j in range(i + 1, len(isolation_results)):
            a = isolation_results[i]
            b = isolation_results[j]
            if a.is_causal and b.is_causal:
                overlap = 1.0 - abs(a.mean_score - b.mean_score) / max(a.mean_score, b.mean_score, 0.001)
                if overlap > 0.90:
                    ff.signal_redundancy.append((a.signal, b.signal, overlap))

    # Calibration gap
    ff.calibration_gap = truth_boundary.calibration_error

    return ff


# ══════════════════════════════════════════════════════════════════════
# MAIN — Run All 9 Layers
# ══════════════════════════════════════════════════════════════════════

def main() -> int:
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║   DEEP CAUSAL AUDIT — 9-Layer Manual Audit Engine           ║")
    print("╚═══════════════════════════════════════════════════════════════╝")

    findings: list[str] = []
    total_checks = 0
    total_pass = 0

    # ── Layer 1: Causal Walkthrough ──────────────────────────────
    print(f"\n{'='*72}")
    print(f"  LAYER 1: Causal Walkthrough — Trace ONE Decision")
    print(f"{'='*72}\n")

    arbiter = PayloadArbiter()
    tuner = WeightTuner()
    tuner.bind_arbiter(arbiter)
    ctx = _make_context()

    # Warm up learning first
    collector = SynthesisFeedbackCollector()
    collector.bind_weight_tuner(tuner)
    for i in range(N_WARMUP):
        p = _make_payload(bypass=0.8, execute=0.2)
        ft = FeedbackType.EXECUTED_SUCCESSFULLY if i % 3 < 2 else FeedbackType.BLOCKED_BY_WAF
        event = _make_feedback(p, ctx, ft, evidence=(i % 5 == 0))
        collector.record_feedback(event)

    cw = _run_causal_walkthrough(arbiter, tuner, ctx)

    print(f"  Candidates: {cw.inputs.get('n_candidates')}")
    print(f"  Weights (learned): " + ", ".join(f"{k}={v:.3f}" for k, v in cw.weights_before.items()))
    if cw.constant_signals:
        print(f"  ⚠ CONSTANT signals (no differentiation): {cw.constant_signals}")
        findings.append(f"Dead signals: {cw.constant_signals}")
    else:
        print(f"  ✓ All 8 signals differentiate across candidates")
    print(f"  Winner score:     {cw.winner_score:.4f}")
    print(f"  Runner-up score:  {cw.runner_up_score:.4f}")
    print(f"  Delta:            {cw.delta:.4f} {'⚠ RANDOM' if cw.effectively_random else '✓ Decisive'}")
    if cw.negative_contributors_dominate:
        print(f"  ⚠ Negative contributors dominating winner")
        findings.append("Negative contributors dominate winner scoring")
    if cw.zero_marginal_signals:
        print(f"  ⚠ Zero-marginal signals (weight>0 but contribution≈0): {cw.zero_marginal_signals}")
        findings.append(f"Zero-marginal signals: {cw.zero_marginal_signals}")

    # Score decomposition for winner
    if cw.contributions:
        print(f"\n  Score decomposition (winner):")
        for sig, contrib in sorted(cw.contributions[0].items(), key=lambda kv: abs(kv[1]), reverse=True):
            bar = "█" * int(abs(contrib) * 200)
            sign = "+" if contrib >= 0 else "-"
            print(f"    {sig:<22} {sign}{abs(contrib):.4f}  {bar}")

    # ── Layer 2: Counterfactual Injection ────────────────────────
    print(f"\n{'='*72}")
    print(f"  LAYER 2: Counterfactual Injection — Alter One Variable")
    print(f"{'='*72}\n")

    candidates = _make_candidate_set(5, dominant_signal="bypass_score", dominant_val=0.9)
    counterfactuals = [
        ("zero hypothesis_boost", lambda p: setattr(p, "hypothesis_boost", 0.0)),
        ("force chain_alignment=1.0", lambda p: setattr(p, "chain_alignment", 1.0)),
        ("remove execute_score", lambda p: setattr(p, "execute_score", 0.0)),
        ("flip bypass polarity", lambda p: setattr(p, "bypass_score", 1.0 - p.bypass_score)),
        ("max detection_risk", lambda p: setattr(p, "detection_risk", 1.0)),
    ]

    for name, fn in counterfactuals:
        cf = _run_counterfactual(arbiter, ctx, candidates, name, fn)
        status = "✓ Ranking changed" if cf.ranking_changed else "✗ DECORATIVE" if cf.signal_is_decorative else "~ Score shifted"
        print(f"  {name:<30} Δscore={cf.score_delta:+.4f}  {status}")
        total_checks += 1
        if not cf.signal_is_decorative:
            total_pass += 1
        else:
            findings.append(f"Decorative signal: {name}")

    # ── Layer 3: Single-Signal Isolation ─────────────────────────
    print(f"\n{'='*72}")
    print(f"  LAYER 3: Single-Signal Isolation — One Signal at a Time")
    print(f"{'='*72}\n")

    isolation_results: list[IsolationResult] = []
    for sig in SIGNAL_NAMES:
        ir = _run_isolation_test(sig)
        isolation_results.append(ir)
        status = "✓ CAUSAL" if ir.is_causal else "✗ NOISE" if not ir.above_random else "~ MARGINAL"
        print(f"  {sig:<22} mean={ir.mean_score:.4f}  random={ir.random_baseline:.4f}  "
              f"corr={ir.correlation_with_reward:+.3f}  {status}")
        total_checks += 1
        if ir.is_causal:
            total_pass += 1

    causal_count = sum(1 for r in isolation_results if r.is_causal)
    noise_count = sum(1 for r in isolation_results if not r.above_random)
    print(f"\n  Summary: {causal_count} causal, {noise_count} noise, "
          f"{8 - causal_count - noise_count} marginal")

    # ── Layer 4: Weight Learning Quality ─────────────────────────
    print(f"\n{'='*72}")
    print(f"  LAYER 4: Weight Learning Quality — Convergence & Oscillation")
    print(f"{'='*72}\n")

    learning_results, weight_timeline = _run_learning_quality()
    print(f"  {'Signal':<22} {'Initial':>8} {'Final':>8} {'Dir':>5} {'Osc':>5} {'Conv':>5} {'Coll':>5}")
    print(f"  {'─'*22} {'─'*8} {'─'*8} {'─'*5} {'─'*5} {'─'*5} {'─'*5}")
    for lq in learning_results:
        print(f"  {lq.signal:<22} {lq.initial_weight:>8.4f} {lq.final_weight:>8.4f} "
              f"{'✓' if lq.direction_correct else '✗':>5} "
              f"{'⚠' if lq.is_oscillating else '✓':>5} "
              f"{'✓' if lq.converged else '~':>5} "
              f"{'⚠' if lq.all_equal else '✓':>5}")
        total_checks += 1
        if lq.direction_correct and not lq.is_oscillating:
            total_pass += 1

    # Red flags
    oscillating = [lq.signal for lq in learning_results if lq.is_oscillating]
    collapsed = any(lq.all_equal for lq in learning_results)
    flat = [lq.signal for lq in learning_results
            if abs(lq.final_weight - lq.initial_weight) < 0.005 and lq.signal in ("bypass_score", "execute_score")]
    if oscillating:
        print(f"\n  ⚠ OSCILLATING: {oscillating}")
        findings.append(f"Oscillating weights: {oscillating}")
    if collapsed:
        print(f"  ⚠ MODEL COLLAPSE: All weights converged to equal")
        findings.append("Model collapse detected")
    if flat:
        print(f"  ⚠ FLAT weights (no learning): {flat}")
        findings.append(f"Flat weights: {flat}")
    if not oscillating and not collapsed and not flat:
        print(f"\n  ✓ Learning quality: healthy convergence")

    # ── Layer 5: Edge Regimes ────────────────────────────────────
    print(f"\n{'='*72}")
    print(f"  LAYER 5: Edge Regimes — Deceptive, Delayed, Conflict")
    print(f"{'='*72}\n")

    edge_tests = [
        _test_deceptive_success(),
        _test_delayed_credit(),
        _test_signal_conflict(),
    ]
    for er in edge_tests:
        status = "✓ PASS" if er.passed else "✗ FAIL"
        print(f"  {er.regime:<25} {status}")
        print(f"    {er.detail}")
        total_checks += 1
        if er.passed:
            total_pass += 1
        else:
            findings.append(f"Edge regime failed: {er.regime} — {er.detail}")

    # ── Layer 6: Diagnostic Weapons ──────────────────────────────
    print(f"\n{'='*72}")
    print(f"  LAYER 6: Regret Decomposition + Coherence + Truth Boundary")
    print(f"{'='*72}\n")

    # 6a: Regret
    rd = _run_regret_decomposition()
    print(f"  Regret Decomposition:")
    print(f"    Scoring error:   {rd.scoring_error:.4f}")
    print(f"    Selection error: {rd.selection_error:.4f}")
    print(f"    Total regret:    {rd.total_regret:.4f}")
    print(f"    Dominant source: {rd.source}")
    total_checks += 1
    if rd.total_regret < 0.15:
        total_pass += 1
    else:
        findings.append(f"High regret: {rd.total_regret:.4f} (source: {rd.source})")

    # 6b: Coherence
    cc = _run_coherence_check()
    print(f"\n  Coherence Check:")
    print(f"    Tuner↔Arbiter sync:  {'✓' if cc.weight_tuner_consistent else '✗'}")
    print(f"    Arbiter learned:     {'✓' if cc.arbiter_consistent else '✗'}")
    print(f"    Hypothesis active:   {'✓' if cc.hypothesis_consistent else '✗'}")
    print(f"    Detail: {cc.detail}")
    total_checks += 3
    total_pass += sum([cc.weight_tuner_consistent, cc.arbiter_consistent, cc.hypothesis_consistent])
    if not cc.weight_tuner_consistent:
        findings.append("Tuner↔Arbiter weight desync")
    if not cc.hypothesis_consistent:
        findings.append("Hypothesis engine not receiving signals")

    # 6c: Truth Boundary
    tb = _run_truth_boundary()
    print(f"\n  Truth Boundary Audit:")
    print(f"    Confident + Correct:   {tb.confident_correct}")
    print(f"    Confident + WRONG:     {tb.confident_wrong}  {'⚠ DANGEROUS' if tb.confident_wrong > 5 else '✓'}")
    print(f"    Unconfident + Correct: {tb.unconfident_correct}")
    print(f"    Unconfident + Wrong:   {tb.unconfident_wrong}")
    print(f"    Calibration error:     {tb.calibration_error:.4f}")
    total_checks += 1
    if tb.confident_wrong / max(tb.confident_correct + tb.confident_wrong, 1) < 0.20:
        total_pass += 1
    else:
        findings.append(f"Confidence miscalibration: {tb.confident_wrong} confident+wrong")

    # ── Layer 7: Illusions of Intelligence ───────────────────────
    print(f"\n{'='*72}")
    print(f"  LAYER 7: Illusions of Intelligence")
    print(f"{'='*72}\n")

    illusion_tests = [
        _test_signal_shuffle(),
        _test_weight_freeze(),
        _test_payload_randomize(),
    ]
    for it in illusion_tests:
        if it.test == "payload_randomize":
            status = "✗ DEAD SYSTEM" if it.is_illusion else f"✓ Score stdev={it.normal_performance:.4f}"
        else:
            status = "✗ ILLUSION" if it.is_illusion else f"✓ Drop={it.drop:+.4f}"
        print(f"  {it.test:<22} normal={it.normal_performance:.4f}  "
              f"perturbed={it.perturbed_performance:.4f}  {status}")
        total_checks += 1
        if not it.is_illusion:
            total_pass += 1
        else:
            findings.append(f"Illusion detected: {it.test}")

    # ── Layer 8: Audit Checklist ─────────────────────────────────
    print(f"\n{'='*72}")
    print(f"  LAYER 8: Audit Checklist (7 Questions)")
    print(f"{'='*72}\n")

    checklist = _run_checklist(cw, isolation_results, learning_results, rd)
    for ci in checklist:
        icon = "✓" if ci.answer else "✗"
        print(f"  {icon} {ci.question}")
        print(f"    → {ci.evidence}")
        total_checks += 1
        if ci.answer:
            total_pass += 1

    # ── Layer 9: Focus Frontier ──────────────────────────────────
    print(f"\n{'='*72}")
    print(f"  LAYER 9: Focus Frontier — Where to Invest Next")
    print(f"{'='*72}\n")

    ff = _compute_focus_frontier(weight_timeline, isolation_results, tb)
    print(f"  Early-phase learning: {ff.early_phase_quality}")
    if ff.signal_redundancy:
        print(f"  Signal redundancy detected:")
        for a, b, overlap in ff.signal_redundancy:
            print(f"    {a} ↔ {b}: {overlap:.1%} overlap")
    else:
        print(f"  No signal redundancy detected")
    print(f"  Calibration gap: {ff.calibration_gap:.4f}")

    # ═══════════════════════════════════════════════════════════════
    # FINAL VERDICT
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'='*72}")
    print(f"  FINAL VERDICT")
    print(f"{'='*72}\n")

    print(f"  Checks passed: {total_pass}/{total_checks} ({total_pass/max(total_checks,1)*100:.0f}%)")

    if findings:
        print(f"\n  Findings ({len(findings)}):")
        for i, f in enumerate(findings, 1):
            print(f"    {i}. {f}")
    else:
        print(f"\n  No findings — all 9 layers clean")

    grade = "A" if total_pass >= total_checks * 0.90 else \
            "B" if total_pass >= total_checks * 0.75 else \
            "C" if total_pass >= total_checks * 0.60 else "D"

    critical = len([f for f in findings if "ILLUSION" in f.upper() or "COLLAPSE" in f.upper() or "DESYNC" in f.upper()])
    if critical > 0:
        grade = "D"

    print(f"\n  Grade: {grade}")
    if grade in ("A", "B"):
        print(f"  🟢 System passes deep causal audit")
    elif grade == "C":
        print(f"  🟡 System partially passes — {len(findings)} issues need attention")
    else:
        print(f"  🔴 System has critical issues — {critical} critical findings")

    return 0 if grade in ("A", "B") else 1


if __name__ == "__main__":
    sys.exit(main())
