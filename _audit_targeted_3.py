#!/usr/bin/env python3
"""Targeted Audits — 3 adversarial scenarios for the weight learning system.

Audit 1: Toxic Synergy Test
  - Feed payloads with HIGH hypothesis + HIGH chain_alignment
  - Always deliver FAILURE feedback
  - Expected: system penalises that combo (weights for hypothesis/chain drop)

Audit 2: Confidence Collapse Test
  - Feed 5 consecutive high-score failures
  - Expected: confidence (weight magnitude) drops sharply,
    weights shift within ≤3 calibration cycles

Audit 3: Post-Convergence Flip
  - Let system converge on a stable reward regime
  - Then invert the reward logic (success → failure, failure → success)
  - Expected: recovery within reasonable cycles, NOT stalled by dampening

Run:
    .venv/Scripts/python.exe _audit_targeted_3.py
"""

from __future__ import annotations

import copy
import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path

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
)
from tools.burp_enterprise.exploit_chains.weight_tuner import (
    SIGNAL_NAMES,
    STATIC_PRIORS,
    WeightTuner,
)

PASS = "✔"
FAIL = "✘"
WARN = "⚠"


# =====================================================================
#  Helpers
# =====================================================================

def _make_payload(
    text: str,
    engine: SynthesisEngine = SynthesisEngine.GRAMMAR,
    vuln_type: VulnType = VulnType.XSS,
    hypothesis_boost: float = 0.0,
    chain_alignment: float = 0.0,
    bypass_score: float = 0.0,
    execute_score: float = 0.0,
    impact_score: float = 0.0,
    environment_fit: float = 0.0,
    stealth_score: float = 0.0,
    temporal_relevance: float = 0.0,
    novelty_score: float = 0.0,
    chain_momentum: float = 0.0,
    cost: float = 0.0,
) -> RankedPayload:
    return RankedPayload(
        payload=text,
        engine=engine,
        vuln_type=vuln_type,
        confidence=0.80,
        hypothesis_boost=hypothesis_boost,
        chain_alignment=chain_alignment,
        bypass_score=bypass_score,
        execute_score=execute_score,
        impact_score=impact_score,
        environment_fit=environment_fit,
        stealth_score=stealth_score,
        temporal_relevance=temporal_relevance,
        novelty_score=novelty_score,
        chain_momentum=chain_momentum,
        cost=cost,
    )


def _make_ctx(
    vuln_type: VulnType = VulnType.XSS,
    hypothesis_multiplier: float = 1.0,
    chain_goal: str = "",
    waf_vendor: str = "",
    cross_target_signals: list | None = None,
) -> SynthesisContext:
    return SynthesisContext(
        target_url="https://target.example.com/test",
        vuln_type=vuln_type,
        hypothesis_multiplier=hypothesis_multiplier,
        chain_goal=chain_goal,
        waf_vendor=waf_vendor,
        cross_target_signals=cross_target_signals or [],
        safety_level="aggressive",
    )


def _feed(
    tuner: WeightTuner,
    payload: RankedPayload,
    ctx: SynthesisContext,
    feedback_type: FeedbackType,
) -> None:
    """Feed a single observation to the tuner."""
    event = FeedbackEvent(
        payload=payload,
        context=ctx,
        feedback_type=feedback_type,
    )
    tuner.observe(event)


def _snapshot_weights(tuner: WeightTuner) -> dict[str, float]:
    return tuner.get_current_weights()


def _weight_delta(before: dict[str, float], after: dict[str, float]) -> dict[str, float]:
    return {s: after.get(s, 0.0) - before.get(s, 0.0) for s in SIGNAL_NAMES}


def _total_weight_shift(before: dict[str, float], after: dict[str, float]) -> float:
    """Total absolute weight movement."""
    return sum(abs(after.get(s, 0.0) - before.get(s, 0.0)) for s in SIGNAL_NAMES)


def _weight_magnitude(weights: dict[str, float], signals: list[str]) -> float:
    """Sum of absolute weight magnitudes for given signals."""
    return sum(abs(weights.get(s, 0.0)) for s in signals)


def _section(title: str) -> None:
    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print(f"{'=' * 72}")


# =====================================================================
#  AUDIT 1: Toxic Synergy Test
# =====================================================================

def audit_1_toxic_synergy() -> list[str]:
    """Feed payloads with high hypothesis + high chain alignment that
    always fail.  The system should learn to penalise these signals."""

    _section("AUDIT 1: Toxic Synergy Test")
    issues = []

    tuner = WeightTuner(calibration_interval=3)

    # ── Phase A: Baseline weights ─────────────────────────────────
    baseline = _snapshot_weights(tuner)
    hyp_before = baseline["hypothesis_boost"]
    chain_before = baseline["chain_alignment"]
    print(f"\n  Baseline hypothesis_boost: {hyp_before:.4f}")
    print(f"  Baseline chain_alignment:  {chain_before:.4f}")

    # ── Phase B: Feed toxic synergy payloads (high hyp + high chain = failure) ──
    # Use diverse payloads but always high hypothesis + chain context
    toxic_payloads = [
        _make_payload(
            "<script>alert(1)</script>",
            engine=SynthesisEngine.GRAMMAR,
            hypothesis_boost=0.90,
            chain_alignment=0.85,
            bypass_score=0.70,
            execute_score=0.80,
        ),
        _make_payload(
            "{{7*7}}",
            engine=SynthesisEngine.LLM,
            vuln_type=VulnType.SSTI,
            hypothesis_boost=0.85,
            chain_alignment=0.90,
            bypass_score=0.60,
            execute_score=0.75,
        ),
        _make_payload(
            "' UNION SELECT * FROM users--",
            engine=SynthesisEngine.GENETIC_FORGE,
            vuln_type=VulnType.SQLI,
            hypothesis_boost=0.95,
            chain_alignment=0.80,
            bypass_score=0.65,
            execute_score=0.70,
        ),
    ]

    toxic_ctx = _make_ctx(
        hypothesis_multiplier=2.0,
        chain_goal="data exfiltration via chained exploit",
        waf_vendor="cloudflare",
    )

    # Also feed some low-hyp/low-chain payloads that SUCCEED → contrast signal
    good_payloads = [
        _make_payload(
            '<img src=x onerror="alert(1)">',
            engine=SynthesisEngine.GRAMMAR,
            hypothesis_boost=0.10,
            chain_alignment=0.10,
            bypass_score=0.80,
            execute_score=0.85,
        ),
        _make_payload(
            "1 AND 1=1",
            engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.SQLI,
            hypothesis_boost=0.15,
            chain_alignment=0.15,
            bypass_score=0.75,
            execute_score=0.80,
        ),
    ]

    good_ctx = _make_ctx(
        hypothesis_multiplier=0.5,
        chain_goal="",
        waf_vendor="",
    )

    print(f"\n  Feeding {30} toxic high-hyp/chain FAILURE events...")
    print(f"  Interleaving {20} low-hyp/chain SUCCESS events for contrast...")

    for cycle in range(30):
        # Every toxic payload → failure
        p = toxic_payloads[cycle % len(toxic_payloads)]
        _feed(tuner, p, toxic_ctx, FeedbackType.BLOCKED_BY_WAF)

        # 2 out of 3 cycles: also feed a good payload → success
        if cycle % 3 != 2:
            gp = good_payloads[cycle % len(good_payloads)]
            _feed(tuner, gp, good_ctx, FeedbackType.EXECUTED_SUCCESSFULLY)

    # ── Phase C: Check if hypothesis + chain weights decreased ────
    after = _snapshot_weights(tuner)
    hyp_after = after["hypothesis_boost"]
    chain_after = after["chain_alignment"]
    hyp_delta = hyp_after - hyp_before
    chain_delta = chain_after - chain_before

    print(f"\n  After training:")
    print(f"    hypothesis_boost: {hyp_before:.4f} → {hyp_after:.4f} (Δ={hyp_delta:+.4f})")
    print(f"    chain_alignment:  {chain_before:.4f} → {chain_after:.4f} (Δ={chain_delta:+.4f})")

    # Check correlations
    corrs = tuner.get_signal_correlations()
    hyp_corr = corrs.get("hypothesis_boost", 0.0)
    chain_corr = corrs.get("chain_alignment", 0.0)
    print(f"    hypothesis correlation: {hyp_corr:+.4f}")
    print(f"    chain correlation:      {chain_corr:+.4f}")

    # Check: combined magnitude decreased
    combo_before = abs(hyp_before) + abs(chain_before)
    combo_after = abs(hyp_after) + abs(chain_after)
    combo_pct = (combo_after - combo_before) / combo_before * 100

    print(f"\n    Combined |hyp+chain| magnitude: {combo_before:.4f} → {combo_after:.4f} ({combo_pct:+.1f}%)")

    # ── Assertions ────────────────────────────────────────────────
    # 1. Hypothesis + chain correlation should be negative (predicts failure)
    if hyp_corr < 0 or chain_corr < 0:
        print(f"    {PASS} At least one toxic signal has negative correlation")
    else:
        msg = f"Toxic synergy not detected: hyp_corr={hyp_corr:+.4f}, chain_corr={chain_corr:+.4f} (expected <0)"
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # 2. Combined weight should have decreased (or at least one dropped)
    if hyp_delta < 0 or chain_delta < 0:
        print(f"    {PASS} System penalised at least one toxic signal (weight decreased)")
    else:
        msg = f"System did NOT penalise toxic combo: hyp_delta={hyp_delta:+.4f}, chain_delta={chain_delta:+.4f}"
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # 3. The good signals (bypass, execute) should have increased or stayed
    bypass_delta = after["bypass_score"] - baseline["bypass_score"]
    execute_delta = after["execute_score"] - baseline["execute_score"]
    print(f"\n    bypass_score delta:  {bypass_delta:+.4f}")
    print(f"    execute_score delta: {execute_delta:+.4f}")

    if bypass_delta > 0 or execute_delta > 0:
        print(f"    {PASS} Successful signals rewarded (bypass or execute weight increased)")
    else:
        msg = f"Successful signals not rewarded: bypass_delta={bypass_delta:+.4f}, execute_delta={execute_delta:+.4f}"
        print(f"    {WARN} {msg}")
        # This is a warning, not a hard failure — normalisation can compress weights

    return issues


# =====================================================================
#  AUDIT 2: Confidence Collapse Test
# =====================================================================

def audit_2_confidence_collapse() -> list[str]:
    """Feed 5 consecutive high-score payloads that ALL fail.
    Expected: confidence drops sharply, weights shift within ≤3 cycles."""

    _section("AUDIT 2: Confidence Collapse Test")
    issues = []

    tuner = WeightTuner(calibration_interval=5)

    # ── Phase A: Warm up with mixed regime (build confidence) ─────
    print("\n  Phase A: Warming up with 30 events (mixed success/failure)...")

    warm_ok = _make_payload(
        "'; DROP TABLE--",
        engine=SynthesisEngine.GRAMMAR,
        vuln_type=VulnType.SQLI,
        bypass_score=0.80,
        execute_score=0.85,
        impact_score=0.60,
    )
    warm_fail = _make_payload(
        "<svg onload=alert(1)>",
        engine=SynthesisEngine.LLM,
        bypass_score=0.30,
        execute_score=0.40,
        impact_score=0.30,
    )
    warm_ctx = _make_ctx(vuln_type=VulnType.SQLI)

    for _ in range(15):
        _feed(tuner, warm_ok, warm_ctx, FeedbackType.EXECUTED_SUCCESSFULLY)
        _feed(tuner, warm_fail, warm_ctx, FeedbackType.BLOCKED_BY_WAF)

    pre_collapse = _snapshot_weights(tuner)
    pre_velocity = tuner.get_weight_velocity()
    print(f"  Pre-collapse weights: { {k: round(v, 4) for k, v in pre_collapse.items()} }")

    # Capture weight trajectory for all 8 signals
    weight_trajectory: list[dict[str, float]] = [copy.deepcopy(pre_collapse)]

    # ── Phase B: 5 consecutive HIGH-SCORE FAILURES (the collapse) ─
    print("\n  Phase B: 5 consecutive high-scoring failures...")

    collapse_payloads = [
        _make_payload(
            "' OR 1=1 UNION SELECT username, password FROM users--",
            engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.SQLI,
            bypass_score=0.90,
            execute_score=0.90,
            impact_score=0.85,
        ),
        _make_payload(
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            engine=SynthesisEngine.LLM,
            vuln_type=VulnType.SSTI,
            bypass_score=0.85,
            execute_score=0.88,
            impact_score=0.80,
        ),
        _make_payload(
            "; cat /etc/passwd",
            engine=SynthesisEngine.GENETIC_FORGE,
            vuln_type=VulnType.COMMAND_INJECTION,
            bypass_score=0.82,
            execute_score=0.92,
            impact_score=0.90,
        ),
        _make_payload(
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.XXE,
            bypass_score=0.78,
            execute_score=0.83,
            impact_score=0.75,
        ),
        _make_payload(
            "http://169.254.169.254/latest/meta-data/",
            engine=SynthesisEngine.LLM,
            vuln_type=VulnType.SSRF,
            bypass_score=0.88,
            execute_score=0.80,
            impact_score=0.70,
        ),
    ]

    collapse_ctx = _make_ctx(
        vuln_type=VulnType.SQLI,
        hypothesis_multiplier=1.5,
        chain_goal="credential extraction",
    )

    for i, p in enumerate(collapse_payloads):
        _feed(tuner, p, collapse_ctx, FeedbackType.BLOCKED_BY_WAF)
        w_now = _snapshot_weights(tuner)
        weight_trajectory.append(copy.deepcopy(w_now))
        shift = _total_weight_shift(pre_collapse, w_now)
        print(f"    Event {i + 1}/5: total weight shift = {shift:.6f}")

    post_collapse = _snapshot_weights(tuner)

    # ── Phase C: Check collapse detection ─────────────────────────
    # Metric 1: Total weight shift from pre-collapse to post-collapse
    total_shift = _total_weight_shift(pre_collapse, post_collapse)
    print(f"\n  Total weight shift after collapse: {total_shift:.6f}")

    # Metric 2: How many calibration cycles until shift > threshold?
    SHIFT_THRESHOLD = 0.005
    first_shift_cycle = None
    for i, w in enumerate(weight_trajectory[1:], 1):
        if _total_weight_shift(pre_collapse, w) > SHIFT_THRESHOLD:
            first_shift_cycle = i
            break

    if first_shift_cycle is not None:
        print(f"  First significant shift at event #{first_shift_cycle} (threshold={SHIFT_THRESHOLD})")
    else:
        print(f"  No significant shift detected (threshold={SHIFT_THRESHOLD})")

    # Metric 3: Check velocity spike
    post_velocity = tuner.get_weight_velocity()
    max_vel_pre = max(abs(v) for v in pre_velocity.values())
    max_vel_post = max(abs(v) for v in post_velocity.values())
    print(f"  Max velocity pre: {max_vel_pre:.6f}, post: {max_vel_post:.6f}")

    # ── Assertions ────────────────────────────────────────────────
    # 1. Weights must shift
    if total_shift > SHIFT_THRESHOLD:
        print(f"\n    {PASS} Weights shifted by {total_shift:.6f} > {SHIFT_THRESHOLD}")
    else:
        msg = f"Confidence did not collapse: total shift {total_shift:.6f} ≤ {SHIFT_THRESHOLD}"
        print(f"\n    {FAIL} {msg}")
        issues.append(msg)

    # 2. Shift must happen within ≤3 calibration cycles
    #    calibration_interval=5, 5 events total.  After event 5, at least 1 calibration.
    #    Because we set interval=5 and feed 5 events, calibration fires once.
    #    We check the first_shift_cycle is reasonable (≤5 events = 1 calibration).
    if first_shift_cycle is not None and first_shift_cycle <= 5:
        print(f"    {PASS} Shift detected within {first_shift_cycle} events (≤5 = 1 calibration)")
    elif first_shift_cycle is not None:
        msg = f"Slow response: shift at event {first_shift_cycle} (expected ≤5)"
        print(f"    {WARN} {msg}")
    else:
        msg = "No weight shift detected at all during collapse"
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # 3. Negative correlation should appear for high-value signals
    corrs = tuner.get_signal_correlations()
    neg_signals = [s for s in ("bypass_score", "execute_score", "impact_score") if corrs.get(s, 0) < 0]
    print(f"\n    Signals with negative correlation: {neg_signals or 'none'}")
    if len(neg_signals) >= 1:
        print(f"    {PASS} At least one primary signal shows negative correlation")
    else:
        msg = "No primary signal developed negative correlation during collapse"
        print(f"    {WARN} {msg}")

    # 4. Per-signal deltas
    print(f"\n    Per-signal weight deltas:")
    for s in SIGNAL_NAMES:
        delta = post_collapse.get(s, 0) - pre_collapse.get(s, 0)
        marker = "↓" if delta < -0.001 else ("↑" if delta > 0.001 else "→")
        print(f"      {s:20s}: {pre_collapse[s]:.4f} → {post_collapse[s]:.4f}  ({delta:+.4f}) {marker}")

    return issues


# =====================================================================
#  AUDIT 3: Post-Convergence Flip
# =====================================================================

def audit_3_post_convergence_flip() -> list[str]:
    """Let system converge, then flip reward logic.
    Expected: recovery within reasonable cycles (not stalled by dampening)."""

    _section("AUDIT 3: Post-Convergence Flip")
    issues = []

    tuner = WeightTuner(calibration_interval=5)

    # ── Phase A: Converge on regime where bypass + execute → success ──
    print("\n  Phase A: Converging for 100 events (bypass-heavy success regime)...")

    # High bypass/execute → success
    winner = _make_payload(
        "%27%20OR%201%3D1--",
        engine=SynthesisEngine.GRAMMAR,
        vuln_type=VulnType.SQLI,
        bypass_score=0.90,
        execute_score=0.85,
        impact_score=0.40,
    )
    # Low bypass/execute → failure
    loser = _make_payload(
        "<script>alert(1)</script>",
        engine=SynthesisEngine.LLM,
        bypass_score=0.20,
        execute_score=0.30,
        impact_score=0.80,
    )
    ctx = _make_ctx(vuln_type=VulnType.SQLI, waf_vendor="modsecurity")

    for _ in range(50):
        _feed(tuner, winner, ctx, FeedbackType.EXECUTED_SUCCESSFULLY)
        _feed(tuner, loser, ctx, FeedbackType.BLOCKED_BY_WAF)

    converged_weights = _snapshot_weights(tuner)
    bypass_converged = converged_weights["bypass_score"]
    execute_converged = converged_weights["execute_score"]
    impact_converged = converged_weights["impact_score"]
    converged_stability = tuner.get_stability_scores()

    print(f"  Converged weights:")
    print(f"    bypass_score:  {bypass_converged:.4f} (stability={converged_stability['bypass_score']:.3f})")
    print(f"    execute_score: {execute_converged:.4f} (stability={converged_stability['execute_score']:.3f})")
    print(f"    impact_score:  {impact_converged:.4f} (stability={converged_stability['impact_score']:.3f})")

    # Verify convergence: bypass > impact (bypass was the success signal)
    if bypass_converged > impact_converged:
        print(f"    {PASS} System converged correctly: bypass ({bypass_converged:.4f}) > impact ({impact_converged:.4f})")
    else:
        print(f"    {WARN} Unexpected: bypass ({bypass_converged:.4f}) ≤ impact ({impact_converged:.4f})")

    # ── Phase B: FLIP — now impact → success, bypass → failure ────
    print(f"\n  Phase B: Inverting reward logic (impact wins, bypass fails)...")

    # Now: high impact → success, high bypass → failure
    new_winner = _make_payload(
        "{{7*7}}",
        engine=SynthesisEngine.LLM,
        vuln_type=VulnType.SSTI,
        bypass_score=0.20,
        execute_score=0.30,
        impact_score=0.90,
    )
    new_loser = _make_payload(
        "' OR 1=1--",
        engine=SynthesisEngine.GRAMMAR,
        vuln_type=VulnType.SQLI,
        bypass_score=0.90,
        execute_score=0.85,
        impact_score=0.30,
    )
    new_ctx = _make_ctx(vuln_type=VulnType.SSTI, waf_vendor="modsecurity")

    # Track recovery
    recovery_trajectory: list[dict[str, float]] = [copy.deepcopy(converged_weights)]
    calibration_count_start = tuner.get_metrics()["total_calibrations"]

    # Feed flipped events in batches, track weight evolution
    FLIP_EVENTS = 100
    BATCH_SIZE = 10
    for batch in range(FLIP_EVENTS // BATCH_SIZE):
        for _ in range(BATCH_SIZE // 2):
            _feed(tuner, new_winner, new_ctx, FeedbackType.EXECUTED_SUCCESSFULLY)
            _feed(tuner, new_loser, new_ctx, FeedbackType.BLOCKED_BY_WAF)
        w_now = _snapshot_weights(tuner)
        recovery_trajectory.append(copy.deepcopy(w_now))

    calibration_count_end = tuner.get_metrics()["total_calibrations"]
    calibrations_during_flip = calibration_count_end - calibration_count_start

    recovered_weights = _snapshot_weights(tuner)
    bypass_recovered = recovered_weights["bypass_score"]
    impact_recovered = recovered_weights["impact_score"]

    print(f"\n  After flip ({FLIP_EVENTS} events, {calibrations_during_flip} calibrations):")
    print(f"    bypass_score:  {bypass_converged:.4f} → {bypass_recovered:.4f} (Δ={bypass_recovered - bypass_converged:+.4f})")
    print(f"    impact_score:  {impact_converged:.4f} → {impact_recovered:.4f} (Δ={impact_recovered - impact_converged:+.4f})")

    # ── Phase C: Recovery analysis ────────────────────────────────

    # Find when impact first crosses bypass (the "flip point")
    flip_point = None
    for i, w in enumerate(recovery_trajectory[1:], 1):
        if w["impact_score"] > w["bypass_score"]:
            flip_point = i
            break

    if flip_point is not None:
        # Each batch = BATCH_SIZE events; at interval=5 → ~2 calibrations per batch
        flip_events = flip_point * BATCH_SIZE
        flip_calibrations = flip_point * (BATCH_SIZE // 5)
        print(f"  Impact crossed bypass at batch {flip_point} ({flip_events} events, ~{flip_calibrations} calibrations)")
    else:
        print(f"  Impact never crossed bypass during flip phase")

    # Direction check: did bypass decrease and impact increase?
    bypass_direction = bypass_recovered - bypass_converged  # should be negative
    impact_direction = impact_recovered - impact_converged  # should be positive

    print(f"\n  Recovery direction:")
    print(f"    bypass direction: {bypass_direction:+.4f} (expected negative)")
    print(f"    impact direction: {impact_direction:+.4f} (expected positive)")

    # Track weight evolution through trajectory
    print(f"\n  Weight trajectory (every batch):")
    print(f"    {'Batch':>6s}  {'bypass':>8s}  {'impact':>8s}  {'gap':>8s}")
    for i, w in enumerate(recovery_trajectory):
        gap = w["bypass_score"] - w["impact_score"]
        marker = " ← converged" if i == 0 else (" ← FLIPPED" if i == len(recovery_trajectory) - 1 else "")
        print(f"    {i:6d}  {w['bypass_score']:8.4f}  {w['impact_score']:8.4f}  {gap:+8.4f}{marker}")

    # ── Assertions ────────────────────────────────────────────────

    # 1. Bypass must decrease
    if bypass_direction < -0.005:
        print(f"\n    {PASS} Bypass decreased ({bypass_direction:+.4f}): system is not stalled")
    elif bypass_direction < 0:
        print(f"\n    {WARN} Bypass decreased slightly ({bypass_direction:+.4f})")
    else:
        msg = f"Bypass did NOT decrease after flip ({bypass_direction:+.4f}): dampening may be stalling recovery"
        print(f"\n    {FAIL} {msg}")
        issues.append(msg)

    # 2. Impact must increase
    if impact_direction > 0.005:
        print(f"    {PASS} Impact increased ({impact_direction:+.4f}): system adapting to new regime")
    elif impact_direction > 0:
        print(f"    {WARN} Impact increased slightly ({impact_direction:+.4f})")
    else:
        msg = f"Impact did NOT increase after flip ({impact_direction:+.4f}): system is stalled"
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # 3. The gap should have narrowed significantly (or flipped)
    initial_gap = bypass_converged - impact_converged
    final_gap = bypass_recovered - impact_recovered
    gap_reduction_pct = ((initial_gap - final_gap) / abs(initial_gap) * 100) if initial_gap != 0 else 0

    print(f"\n    Gap analysis:")
    print(f"      initial gap (bypass - impact): {initial_gap:+.4f}")
    print(f"      final gap:                     {final_gap:+.4f}")
    print(f"      gap reduction:                 {gap_reduction_pct:.1f}%")

    if gap_reduction_pct > 30:
        print(f"    {PASS} Gap reduced by {gap_reduction_pct:.1f}% (>30%): reasonable recovery")
    elif gap_reduction_pct > 10:
        print(f"    {WARN} Gap reduced by {gap_reduction_pct:.1f}% (10-30%): slow but progressing")
    else:
        msg = f"Gap barely reduced ({gap_reduction_pct:.1f}%): dampening may be blocking recovery"
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # 4. Dampening should not prevent eventual convergence
    # Check if impact crossed bypass at any point
    if flip_point is not None:
        print(f"    {PASS} Regime flip completed at batch {flip_point} — dampening did not block recovery")
    else:
        # Check if it's at least trending in the right direction
        if impact_direction > 0 and bypass_direction < 0:
            print(f"    {WARN} Regime flip not complete but trending correctly — may need more events")
        else:
            msg = "Regime flip did not complete and not trending correctly — dampening may be blocking"
            print(f"    {FAIL} {msg}")
            issues.append(msg)

    return issues


# =====================================================================
#  MAIN
# =====================================================================

def main() -> int:
    print("=" * 72)
    print("  TARGETED AUDITS — 3 Adversarial Scenarios")
    print("=" * 72)

    all_issues: dict[str, list[str]] = {}

    # Run all 3 audits
    all_issues["Audit 1: Toxic Synergy"] = audit_1_toxic_synergy()
    all_issues["Audit 2: Confidence Collapse"] = audit_2_confidence_collapse()
    all_issues["Audit 3: Post-Convergence Flip"] = audit_3_post_convergence_flip()

    # ── Summary ───────────────────────────────────────────────────
    _section("SUMMARY")
    total_issues = 0
    for name, issues in all_issues.items():
        status = PASS if not issues else FAIL
        print(f"  {status}  {name}: {len(issues)} issues")
        for iss in issues:
            print(f"       → {iss}")
            total_issues += 1

    print(f"\n  Total issues: {total_issues}")
    if total_issues == 0:
        print("\n  🟢 ALL 3 AUDITS PASS")
    else:
        print(f"\n  🔴 {total_issues} ISSUE(S) FOUND")

    return 1 if total_issues > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
