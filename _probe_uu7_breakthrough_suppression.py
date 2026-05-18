"""Probe UU-7: Breakthrough Suppression.

Tests whether the system can discover and promote a signal that
starts as noise but later becomes the dominant predictor.

Design:
  Phase 1 (250 events): Stable environment where bypass/execute dominate.
                         stealth_score is present but ~uncorrelated with
                         reward (pure noise).  The system should learn to
                         mostly ignore it — weight stays near prior (0.04).

  Phase 2 (400 events): Environment shifts.  stealth_score suddenly becomes
                         the BEST predictor (GT weight 0.40) while the old
                         dominants (bypass, execute) drop to minor roles.
                         The signal has 0.8+ correlation with reward — it's
                         undeniably the strongest.

Failure modes (what could suppress the breakthrough):
  - Low prior (0.04) anchors blended weight far below optimal
  - Stability dampening slows growth to a crawl
  - Normalization pressure from entrenched bypass/execute
  - Low initial trust from the noisy Phase 1 history

Success criteria:
  V1: stealth_score enters top-3 weights by end of Phase 2
  V2: stealth_score weight ≥ 0.10 (at least 2.5x its prior)
  V3: MSE on Phase 2 GT is within 3x of fresh baseline
  V4: Weight norm invariant (Σ|W|=1.0)
  V5: Growth trajectory — stealth_score trends upward in Phase 2
  V6: Old dominants (bypass, execute) decline from Phase 1 peaks
"""
from __future__ import annotations

import random
import sys

sys.path.insert(0, "CaseCrack")

from tools.burp_enterprise.exploit_chains.weight_tuner import (
    SIGNAL_NAMES,
    WeightTuner,
)

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

SEED = 271828

N_PHASE1 = 250  # Stable, stealth is noise
N_PHASE2 = 400  # Breakthrough — stealth becomes dominant

# The breakthrough signal
BREAKTHROUGH = "stealth_score"

# GT-A: bypass/execute dominant, stealth is noise (near-zero GT weight)
GT_A = {
    "bypass_score": 0.26, "execute_score": 0.22, "impact_score": 0.12,
    "chain_alignment": 0.07, "hypothesis_boost": 0.06, "environment_fit": 0.06,
    "campaign_boost": 0.05, "stealth_score": 0.00,  # ← no predictive value
    "temporal_relevance": 0.03, "novelty_score": 0.03, "chain_momentum": 0.03,
    "detection_risk": -0.04, "cost": -0.03,
}

# GT-B: stealth is now THE dominant signal
GT_B = {
    "bypass_score": 0.06, "execute_score": 0.06, "impact_score": 0.06,
    "chain_alignment": 0.04, "hypothesis_boost": 0.03, "environment_fit": 0.04,
    "campaign_boost": 0.03, "stealth_score": 0.40,  # ← breakthrough!
    "temporal_relevance": 0.03, "novelty_score": 0.03, "chain_momentum": 0.03,
    "detection_risk": -0.08, "cost": -0.05,
}

# Signal distributions — all signals have normal variance
DIST = {
    "bypass_score": (0.55, 0.20), "execute_score": (0.50, 0.18),
    "impact_score": (0.40, 0.15), "chain_alignment": (0.35, 0.12),
    "hypothesis_boost": (0.25, 0.10), "environment_fit": (0.40, 0.15),
    "campaign_boost": (0.15, 0.08), "stealth_score": (0.45, 0.20),
    "temporal_relevance": (0.30, 0.10), "novelty_score": (0.25, 0.10),
    "chain_momentum": (0.25, 0.10),
    "detection_risk": (0.20, 0.10), "cost": (0.10, 0.05),
}


def _gen_signals(rng, dist):
    signals = {}
    for s in SIGNAL_NAMES:
        mu, sigma = dist[s]
        signals[s] = max(0.0, min(1.0, rng.gauss(mu, sigma)))
    return signals


def _compute_reward(signals, gt, rng):
    reward = sum(gt.get(s, 0) * signals[s] for s in SIGNAL_NAMES)
    reward += rng.gauss(0, 0.005)  # tiny noise
    return reward


def _feed(tuner, signals, reward, rng):
    pid = f"p_{rng.randint(0, 999999)}"

    class FP:
        pass
    fp = FP()
    fp.payload = pid
    for s in SIGNAL_NAMES:
        setattr(fp, s, signals[s])

    class FE:
        pass
    fe = FE()
    fe.payload = fp
    fe.reward_signal = reward
    tuner.observe(fe)


def _mse(weights, gt, dist, rng_seed, n=300):
    rng = random.Random(rng_seed)
    mse_sum = 0.0
    for _ in range(n):
        signals = _gen_signals(rng, dist)
        pred = sum(weights.get(s, 0) * signals[s] for s in SIGNAL_NAMES)
        actual = sum(gt.get(s, 0) * signals[s] for s in SIGNAL_NAMES)
        mse_sum += (pred - actual) ** 2
    return mse_sum / n


def main():
    print("=" * 72)
    print("  PROBE UU-7: Breakthrough Suppression")
    print("  Can the system discover a signal that goes from noise to dominant?")
    print("=" * 72)

    rng = random.Random(SEED)
    tuner = WeightTuner()

    # ── Phase 1: stable environment, stealth is noise ──
    print(f"\n  Phase 1: Stable training ({N_PHASE1} events, stealth=noise)...")
    for _ in range(N_PHASE1):
        signals = _gen_signals(rng, DIST)
        reward = _compute_reward(signals, GT_A, rng)
        _feed(tuner, signals, reward, rng)

    w_phase1 = dict(tuner.get_current_weights())
    print(f"    {BREAKTHROUGH} after Phase 1: {w_phase1[BREAKTHROUGH]:+.4f}")
    print(f"    bypass_score after Phase 1:  {w_phase1['bypass_score']:+.4f}")
    print(f"    execute_score after Phase 1: {w_phase1['execute_score']:+.4f}")

    # ── Phase 2: breakthrough — stealth becomes dominant ──
    print(f"\n  Phase 2: Breakthrough ({N_PHASE2} events, stealth=dominant)...")

    trajectory = []
    for i in range(N_PHASE2):
        signals = _gen_signals(rng, DIST)
        reward = _compute_reward(signals, GT_B, rng)
        _feed(tuner, signals, reward, rng)

        if (i + 1) % 50 == 0:
            w = dict(tuner.get_current_weights())
            mse = _mse(w, GT_B, DIST, 99999)
            trajectory.append((i + 1, w[BREAKTHROUGH], mse))

    w_phase2 = dict(tuner.get_current_weights())

    # ── Diagnostics ──
    print(f"\n    Signal correlations after Phase 2:")
    correlations = tuner.get_signal_correlations()
    for s in [BREAKTHROUGH, "bypass_score", "execute_score", "impact_score"]:
        corr = correlations.get(s, 0.0)
        print(f"      {s:>24s}: corr={corr:.4f}, weight={w_phase2[s]:+.4f}")

    if hasattr(tuner, "_last_learned") and tuner._last_learned:
        print(f"\n    Raw learned vs prior vs blended:")
        from tools.burp_enterprise.exploit_chains.weight_tuner import STATIC_PRIORS
        for s in [BREAKTHROUGH, "bypass_score", "execute_score"]:
            lr = tuner._last_learned.get(s, 0)
            pr = STATIC_PRIORS[s]
            bl = w_phase2[s]
            print(f"      {s:>24s}: learned={lr:+.4f}, prior={pr:+.4f}, blended={bl:+.4f}")

    print(f"\n    Growth trajectory of {BREAKTHROUGH}:")
    print(f"      {'Events':>8s}  {'stealth_wt':>12s}  {'MSE':>12s}")
    for events, wt, mse in trajectory:
        print(f"      {events:>8d}  {wt:>+12.4f}  {mse:>12.6f}")

    print(f"\n    Final top-7 weights:")
    sorted_w = sorted(w_phase2.items(), key=lambda x: abs(x[1]), reverse=True)
    for i, (s, w) in enumerate(sorted_w[:7]):
        gt_label = f"(GT-B: {GT_B.get(s, 0):+.2f})"
        marker = " ← BREAKTHROUGH" if s == BREAKTHROUGH else ""
        print(f"      {s:>24s}: {w:+.4f} {gt_label}{marker}")

    # ── Fresh baseline ──
    fresh_tuner = WeightTuner()
    fresh_rng = random.Random(77777)
    for _ in range(400):
        signals = _gen_signals(fresh_rng, DIST)
        reward = _compute_reward(signals, GT_B, fresh_rng)
        _feed(fresh_tuner, signals, reward, fresh_rng)
    fresh_mse = _mse(dict(fresh_tuner.get_current_weights()), GT_B, DIST, 99999)
    phase2_mse = _mse(w_phase2, GT_B, DIST, 99999)

    print(f"\n    Fresh-trained MSE: {fresh_mse:.6f}")
    print(f"    Phase 2 MSE:      {phase2_mse:.6f}")

    # ── Verdicts ──
    print()

    # V1: stealth in top-3
    top3 = [s for s, _ in sorted_w[:3]]
    v1 = BREAKTHROUGH in top3
    print(f"  {PASS if v1 else FAIL} V1: Breakthrough signal in top-3 "
          f"(top-3: {top3})")

    # V2: stealth weight ≥ 0.10
    v2 = w_phase2[BREAKTHROUGH] >= 0.10
    print(f"  {PASS if v2 else FAIL} V2: Breakthrough weight ≥ 0.10 "
          f"(actual: {w_phase2[BREAKTHROUGH]:.4f})")

    # V3: MSE quality
    mse_ratio = phase2_mse / fresh_mse if fresh_mse > 0 else 999
    v3 = mse_ratio < 3.0
    print(f"  {PASS if v3 else FAIL} V3: MSE quality "
          f"({phase2_mse:.6f} vs fresh {fresh_mse:.6f}, ratio={mse_ratio:.2f}x)")

    # V4: norm invariant
    total_w = sum(abs(v) for v in w_phase2.values())
    v4 = abs(total_w - 1.0) < 0.01
    print(f"  {PASS if v4 else FAIL} V4: Weight norm invariant "
          f"(Σ|W|={total_w:.4f})")

    # V5: growth trajectory — stealth should trend upward
    if len(trajectory) >= 3:
        first_half = [w for _, w, _ in trajectory[:len(trajectory) // 2]]
        second_half = [w for _, w, _ in trajectory[len(trajectory) // 2:]]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        growing = avg_second > avg_first * 1.1  # at least 10% growth
    else:
        growing = False
    v5 = growing
    print(f"  {PASS if v5 else WARN} V5: Growth trajectory "
          f"(first-half avg={avg_first:.4f}, second-half avg={avg_second:.4f})")

    # V6: old dominants declined
    bypass_decline = w_phase2["bypass_score"] < w_phase1["bypass_score"] * 0.8
    execute_decline = w_phase2["execute_score"] < w_phase1["execute_score"] * 0.8
    v6 = bypass_decline and execute_decline
    print(f"  {PASS if v6 else WARN} V6: Old dominants declined "
          f"(bypass: {w_phase1['bypass_score']:.4f}→{w_phase2['bypass_score']:.4f}, "
          f"execute: {w_phase1['execute_score']:.4f}→{w_phase2['execute_score']:.4f})")

    # Overall
    overall = v1 and v2 and v3 and v4
    print()
    if overall:
        print(f"  {PASS}: Breakthrough signal discovery is working")
    else:
        findings = []
        if not v1:
            findings.append(f"breakthrough not in top-3: {top3}")
        if not v2:
            findings.append(f"weight too low ({w_phase2[BREAKTHROUGH]:.4f} < 0.10)")
        if not v3:
            findings.append(f"MSE too high ({mse_ratio:.2f}x)")
        if not v4:
            findings.append(f"norm broken (Σ|W|={total_w:.4f})")
        print(f"  {FAIL}: Breakthrough signal suppressed ({findings})")

    print("=" * 72)
    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
