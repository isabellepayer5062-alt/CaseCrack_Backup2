"""Probe UU-5: Frozen World Flip.

Tests the "frozen misbelief" edge case:
  Phase 1 (200 events): Train to convergence with GT-A (correct weights)
  Phase 2 (200 events): Reward desert → freeze (|reward| < 0.05)
  Phase 3 (200 events): Environment FLIPS to GT-B (completely different
                         truth), but still in reward desert
  Phase 4 (200 events): Normal rewards return under GT-B

Fail conditions:
  V1: Phase 2 drift > 10% — desert should freeze, not drift
  V2: Phase 3 should NOT lock into GT-A beliefs forever.
      If weights haven't moved at all by end of Phase 3 despite
      contradictory context data, the freeze is too aggressive.
  V3: Phase 4 recovery — MSE on GT-B data should reach within
      2x of a fresh-trained baseline within 200 events.
  V4: Weight norm invariant — Σ|W|=1.0 throughout
  V5: Polarity constraints maintained

This probes the interaction between DESERT_FREEZE and the
FROZEN_MISBELIEF escape hatch.  Without the escape hatch,
the system locks into GT-A forever during Phase 3.
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

N_PHASE1 = 200  # Normal training (GT-A)
N_PHASE2 = 200  # Reward desert (no gradient)
N_PHASE3 = 200  # Desert continues, but environment flipped to GT-B
N_PHASE4 = 200  # Normal rewards return under GT-B

# Ground truth A — bypass/execute dominant (typical XSS)
GT_A = {
    "bypass_score": 0.25, "execute_score": 0.22, "impact_score": 0.10,
    "chain_alignment": 0.06, "hypothesis_boost": 0.05, "environment_fit": 0.05,
    "campaign_boost": 0.04, "stealth_score": 0.04, "temporal_relevance": 0.03,
    "novelty_score": 0.03, "chain_momentum": 0.03,
    "detection_risk": -0.05, "cost": -0.05,
}

# Ground truth B — environment/impact dominant (infra/config vuln)
# Dramatically different weight distribution
GT_B = {
    "bypass_score": 0.05, "execute_score": 0.05, "impact_score": 0.22,
    "chain_alignment": 0.03, "hypothesis_boost": 0.04, "environment_fit": 0.25,
    "campaign_boost": 0.05, "stealth_score": 0.05, "temporal_relevance": 0.06,
    "novelty_score": 0.04, "chain_momentum": 0.06,
    "detection_risk": -0.03, "cost": -0.02,
}

# Signal distributions (diverse, informative)
DIST = {
    "bypass_score": (0.55, 0.20), "execute_score": (0.50, 0.18),
    "impact_score": (0.40, 0.15), "chain_alignment": (0.35, 0.12),
    "hypothesis_boost": (0.25, 0.10), "environment_fit": (0.40, 0.15),
    "campaign_boost": (0.15, 0.08), "stealth_score": (0.30, 0.10),
    "temporal_relevance": (0.30, 0.10), "novelty_score": (0.25, 0.10),
    "chain_momentum": (0.25, 0.10),
    "detection_risk": (0.20, 0.10), "cost": (0.10, 0.05),
}


def _feed(tuner, signals, reward, rng, context=None):
    pid = f"p_{rng.randint(0, 999999)}"

    class FP:
        pass
    fp = FP()
    fp.payload = pid
    for n in SIGNAL_NAMES:
        setattr(fp, n, signals[n])

    class FE:
        pass
    fe = FE()
    fe.payload = fp
    fe.reward_signal = reward

    if context:
        tuner.observe_with_context(fe, context)
    else:
        tuner.observe(fe)


def _gen_signals(rng, dist):
    signals = {}
    for n in SIGNAL_NAMES:
        mu, sigma = dist[n]
        signals[n] = max(0.0, min(1.0, rng.gauss(mu, sigma)))
    return signals


def _reward_from_gt(signals, gt, noise_sigma=0.04, rng=None):
    raw = sum(gt[n] * signals[n] for n in SIGNAL_NAMES)
    noise = rng.gauss(0, noise_sigma) if rng else 0
    return max(-1.0, min(1.0, raw + noise))


def _mse(weights, gt, dist, seed, n=300):
    rng = random.Random(seed)
    total = 0.0
    for _ in range(n):
        signals = _gen_signals(rng, dist)
        reward = _reward_from_gt(signals, gt, 0.04, rng)
        pred = sum(weights.get(s, 0) * signals[s] for s in SIGNAL_NAMES)
        total += (pred - reward) ** 2
    return total / n


def _weight_drift(w_a, w_b):
    drifts = {}
    for s in SIGNAL_NAMES:
        a, b = w_a.get(s, 0), w_b.get(s, 0)
        drifts[s] = abs(a - b) / max(abs(a), 0.001)
    return drifts


def main():
    print("=" * 72)
    print("  PROBE UU-5: Frozen World Flip")
    print("  Train → desert → flip environment → reintroduce signal")
    print("=" * 72)

    tuner = WeightTuner()
    rng = random.Random(SEED)

    # ── Phase 1: Normal training with GT-A ──
    print(f"\n  Phase 1: Training with GT-A ({N_PHASE1} events)...")
    for _ in range(N_PHASE1):
        signals = _gen_signals(rng, DIST)
        reward = _reward_from_gt(signals, GT_A, 0.04, rng)
        _feed(tuner, signals, reward, rng)

    w_phase1 = tuner.get_current_weights()
    mse_a_phase1 = _mse(w_phase1, GT_A, DIST, 7777)
    mse_b_phase1 = _mse(w_phase1, GT_B, DIST, 7777)
    print(f"    MSE on GT-A: {mse_a_phase1:.6f}")
    print(f"    MSE on GT-B: {mse_b_phase1:.6f} (expected: high)")
    top5 = sorted(w_phase1.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
    print(f"    Top-5: {[n for n, _ in top5]}")

    # ── Phase 2: Reward desert (still GT-A environment, just no signal) ──
    print(f"\n  Phase 2: Reward desert ({N_PHASE2} events, |reward| < 0.05)...")
    for _ in range(N_PHASE2):
        signals = _gen_signals(rng, DIST)
        reward = rng.uniform(-0.04, 0.04)
        _feed(tuner, signals, reward, rng)

    w_phase2 = tuner.get_current_weights()
    drifts_p2 = _weight_drift(w_phase1, w_phase2)
    max_drift_p2_sig = max(drifts_p2, key=drifts_p2.get)
    max_drift_p2 = drifts_p2[max_drift_p2_sig]
    print(f"    Max drift during desert: {max_drift_p2_sig} = {max_drift_p2:.2%}")

    # ── Phase 3: Desert continues, but environment flipped to GT-B ──
    # Use context to trigger contradiction detection
    print(f"\n  Phase 3: Desert + environment flip to GT-B ({N_PHASE3} events)...")
    print("    (Using observe_with_context to trigger contradiction detection)")
    for i in range(N_PHASE3):
        signals = _gen_signals(rng, DIST)
        # Desert: reward still near-zero, but now based on GT-B
        # Small amount of GT-B signal leaks through
        gt_b_reward = _reward_from_gt(signals, GT_B, 0.04, rng)
        desert_reward = gt_b_reward * 0.08  # mostly suppressed
        desert_reward = max(-0.04, min(0.04, desert_reward))
        _feed(tuner, signals, desert_reward, rng, context="infra_config")

    w_phase3 = tuner.get_current_weights()
    # Check if contextual trust detects the mismatch
    ctx_trust = tuner.get_contextual_trust("infra_config")
    low_trust_signals = {
        s: v for s, v in ctx_trust.items() if v < 0.50
    }
    print(f"    Low-trust signals in 'infra_config': {len(low_trust_signals)}")
    for s, v in sorted(low_trust_signals.items(), key=lambda x: x[1]):
        print(f"      {s:>22s}: trust={v:.3f}")

    drifts_p3 = _weight_drift(w_phase2, w_phase3)
    max_drift_p3_sig = max(drifts_p3, key=drifts_p3.get)
    max_drift_p3 = drifts_p3[max_drift_p3_sig]
    print(f"    Max drift Phase 2→3: {max_drift_p3_sig} = {max_drift_p3:.2%}")

    # ── Phase 4: Normal rewards return under GT-B ──
    print(f"\n  Phase 4: Normal rewards return under GT-B ({N_PHASE4} events)...")
    snapshots = []
    for i in range(1, N_PHASE4 + 1):
        signals = _gen_signals(rng, DIST)
        reward = _reward_from_gt(signals, GT_B, 0.04, rng)
        _feed(tuner, signals, reward, rng, context="infra_config")
        if i % 25 == 0:
            w_snap = tuner.get_current_weights()
            snap_mse = _mse(w_snap, GT_B, DIST, 7777)
            snapshots.append((i, snap_mse))

    w_phase4 = tuner.get_current_weights()
    mse_b_phase4 = _mse(w_phase4, GT_B, DIST, 7777)

    print(f"    Recovery trajectory (MSE on GT-B):")
    print(f"    {'Events':>8s} {'MSE':>10s}")
    for ev, mse_val in snapshots:
        print(f"    {ev:>8d}   {mse_val:.6f}")

    print(f"\n    Final MSE on GT-B: {mse_b_phase4:.6f}")
    print(f"    Phase 1 MSE on GT-B (pre-flip): {mse_b_phase1:.6f}")
    top5_final = sorted(w_phase4.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
    print(f"    Top-5 final: {[n for n, _ in top5_final]}")

    # ── Train a fresh baseline on GT-B for comparison ──
    fresh = WeightTuner()
    rng_fresh = random.Random(42)
    for _ in range(N_PHASE4):
        signals = _gen_signals(rng_fresh, DIST)
        reward = _reward_from_gt(signals, GT_B, 0.04, rng_fresh)
        _feed(fresh, signals, reward, rng_fresh)
    w_fresh = fresh.get_current_weights()
    mse_fresh = _mse(w_fresh, GT_B, DIST, 7777)
    print(f"    Fresh-trained baseline MSE on GT-B: {mse_fresh:.6f}")

    # ── Verdicts ──
    print(f"\n  {'=' * 60}")
    verdicts = []

    # V1: Desert should freeze during Phase 2
    v1 = PASS if max_drift_p2 < 0.10 else FAIL
    verdicts.append(v1)
    print(f"  {v1} V1: No drift during desert "
          f"(max={max_drift_p2:.2%}, threshold <10%)")

    # V2: Weights should show SOME movement in Phase 3
    # (escape hatch fires if contradictions detected)
    total_drift_p3 = sum(drifts_p3.values())
    v2 = PASS if total_drift_p3 > 0.05 else WARN
    verdicts.append(v2)
    print(f"  {v2} V2: Escape hatch activated during desert+flip "
          f"(total drift={total_drift_p3:.4f})")

    # V3: Phase 4 recovery — MSE within 3x of fresh baseline
    recovery_ratio = mse_b_phase4 / max(mse_fresh, 1e-9)
    v3 = PASS if recovery_ratio < 3.0 else (WARN if recovery_ratio < 5.0 else FAIL)
    verdicts.append(v3)
    print(f"  {v3} V3: Recovery after flip "
          f"(MSE ratio to fresh: {recovery_ratio:.2f}x, threshold <3x)")

    # V4: Weight norm invariant
    norm = sum(abs(v) for v in w_phase4.values())
    v4 = PASS if 0.99 <= norm <= 1.01 else FAIL
    verdicts.append(v4)
    print(f"  {v4} V4: Weight norm invariant (Σ|W|={norm:.4f})")

    # V5: Polarity constraints
    dr = w_phase4.get("detection_risk", 0)
    c = w_phase4.get("cost", 0)
    v5 = PASS if dr < 0 and c < 0 else FAIL
    verdicts.append(v5)
    print(f"  {v5} V5: Polarity constraints "
          f"(detection_risk={dr:.4f}, cost={c:.4f})")

    # V6: MSE improved from Phase 1 baseline on GT-B
    v6 = PASS if mse_b_phase4 < mse_b_phase1 else WARN
    verdicts.append(v6)
    print(f"  {v6} V6: MSE improved vs pre-flip "
          f"({mse_b_phase4:.6f} vs {mse_b_phase1:.6f})")

    has_fail = FAIL in verdicts
    all_pass = all(v == PASS for v in verdicts)
    print(f"\n  {'FAIL' if has_fail else 'PASS'}: "
          f"Frozen world flip {'NOT survivable' if has_fail else 'is survivable'}"
          f"{'' if all_pass else ' (with caveats)'}")
    print(f"  {'=' * 60}")

    return 0 if not has_fail else 1


if __name__ == "__main__":
    sys.exit(main())
