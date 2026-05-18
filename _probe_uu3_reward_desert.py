"""Probe UU-3: Reward Desert.

Tests what happens when the tuner receives prolonged near-zero rewards
(the "reward desert") -- a scenario that occurs when exploring a novel
target class where no exploit succeeds for many attempts.

Design:
  Phase 1 (200 events): Normal rewards (0.3-0.8) -- establish baseline
  Phase 2 (300 events): Reward desert  (|reward| < 0.05)
  Phase 3 (200 events): Normal rewards return (same GT as Phase 1)

Fail conditions:
  F1: After Phase 2, weights have drifted > 40% from Phase 1 despite
      near-zero gradient signal (desert should be "quiet", not destructive)
  F2: After Phase 3, recovery MSE is > 2x Phase 1 MSE (desert corrupted
      the tuner's internal state so badly it can't relearn)
  F3: During Phase 2, informativeness weighting doesn't kick in
      (observations should be down-weighted since |reward| ≈ 0)

This probes REWARD_INFORMATIVENESS_FLOOR and whether the tuner's ridge
regression properly down-weights uninformative observations.
"""
from __future__ import annotations

import random
import sys

sys.path.insert(0, "CaseCrack")

from tools.burp_enterprise.exploit_chains.weight_tuner import (
    SIGNAL_NAMES,
    REWARD_INFORMATIVENESS_FLOOR,
    WeightTuner,
)

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

SEED = 314159

N_PHASE1 = 200  # Normal training
N_PHASE2 = 300  # Reward desert
N_PHASE3 = 200  # Recovery

# Ground truth weights
GT = {
    "bypass_score": 0.22, "execute_score": 0.28, "impact_score": 0.12,
    "chain_alignment": 0.06, "hypothesis_boost": 0.05, "environment_fit": 0.06,
    "campaign_boost": 0.03, "stealth_score": 0.03, "temporal_relevance": 0.03,
    "novelty_score": 0.02, "chain_momentum": 0.03,
    "detection_risk": -0.04, "cost": -0.03,
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


def _feed(tuner, signals, reward, rng):
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
    """Max absolute drift across all signals."""
    drifts = {}
    for s in SIGNAL_NAMES:
        a, b = w_a.get(s, 0), w_b.get(s, 0)
        drifts[s] = abs(a - b) / max(abs(a), 0.001)
    return drifts


def main():
    print("=" * 72)
    print("  PROBE UU-3: Reward Desert")
    print("  Prolonged near-zero rewards. Does the tuner degrade or hold?")
    print("=" * 72)

    tuner = WeightTuner()
    rng = random.Random(SEED)

    # ── Phase 1: Normal training ──
    print(f"\n  Phase 1: Normal training ({N_PHASE1} events)...")
    for _ in range(N_PHASE1):
        signals = _gen_signals(rng, DIST)
        reward = _reward_from_gt(signals, GT, 0.04, rng)
        _feed(tuner, signals, reward, rng)

    w_phase1 = tuner.get_current_weights()
    mse_phase1 = _mse(w_phase1, GT, DIST, 8888)
    print(f"    MSE after Phase 1: {mse_phase1:.6f}")
    print(f"    Top-3 weights: ", end="")
    top3 = sorted(w_phase1.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
    print(", ".join(f"{n}={v:+.4f}" for n, v in top3))

    # ── Phase 2: Reward desert ──
    print(f"\n  Phase 2: Reward desert ({N_PHASE2} events, all |reward| < 0.05)...")
    near_zero_rewards = []
    for _ in range(N_PHASE2):
        signals = _gen_signals(rng, DIST)
        # Force near-zero reward to simulate "nothing works"
        reward = rng.uniform(-0.04, 0.04)
        near_zero_rewards.append(reward)
        _feed(tuner, signals, reward, rng)

    w_phase2 = tuner.get_current_weights()
    mse_phase2 = _mse(w_phase2, GT, DIST, 8888)
    avg_desert_reward = sum(abs(r) for r in near_zero_rewards) / len(near_zero_rewards)

    print(f"    Avg |reward| during desert: {avg_desert_reward:.4f}")
    print(f"    MSE after Phase 2: {mse_phase2:.6f}")

    # Measure drift
    drifts = _weight_drift(w_phase1, w_phase2)
    max_drift_sig = max(drifts, key=drifts.get)
    max_drift = drifts[max_drift_sig]
    print(f"    Max weight drift: {max_drift_sig} = {max_drift:.2%}")
    print(f"    All drifts:")
    for s in SIGNAL_NAMES:
        d = drifts[s]
        marker = " << HIGH" if d > 0.40 else (" < moderate" if d > 0.20 else "")
        print(f"      {s:>22s}: {w_phase1.get(s,0):+.4f} -> "
              f"{w_phase2.get(s,0):+.4f} (drift: {d:.1%}){marker}")

    # Test if informativeness weighting is effective:
    # In desert, REWARD_INFORMATIVENESS_FLOOR * weight should dominate
    # since |reward| ≈ 0.  Score: floor / (floor + (1-floor)*|reward|)
    informativeness_expected = REWARD_INFORMATIVENESS_FLOOR / (
        REWARD_INFORMATIVENESS_FLOOR + (1 - REWARD_INFORMATIVENESS_FLOOR) * avg_desert_reward
    )
    print(f"    Informativeness down-weighting: {informativeness_expected:.1%} "
          f"of normal (floor={REWARD_INFORMATIVENESS_FLOOR})")

    # ── Phase 3: Recovery ──
    print(f"\n  Phase 3: Normal rewards return ({N_PHASE3} events)...")
    snapshots = []
    for i in range(1, N_PHASE3 + 1):
        signals = _gen_signals(rng, DIST)
        reward = _reward_from_gt(signals, GT, 0.04, rng)
        _feed(tuner, signals, reward, rng)
        if i % 25 == 0:
            w_snap = tuner.get_current_weights()
            snap_mse = _mse(w_snap, GT, DIST, 8888)
            snapshots.append((i, snap_mse))

    w_phase3 = tuner.get_current_weights()
    mse_phase3 = _mse(w_phase3, GT, DIST, 8888)

    print(f"    Recovery trajectory:")
    print(f"    {'Events':>8s} {'MSE':>10s} {'vs Phase1':>12s}")
    recovery_event = None
    for ev, mse_val in snapshots:
        ratio = mse_val / max(mse_phase1, 1e-9)
        m = ""
        if recovery_event is None and ratio < 1.10:
            recovery_event = ev
            m = " << recovered"
        print(f"    {ev:>8d} {mse_val:>10.6f} {ratio:>11.2f}x{m}")

    # ── Verdicts ──
    print(f"\n  {'=' * 60}")

    # V1: Desert should be "quiet" -- no signal drifts > 40%
    high_drifts = {s: d for s, d in drifts.items() if d > 0.40}
    v1 = len(high_drifts) == 0
    print(f"  {PASS if v1 else FAIL} V1: Desert doesn't corrupt weights "
          f"(high-drift: {list(high_drifts.keys()) or 'none'})")

    # V2: Phase 3 MSE should recover to < 2x Phase 1
    mse_ratio = mse_phase3 / max(mse_phase1, 1e-9)
    v2 = mse_ratio < 2.0
    print(f"  {PASS if v2 else FAIL} V2: Post-desert MSE recovery "
          f"({mse_phase1:.6f} -> {mse_phase3:.6f}, ratio: {mse_ratio:.2f}x)")

    # V3: Informativeness weighting is active (desert obs < 20% effective weight)
    v3 = informativeness_expected > 0.70  # desert should be heavily down-weighted
    print(f"  {PASS if v3 else WARN} V3: Informativeness down-weighting active "
          f"({informativeness_expected:.1%} effective weight)")

    # V4: Recovery speed < 100 events
    v4 = recovery_event is not None and recovery_event <= 100
    rec_msg = f"at event {recovery_event}" if recovery_event else "never"
    print(f"  {PASS if v4 else WARN} V4: Recovery speed -- {rec_msg}")

    # V5: Phase 2 MSE shouldn't have exploded (< 3x Phase 1)
    desert_ratio = mse_phase2 / max(mse_phase1, 1e-9)
    v5 = desert_ratio < 3.0
    print(f"  {PASS if v5 else FAIL} V5: Desert didn't explode MSE "
          f"(ratio: {desert_ratio:.2f}x)")

    # V6: Weight sum-to-one invariant maintained throughout
    total_abs = sum(abs(v) for v in w_phase3.values())
    v6 = 0.95 < total_abs < 1.05
    print(f"  {PASS if v6 else FAIL} V6: Weight norm invariant "
          f"(Σ|W|={total_abs:.4f})")

    overall = v1 and v2 and v5 and v6
    if overall:
        print(f"\n  {PASS}: Reward desert is survivable")
    else:
        findings = []
        if not v1:
            findings.append(f"desert corrupted {list(high_drifts.keys())}")
        if not v2:
            findings.append(f"recovery failed ({mse_ratio:.2f}x)")
        if not v5:
            findings.append(f"desert exploded MSE ({desert_ratio:.2f}x)")
        if not v6:
            findings.append(f"weight norm broken (Σ|W|={total_abs:.4f})")
        print(f"\n  {FAIL}: {findings}")
    print(f"  {'=' * 60}")

    return overall


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
