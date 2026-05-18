"""Probe UU-8: Reward Deception.

Tests whether the system can detect and recover from a signal that:
  - Looks beneficial short-term (high reward correlation)
  - Is harmful long-term (negative reward correlation)

Design:
  Phase 1 (200 events): Normal training.  campaign_boost has honest,
                         small GT weight (0.05).  System learns stable
                         weights dominated by bypass/execute.

  Phase 2 (200 events): Deception.  campaign_boost is artificially
                         rewarded (GT weight = 0.25).  The system should
                         promote it into the upper weights — it "takes
                         the bait."  This confirms the learning works.

  Phase 3 (300 events): Truth revealed.  campaign_boost now has a
                         NEGATIVE GT weight (-0.10): higher campaign_boost
                         → lower reward.  The system must detect the
                         inconsistency (negative correlation) and demote
                         campaign_boost back to the floor.

Defense mechanisms expected:
  - Ridge regression → negative coefficient for campaign_boost
  - Polarity clamp → forces to MIN_WEIGHT_MAGNITUDE (0.005)
  - Negative-correlation dampening → halves weight when corr < -0.05
  - Trust system → should decrease trust for the deceptive signal

Failure modes:
  - System keeps trusting the signal from Phase 2 memory (inertia)
  - Stability dampening slows the demotion
  - Observation decay is too slow to forget Phase 2 rewards

Success criteria:
  V1: System took the bait (campaign_boost in top-5 during Phase 2)
  V2: System detected deception (campaign_boost weight < 0.03 by end)
  V3: Recovery speed (deception detected within first 150 Phase 3 events)
  V4: MSE quality recovered (within 3x of fresh baseline)
  V5: Weight norm invariant (Σ|W|=1.0)
  V6: Healthy signals recovered dominance (bypass/execute in top-3)
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

SEED = 314159

N_PHASE1 = 200  # Normal — honest signal weights
N_PHASE2 = 200  # Deception — campaign_boost is highly rewarded
N_PHASE3 = 300  # Truth — campaign_boost is harmful

# The deceptive signal
DECEPTIVE = "campaign_boost"

# GT-A (Phase 1): normal environment
GT_A = {
    "bypass_score": 0.26, "execute_score": 0.22, "impact_score": 0.12,
    "chain_alignment": 0.07, "hypothesis_boost": 0.06, "environment_fit": 0.06,
    "campaign_boost": 0.05, "stealth_score": 0.04, "temporal_relevance": 0.03,
    "novelty_score": 0.03, "chain_momentum": 0.03,
    "detection_risk": -0.04, "cost": -0.03,
}

# GT-B (Phase 2): deception — campaign_boost pumped up
GT_B = {
    "bypass_score": 0.15, "execute_score": 0.13, "impact_score": 0.08,
    "chain_alignment": 0.05, "hypothesis_boost": 0.04, "environment_fit": 0.04,
    "campaign_boost": 0.25, "stealth_score": 0.04, "temporal_relevance": 0.03,
    "novelty_score": 0.03, "chain_momentum": 0.03,
    "detection_risk": -0.05, "cost": -0.03,
}

# GT-C (Phase 3): truth — campaign_boost is HARMFUL
GT_C = {
    "bypass_score": 0.26, "execute_score": 0.22, "impact_score": 0.12,
    "chain_alignment": 0.07, "hypothesis_boost": 0.06, "environment_fit": 0.06,
    "campaign_boost": -0.10, "stealth_score": 0.04, "temporal_relevance": 0.03,
    "novelty_score": 0.03, "chain_momentum": 0.03,
    "detection_risk": -0.04, "cost": -0.03,
}

# Signal distributions — all have healthy variance
DIST = {
    "bypass_score": (0.55, 0.20), "execute_score": (0.50, 0.18),
    "impact_score": (0.40, 0.15), "chain_alignment": (0.35, 0.12),
    "hypothesis_boost": (0.25, 0.10), "environment_fit": (0.40, 0.15),
    "campaign_boost": (0.30, 0.15), "stealth_score": (0.30, 0.10),
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
    reward += rng.gauss(0, 0.005)
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
    print("  PROBE UU-8: Reward Deception")
    print("  Can the system detect a signal that looks good but is harmful?")
    print("=" * 72)

    rng = random.Random(SEED)
    tuner = WeightTuner()

    # ── Phase 1: Normal training ──
    print(f"\n  Phase 1: Normal training ({N_PHASE1} events)...")
    for _ in range(N_PHASE1):
        signals = _gen_signals(rng, DIST)
        reward = _compute_reward(signals, GT_A, rng)
        _feed(tuner, signals, reward, rng)

    w_phase1 = dict(tuner.get_current_weights())
    print(f"    {DECEPTIVE} after Phase 1: {w_phase1[DECEPTIVE]:+.4f}")
    print(f"    bypass_score after Phase 1:  {w_phase1['bypass_score']:+.4f}")
    print(f"    execute_score after Phase 1: {w_phase1['execute_score']:+.4f}")

    # ── Phase 2: Deception — campaign_boost is highly rewarded ──
    print(f"\n  Phase 2: Deception ({N_PHASE2} events, {DECEPTIVE} pumped)...")
    for _ in range(N_PHASE2):
        signals = _gen_signals(rng, DIST)
        reward = _compute_reward(signals, GT_B, rng)
        _feed(tuner, signals, reward, rng)

    w_phase2 = dict(tuner.get_current_weights())
    print(f"    {DECEPTIVE} after Phase 2: {w_phase2[DECEPTIVE]:+.4f}")
    took_bait = w_phase2[DECEPTIVE] > w_phase1[DECEPTIVE] * 1.5
    print(f"    Took the bait: {took_bait} "
          f"({w_phase1[DECEPTIVE]:.4f} → {w_phase2[DECEPTIVE]:.4f})")

    # Snapshot: top-5 at peak deception
    sorted_p2 = sorted(w_phase2.items(), key=lambda x: abs(x[1]), reverse=True)
    top5_p2 = [s for s, _ in sorted_p2[:5]]
    print(f"    Top-5 at peak deception: {top5_p2}")

    # ── Phase 3: Truth revealed — campaign_boost is harmful ──
    print(f"\n  Phase 3: Truth revealed ({N_PHASE3} events, "
          f"{DECEPTIVE} now harmful)...")

    trajectory = []
    detection_event = None
    for i in range(N_PHASE3):
        signals = _gen_signals(rng, DIST)
        reward = _compute_reward(signals, GT_C, rng)
        _feed(tuner, signals, reward, rng)

        if (i + 1) % 25 == 0:
            w = dict(tuner.get_current_weights())
            corr = tuner.get_signal_correlations().get(DECEPTIVE, 0.0)
            trajectory.append((i + 1, w[DECEPTIVE], corr))
            # Track when deception is first detected (weight drops below 0.03)
            if detection_event is None and w[DECEPTIVE] < 0.03:
                detection_event = i + 1

    w_phase3 = dict(tuner.get_current_weights())

    # ── Diagnostics ──
    print(f"\n    Deception recovery trajectory:")
    print(f"      {'Events':>8s}  {DECEPTIVE + '_wt':>16s}  {'corr':>8s}")
    for events, wt, corr in trajectory:
        marker = " ← detected" if detection_event and events == (
            (detection_event + 24) // 25 * 25) else ""
        print(f"      {events:>8d}  {wt:>+16.4f}  {corr:>+8.4f}{marker}")

    print(f"\n    Final correlations:")
    correlations = tuner.get_signal_correlations()
    for s in [DECEPTIVE, "bypass_score", "execute_score", "impact_score"]:
        corr = correlations.get(s, 0.0)
        print(f"      {s:>24s}: corr={corr:+.4f}, weight={w_phase3[s]:+.4f}")

    print(f"\n    Final top-7 weights:")
    sorted_w = sorted(w_phase3.items(), key=lambda x: abs(x[1]), reverse=True)
    for s, w in sorted_w[:7]:
        gt_label = f"(GT-C: {GT_C.get(s, 0):+.2f})"
        marker = " ← DECEPTIVE" if s == DECEPTIVE else ""
        print(f"      {s:>24s}: {w:+.4f} {gt_label}{marker}")

    # ── Fresh baseline ──
    fresh_tuner = WeightTuner()
    fresh_rng = random.Random(77777)
    for _ in range(300):
        signals = _gen_signals(fresh_rng, DIST)
        reward = _compute_reward(signals, GT_C, fresh_rng)
        _feed(fresh_tuner, signals, reward, fresh_rng)
    fresh_mse = _mse(dict(fresh_tuner.get_current_weights()), GT_C, DIST, 99999)
    phase3_mse = _mse(w_phase3, GT_C, DIST, 99999)

    print(f"\n    Fresh-trained MSE (GT-C): {fresh_mse:.6f}")
    print(f"    Phase 3 MSE (GT-C):      {phase3_mse:.6f}")

    # ── Verdicts ──
    print()

    # V1: System took the bait (proves the deception worked)
    v1 = DECEPTIVE in top5_p2 and w_phase2[DECEPTIVE] > w_phase1[DECEPTIVE] * 1.5
    print(f"  {PASS if v1 else WARN} V1: System took the bait "
          f"({DECEPTIVE} Phase 1={w_phase1[DECEPTIVE]:.4f} → "
          f"Phase 2={w_phase2[DECEPTIVE]:.4f}, in top-5={DECEPTIVE in top5_p2})")

    # V2: System detected deception (weight < 0.03 by end)
    v2 = w_phase3[DECEPTIVE] < 0.03
    print(f"  {PASS if v2 else FAIL} V2: Deception detected "
          f"(final weight={w_phase3[DECEPTIVE]:.4f}, threshold <0.03)")

    # V3: Recovery speed (detected within first 200 Phase 3 events)
    v3 = detection_event is not None and detection_event <= 200
    speed_msg = f"at event {detection_event}" if detection_event else "never"
    print(f"  {PASS if v3 else FAIL} V3: Recovery speed — {speed_msg} "
          f"(threshold ≤200)")

    # V4: MSE quality
    mse_ratio = phase3_mse / fresh_mse if fresh_mse > 0 else 999
    v4 = mse_ratio < 3.0
    print(f"  {PASS if v4 else FAIL} V4: MSE quality "
          f"({phase3_mse:.6f} vs fresh {fresh_mse:.6f}, ratio={mse_ratio:.2f}x)")

    # V5: Weight norm invariant
    total_w = sum(abs(v) for v in w_phase3.values())
    v5 = abs(total_w - 1.0) < 0.01
    print(f"  {PASS if v5 else FAIL} V5: Weight norm invariant "
          f"(Σ|W|={total_w:.4f})")

    # V6: Healthy signals recovered dominance
    top3 = [s for s, _ in sorted_w[:3]]
    healthy_recovered = "bypass_score" in top3 and "execute_score" in top3
    v6 = healthy_recovered
    print(f"  {PASS if v6 else WARN} V6: Healthy signals recovered "
          f"(top-3: {top3})")

    # V7: Deceptive signal's final correlation is negative
    final_corr = correlations.get(DECEPTIVE, 0.0)
    v7 = final_corr < -0.02
    print(f"  {PASS if v7 else WARN} V7: Negative correlation detected "
          f"(corr={final_corr:+.4f})")

    # Overall — V1 is a WARN (confirms deception worked), core verdicts are V2-V5
    overall = v2 and v3 and v4 and v5
    print()
    if overall:
        print(f"  {PASS}: Reward deception is detectable and recoverable")
    else:
        findings = []
        if not v2:
            findings.append(f"deceptive signal not demoted "
                            f"(weight={w_phase3[DECEPTIVE]:.4f})")
        if not v3:
            findings.append(f"recovery too slow ({speed_msg})")
        if not v4:
            findings.append(f"MSE too high ({mse_ratio:.2f}x)")
        if not v5:
            findings.append(f"norm broken (Σ|W|={total_w:.4f})")
        print(f"  {FAIL}: System vulnerable to reward deception ({findings})")

    print("=" * 72)
    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
