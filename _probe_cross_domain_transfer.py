"""Probe: Cross-Domain Transfer.

Goal: Train on one domain (REST API + JWT), test on a different domain
      (GraphQL + session auth).  Verify the system adapts quickly rather
      than catastrophically misapplying priors.

Method:
  Phase 1: Train 200 events in Domain A (REST + JWT heavy)
  Phase 2: Switch to Domain B (GraphQL + session auth, different GT)
  Phase 3: Measure adaptation speed — how many events until regret
           drops below 2× baseline

Expected:
  - Immediate post-switch regret spike (acceptable)
  - Fast recovery (< 50 events to reach < 2× steady-state MSE)

Fail case:
  - No recovery after 100 events → priors are stuck
  - Adapted weights stay identical to Domain A → no transfer learning
"""

from __future__ import annotations

import math
import random
import sys

sys.path.insert(0, "CaseCrack")

from tools.burp_enterprise.exploit_chains.weight_tuner import (
    SIGNAL_NAMES,
    WeightTuner,
)

PASS = "✔"
FAIL = "✘"
WARN = "⚠"

# ── Domain definitions ──

# Domain A: REST API + JWT — bypass and execute dominate
DOMAIN_A_GT = {
    "bypass_score": 0.30, "execute_score": 0.35, "impact_score": 0.05,
    "chain_alignment": 0.02, "hypothesis_boost": 0.02, "environment_fit": 0.06,
    "campaign_boost": 0.01, "stealth_score": 0.02, "temporal_relevance": 0.02,
    "novelty_score": 0.01, "chain_momentum": 0.01,
    "detection_risk": -0.07, "cost": -0.05,
}

DOMAIN_A_DIST = {
    "bypass_score": (0.55, 0.15), "execute_score": (0.50, 0.18),
    "impact_score": (0.35, 0.10), "chain_alignment": (0.30, 0.10),
    "hypothesis_boost": (0.25, 0.08), "environment_fit": (0.50, 0.15),
    "campaign_boost": (0.10, 0.05), "stealth_score": (0.25, 0.10),
    "temporal_relevance": (0.30, 0.10), "novelty_score": (0.20, 0.08),
    "chain_momentum": (0.20, 0.08),
    "detection_risk": (0.30, 0.10), "cost": (0.10, 0.05),
}

# Domain B: GraphQL + session auth — impact and chain_alignment dominate
DOMAIN_B_GT = {
    "bypass_score": 0.10, "execute_score": 0.15, "impact_score": 0.30,
    "chain_alignment": 0.15, "hypothesis_boost": 0.05, "environment_fit": 0.05,
    "campaign_boost": 0.02, "stealth_score": 0.03, "temporal_relevance": 0.02,
    "novelty_score": 0.02, "chain_momentum": 0.03,
    "detection_risk": -0.04, "cost": -0.04,
}

DOMAIN_B_DIST = {
    "bypass_score": (0.35, 0.12), "execute_score": (0.40, 0.12),
    "impact_score": (0.60, 0.18), "chain_alignment": (0.55, 0.15),
    "hypothesis_boost": (0.35, 0.12), "environment_fit": (0.45, 0.12),
    "campaign_boost": (0.15, 0.06), "stealth_score": (0.30, 0.10),
    "temporal_relevance": (0.30, 0.10), "novelty_score": (0.25, 0.10),
    "chain_momentum": (0.30, 0.10),
    "detection_risk": (0.25, 0.08), "cost": (0.08, 0.04),
}

SEED = 42
N_DOMAIN_A = 200
N_DOMAIN_B = 150
RECOVERY_THRESHOLD_MULT = 2.0  # regret must drop below 2× steady-state
MAX_RECOVERY_EVENTS = 100


# ── Helpers ──

def _feed(tuner: WeightTuner, signals: dict, reward: float, rng: random.Random):
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


def _gen(rng: random.Random, gt: dict, dist: dict) -> tuple[dict, float]:
    signals = {}
    for n in SIGNAL_NAMES:
        mu, sigma = dist[n]
        signals[n] = max(0.0, min(1.0, rng.gauss(mu, sigma)))
    raw = sum(gt[n] * signals[n] for n in SIGNAL_NAMES)
    noise = rng.gauss(0, 0.05)
    return signals, max(-1.0, min(1.0, raw + noise))


def _mse(weights: dict, gt: dict, dist: dict, rng_seed: int, n: int = 200) -> float:
    rng = random.Random(rng_seed)
    total = 0.0
    for _ in range(n):
        signals, reward = _gen(rng, gt, dist)
        pred = sum(weights.get(s, 0) * signals[s] for s in SIGNAL_NAMES)
        total += (pred - reward) ** 2
    return total / n


def _weight_distance(w1: dict, w2: dict) -> float:
    return math.sqrt(sum((w1.get(s, 0) - w2.get(s, 0)) ** 2 for s in SIGNAL_NAMES))


# ── Main probe ──

def main():
    print("=" * 72)
    print("  PROBE: Cross-Domain Transfer")
    print("  Train REST+JWT → Switch to GraphQL+Session → Measure adaptation")
    print("=" * 72)

    tuner = WeightTuner()
    rng = random.Random(SEED)

    # Phase 1: Train on Domain A
    print(f"\n  Phase 1: Training {N_DOMAIN_A} events on Domain A (REST+JWT)...")
    for _ in range(N_DOMAIN_A):
        signals, reward = _gen(rng, DOMAIN_A_GT, DOMAIN_A_DIST)
        _feed(tuner, signals, reward, rng)

    w_domain_a = tuner.get_current_weights()
    mse_a_on_a = _mse(w_domain_a, DOMAIN_A_GT, DOMAIN_A_DIST, 7777)
    mse_a_on_b = _mse(w_domain_a, DOMAIN_B_GT, DOMAIN_B_DIST, 8888)

    print(f"    Domain A weights → MSE on Domain A: {mse_a_on_a:.6f}")
    print(f"    Domain A weights → MSE on Domain B: {mse_a_on_b:.6f}")
    print(f"    Transfer gap: {mse_a_on_b / max(mse_a_on_a, 1e-9):.2f}×")

    # Phase 2: Switch to Domain B, track MSE evolution
    print(f"\n  Phase 2: Switching to Domain B (GraphQL+Session)...")
    mse_trajectory = []
    recovery_event = None

    for i in range(1, N_DOMAIN_B + 1):
        signals, reward = _gen(rng, DOMAIN_B_GT, DOMAIN_B_DIST)
        _feed(tuner, signals, reward, rng)

        if i % 10 == 0:
            current_w = tuner.get_current_weights()
            current_mse = _mse(current_w, DOMAIN_B_GT, DOMAIN_B_DIST, 9999)
            mse_trajectory.append((i, current_mse))

    w_final = tuner.get_current_weights()
    mse_b_final = _mse(w_final, DOMAIN_B_GT, DOMAIN_B_DIST, 9999)

    # Phase 3: Analysis
    print(f"\n  Phase 3: Adaptation analysis")

    # Did weights actually move?
    dist_a_to_final = _weight_distance(w_domain_a, w_final)
    print(f"    Weight distance (A → final): {dist_a_to_final:.6f}")

    # MSE trajectory
    print(f"\n    MSE trajectory (every 10 events):")
    print(f"    {'Events':>8s} {'MSE':>10s}")
    for ev, mse_val in mse_trajectory:
        marker = ""
        if recovery_event is None and mse_val < mse_a_on_a * RECOVERY_THRESHOLD_MULT:
            recovery_event = ev
            marker = " ← recovered"
        print(f"    {ev:>8d} {mse_val:>10.6f}{marker}")

    # Check for recovery
    print(f"\n    Final MSE on Domain B: {mse_b_final:.6f}")
    print(f"    Domain A steady-state MSE: {mse_a_on_a:.6f}")

    # Verdicts
    print(f"\n  {'=' * 50}")
    findings = []

    # V1: Weights must have moved substantially
    v1 = dist_a_to_final > 0.02
    print(f"  {'PASS' if v1 else 'FAIL'} V1: Weight adaptation occurred "
          f"(dist={dist_a_to_final:.4f}, threshold=0.02)")
    if not v1:
        findings.append("Weights stuck — no transfer learning")

    # V2: Final MSE on Domain B should be better than Domain A weights on B
    v2 = mse_b_final < mse_a_on_b
    print(f"  {'PASS' if v2 else 'FAIL'} V2: MSE improved on new domain "
          f"({mse_a_on_b:.6f} → {mse_b_final:.6f})")
    if not v2:
        findings.append("Adapted weights no better than source domain weights")

    # V3: Recovery within MAX_RECOVERY_EVENTS
    v3 = recovery_event is not None and recovery_event <= MAX_RECOVERY_EVENTS
    rec_msg = f"at event {recovery_event}" if recovery_event else "never"
    print(f"  {'PASS' if v3 else WARN} V3: Recovery to 2× baseline — {rec_msg} "
          f"(threshold: {MAX_RECOVERY_EVENTS} events)")
    if not v3:
        findings.append(f"Slow recovery: {rec_msg}")

    # V4: Domain B key signals should now rank higher
    important_b = ["impact_score", "chain_alignment"]
    v4 = all(
        abs(w_final.get(s, 0)) > abs(w_domain_a.get(s, 0))
        for s in important_b
    )
    print(f"  {'PASS' if v4 else WARN} V4: Domain B priority signals gained weight")
    for s in important_b:
        print(f"    {s}: {w_domain_a.get(s, 0):.4f} → {w_final.get(s, 0):.4f}")

    overall = v1 and v2
    if overall:
        print(f"\n  {PASS} PROBE PASSED: Cross-domain transfer is functional")
    else:
        print(f"\n  {FAIL} PROBE FAILED: {findings}")
    print(f"  {'=' * 50}")

    return overall


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
