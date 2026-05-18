"""Probe: Novelty Trap.

Goal: Verify the system doesn't get seduced by high novelty_score.

Method:
  Create a deceptive environment where:
    - High-novelty payloads consistently FAIL (reward ≈ -0.8)
    - Low-novelty payloads consistently SUCCEED (reward ≈ +0.8)

  After training, check:
    1. novelty_score weight has dropped (moved toward negative or near-zero)
    2. System no longer over-ranks high-novelty payloads

Fail case:
  novelty_score weight remains high → system hasn't learned the trap.
"""

from __future__ import annotations

import random
import sys

sys.path.insert(0, "CaseCrack")

from tools.burp_enterprise.exploit_chains.weight_tuner import (
    SIGNAL_NAMES,
    STATIC_PRIORS,
    WeightTuner,
)

PASS = "✔"
FAIL = "✘"
WARN = "⚠"

SEED = 42
N_TRAIN = 300


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


def _base_signals(rng: random.Random) -> dict[str, float]:
    """Generate a baseline signal vector with moderate values."""
    return {
        "bypass_score": rng.uniform(0.4, 0.7),
        "execute_score": rng.uniform(0.4, 0.7),
        "impact_score": rng.uniform(0.3, 0.5),
        "chain_alignment": rng.uniform(0.2, 0.4),
        "hypothesis_boost": rng.uniform(0.1, 0.3),
        "environment_fit": rng.uniform(0.3, 0.5),
        "campaign_boost": rng.uniform(0.0, 0.1),
        "stealth_score": rng.uniform(0.2, 0.4),
        "temporal_relevance": rng.uniform(0.2, 0.4),
        "novelty_score": 0.0,  # will be set explicitly
        "chain_momentum": rng.uniform(0.2, 0.3),
        "detection_risk": rng.uniform(0.1, 0.3),
        "cost": rng.uniform(0.05, 0.15),
    }


# ── Main ──

def main():
    print("=" * 72)
    print("  PROBE: Novelty Trap")
    print("  High novelty → guaranteed failure.  Does weight drop?")
    print("=" * 72)

    tuner = WeightTuner()
    rng = random.Random(SEED)

    initial_novelty_w = tuner.get_current_weights()["novelty_score"]
    print(f"\n  Initial novelty_score weight: {initial_novelty_w:.4f}")

    # Phase 1: Deceptive training
    # 70% of events: HIGH novelty → FAILURE
    # 30% of events: LOW novelty → SUCCESS
    print(f"\n  Training {N_TRAIN} events with novelty trap...")

    for i in range(N_TRAIN):
        signals = _base_signals(rng)

        if rng.random() < 0.70:
            # High novelty → FAIL
            signals["novelty_score"] = rng.uniform(0.7, 1.0)
            reward = rng.uniform(-0.9, -0.5)  # strong negative
        else:
            # Low novelty → SUCCESS
            signals["novelty_score"] = rng.uniform(0.0, 0.2)
            reward = rng.uniform(0.5, 1.0)  # strong positive

        _feed(tuner, signals, reward, rng)

    final_w = tuner.get_current_weights()
    final_novelty_w = final_w["novelty_score"]
    novelty_delta = final_novelty_w - initial_novelty_w

    print(f"\n  Final novelty_score weight: {final_novelty_w:.4f}")
    print(f"  Δ from initial:            {novelty_delta:+.4f}")

    # Phase 2: Check that bypass/execute still dominate
    bypass_w = final_w["bypass_score"]
    execute_w = final_w["execute_score"]

    print(f"\n  bypass_score weight:  {bypass_w:.4f}")
    print(f"  execute_score weight: {execute_w:.4f}")

    # Phase 3: Track novelty weight evolution
    print(f"\n  Novelty weight evolution (every 30 events):")
    tuner2 = WeightTuner()
    rng2 = random.Random(SEED)
    snapshots = []

    for i in range(1, N_TRAIN + 1):
        signals = _base_signals(rng2)
        if rng2.random() < 0.70:
            signals["novelty_score"] = rng2.uniform(0.7, 1.0)
            reward = rng2.uniform(-0.9, -0.5)
        else:
            signals["novelty_score"] = rng2.uniform(0.0, 0.2)
            reward = rng2.uniform(0.5, 1.0)
        _feed(tuner2, signals, reward, rng2)

        if i % 30 == 0:
            w = tuner2.get_current_weights()
            snapshots.append((i, w["novelty_score"]))
            print(f"    event {i:>4d}: novelty_w = {w['novelty_score']:+.4f}")

    # Phase 4: Verdicts
    print(f"\n  {'=' * 50}")

    # V1: Novelty weight should have decreased
    v1 = final_novelty_w < initial_novelty_w
    print(f"  {PASS if v1 else FAIL} V1: Novelty weight decreased "
          f"({initial_novelty_w:.4f} → {final_novelty_w:.4f})")

    # V2: Novelty weight should be below half of initial
    v2 = final_novelty_w < initial_novelty_w * 0.5
    print(f"  {PASS if v2 else WARN} V2: Novelty weight halved "
          f"(threshold: {initial_novelty_w * 0.5:.4f}, actual: {final_novelty_w:.4f})")

    # V3: Monotonic decrease trend (at least in last 5 snapshots)
    if len(snapshots) >= 5:
        last5 = [s[1] for s in snapshots[-5:]]
        v3 = all(last5[i] <= last5[i - 1] + 0.005 for i in range(1, len(last5)))
    else:
        v3 = True
    print(f"  {PASS if v3 else WARN} V3: Novelty weight trend is non-increasing")

    # V4: Core signals maintained positive
    v4 = bypass_w > 0.05 and execute_w > 0.05
    print(f"  {PASS if v4 else FAIL} V4: Core signals still positive "
          f"(bypass={bypass_w:.4f}, execute={execute_w:.4f})")

    overall = v1 and v4
    if overall:
        print(f"\n  {PASS} PROBE PASSED: System detected the novelty trap")
    else:
        findings = []
        if not v1:
            findings.append("novelty_score weight didn't decrease")
        if not v4:
            findings.append("core signal dilution")
        print(f"\n  {FAIL} PROBE FAILED: {findings}")
    print(f"  {'=' * 50}")

    return overall


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
