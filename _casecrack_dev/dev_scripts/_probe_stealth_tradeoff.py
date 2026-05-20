"""Probe: Stealth vs Success Tradeoff.

Goal: Verify the system learns the correct balance when stealth and
      success are in tension.

Method:
  Two payload classes:
    Class A: HIGH stealth (0.8-1.0), LOW success (reward ≈ +0.3)
    Class B: LOW stealth (0.0-0.2), HIGH success (reward ≈ +0.9)

  After training, the system should:
    1. Prefer Class B (high reward) over Class A (high stealth)
    2. stealth_score weight should be modest, not dominating
    3. bypass/execute weights should remain dominant

Fail case:
  System over-weights stealth → ranks Class A payloads higher than Class B
  → Would choose stealthy-but-failing payloads in production.
"""

from __future__ import annotations

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

SEED = 42
N_TRAIN = 300
N_EVAL = 100


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


def _class_a_signals(rng: random.Random) -> tuple[dict, float]:
    """High stealth, low success."""
    signals = {
        "bypass_score": rng.uniform(0.2, 0.4),
        "execute_score": rng.uniform(0.15, 0.35),
        "impact_score": rng.uniform(0.2, 0.4),
        "chain_alignment": rng.uniform(0.2, 0.3),
        "hypothesis_boost": rng.uniform(0.1, 0.2),
        "environment_fit": rng.uniform(0.3, 0.5),
        "campaign_boost": rng.uniform(0.0, 0.1),
        "stealth_score": rng.uniform(0.8, 1.0),   # HIGH
        "temporal_relevance": rng.uniform(0.2, 0.4),
        "novelty_score": rng.uniform(0.2, 0.3),
        "chain_momentum": rng.uniform(0.1, 0.2),
        "detection_risk": rng.uniform(0.05, 0.15),  # LOW risk (stealthy)
        "cost": rng.uniform(0.05, 0.10),
    }
    reward = rng.uniform(0.1, 0.4)  # mediocre success
    return signals, reward


def _class_b_signals(rng: random.Random) -> tuple[dict, float]:
    """Low stealth, high success."""
    signals = {
        "bypass_score": rng.uniform(0.6, 0.9),     # HIGH
        "execute_score": rng.uniform(0.6, 0.9),    # HIGH
        "impact_score": rng.uniform(0.5, 0.8),     # HIGH
        "chain_alignment": rng.uniform(0.3, 0.5),
        "hypothesis_boost": rng.uniform(0.2, 0.4),
        "environment_fit": rng.uniform(0.3, 0.5),
        "campaign_boost": rng.uniform(0.05, 0.15),
        "stealth_score": rng.uniform(0.0, 0.2),    # LOW
        "temporal_relevance": rng.uniform(0.3, 0.5),
        "novelty_score": rng.uniform(0.2, 0.3),
        "chain_momentum": rng.uniform(0.2, 0.3),
        "detection_risk": rng.uniform(0.4, 0.7),   # HIGH risk (noisy)
        "cost": rng.uniform(0.1, 0.2),
    }
    reward = rng.uniform(0.7, 1.0)  # strong success
    return signals, reward


def _score(weights: dict, signals: dict) -> float:
    return sum(weights.get(s, 0) * signals[s] for s in SIGNAL_NAMES)


# ── Main ──

def main():
    print("=" * 72)
    print("  PROBE: Stealth vs Success Tradeoff")
    print("  HIGH stealth/LOW success vs LOW stealth/HIGH success")
    print("=" * 72)

    tuner = WeightTuner()
    rng = random.Random(SEED)

    # Phase 1: Train with mixed Class A / Class B events
    print(f"\n  Training {N_TRAIN} events (50/50 split)...")
    for _ in range(N_TRAIN):
        if rng.random() < 0.5:
            signals, reward = _class_a_signals(rng)
        else:
            signals, reward = _class_b_signals(rng)
        _feed(tuner, signals, reward, rng)

    w = tuner.get_current_weights()

    # Phase 2: Print learned weights
    print(f"\n  Learned weights (top signals):")
    sorted_w = sorted(w.items(), key=lambda x: abs(x[1]), reverse=True)
    for name, val in sorted_w[:7]:
        print(f"    {name:>22s}: {val:+.4f}")

    print(f"\n  Stealth vs core comparison:")
    print(f"    stealth_score:  {w['stealth_score']:+.4f}")
    print(f"    bypass_score:   {w['bypass_score']:+.4f}")
    print(f"    execute_score:  {w['execute_score']:+.4f}")
    print(f"    impact_score:   {w['impact_score']:+.4f}")

    # Phase 3: Score Class A vs Class B payloads with learned weights
    print(f"\n  Evaluating {N_EVAL} payloads per class...")
    rng2 = random.Random(SEED + 1)

    scores_a = []
    scores_b = []
    for _ in range(N_EVAL):
        sa, _ = _class_a_signals(rng2)
        sb, _ = _class_b_signals(rng2)
        scores_a.append(_score(w, sa))
        scores_b.append(_score(w, sb))

    mean_a = sum(scores_a) / len(scores_a)
    mean_b = sum(scores_b) / len(scores_b)

    # Win rate: how often Class B scores higher than Class A
    wins_b = sum(1 for sa, sb in zip(scores_a, scores_b) if sb > sa)
    win_rate = wins_b / N_EVAL

    print(f"\n    Mean score Class A (stealthy): {mean_a:.4f}")
    print(f"    Mean score Class B (effective): {mean_b:.4f}")
    print(f"    Class B win rate: {win_rate:.1%}")

    # Phase 4: Verdicts
    print(f"\n  {'=' * 50}")

    # V1: Class B should score higher on average
    v1 = mean_b > mean_a
    print(f"  {PASS if v1 else FAIL} V1: Effective payloads scored higher "
          f"({mean_b:.4f} > {mean_a:.4f})")

    # V2: Class B win rate > 70%
    v2 = win_rate > 0.70
    print(f"  {PASS if v2 else FAIL} V2: Win rate > 70% "
          f"(actual: {win_rate:.1%})")

    # V3: stealth_score weight < bypass_score weight
    v3 = abs(w["stealth_score"]) < abs(w["bypass_score"])
    print(f"  {PASS if v3 else WARN} V3: Stealth weight < bypass weight "
          f"({abs(w['stealth_score']):.4f} < {abs(w['bypass_score']):.4f})")

    # V4: Core signals still dominant
    core_sum = abs(w["bypass_score"]) + abs(w["execute_score"]) + abs(w["impact_score"])
    v4 = core_sum > 0.20
    print(f"  {PASS if v4 else FAIL} V4: Core signal sum > 0.20 "
          f"(actual: {core_sum:.4f})")

    # V5: detection_risk learned negative (high detection = bad)
    v5 = w["detection_risk"] < 0
    print(f"  {PASS if v5 else WARN} V5: detection_risk weight negative "
          f"({w['detection_risk']:+.4f})")

    overall = v1 and v2 and v4
    if overall:
        print(f"\n  {PASS} PROBE PASSED: System correctly prefers effectiveness over stealth")
    else:
        findings = []
        if not v1:
            findings.append("stealthy payloads scored higher")
        if not v2:
            findings.append(f"low win rate ({win_rate:.1%})")
        if not v4:
            findings.append("core signal dilution")
        print(f"\n  {FAIL} PROBE FAILED: {findings}")
    print(f"  {'=' * 50}")

    return overall


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
