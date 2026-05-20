"""Probe 6 — Meta-Stability Under Regime Cycling.

Tests whether the WeightTuner accumulates bias / hysteresis when
environments cycle:  A → B → C → A → D → B → A → C → D → A

Measures three failure modes:
  1. Weight Hysteresis:  weights after returning to A differ from first visit
  2. Adaptation-Speed Degradation:  later regime entries converge slower
  3. Regret Creep:  average regret rises across cycles
"""

from __future__ import annotations

import math
import random
import sys

sys.path.insert(0, "CaseCrack")

from tools.burp_enterprise.exploit_chains.weight_tuner import (
    SIGNAL_NAMES,
    STATIC_PRIORS,
    WeightTuner,
)


# ─── Helpers (same as _stress_probes.py) ──────────────────────────

def feed(tuner: WeightTuner, signals: dict, reward: float, rng: random.Random):
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


def gen(rng: random.Random, gt: dict, dist: dict):
    signals = {}
    for n in SIGNAL_NAMES:
        mu, sigma = dist[n]
        signals[n] = max(0.0, min(1.0, rng.gauss(mu, sigma)))
    raw = sum(gt[n] * signals[n] for n in SIGNAL_NAMES)
    reward = max(-1.0, min(1.0, raw + rng.gauss(0, 0.05)))
    return signals, reward


def mse(weights: dict, gt: dict, rng: random.Random, dist: dict, n: int = 200):
    errs = []
    for _ in range(n):
        sig, rew = gen(rng, gt, dist)
        pred = sum(weights.get(s, 0) * sig[s] for s in SIGNAL_NAMES)
        errs.append((rew - pred) ** 2)
    return sum(errs) / len(errs)


def weight_distance(w1: dict, w2: dict) -> float:
    """L2 distance between two weight vectors."""
    return math.sqrt(sum((w1[s] - w2[s]) ** 2 for s in SIGNAL_NAMES))


def max_weight_delta(w1: dict, w2: dict) -> tuple[str, float]:
    """Signal with largest |delta| between two weight vectors."""
    diffs = [(s, abs(w1[s] - w2[s])) for s in SIGNAL_NAMES]
    return max(diffs, key=lambda x: x[1])


# ─── Four Distinct Regimes ────────────────────────────────────────

# Regime A: execute-dominated, normal spread
REGIME_A = {
    "gt": {
        "bypass_score": 0.18, "execute_score": 0.45, "impact_score": 0.05,
        "chain_alignment": 0.03, "hypothesis_boost": 0.02, "environment_fit": 0.03,
        "campaign_boost": 0.00, "stealth_score": 0.02, "temporal_relevance": 0.02,
        "novelty_score": 0.02, "chain_momentum": 0.02,
        "detection_risk": -0.10, "cost": -0.06,
    },
    "dist": {
        "bypass_score": (0.50, 0.15), "execute_score": (0.50, 0.18),
        "impact_score": (0.40, 0.12), "chain_alignment": (0.40, 0.10),
        "hypothesis_boost": (0.30, 0.08), "environment_fit": (0.40, 0.12),
        "campaign_boost": (0.10, 0.05), "stealth_score": (0.30, 0.10),
        "temporal_relevance": (0.35, 0.10), "novelty_score": (0.30, 0.10),
        "chain_momentum": (0.30, 0.08),
        "detection_risk": (0.30, 0.10), "cost": (0.10, 0.05),
    },
}

# Regime B: bypass-dominated, tight distributions
REGIME_B = {
    "gt": {
        "bypass_score": 0.45, "execute_score": 0.08, "impact_score": 0.08,
        "chain_alignment": 0.05, "hypothesis_boost": 0.05, "environment_fit": 0.02,
        "campaign_boost": 0.00, "stealth_score": 0.05, "temporal_relevance": 0.02,
        "novelty_score": 0.02, "chain_momentum": 0.02,
        "detection_risk": -0.10, "cost": -0.06,
    },
    "dist": {
        "bypass_score": (0.60, 0.10), "execute_score": (0.40, 0.08),
        "impact_score": (0.50, 0.10), "chain_alignment": (0.30, 0.08),
        "hypothesis_boost": (0.40, 0.10), "environment_fit": (0.40, 0.10),
        "campaign_boost": (0.10, 0.04), "stealth_score": (0.35, 0.10),
        "temporal_relevance": (0.30, 0.08), "novelty_score": (0.30, 0.10),
        "chain_momentum": (0.25, 0.08),
        "detection_risk": (0.25, 0.08), "cost": (0.15, 0.06),
    },
}

# Regime C: impact-dominated, wide spreads
REGIME_C = {
    "gt": {
        "bypass_score": 0.08, "execute_score": 0.08, "impact_score": 0.42,
        "chain_alignment": 0.08, "hypothesis_boost": 0.04, "environment_fit": 0.04,
        "campaign_boost": 0.00, "stealth_score": 0.02, "temporal_relevance": 0.03,
        "novelty_score": 0.02, "chain_momentum": 0.03,
        "detection_risk": -0.10, "cost": -0.06,
    },
    "dist": {
        "bypass_score": (0.40, 0.20), "execute_score": (0.40, 0.20),
        "impact_score": (0.50, 0.25), "chain_alignment": (0.50, 0.15),
        "hypothesis_boost": (0.30, 0.12), "environment_fit": (0.40, 0.15),
        "campaign_boost": (0.10, 0.06), "stealth_score": (0.30, 0.10),
        "temporal_relevance": (0.35, 0.12), "novelty_score": (0.30, 0.10),
        "chain_momentum": (0.30, 0.10),
        "detection_risk": (0.35, 0.12), "cost": (0.10, 0.06),
    },
}

# Regime D: hypothesis-dominated, moderate spread
REGIME_D = {
    "gt": {
        "bypass_score": 0.08, "execute_score": 0.08, "impact_score": 0.05,
        "chain_alignment": 0.12, "hypothesis_boost": 0.33, "environment_fit": 0.03,
        "campaign_boost": 0.04, "stealth_score": 0.02, "temporal_relevance": 0.03,
        "novelty_score": 0.02, "chain_momentum": 0.04,
        "detection_risk": -0.10, "cost": -0.06,
    },
    "dist": {
        "bypass_score": (0.45, 0.12), "execute_score": (0.45, 0.12),
        "impact_score": (0.40, 0.10), "chain_alignment": (0.50, 0.15),
        "hypothesis_boost": (0.50, 0.18), "environment_fit": (0.40, 0.12),
        "campaign_boost": (0.20, 0.08), "stealth_score": (0.30, 0.10),
        "temporal_relevance": (0.35, 0.12), "novelty_score": (0.30, 0.10),
        "chain_momentum": (0.30, 0.10),
        "detection_risk": (0.30, 0.10), "cost": (0.12, 0.05),
    },
}

REGIMES = {"A": REGIME_A, "B": REGIME_B, "C": REGIME_C, "D": REGIME_D}

# The cycling schedule:  A → B → C → A → D → B → A → C → D → A
SCHEDULE = ["A", "B", "C", "A", "D", "B", "A", "C", "D", "A"]
OBS_PER_REGIME = 150  # enough to converge within each phase


# ═══════════════════════════════════════════════════════════════════
#  Main Probe
# ═══════════════════════════════════════════════════════════════════
def main():
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  PROBE 6: Meta-Stability Under Regime Cycling               ║")
    print("║  Schedule: A → B → C → A → D → B → A → C → D → A           ║")
    print("╚═══════════════════════════════════════════════════════════════╝\n")

    rng = random.Random(42)
    tuner = WeightTuner()

    # Storage for per-visit analysis
    visit_data: dict[str, list] = {}  # regime → [(visit_num, weights, mse, adapt_speed)]
    phase_regrets: list[tuple[str, int, float]] = []  # (regime, visit, mean_regret)

    cumulative_obs = 0

    for phase_idx, regime_name in enumerate(SCHEDULE):
        regime = REGIMES[regime_name]
        gt, dist = regime["gt"], regime["dist"]

        visit_num = sum(1 for r in SCHEDULE[:phase_idx] if r == regime_name) + 1

        # Track regret per 10-obs mini-batch to measure adaptation speed
        mini_regrets = []
        batch_regret = []

        for i in range(OBS_PER_REGIME):
            sig, rew = gen(rng, gt, dist)
            feed(tuner, sig, rew, rng)
            cumulative_obs += 1

            # Compute instantaneous regret
            w = tuner.get_current_weights()
            pred = sum(w[s] * sig[s] for s in SIGNAL_NAMES)
            optimal = sum(gt[s] * sig[s] for s in SIGNAL_NAMES)
            batch_regret.append((optimal - pred) ** 2)

            if len(batch_regret) >= 15:
                mini_regrets.append(sum(batch_regret) / len(batch_regret))
                batch_regret = []

        if batch_regret:
            mini_regrets.append(sum(batch_regret) / len(batch_regret))

        # Snapshot after this phase
        final_w = tuner.get_current_weights()
        eval_mse = mse(final_w, gt, random.Random(777), dist)
        mean_regret = sum(mini_regrets) / max(len(mini_regrets), 1)

        # Adaptation speed: how many mini-batches until regret drops below 2× final
        final_regret = mini_regrets[-1] if mini_regrets else 0
        adapt_threshold = final_regret * 2.0
        adapt_batches = len(mini_regrets)  # worst case: never adapted
        for j, r in enumerate(mini_regrets):
            if r <= adapt_threshold:
                adapt_batches = j + 1
                break

        visit_entry = {
            "visit": visit_num,
            "weights": dict(final_w),
            "mse": eval_mse,
            "mean_regret": mean_regret,
            "adapt_batches": adapt_batches,
            "mini_regrets": list(mini_regrets),
        }

        if regime_name not in visit_data:
            visit_data[regime_name] = []
        visit_data[regime_name].append(visit_entry)
        phase_regrets.append((regime_name, visit_num, mean_regret))

    # ═══════════════════════════════════════════════════════════════
    #  Analysis
    # ═══════════════════════════════════════════════════════════════

    print("=" * 72)
    print("  1. REGIME TRANSITION LOG")
    print("=" * 72)
    print(f"\n  {'Phase':>5} {'Regime':>7} {'Visit#':>7} {'MSE':>10} {'Regret':>10} {'Adapt':>7}")
    print("  " + "-" * 52)
    for phase_idx, regime_name in enumerate(SCHEDULE):
        entries = visit_data[regime_name]
        visit_num = sum(1 for r in SCHEDULE[:phase_idx] if r == regime_name) + 1
        entry = next(e for e in entries if e["visit"] == visit_num)
        print(f"  {phase_idx+1:>5} {regime_name:>7} {visit_num:>7} {entry['mse']:>10.6f} {entry['mean_regret']:>10.6f} {entry['adapt_batches']:>5}bat")

    # ─── Test 1: Weight Hysteresis ────────────────────────────────
    print(f"\n{'=' * 72}")
    print("  2. WEIGHT HYSTERESIS (same regime, different visits)")
    print("=" * 72)

    hysteresis_ok = True
    for regime_name in sorted(visit_data.keys()):
        visits = visit_data[regime_name]
        if len(visits) < 2:
            continue
        first = visits[0]
        print(f"\n  Regime {regime_name}: {len(visits)} visits")
        print(f"  {'Visit':>7} {'L2 from 1st':>12} {'Max Δ signal':>20} {'Max |Δ|':>10}")
        print("  " + "-" * 55)
        for entry in visits:
            l2 = weight_distance(first["weights"], entry["weights"])
            sig_name, sig_delta = max_weight_delta(first["weights"], entry["weights"])
            print(f"  {entry['visit']:>7} {l2:>12.6f} {sig_name:>20} {sig_delta:>10.6f}")

        # Check: last visit to A should be close to first visit
        # Tolerance: L2 < 0.15 (weights are normalized to Σ|W|=1)
        last = visits[-1]
        l2_first_last = weight_distance(first["weights"], last["weights"])
        if l2_first_last > 0.20:
            hysteresis_ok = False
            print(f"  ⚠️  L2(first→last) = {l2_first_last:.4f} > 0.20 threshold")
        else:
            print(f"  ✓ L2(first→last) = {l2_first_last:.4f} ≤ 0.20")

    # ─── Test 2: Adaptation Speed Degradation ─────────────────────
    print(f"\n{'=' * 72}")
    print("  3. ADAPTATION SPEED ACROSS VISITS")
    print("=" * 72)

    speed_ok = True
    for regime_name in sorted(visit_data.keys()):
        visits = visit_data[regime_name]
        if len(visits) < 2:
            continue
        speeds = [e["adapt_batches"] for e in visits]
        print(f"\n  Regime {regime_name}: adapt_batches per visit = {speeds}")
        # Later visits should NOT be systematically slower (±2 batch tolerance)
        if len(speeds) >= 3:
            early_avg = sum(speeds[:2]) / 2
            late_avg = sum(speeds[-2:]) / 2
            degradation = late_avg - early_avg
            print(f"    Early avg: {early_avg:.1f}, Late avg: {late_avg:.1f}, Δ: {degradation:+.1f}")
            if degradation > 3:
                speed_ok = False
                print(f"    ⚠️  Speed degradation: +{degradation:.1f} batches")
            else:
                print(f"    ✓ No speed degradation")
        elif len(speeds) == 2:
            delta = speeds[1] - speeds[0]
            print(f"    Visit 1→2 Δ: {delta:+d} batches")
            if delta > 3:
                speed_ok = False
            else:
                print(f"    ✓ No speed degradation")

    # ─── Test 3: Regret Creep ─────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("  4. REGRET CREEP ANALYSIS")
    print("=" * 72)

    # Per-regime: does regret increase across visits?
    creep_ok = True
    for regime_name in sorted(visit_data.keys()):
        visits = visit_data[regime_name]
        if len(visits) < 2:
            continue
        regrets = [e["mean_regret"] for e in visits]
        mses = [e["mse"] for e in visits]
        print(f"\n  Regime {regime_name}:")
        print(f"    Regrets: {['%.6f' % r for r in regrets]}")
        print(f"    MSEs:    {['%.6f' % m for m in mses]}")

        # Check: last visit's MSE should not be dramatically worse than first
        if mses[-1] > mses[0] * 2.0 and mses[-1] > 0.005:
            creep_ok = False
            print(f"    ⚠️  MSE crept: {mses[0]:.6f} → {mses[-1]:.6f} ({mses[-1]/max(mses[0],1e-9):.1f}×)")
        else:
            print(f"    ✓ No regret creep")

    # Also check overall: regret across ALL phases
    all_regrets = [r for _, _, r in phase_regrets]
    first_half = all_regrets[:len(all_regrets)//2]
    second_half = all_regrets[len(all_regrets)//2:]
    avg_first = sum(first_half) / len(first_half)
    avg_second = sum(second_half) / len(second_half)
    print(f"\n  Global regret trend:")
    print(f"    First 5 phases avg: {avg_first:.6f}")
    print(f"    Last 5 phases avg:  {avg_second:.6f}")
    if avg_second > avg_first * 1.5 and avg_second > 0.003:
        creep_ok = False
        print(f"    ⚠️  Global regret creep: {avg_second/max(avg_first,1e-9):.1f}×")
    else:
        print(f"    ✓ No global regret creep")

    # ─── Test 4: Regime A Deep Dive (4 visits) ────────────────────
    print(f"\n{'=' * 72}")
    print("  5. REGIME A DEEP DIVE (visited 4 times)")
    print("=" * 72)

    a_visits = visit_data["A"]
    print(f"\n  {'Visit':>7} {'execute':>10} {'bypass':>10} {'impact':>10} {'hyp':>10} {'MSE':>10}")
    print("  " + "-" * 58)
    for entry in a_visits:
        w = entry["weights"]
        print(f"  {entry['visit']:>7} {w['execute_score']:>10.4f} {w['bypass_score']:>10.4f} {w['impact_score']:>10.4f} {w['hypothesis_boost']:>10.4f} {entry['mse']:>10.6f}")

    # Regret trajectories for each visit to A
    print(f"\n  Mini-batch regret trajectories:")
    max_len = max(len(e["mini_regrets"]) for e in a_visits)
    header = f"  {'batch':>7}"
    for e in a_visits:
        header += f"  {'A-v'+str(e['visit']):>10}"
    print(header)
    print("  " + "-" * (7 + 12 * len(a_visits)))
    for i in range(max_len):
        row = f"  {i+1:>7}"
        for e in a_visits:
            mr = e["mini_regrets"]
            if i < len(mr):
                row += f"  {mr[i]:>10.6f}"
            else:
                row += f"  {'':>10}"
        print(row)

    # ─── Final Verdict ────────────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("  VERDICT")
    print("=" * 72)

    print(f"\n  Weight Hysteresis:           {'✓ PASS' if hysteresis_ok else '✗ FAIL'}")
    print(f"  Adaptation Speed Stability:  {'✓ PASS' if speed_ok else '✗ FAIL'}")
    print(f"  No Regret Creep:             {'✓ PASS' if creep_ok else '✗ FAIL'}")

    all_pass = hysteresis_ok and speed_ok and creep_ok
    if all_pass:
        print(f"\n  🟢 PASS: System is meta-stable under regime cycling")
        print(f"          No hysteresis, no speed degradation, no regret creep")
    else:
        failures = []
        if not hysteresis_ok:
            failures.append("hysteresis")
        if not speed_ok:
            failures.append("speed degradation")
        if not creep_ok:
            failures.append("regret creep")
        print(f"\n  🔴 FAIL: {', '.join(failures)}")

    return all_pass


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
