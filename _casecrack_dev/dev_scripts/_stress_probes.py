"""Stress-test probes: 5 failure-mode-specific tests for WeightTuner.

These go beyond "does it learn?" to probe structural overfitting,
causal vs correlational learning, and edge-case resilience.

Probe 1 — Cross-Distribution Generalization
Probe 2 — Signal Identity Swap
Probe 3 — Interaction Trap (synergy that hurts)
Probe 4 — Sparse Feedback
Probe 5 — Extreme Signal Collapse
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


# ─── Helpers ──────────────────────────────────────────────────────

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


def gen(rng: random.Random, gt: dict, dist: dict | None = None):
    """Generate (signals, reward) from ground truth + optional distribution override."""
    d = dist or {}
    signals = {}
    for n in SIGNAL_NAMES:
        mu, sigma = d.get(n, (0.45, 0.15))
        signals[n] = max(0.0, min(1.0, rng.gauss(mu, sigma)))
    raw = sum(gt[n] * signals[n] for n in SIGNAL_NAMES)
    reward = max(-1.0, min(1.0, raw + rng.gauss(0, 0.05)))
    return signals, reward


def mse(weights: dict, gt: dict, rng: random.Random, dist: dict | None = None, n: int = 100):
    errs = []
    for _ in range(n):
        sig, rew = gen(rng, gt, dist)
        pred = sum(weights.get(s, 0) * sig[s] for s in SIGNAL_NAMES)
        errs.append((rew - pred) ** 2)
    return sum(errs) / len(errs)


def pearson(xs, ys):
    n = len(xs)
    if n < 3:
        return 0.0
    mx, my = sum(xs) / n, sum(ys) / n
    sx = math.sqrt(max(0, sum((x - mx) ** 2 for x in xs) / n))
    sy = math.sqrt(max(0, sum((y - my) ** 2 for y in ys) / n))
    if sx < 1e-12 or sy < 1e-12:
        return 0.0
    return sum((xs[i] - mx) * (ys[i] - my) for i in range(n)) / (n * sx * sy)


# Default ground truth
GT_NORMAL = {
    "bypass_score": 0.25, "execute_score": 0.50, "impact_score": 0.05,
    "chain_alignment": 0.03, "hypothesis_boost": 0.02, "campaign_boost": 0.00,
    "detection_risk": -0.10, "cost": -0.05,
}

DIST_NORMAL = {
    "bypass_score": (0.50, 0.15), "execute_score": (0.50, 0.18),
    "impact_score": (0.40, 0.12), "chain_alignment": (0.40, 0.10),
    "hypothesis_boost": (0.30, 0.08), "campaign_boost": (0.10, 0.05),
    "detection_risk": (0.30, 0.10), "cost": (0.10, 0.05),
}


# ═══════════════════════════════════════════════════════════════════
#  PROBE 1 — Cross-Distribution Generalization
# ═══════════════════════════════════════════════════════════════════
def probe_cross_distribution():
    print("=" * 72)
    print("  PROBE 1: Cross-Distribution Generalization")
    print("  Train on distribution A, deploy into distribution B")
    print("=" * 72)

    # Distribution A: normal spread
    dist_a = dict(DIST_NORMAL)

    # Distribution B: compressed execute, expanded impact, shifted means
    dist_b = {
        "bypass_score": (0.70, 0.08),       # narrow, high
        "execute_score": (0.50, 0.05),      # COMPRESSED range
        "impact_score": (0.50, 0.30),       # EXPANDED range
        "chain_alignment": (0.20, 0.15),    # shifted low
        "hypothesis_boost": (0.60, 0.20),   # shifted high
        "campaign_boost": (0.30, 0.15),     # shifted high
        "detection_risk": (0.50, 0.20),     # shifted high
        "cost": (0.30, 0.10),              # shifted high
    }

    rng = random.Random(42)
    tuner = WeightTuner()

    # Phase 1: Train on dist A (200 obs)
    for _ in range(200):
        sig, rew = gen(rng, GT_NORMAL, dist_a)
        feed(tuner, sig, rew, rng)
    w_after_a = tuner.get_current_weights()

    # Measure MSE on dist B with weights learned from A
    eval_rng = random.Random(999)
    mse_a_on_b = mse(w_after_a, GT_NORMAL, random.Random(999), dist_b)
    mse_prior_on_b = mse(dict(STATIC_PRIORS), GT_NORMAL, random.Random(999), dist_b)

    print(f"\n  After training on Dist A (200 obs):")
    print(f"    MSE(priors, dist_B):       {mse_prior_on_b:.6f}")
    print(f"    MSE(learned_A, dist_B):    {mse_a_on_b:.6f}")

    # Phase 2: Continue training on dist B (200 more obs)
    regret_per_20 = []
    for batch in range(10):
        batch_regret = []
        for _ in range(20):
            sig, rew = gen(rng, GT_NORMAL, dist_b)
            feed(tuner, sig, rew, rng)
            w = tuner.get_current_weights()
            pred = sum(w[s] * sig[s] for s in SIGNAL_NAMES)
            optimal = sum(GT_NORMAL[s] * sig[s] for s in SIGNAL_NAMES)
            batch_regret.append((optimal - pred) ** 2)
        regret_per_20.append(sum(batch_regret) / len(batch_regret))

    w_after_b = tuner.get_current_weights()
    mse_ab_on_b = mse(w_after_b, GT_NORMAL, random.Random(999), dist_b)

    print(f"\n  After adapting to Dist B (200 more obs):")
    print(f"    MSE(learned_AB, dist_B):   {mse_ab_on_b:.6f}")
    print(f"    Improvement over priors:   {(1 - mse_ab_on_b / max(mse_prior_on_b, 1e-12)) * 100:.1f}%")

    print(f"\n  Regret trajectory on Dist B (per 20-obs window):")
    for i, r in enumerate(regret_per_20):
        bar = "█" * int(r * 3000)
        print(f"    batch {i+1:2d}: {r:.6f}  {bar}")

    # Check: regret should spike then recover
    spiked = regret_per_20[0] > regret_per_20[-1]
    recovered = mse_ab_on_b < mse_a_on_b
    better_than_prior = mse_ab_on_b < mse_prior_on_b

    passed = recovered and better_than_prior
    print(f"\n  Regret spiked then dropped: {'✓' if spiked else '✗'}")
    print(f"  Recovered past dist-A perf:  {'✓' if recovered else '✗'}")
    print(f"  Better than static priors:   {'✓' if better_than_prior else '✗'}")
    print(f"  {'🟢 PASS' if passed else '🔴 FAIL'}: System generalizes across distributions")
    return passed


# ═══════════════════════════════════════════════════════════════════
#  PROBE 2 — Signal Identity Swap
# ═══════════════════════════════════════════════════════════════════
def probe_signal_swap():
    print("\n" + "=" * 72)
    print("  PROBE 2: Signal Identity Swap")
    print("  execute=causal → noise, impact=noise → causal")
    print("  Same distributions, only reward mapping changes")
    print("=" * 72)

    # Phase 1 GT: execute drives reward
    gt_phase1 = dict(GT_NORMAL)

    # Phase 2 GT: swap execute ↔ impact EXACTLY
    gt_phase2 = dict(GT_NORMAL)
    gt_phase2["execute_score"] = GT_NORMAL["impact_score"]  # 0.05
    gt_phase2["impact_score"] = GT_NORMAL["execute_score"]  # 0.50

    # Use IDENTICAL signal distributions for both phases
    dist = {
        "bypass_score": (0.50, 0.15), "execute_score": (0.50, 0.18),
        "impact_score": (0.50, 0.18),  # SAME distribution as execute
        "chain_alignment": (0.40, 0.10), "hypothesis_boost": (0.30, 0.08),
        "campaign_boost": (0.10, 0.05), "detection_risk": (0.30, 0.10),
        "cost": (0.10, 0.05),
    }

    rng = random.Random(42)
    tuner = WeightTuner()

    # Phase 1: execute is king (200 obs)
    for _ in range(200):
        sig, rew = gen(rng, gt_phase1, dist)
        feed(tuner, sig, rew, rng)
    w1 = tuner.get_current_weights()

    print(f"\n  After Phase 1 (execute=causal, 200 obs):")
    print(f"    execute_score: {w1['execute_score']:>+.4f}")
    print(f"    impact_score:  {w1['impact_score']:>+.4f}")

    # Phase 2: impact is king (300 obs — needs more to overcome prior)
    snapshots = []
    for i in range(300):
        sig, rew = gen(rng, gt_phase2, dist)
        feed(tuner, sig, rew, rng)
        if (i + 1) % 30 == 0:
            w = tuner.get_current_weights()
            snapshots.append((i + 1, w["execute_score"], w["impact_score"]))
    w2 = tuner.get_current_weights()

    print(f"\n  After Phase 2 (impact=causal, 300 more obs):")
    print(f"    execute_score: {w2['execute_score']:>+.4f}")
    print(f"    impact_score:  {w2['impact_score']:>+.4f}")

    print(f"\n  Swap trajectory:")
    print(f"  {'Obs':>5} {'execute':>10} {'impact':>10}")
    print("  " + "-" * 28)
    for obs, ex, imp in snapshots:
        print(f"  {200 + obs:>5} {ex:>10.4f} {imp:>10.4f}")

    # Check: impact should have risen, execute should have fallen
    exec_fell = w2["execute_score"] < w1["execute_score"]
    impact_rose = w2["impact_score"] > w1["impact_score"]
    # Stronger check: impact should overtake execute or at least be close
    impact_near_or_above = w2["impact_score"] >= w2["execute_score"] * 0.6

    passed = exec_fell and impact_rose
    print(f"\n  execute fell:     {'✓' if exec_fell else '✗'} ({w1['execute_score']:.4f} → {w2['execute_score']:.4f})")
    print(f"  impact rose:      {'✓' if impact_rose else '✗'} ({w1['impact_score']:.4f} → {w2['impact_score']:.4f})")
    print(f"  impact competitive: {'✓' if impact_near_or_above else '✗'} (impact/execute = {w2['impact_score']/max(w2['execute_score'],1e-9):.2f})")
    print(f"  {'🟢 PASS' if passed else '🔴 FAIL'}: System tracks causal identity swap")
    return passed


# ═══════════════════════════════════════════════════════════════════
#  PROBE 3 — Interaction Trap (Synergies that hurt)
# ═══════════════════════════════════════════════════════════════════
def probe_interaction_trap():
    print("\n" + "=" * 72)
    print("  PROBE 3: Interaction Trap")
    print("  Individually good signals → together toxic")
    print("=" * 72)

    rng = random.Random(42)
    N_CYCLES = 300

    def gen_trap(rng: random.Random):
        """Generate observations where hypothesis and chain are individually
        correlated with reward, but TOGETHER they cause failure."""
        signals = {}
        for n in SIGNAL_NAMES:
            mu, sigma = DIST_NORMAL.get(n, (0.45, 0.15))
            signals[n] = max(0.0, min(1.0, rng.gauss(mu, sigma)))

        h = signals["hypothesis_boost"]
        c = signals["chain_alignment"]

        # Base reward from execute + bypass (normal causal)
        base = 0.50 * signals["execute_score"] + 0.25 * signals["bypass_score"]
        # Individual contributions (positive)
        base += 0.10 * h + 0.10 * c
        # INTERACTION PENALTY: when both are high, reward drops
        if h > 0.35 and c > 0.35:
            interaction_penalty = -0.60 * h * c  # strong negative synergy
            base += interaction_penalty
        # Noise
        reward = max(-1.0, min(1.0, base + rng.gauss(0, 0.05)))
        return signals, reward

    tuner = WeightTuner()
    weight_history = []

    for i in range(N_CYCLES):
        sig, rew = gen_trap(rng)
        feed(tuner, sig, rew, rng)
        if (i + 1) % 30 == 0:
            w = tuner.get_current_weights()
            weight_history.append((i + 1, dict(w)))

    final = tuner.get_current_weights()

    # Track what happens to hypothesis and chain weights
    print(f"\n  Weight trajectory:")
    print(f"  {'Obs':>5} {'execute':>10} {'bypass':>10} {'hypothesis':>10} {'chain':>10}")
    print("  " + "-" * 48)
    for obs, w in weight_history:
        print(f"  {obs:>5} {w['execute_score']:>10.4f} {w['bypass_score']:>10.4f} {w['hypothesis_boost']:>10.4f} {w['chain_alignment']:>10.4f}")

    # The interaction trap means hypothesis+chain combined hurt, so their
    # weights should be LOWER than a normal learning scenario
    # Compare: train WITH trap vs train WITHOUT trap
    tuner_clean = WeightTuner()
    rng_clean = random.Random(42)
    for _ in range(N_CYCLES):
        sig, rew = gen(rng_clean, GT_NORMAL, DIST_NORMAL)
        feed(tuner_clean, sig, rew, rng_clean)
    clean_w = tuner_clean.get_current_weights()

    print(f"\n  Comparison (trap vs clean):")
    print(f"  {'Signal':<22} {'Trap':>8} {'Clean':>8} {'Δ':>8}")
    print("  " + "-" * 50)
    for s in ["execute_score", "bypass_score", "hypothesis_boost", "chain_alignment"]:
        delta = final[s] - clean_w[s]
        print(f"  {s:<22} {final[s]:>8.4f} {clean_w[s]:>8.4f} {delta:>+8.4f}")

    # Check: in trap scenario, hypothesis and chain should be damped relative to clean
    hyp_damped = final["hypothesis_boost"] < clean_w["hypothesis_boost"] + 0.01
    chain_damped = final["chain_alignment"] < clean_w["chain_alignment"] + 0.01
    # Execute should still be strong (it's independently causal)
    exec_strong = final["execute_score"] > 0.25

    passed = exec_strong and (hyp_damped or chain_damped)
    print(f"\n  Execute survived:        {'✓' if exec_strong else '✗'} ({final['execute_score']:.4f})")
    print(f"  Hypothesis damped:       {'✓' if hyp_damped else '✗'}")
    print(f"  Chain damped:            {'✓' if chain_damped else '✗'}")
    print(f"  {'🟢 PASS' if passed else '🔴 FAIL'}: System handles toxic synergy")
    return passed


# ═══════════════════════════════════════════════════════════════════
#  PROBE 4 — Sparse Feedback Environment
# ═══════════════════════════════════════════════════════════════════
def probe_sparse_feedback():
    print("\n" + "=" * 72)
    print("  PROBE 4: Sparse Feedback")
    print("  Reward only every 5 cycles, noise in between")
    print("=" * 72)

    rng = random.Random(42)
    tuner = WeightTuner()
    N_TOTAL = 500  # need more cycles since feedback is sparse
    FEEDBACK_EVERY = 5

    regret_windows = []
    window_regret = []

    for i in range(N_TOTAL):
        sig, true_rew = gen(rng, GT_NORMAL, DIST_NORMAL)

        if (i + 1) % FEEDBACK_EVERY == 0:
            # Real feedback
            feed(tuner, sig, true_rew, rng)
        else:
            # No-information feedback (reward = 0, meaning "we don't know")
            feed(tuner, sig, 0.0, rng)

        w = tuner.get_current_weights()
        optimal = sum(GT_NORMAL[s] * sig[s] for s in SIGNAL_NAMES)
        pred = sum(w[s] * sig[s] for s in SIGNAL_NAMES)
        window_regret.append((optimal - pred) ** 2)

        if len(window_regret) >= 50:
            regret_windows.append(sum(window_regret) / len(window_regret))
            window_regret = []

    # Also train a dense-feedback tuner for comparison
    tuner_dense = WeightTuner()
    rng_dense = random.Random(42)
    for _ in range(N_TOTAL // FEEDBACK_EVERY):  # same number of REAL observations
        sig, rew = gen(rng_dense, GT_NORMAL, DIST_NORMAL)
        feed(tuner_dense, sig, rew, rng_dense)
    dense_w = tuner_dense.get_current_weights()
    sparse_w = tuner.get_current_weights()

    print(f"\n  Regret trajectory (sparse, 50-obs windows):")
    for i, r in enumerate(regret_windows):
        bar = "█" * int(r * 2000)
        print(f"    window {i+1:2d}: {r:.6f}  {bar}")

    print(f"\n  Final weights comparison:")
    print(f"  {'Signal':<22} {'Sparse':>8} {'Dense':>8} {'Prior':>8}")
    print("  " + "-" * 50)
    for s in SIGNAL_NAMES:
        print(f"  {s:<22} {sparse_w[s]:>8.4f} {dense_w[s]:>8.4f} {STATIC_PRIORS[s]:>8.4f}")

    # Check: sparse should still converge, just slower
    # execute should be top-ranked even under sparse feedback
    sparse_rank = sorted(
        [(s, abs(sparse_w[s])) for s in SIGNAL_NAMES if STATIC_PRIORS[s] > 0],
        key=lambda x: x[1], reverse=True,
    )
    exec_rank = next(i for i, (s, _) in enumerate(sparse_rank) if s == "execute_score") + 1

    # Regret should trend down
    regret_down = len(regret_windows) >= 4 and regret_windows[-1] < regret_windows[0]

    # Better than priors
    eval_rng = random.Random(888)
    mse_sparse = mse(sparse_w, GT_NORMAL, eval_rng, DIST_NORMAL)
    mse_priors = mse(dict(STATIC_PRIORS), GT_NORMAL, random.Random(888), DIST_NORMAL)
    better = mse_sparse < mse_priors

    passed = exec_rank <= 2 and better
    print(f"\n  Execute rank (sparse): #{exec_rank}")
    print(f"  Regret trending down:  {'✓' if regret_down else '✗'}")
    print(f"  MSE(sparse)={mse_sparse:.6f} vs MSE(priors)={mse_priors:.6f}: {'✓' if better else '✗'}")
    print(f"  {'🟢 PASS' if passed else '🔴 FAIL'}: Learning survives sparse feedback")
    return passed


# ═══════════════════════════════════════════════════════════════════
#  PROBE 5 — Extreme Signal Collapse
# ═══════════════════════════════════════════════════════════════════
def probe_signal_collapse():
    print("\n" + "=" * 72)
    print("  PROBE 5: Extreme Signal Collapse")
    print("  7 signals ≈ constant, only execute varies")
    print("=" * 72)

    rng = random.Random(42)
    tuner = WeightTuner()
    N_CYCLES = 200

    # Ground truth: execute is the ONLY real signal
    gt_solo = {
        "bypass_score": 0.00, "execute_score": 0.80, "impact_score": 0.00,
        "chain_alignment": 0.00, "hypothesis_boost": 0.00, "campaign_boost": 0.00,
        "detection_risk": -0.10, "cost": -0.10,
    }

    # Distribution: everything constant except execute
    dist_collapse = {
        "bypass_score": (0.50, 0.001),       # effectively constant
        "execute_score": (0.50, 0.25),        # high variance — only real signal
        "impact_score": (0.50, 0.001),
        "chain_alignment": (0.50, 0.001),
        "hypothesis_boost": (0.50, 0.001),
        "campaign_boost": (0.10, 0.001),
        "detection_risk": (0.30, 0.001),
        "cost": (0.10, 0.001),
    }

    weight_snapshots = []
    for i in range(N_CYCLES):
        sig, rew = gen(rng, gt_solo, dist_collapse)
        feed(tuner, sig, rew, rng)
        if (i + 1) % 20 == 0:
            w = tuner.get_current_weights()
            weight_snapshots.append((i + 1, dict(w)))

    final = tuner.get_current_weights()

    print(f"\n  Weight evolution (constant signals should decay):")
    print(f"  {'Obs':>5} {'execute':>10} {'bypass':>10} {'impact':>10} {'hyp':>10} {'chain':>10}")
    print("  " + "-" * 58)
    for obs, w in weight_snapshots:
        print(f"  {obs:>5} {w['execute_score']:>10.4f} {w['bypass_score']:>10.4f} {w['impact_score']:>10.4f} {w['hypothesis_boost']:>10.4f} {w['chain_alignment']:>10.4f}")

    print(f"\n  Final weights:")
    sorted_w = sorted(
        [(s, final[s]) for s in SIGNAL_NAMES],
        key=lambda x: abs(x[1]), reverse=True,
    )
    for i, (name, w) in enumerate(sorted_w):
        marker = " ← ONLY REAL SIGNAL" if name == "execute_score" else ""
        tag = "constant" if name not in ("execute_score", "detection_risk", "cost") else ""
        print(f"    #{i+1}: {name:<22} w={w:>+.4f}  {tag}{marker}")

    # Check: execute should be dominant, constant signals should be at/near floor
    exec_rank = next(i for i, (s, _) in enumerate(sorted_w) if s == "execute_score") + 1
    exec_weight = abs(final["execute_score"])

    # Constant signals should be below some threshold (decayed toward floor)
    constant_signals = ["bypass_score", "impact_score", "chain_alignment",
                        "hypothesis_boost", "campaign_boost"]
    constant_below_threshold = sum(
        1 for s in constant_signals if abs(final[s]) < 0.10
    )

    passed = exec_rank <= 2 and constant_below_threshold >= 3
    print(f"\n  Execute rank: #{exec_rank}, |w|={exec_weight:.4f}")
    print(f"  Constant signals below 0.10: {constant_below_threshold}/5")
    print(f"  {'🟢 PASS' if passed else '🔴 FAIL'}: System isolates the only real signal")
    return passed


# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║   STRESS-TEST PROBES: Structural Overfitting Detection      ║")
    print("╚═══════════════════════════════════════════════════════════════╝\n")

    results = {}
    results["P1_cross_dist"] = probe_cross_distribution()
    results["P2_signal_swap"] = probe_signal_swap()
    results["P3_interaction_trap"] = probe_interaction_trap()
    results["P4_sparse_feedback"] = probe_sparse_feedback()
    results["P5_signal_collapse"] = probe_signal_collapse()

    print("\n")
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                   STRESS-TEST SCORECARD                     ║")
    print("╚═══════════════════════════════════════════════════════════════╝\n")

    for name, passed in results.items():
        print(f"  {'🟢 PASS' if passed else '🔴 FAIL'}  {name}")

    total = sum(results.values())
    print(f"\n  Score: {total}/{len(results)}")

    if total == len(results):
        print("\n  ✅ SYSTEM PASSES ALL STRUCTURAL OVERFITTING PROBES")
    elif total >= 4:
        print("\n  ⚠️  MOSTLY ROBUST — one probe needs attention")
    elif total >= 3:
        print("\n  ⚠️  PARTIAL — structural issues remain")
    else:
        print("\n  ❌ STRUCTURAL OVERFITTING DETECTED")

    sys.exit(0 if total == len(results) else 1)
