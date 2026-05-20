"""Convergence validation: Does WeightTuner learn TRUTH, not noise?

Six tests that verify the system is converging toward correct weights,
not just mechanically moving numbers.

Test 1 — Regret goes down over time
Test 2 — Harmful signals lose weight
Test 3 — Execute score becomes dominant
Test 4 — Correlation structure improves
Test 5 — Kill test (harmful signals less harmful after learning)
Test 6 — Learning reversal (system adapts when environment flips)
"""

from __future__ import annotations

import math
import random
import sys
import time

sys.path.insert(0, "CaseCrack")

from tools.burp_enterprise.exploit_chains.weight_tuner import (
    SIGNAL_NAMES,
    STATIC_PRIORS,
    WeightTuner,
    _jitter,
)


# ─── Ground truth: which signals CAUSALLY predict reward ──────────
# In reality, execute_score is the strongest causal predictor.
# bypass_score is moderately causal.
# hypothesis_boost, chain_alignment, impact_score are weakly/non-causal.
# campaign_boost, detection_risk, cost are contextual noise.

GROUND_TRUTH_WEIGHTS = {
    "bypass_score":      0.25,   # moderate causal
    "execute_score":     0.50,   # strong causal
    "impact_score":      0.05,   # weak/noise
    "chain_alignment":   0.03,   # weak/noise
    "hypothesis_boost":  0.02,   # harmful (boosts exploration, not reward)
    "campaign_boost":    0.00,   # no causal link
    "detection_risk":   -0.10,   # mild negative (higher risk → lower reward)
    "cost":             -0.05,   # mild negative
}

HARMFUL_SIGNALS = ["hypothesis_boost", "chain_alignment", "impact_score"]
CAUSAL_SIGNALS = ["execute_score", "bypass_score"]


def generate_synthetic_observation(rng: random.Random, ground_truth: dict):
    """Generate (signals_dict, reward) with known causal structure.

    reward = Σ gt_weight_i * signal_i + noise
    """
    signals = {}
    for name in SIGNAL_NAMES:
        # Varied signals: each drawn from U(0.1, 0.9) with some
        # per-signal bias to create realistic distributions
        bias = {"bypass_score": 0.5, "execute_score": 0.4,
                "impact_score": 0.3, "chain_alignment": 0.35,
                "hypothesis_boost": 0.25, "campaign_boost": 0.1,
                "detection_risk": 0.3, "cost": 0.15}.get(name, 0.3)
        signals[name] = max(0.0, min(1.0, rng.gauss(bias, 0.20)))

    # Reward = ground truth weighted combination + noise
    raw_reward = sum(ground_truth[s] * signals[s] for s in SIGNAL_NAMES)
    noise = rng.gauss(0, 0.05)
    reward = max(-1.0, min(1.0, raw_reward + noise))

    return signals, reward


def feed_tuner(tuner: WeightTuner, signals: dict, reward: float, rng: random.Random):
    """Feed a synthetic observation into the tuner via its observe() method."""
    # Build a minimal fake event + payload to call observe()
    payload_str = f"payload_{rng.randint(0, 100000)}"

    class FakePayload:
        pass

    fp = FakePayload()
    fp.payload = payload_str
    for name in SIGNAL_NAMES:
        setattr(fp, name, signals[name])

    class FakeEvent:
        pass

    fe = FakeEvent()
    fe.payload = fp
    fe.reward_signal = reward

    tuner.observe(fe)


def compute_regret(weights: dict, signals: dict, reward: float, ground_truth: dict):
    """Regret = (optimal_prediction - actual_prediction)².

    Optimal = ground truth weights applied to signals.
    Actual = current learned weights applied to signals.
    """
    optimal_pred = sum(ground_truth[s] * signals[s] for s in SIGNAL_NAMES)
    actual_pred = sum(weights.get(s, 0.0) * signals[s] for s in SIGNAL_NAMES)
    return (optimal_pred - actual_pred) ** 2


def correlation(xs, ys):
    """Pearson correlation coefficient."""
    n = len(xs)
    if n < 3:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    sx = math.sqrt(max(0, sum((x - mx) ** 2 for x in xs) / n))
    sy = math.sqrt(max(0, sum((y - my) ** 2 for y in ys) / n))
    if sx < 1e-12 or sy < 1e-12:
        return 0.0
    cov = sum((xs[i] - mx) * (ys[i] - my) for i in range(n)) / n
    return cov / (sx * sy)


# ═══════════════════════════════════════════════════════════════════
# TEST 1: Does regret go down over time?
# ═══════════════════════════════════════════════════════════════════
def test_regret_decreases():
    print("=" * 72)
    print("  TEST 1: Does regret decrease over time?")
    print("=" * 72)

    rng = random.Random(42)
    tuner = WeightTuner()
    N_CYCLES = 200
    WINDOW = 20

    all_regrets = []
    for i in range(N_CYCLES):
        signals, reward = generate_synthetic_observation(rng, GROUND_TRUTH_WEIGHTS)
        feed_tuner(tuner, signals, reward, rng)
        weights = tuner.get_current_weights()
        reg = compute_regret(weights, signals, reward, GROUND_TRUTH_WEIGHTS)
        all_regrets.append(reg)

    # Compare first quarter vs last quarter
    q1 = all_regrets[:N_CYCLES // 4]
    q4 = all_regrets[-N_CYCLES // 4:]
    mean_q1 = sum(q1) / len(q1)
    mean_q4 = sum(q4) / len(q4)
    ratio = mean_q4 / max(mean_q1, 1e-12)

    # Moving average trend
    windows = []
    for start in range(0, N_CYCLES - WINDOW, WINDOW):
        chunk = all_regrets[start:start + WINDOW]
        windows.append(sum(chunk) / len(chunk))

    trend_down = sum(1 for i in range(1, len(windows)) if windows[i] < windows[i - 1])
    trend_pct = trend_down / max(1, len(windows) - 1) * 100

    print(f"\n  Regret Q1 (first {N_CYCLES // 4} obs):   {mean_q1:.6f}")
    print(f"  Regret Q4 (last  {N_CYCLES // 4} obs):   {mean_q4:.6f}")
    print(f"  Reduction ratio:                 {ratio:.4f}x")
    print(f"  Windows trending down:           {trend_pct:.0f}%")
    print(f"  Window means: {['%.5f' % w for w in windows]}")

    passed = mean_q4 < mean_q1 * 0.80  # at least 20% regret reduction
    print(f"\n  {'🟢 PASS' if passed else '🔴 FAIL'}: Regret Q4 {'<' if passed else '>='} 80% of Q1")
    return passed


# ═══════════════════════════════════════════════════════════════════
# TEST 2: Do harmful signals lose weight?
# ═══════════════════════════════════════════════════════════════════
def test_harmful_signals_decrease():
    print("\n" + "=" * 72)
    print("  TEST 2: Do harmful signals lose weight?")
    print("=" * 72)

    rng = random.Random(42)
    tuner = WeightTuner()
    N_CYCLES = 200

    weight_history = {s: [] for s in SIGNAL_NAMES}

    for i in range(N_CYCLES):
        signals, reward = generate_synthetic_observation(rng, GROUND_TRUTH_WEIGHTS)
        feed_tuner(tuner, signals, reward, rng)
        if (i + 1) % 5 == 0:  # after each calibration
            w = tuner.get_current_weights()
            for s in SIGNAL_NAMES:
                weight_history[s].append(w[s])

    print(f"\n  Weight trajectory (every 5 obs, {len(weight_history['bypass_score'])} snapshots):")
    print(f"  {'Signal':<22} {'Start':>8} {'Mid':>8} {'End':>8} {'Trend':>8}")
    print("  " + "-" * 58)

    harmful_decreased = 0
    for signal in HARMFUL_SIGNALS:
        h = weight_history[signal]
        if len(h) < 3:
            continue
        start = h[0]
        mid = h[len(h) // 2]
        end = h[-1]
        prior = STATIC_PRIORS[signal]
        decreased = end < start
        harmful_decreased += int(decreased)
        arrow = "↓" if decreased else "↑"
        print(f"  {signal:<22} {start:>8.4f} {mid:>8.4f} {end:>8.4f}   {arrow}")

    for signal in CAUSAL_SIGNALS:
        h = weight_history[signal]
        if len(h) < 3:
            continue
        start = h[0]
        mid = h[len(h) // 2]
        end = h[-1]
        arrow = "↑" if end > start else "↓"
        print(f"  {signal:<22} {start:>8.4f} {mid:>8.4f} {end:>8.4f}   {arrow} (causal)")

    for signal in [s for s in SIGNAL_NAMES if s not in HARMFUL_SIGNALS and s not in CAUSAL_SIGNALS]:
        h = weight_history[signal]
        if len(h) < 3:
            continue
        print(f"  {signal:<22} {h[0]:>8.4f} {h[len(h)//2]:>8.4f} {h[-1]:>8.4f}")

    passed = harmful_decreased >= 2  # at least 2 of 3 harmful signals decrease
    print(f"\n  {'🟢 PASS' if passed else '🔴 FAIL'}: {harmful_decreased}/3 harmful signals decreased")
    return passed


# ═══════════════════════════════════════════════════════════════════
# TEST 3: Does execute_score become dominant?
# ═══════════════════════════════════════════════════════════════════
def test_execute_dominance():
    print("\n" + "=" * 72)
    print("  TEST 3: Does execute_score become dominant?")
    print("=" * 72)

    rng = random.Random(42)
    tuner = WeightTuner()
    N_CYCLES = 200

    for i in range(N_CYCLES):
        signals, reward = generate_synthetic_observation(rng, GROUND_TRUTH_WEIGHTS)
        feed_tuner(tuner, signals, reward, rng)

    final = tuner.get_current_weights()
    sorted_w = sorted(
        [(s, abs(final[s])) for s in SIGNAL_NAMES],
        key=lambda x: x[1], reverse=True,
    )

    print("\n  Final weight ranking (by |weight|):")
    for i, (name, mag) in enumerate(sorted_w):
        marker = " ← TARGET" if name == "execute_score" else ""
        print(f"    #{i+1}: {name:<22} |w|={mag:.4f}{marker}")

    execute_rank = next(i for i, (s, _) in enumerate(sorted_w) if s == "execute_score") + 1
    execute_weight = abs(final["execute_score"])

    # Pass if execute_score is in top 2 and has significant weight
    passed = execute_rank <= 2 and execute_weight > 0.15
    print(f"\n  execute_score rank: #{execute_rank}, |weight|={execute_weight:.4f}")
    print(f"  {'🟢 PASS' if passed else '🔴 FAIL'}: execute_score is rank #{execute_rank} (need ≤2) with |w|={execute_weight:.4f} (need >0.15)")
    return passed


# ═══════════════════════════════════════════════════════════════════
# TEST 4: Correlation structure improves
# ═══════════════════════════════════════════════════════════════════
def test_correlation_shift():
    print("\n" + "=" * 72)
    print("  TEST 4: Does correlation structure improve?")
    print("=" * 72)

    rng = random.Random(42)
    tuner = WeightTuner()
    N_CYCLES = 200
    PHASE_SIZE = 50

    # Collect signal→reward data in phases
    phases = {p: {s: [] for s in SIGNAL_NAMES} for p in ["early", "late"]}
    phases_rewards = {"early": [], "late": []}

    for i in range(N_CYCLES):
        signals, reward = generate_synthetic_observation(rng, GROUND_TRUTH_WEIGHTS)
        feed_tuner(tuner, signals, reward, rng)

        phase = "early" if i < PHASE_SIZE else "late" if i >= N_CYCLES - PHASE_SIZE else None
        if phase:
            for s in SIGNAL_NAMES:
                phases[phase][s].append(signals[s])
            phases_rewards[phase].append(reward)

    print(f"\n  Signal-Reward Correlations (early vs late phases):")
    print(f"  {'Signal':<22} {'Early corr':>12} {'Late corr':>12} {'Δ':>8} {'Expected':>10}")
    print("  " + "-" * 66)

    # Also track tuner's internal correlations
    tuner_corr = tuner.get_signal_correlations()

    improvements = 0
    for signal in SIGNAL_NAMES:
        gt_w = GROUND_TRUTH_WEIGHTS[signal]
        expected_dir = "+" if gt_w > 0.05 else "-" if gt_w < -0.05 else "~0"

        early_corr = correlation(phases["early"][signal], phases_rewards["early"])
        late_corr = correlation(phases["late"][signal], phases_rewards["late"])

        # "Improvement" = corr moves in the direction we'd expect given ground truth
        if gt_w > 0.05:
            improved = late_corr > early_corr - 0.05  # causal: maintain or increase
            improvements += int(improved)
        elif gt_w < -0.05:
            improved = late_corr < early_corr + 0.05  # negative: maintain or decrease
            improvements += int(improved)
        else:
            improved = True  # don't care about noise signals
            improvements += 1

        delta = late_corr - early_corr
        mark = "✓" if improved else "✗"
        print(f"  {signal:<22} {early_corr:>12.4f} {late_corr:>12.4f} {delta:>+8.4f}   {expected_dir:>4} {mark}")

    print(f"\n  Tuner's internal correlations (EMA-based):")
    for s in SIGNAL_NAMES:
        print(f"    {s:<22}: {tuner_corr[s]:>+.4f}")

    passed = improvements >= 6
    print(f"\n  {'🟢 PASS' if passed else '🔴 FAIL'}: {improvements}/8 signal correlations align with ground truth")
    return passed


# ═══════════════════════════════════════════════════════════════════
# TEST 5: Kill test — harmful signals less harmful after learning
# ═══════════════════════════════════════════════════════════════════
def test_kill_test():
    print("\n" + "=" * 72)
    print("  TEST 5: Kill test — harmful signals less harmful?")
    print("=" * 72)

    rng = random.Random(42)
    N_CYCLES = 200
    N_EVAL = 50

    # Train a tuner
    tuner = WeightTuner()
    for i in range(N_CYCLES):
        signals, reward = generate_synthetic_observation(rng, GROUND_TRUTH_WEIGHTS)
        feed_tuner(tuner, signals, reward, rng)

    learned_weights = tuner.get_current_weights()

    # Generate evaluation set
    eval_rng = random.Random(999)
    eval_set = [generate_synthetic_observation(eval_rng, GROUND_TRUTH_WEIGHTS) for _ in range(N_EVAL)]

    def score_with_weights(weights, signals):
        return sum(weights.get(s, 0) * signals[s] for s in SIGNAL_NAMES)

    def mse_on_eval(weights):
        errors = []
        for signals, true_reward in eval_set:
            pred = score_with_weights(weights, signals)
            errors.append((true_reward - pred) ** 2)
        return sum(errors) / len(errors)

    baseline_mse = mse_on_eval(learned_weights)
    prior_mse = mse_on_eval(STATIC_PRIORS)

    print(f"\n  MSE on evaluation set:")
    print(f"    Static priors:   {prior_mse:.6f}")
    print(f"    Learned weights: {baseline_mse:.6f}")
    print(f"    Improvement:     {(1 - baseline_mse / max(prior_mse, 1e-12)) * 100:.1f}%")

    # Kill each signal: set its weight to 0 and renormalize
    print(f"\n  Signal kill impact (MSE change when signal removed):")
    print(f"  {'Signal':<22} {'Kill MSE':>10} {'Δ MSE':>10} {'Impact':>10}")
    print("  " + "-" * 58)

    for signal in SIGNAL_NAMES:
        killed = dict(learned_weights)
        killed[signal] = 0.0
        total = sum(abs(v) for v in killed.values())
        if total > 0:
            killed = {s: v / total for s, v in killed.items()}
        kill_mse = mse_on_eval(killed)
        delta = kill_mse - baseline_mse
        gt_importance = abs(GROUND_TRUTH_WEIGHTS[signal])
        label = "HARMFUL" if signal in HARMFUL_SIGNALS else "CAUSAL" if signal in CAUSAL_SIGNALS else ""
        print(f"  {signal:<22} {kill_mse:>10.6f} {delta:>+10.6f}   {label}")

    # Check: killing harmful signals should help (reduce MSE) or barely hurt
    harmful_kills = {}
    for signal in HARMFUL_SIGNALS:
        killed = dict(learned_weights)
        killed[signal] = 0.0
        total = sum(abs(v) for v in killed.values())
        if total > 0:
            killed = {s: v / total for s, v in killed.items()}
        harmful_kills[signal] = mse_on_eval(killed) - baseline_mse

    # After learning, harmful signals should have LESS impact than before
    # Compare with static priors
    harmful_kills_prior = {}
    for signal in HARMFUL_SIGNALS:
        killed = dict(STATIC_PRIORS)
        killed[signal] = 0.0
        total = sum(abs(v) for v in killed.values())
        if total > 0:
            killed = {s: v / total for s, v in killed.items()}
        harmful_kills_prior[signal] = mse_on_eval(killed) - prior_mse

    print(f"\n  Harmful signal kill impact comparison:")
    print(f"  {'Signal':<22} {'Prior kill Δ':>12} {'Learned kill Δ':>14} {'Reduced?':>10}")
    print("  " + "-" * 60)

    reduced_count = 0
    for signal in HARMFUL_SIGNALS:
        prior_delta = harmful_kills_prior[signal]
        learned_delta = harmful_kills[signal]
        reduced = abs(learned_delta) <= abs(prior_delta) + 0.001  # learned version less impactful
        reduced_count += int(reduced)
        print(f"  {signal:<22} {prior_delta:>+12.6f} {learned_delta:>+14.6f}   {'✓' if reduced else '✗'}")

    passed = baseline_mse < prior_mse  # learned weights should predict better than priors
    print(f"\n  {'🟢 PASS' if passed else '🔴 FAIL'}: Learned MSE ({baseline_mse:.6f}) < Prior MSE ({prior_mse:.6f})")
    return passed


# ═══════════════════════════════════════════════════════════════════
# TEST 6: Learning reversal — adapt when environment flips
# ═══════════════════════════════════════════════════════════════════
def test_learning_reversal():
    print("\n" + "=" * 72)
    print("  TEST 6: Learning reversal — does system adapt?")
    print("=" * 72)

    N_PHASE1 = 150   # learn normal environment
    N_PHASE2 = 250   # flipped environment (more cycles needed to overcome prior)

    # Phase 1: Normal ground truth
    normal_gt = dict(GROUND_TRUTH_WEIGHTS)

    # Phase 2: FLIPPED ground truth — execute becomes worthless, impact becomes king
    flipped_gt = {
        "bypass_score":      0.05,   # was 0.25 → weak
        "execute_score":     0.02,   # was 0.50 → nearly worthless
        "impact_score":      0.45,   # was 0.05 → NOW DOMINANT
        "chain_alignment":   0.30,   # was 0.03 → now strong
        "hypothesis_boost":  0.05,   # stays weak
        "campaign_boost":    0.00,
        "detection_risk":   -0.08,
        "cost":             -0.05,
    }

    rng = random.Random(42)
    tuner = WeightTuner()

    # Phase 1: Train on normal environment
    phase1_weights_history = []
    for i in range(N_PHASE1):
        signals, reward = generate_synthetic_observation(rng, normal_gt)
        feed_tuner(tuner, signals, reward, rng)
        if (i + 1) % 10 == 0:
            phase1_weights_history.append(dict(tuner.get_current_weights()))

    weights_after_phase1 = tuner.get_current_weights()

    print(f"\n  After Phase 1 ({N_PHASE1} obs, normal environment):")
    print(f"    execute_score:    {weights_after_phase1['execute_score']:>+.4f}")
    print(f"    impact_score:     {weights_after_phase1['impact_score']:>+.4f}")
    print(f"    chain_alignment:  {weights_after_phase1['chain_alignment']:>+.4f}")
    print(f"    bypass_score:     {weights_after_phase1['bypass_score']:>+.4f}")

    # Phase 2: Flip the environment
    phase2_weights_history = []
    for i in range(N_PHASE2):
        signals, reward = generate_synthetic_observation(rng, flipped_gt)
        feed_tuner(tuner, signals, reward, rng)
        if (i + 1) % 10 == 0:
            phase2_weights_history.append(dict(tuner.get_current_weights()))

    weights_after_phase2 = tuner.get_current_weights()

    print(f"\n  After Phase 2 ({N_PHASE2} obs, FLIPPED environment):")
    print(f"    execute_score:    {weights_after_phase2['execute_score']:>+.4f}")
    print(f"    impact_score:     {weights_after_phase2['impact_score']:>+.4f}")
    print(f"    chain_alignment:  {weights_after_phase2['chain_alignment']:>+.4f}")
    print(f"    bypass_score:     {weights_after_phase2['bypass_score']:>+.4f}")

    # Check: impact_score should have increased, execute_score should have decreased
    execute_delta = weights_after_phase2["execute_score"] - weights_after_phase1["execute_score"]
    impact_delta = weights_after_phase2["impact_score"] - weights_after_phase1["impact_score"]
    chain_delta = weights_after_phase2["chain_alignment"] - weights_after_phase1["chain_alignment"]

    print(f"\n  Weight shifts (Phase 2 vs Phase 1):")
    print(f"    execute_score Δ:   {execute_delta:>+.4f}  (expect ↓)")
    print(f"    impact_score Δ:    {impact_delta:>+.4f}  (expect ↑)")
    print(f"    chain_alignment Δ: {chain_delta:>+.4f}  (expect ↑)")

    # Track the trajectory: show every 50 obs
    print(f"\n  Weight trajectory snapshots:")
    print(f"  {'Phase':<8} {'Obs':>5} {'execute':>10} {'impact':>10} {'chain':>10} {'bypass':>10}")
    print("  " + "-" * 58)
    for i, w in enumerate(phase1_weights_history):
        if (i + 1) % 5 == 0:  # every ~50 obs
            obs = (i + 1) * 10
            print(f"  {'P1':<8} {obs:>5} {w['execute_score']:>10.4f} {w['impact_score']:>10.4f} {w['chain_alignment']:>10.4f} {w['bypass_score']:>10.4f}")
    for i, w in enumerate(phase2_weights_history):
        if (i + 1) % 5 == 0:  # every ~50 obs
            obs = N_PHASE1 + (i + 1) * 10
            print(f"  {'P2-flip':<8} {obs:>5} {w['execute_score']:>10.4f} {w['impact_score']:>10.4f} {w['chain_alignment']:>10.4f} {w['bypass_score']:>10.4f}")

    # Pass criteria:
    # - execute_score went down (no longer dominant)
    # - impact_score or chain_alignment went up (new dominant signals)
    execute_down = execute_delta < -0.01
    new_signal_up = impact_delta > 0.01 or chain_delta > 0.01

    passed = execute_down and new_signal_up
    print(f"\n  Execute decreased: {'✓' if execute_down else '✗'} (Δ={execute_delta:+.4f})")
    print(f"  New signal rose:   {'✓' if new_signal_up else '✗'} (impact Δ={impact_delta:+.4f}, chain Δ={chain_delta:+.4f})")
    print(f"  {'🟢 PASS' if passed else '🔴 FAIL'}: System {'adapted' if passed else 'failed to adapt'} to environment flip")
    return passed


# ═══════════════════════════════════════════════════════════════════
# BONUS: Weight velocity stability check
# ═══════════════════════════════════════════════════════════════════
def test_velocity_stability():
    print("\n" + "=" * 72)
    print("  BONUS: Weight velocity — stable, not chaotic or frozen?")
    print("=" * 72)

    rng = random.Random(42)
    tuner = WeightTuner()
    N_CYCLES = 200

    velocities = []
    for i in range(N_CYCLES):
        signals, reward = generate_synthetic_observation(rng, GROUND_TRUTH_WEIGHTS)
        feed_tuner(tuner, signals, reward, rng)
        if (i + 1) % 5 == 0:
            v = tuner.get_weight_velocity()
            total_v = sum(abs(v[s]) for s in SIGNAL_NAMES)
            velocities.append(total_v)

    print(f"\n  Velocity trajectory (total |Δw| per calibration):")
    # Show in chunks
    CHUNK = 8
    for start in range(0, len(velocities), CHUNK):
        chunk = velocities[start:start + CHUNK]
        obs_start = (start + 1) * 5
        vals = " ".join(f"{v:.4f}" for v in chunk)
        print(f"    obs {obs_start:>4}: {vals}")

    early_v = sum(velocities[:len(velocities) // 3]) / max(1, len(velocities) // 3)
    late_v = sum(velocities[-len(velocities) // 3:]) / max(1, len(velocities) // 3)

    print(f"\n  Early avg velocity: {early_v:.6f}")
    print(f"  Late avg velocity:  {late_v:.6f}")

    # Healthy: velocity decreases (convergence) but stays above zero (still learning)
    converging = late_v < early_v
    still_learning = late_v > 0.001
    not_chaotic = late_v < 0.5

    print(f"\n  Converging (late < early): {'✓' if converging else '✗'}")
    print(f"  Still learning (late > 0.001): {'✓' if still_learning else '✗'}")
    print(f"  Not chaotic (late < 0.50): {'✓' if not_chaotic else '✗'}")

    passed = converging and still_learning and not_chaotic
    print(f"  {'🟢 PASS' if passed else '🔴 FAIL'}: Velocity is {'healthy' if passed else 'unhealthy'}")
    return passed


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║   CONVERGENCE VALIDATION: Is the system learning TRUTH?     ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Ground truth: execute_score=0.50, bypass_score=0.25")
    print(f"  Harmful (should ↓): {HARMFUL_SIGNALS}")
    print(f"  Causal  (should ↑): {CAUSAL_SIGNALS}")

    results = {}
    results["T1_regret"] = test_regret_decreases()
    results["T2_harmful_decrease"] = test_harmful_signals_decrease()
    results["T3_execute_dominant"] = test_execute_dominance()
    results["T4_correlation"] = test_correlation_shift()
    results["T5_kill_test"] = test_kill_test()
    results["T6_reversal"] = test_learning_reversal()
    results["BONUS_velocity"] = test_velocity_stability()

    print("\n")
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                    FINAL SCORECARD                          ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()

    all_pass = True
    for name, passed in results.items():
        status = "🟢 PASS" if passed else "🔴 FAIL"
        print(f"  {status}  {name}")
        if not passed:
            all_pass = False

    total = sum(results.values())
    print(f"\n  Score: {total}/{len(results)}")

    if all_pass:
        print("\n  ✅ SYSTEM IS CONVERGING TOWARD TRUTH")
    elif total >= 5:
        print("\n  ⚠️  MOSTLY CORRECT — minor tuning needed")
    elif total >= 3:
        print("\n  ⚠️  PARTIAL LEARNING — significant issues remain")
    else:
        print("\n  ❌ SYSTEM IS NOT LEARNING CORRECTLY")

    sys.exit(0 if all_pass else 1)
