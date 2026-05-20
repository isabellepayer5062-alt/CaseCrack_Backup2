"""Probe: Signal Admission Control — Ablation Study.

Goal: Do new signals earn their place?

Method:
  For each of the 13 signals, run a full training loop with that signal
  zeroed out (ablated).  Measure the resulting MSE vs ground truth.
  Compare to the full-signal baseline.

Expected outcomes:
  - Core signals (bypass, execute, impact) → large MSE increase when ablated
  - New signals (stealth, novelty, temporal, environment, momentum) →
    neutral to moderate increase (context-dependent contribution)
  - FAIL CASE: if ablating a signal *consistently improves* performance,
    that signal is actively harmful and should be removed.

Verdict:
  PASS  — no signal consistently harms performance
  WARN  — a signal is purely neutral (Δ% ≈ 0)
  FAIL  — a signal consistently increases MSE by > 2% (negative contribution)
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

PASS = "✔"
FAIL = "✘"
WARN = "⚠"

# ── Ground truth: what the ideal weight vector looks like ──

GT = {
    "bypass_score": 0.22, "execute_score": 0.38, "impact_score": 0.08,
    "chain_alignment": 0.04, "hypothesis_boost": 0.03, "environment_fit": 0.04,
    "campaign_boost": 0.02, "stealth_score": 0.03, "temporal_relevance": 0.02,
    "novelty_score": 0.02, "chain_momentum": 0.02,
    "detection_risk": -0.06, "cost": -0.04,
}

# Distribution parameters: (mean, std) for each signal
DIST = {
    "bypass_score": (0.50, 0.20), "execute_score": (0.50, 0.20),
    "impact_score": (0.40, 0.15), "chain_alignment": (0.35, 0.12),
    "hypothesis_boost": (0.25, 0.10), "environment_fit": (0.40, 0.12),
    "campaign_boost": (0.10, 0.06), "stealth_score": (0.30, 0.12),
    "temporal_relevance": (0.30, 0.10), "novelty_score": (0.30, 0.12),
    "chain_momentum": (0.25, 0.10),
    "detection_risk": (0.30, 0.10), "cost": (0.12, 0.06),
}

N_TRAIN = 200
N_EVAL = 300
SEED = 42


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


def _gen_sample(rng: random.Random) -> tuple[dict[str, float], float]:
    """Generate one (signals, reward) sample from the ground truth."""
    signals = {}
    for n in SIGNAL_NAMES:
        mu, sigma = DIST[n]
        signals[n] = max(0.0, min(1.0, rng.gauss(mu, sigma)))

    raw = sum(GT[n] * signals[n] for n in SIGNAL_NAMES)
    noise = rng.gauss(0, 0.05)
    reward = max(-1.0, min(1.0, raw + noise))
    return signals, reward


def _mse(weights: dict, rng_seed: int) -> float:
    """Compute prediction MSE against ground truth over N_EVAL samples."""
    rng = random.Random(rng_seed)
    total_sq = 0.0
    for _ in range(N_EVAL):
        signals, true_reward = _gen_sample(rng)
        pred = sum(weights.get(s, 0) * signals[s] for s in SIGNAL_NAMES)
        total_sq += (pred - true_reward) ** 2
    return total_sq / N_EVAL


def _run_ablation(ablated_signal: str | None) -> tuple[float, dict]:
    """Train a tuner with one signal ablated, return (MSE, final_weights)."""
    tuner = WeightTuner()
    rng = random.Random(SEED)

    for _ in range(N_TRAIN):
        signals, reward = _gen_sample(rng)
        if ablated_signal:
            signals[ablated_signal] = 0.0  # zero out the ablated signal
        _feed(tuner, signals, reward, rng)

    weights = tuner.get_current_weights()
    mse = _mse(weights, SEED + 1000)
    return mse, weights


# ── Main probe ──

def main():
    print("=" * 72)
    print("  PROBE: Signal Admission Control — Ablation Study")
    print("=" * 72)

    # Step 1: Baseline (no ablation)
    print("\n  Training baseline (all 13 signals active)...")
    baseline_mse, baseline_w = _run_ablation(None)
    print(f"  Baseline MSE: {baseline_mse:.6f}")

    # Step 2: Ablate each signal
    results = {}
    print(f"\n  {'Signal':<22s} {'MSE':>10s} {'ΔMSE%':>8s} {'Verdict':>8s}")
    print("  " + "-" * 52)

    harmful_signals = []
    neutral_signals = []
    beneficial_signals = []

    for sig in SIGNAL_NAMES:
        mse, w = _run_ablation(sig)
        delta_pct = ((mse - baseline_mse) / max(baseline_mse, 1e-9)) * 100
        results[sig] = {"mse": mse, "delta_pct": delta_pct}

        if delta_pct < -2.0:
            # Removing this signal HELPS → signal is harmful
            verdict = f"{FAIL} HARM"
            harmful_signals.append(sig)
        elif delta_pct < 0.5:
            verdict = f"{WARN} neutral"
            neutral_signals.append(sig)
        else:
            verdict = f"{PASS} earns"
            beneficial_signals.append(sig)

        print(f"  {sig:<22s} {mse:>10.6f} {delta_pct:>+7.2f}% {verdict}")

    # Step 3: Summary
    print("\n" + "=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"\n  Beneficial (ablation hurts): {len(beneficial_signals)}")
    for s in beneficial_signals:
        print(f"    {PASS} {s}: +{results[s]['delta_pct']:.2f}% MSE when removed")

    print(f"\n  Neutral (Δ < 0.5%): {len(neutral_signals)}")
    for s in neutral_signals:
        print(f"    {WARN} {s}: {results[s]['delta_pct']:+.2f}% MSE when removed")

    print(f"\n  Harmful (removal helps > 2%): {len(harmful_signals)}")
    for s in harmful_signals:
        print(f"    {FAIL} {s}: {results[s]['delta_pct']:+.2f}% MSE when removed — INVESTIGATE")

    # Step 4: Specific check — do core signals maintain dominance?
    print("\n  Core signal dominance check:")
    core = ["bypass_score", "execute_score", "impact_score"]
    for c in core:
        d = results[c]["delta_pct"]
        status = PASS if d > 1.0 else (WARN if d > 0 else FAIL)
        print(f"    {status} {c}: Δ{d:+.2f}% — {'dominant' if d > 1.0 else 'weakened' if d > 0 else 'DILUTED'}")

    # Final verdict
    all_pass = len(harmful_signals) == 0
    core_dominant = all(results[c]["delta_pct"] > 0.5 for c in core)

    print(f"\n  {'=' * 50}")
    if all_pass and core_dominant:
        print(f"  {PASS} PROBE PASSED: All signals earn their place, core signals dominant")
    elif all_pass:
        print(f"  {WARN} PROBE WARN: No harmful signals, but core dilution detected")
    else:
        print(f"  {FAIL} PROBE FAILED: {len(harmful_signals)} harmful signal(s) detected")
    print(f"  {'=' * 50}")

    return all_pass, core_dominant, results


if __name__ == "__main__":
    all_pass, core_dom, _ = main()
    sys.exit(0 if all_pass else 1)
