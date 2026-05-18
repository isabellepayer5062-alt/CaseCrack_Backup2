"""Probe UU-1: Partial Observability Recovery.

Tests whether the weight tuner permanently decays context-dependent
signals when they collapse to fixed baselines during a "dark" period
(no recon data), and whether it can recover when rich context returns.

Design:
  Phase 1 (200 events): Full context  --> all 13 signals are informative
  Phase 2 (200 events): Empty context --> 4+ signals collapse to baselines
  Phase 3 (200 events): Full context  --> signals should recover

Fail conditions:
  F1: After Phase 3, any previously-healthy signal has weight < 50%
      of its Phase 1 weight  (permanent decay)
  F2: Low-variance decay triggers during Phase 2 and is never reversed
  F3: Recovery takes more than 100 events to reach 90% of Phase 1 MSE

Ground truth:
  Phase 1/3 GT has diverse, informative signals.
  Phase 2 GT has ~same rewards but signals are collapsed, so the
  tuner should learn to ignore them (temporarily) but NOT permanently.
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

SEED = 42

# Phase sizes
N_PHASE1 = 200  # Rich context training
N_PHASE2 = 200  # Dark period (partial observability)
N_PHASE3 = 200  # Recovery (rich context returns)

# Ground truth weights for rich-context environment
GT_RICH = {
    "bypass_score": 0.22, "execute_score": 0.30, "impact_score": 0.10,
    "chain_alignment": 0.05, "hypothesis_boost": 0.04, "environment_fit": 0.06,
    "campaign_boost": 0.03, "stealth_score": 0.04, "temporal_relevance": 0.03,
    "novelty_score": 0.02, "chain_momentum": 0.03,
    "detection_risk": -0.06, "cost": -0.04,
}

# Signal distributions for rich context (all signals informative)
DIST_RICH = {
    "bypass_score": (0.55, 0.18), "execute_score": (0.50, 0.20),
    "impact_score": (0.40, 0.15), "chain_alignment": (0.35, 0.12),
    "hypothesis_boost": (0.30, 0.10), "environment_fit": (0.45, 0.15),
    "campaign_boost": (0.15, 0.06), "stealth_score": (0.35, 0.12),
    "temporal_relevance": (0.35, 0.10), "novelty_score": (0.30, 0.10),
    "chain_momentum": (0.30, 0.10),
    "detection_risk": (0.25, 0.10), "cost": (0.10, 0.05),
}

# Collapsed signals during dark period -- these return fixed baselines
COLLAPSED_SIGNALS = {
    "environment_fit", "temporal_relevance", "chain_momentum", "stealth_score",
}

# Signal distributions for dark period
# Non-collapsed signals: same as rich.  Collapsed: near-zero variance.
DIST_DARK = dict(DIST_RICH)
for s in COLLAPSED_SIGNALS:
    DIST_DARK[s] = (0.40, 0.005)  # collapsed to baseline ~0.40 +/- noise


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
    noise = rng.gauss(0, 0.04)
    return signals, max(-1.0, min(1.0, raw + noise))


def _mse(weights: dict, gt: dict, dist: dict, seed: int, n: int = 300) -> float:
    rng = random.Random(seed)
    total = 0.0
    for _ in range(n):
        signals, reward = _gen(rng, gt, dist)
        pred = sum(weights.get(s, 0) * signals[s] for s in SIGNAL_NAMES)
        total += (pred - reward) ** 2
    return total / n


def main():
    print("=" * 72)
    print("  PROBE UU-1: Partial Observability Recovery")
    print("  Train rich -> dark period -> rich again. Do signals recover?")
    print("=" * 72)

    tuner = WeightTuner()
    rng = random.Random(SEED)

    # ── Phase 1: Rich context ──
    print(f"\n  Phase 1: Training {N_PHASE1} events with rich context...")
    for _ in range(N_PHASE1):
        signals, reward = _gen(rng, GT_RICH, DIST_RICH)
        _feed(tuner, signals, reward, rng)

    w_phase1 = tuner.get_current_weights()
    mse_phase1 = _mse(w_phase1, GT_RICH, DIST_RICH, 7777)
    print(f"    MSE (rich): {mse_phase1:.6f}")
    print(f"    Collapsed signal weights after Phase 1:")
    for s in sorted(COLLAPSED_SIGNALS):
        print(f"      {s:>22s}: {w_phase1[s]:+.4f}")

    # ── Phase 2: Dark period (partial observability) ──
    print(f"\n  Phase 2: Dark period - {N_PHASE2} events, "
          f"{len(COLLAPSED_SIGNALS)} signals collapsed...")
    for _ in range(N_PHASE2):
        signals, reward = _gen(rng, GT_RICH, DIST_DARK)
        _feed(tuner, signals, reward, rng)

    w_phase2 = tuner.get_current_weights()
    print(f"    Collapsed signal weights after dark period:")
    decay_ratios = {}
    for s in sorted(COLLAPSED_SIGNALS):
        r = w_phase2[s] / w_phase1[s] if abs(w_phase1[s]) > 1e-9 else 1.0
        decay_ratios[s] = r
        marker = " << SEVERE DECAY" if r < 0.3 else (" < decayed" if r < 0.7 else "")
        print(f"      {s:>22s}: {w_phase2[s]:+.4f} "
              f"(ratio to Phase 1: {r:.2f}){marker}")

    # ── Phase 3: Recovery (rich context returns) ──
    print(f"\n  Phase 3: Recovery - {N_PHASE3} events with rich context...")

    # Track recovery trajectory
    recovery_snapshots = []
    for i in range(1, N_PHASE3 + 1):
        signals, reward = _gen(rng, GT_RICH, DIST_RICH)
        _feed(tuner, signals, reward, rng)
        if i % 20 == 0:
            w_snap = tuner.get_current_weights()
            snap_mse = _mse(w_snap, GT_RICH, DIST_RICH, 7777)
            recovery_snapshots.append((i, snap_mse, dict(w_snap)))

    w_phase3 = tuner.get_current_weights()
    mse_phase3 = _mse(w_phase3, GT_RICH, DIST_RICH, 7777)

    print(f"    Recovery trajectory (MSE on rich):")
    print(f"    {'Events':>8s} {'MSE':>10s} {'vs Phase1':>12s}")
    recovery_event = None
    for ev, mse_val, _ in recovery_snapshots:
        ratio = mse_val / max(mse_phase1, 1e-9)
        marker = ""
        if recovery_event is None and ratio < 1.10:
            recovery_event = ev
            marker = " << recovered"
        print(f"    {ev:>8d} {mse_val:>10.6f} {ratio:>11.2f}x{marker}")

    print(f"\n    Final collapsed signal weights after recovery:")
    recovery_ratios = {}
    for s in sorted(COLLAPSED_SIGNALS):
        r = w_phase3[s] / w_phase1[s] if abs(w_phase1[s]) > 1e-9 else 1.0
        recovery_ratios[s] = r
        status = "RECOVERED" if r > 0.50 else "PERMANENT DECAY"
        print(f"      {s:>22s}: {w_phase3[s]:+.4f} "
              f"(ratio to Phase 1: {r:.2f}) [{status}]")

    # ── Verdicts ──
    print(f"\n  {'=' * 60}")

    # V1: No permanent decay -- recovered weights > 50% of Phase 1
    permanently_decayed = [
        s for s in COLLAPSED_SIGNALS if recovery_ratios[s] < 0.50
    ]
    v1 = len(permanently_decayed) == 0
    print(f"  {PASS if v1 else FAIL} V1: No permanent signal decay "
          f"(decayed: {permanently_decayed or 'none'})")

    # V2: MSE recovers to within 50% of Phase 1
    mse_recovery = mse_phase3 / max(mse_phase1, 1e-9)
    v2 = mse_recovery < 1.50
    print(f"  {PASS if v2 else FAIL} V2: MSE recovered "
          f"({mse_phase1:.6f} -> {mse_phase3:.6f}, ratio: {mse_recovery:.2f}x)")

    # V3: Recovery speed -- should reach 90% of Phase 1 MSE within 100 events
    v3 = recovery_event is not None and recovery_event <= 100
    rec_msg = f"at event {recovery_event}" if recovery_event else "never"
    print(f"  {PASS if v3 else WARN} V3: Recovery speed -- {rec_msg} "
          f"(threshold: 100 events)")

    # V4: Non-collapsed signals should NOT have been damaged
    non_collapsed = set(SIGNAL_NAMES) - COLLAPSED_SIGNALS
    damaged = []
    for s in non_collapsed:
        r = w_phase3[s] / w_phase1[s] if abs(w_phase1[s]) > 1e-9 else 1.0
        if abs(r) < 0.30:
            damaged.append(s)
    v4 = len(damaged) == 0
    print(f"  {PASS if v4 else FAIL} V4: Non-collapsed signals undamaged "
          f"(damaged: {damaged or 'none'})")

    # V5: Phase 2 SHOULD have decayed collapsed signals (the system responded)
    responded = sum(1 for s in COLLAPSED_SIGNALS if decay_ratios[s] < 0.90)
    v5 = responded >= 1
    print(f"  {PASS if v5 else WARN} V5: System responded to dark period "
          f"({responded}/{len(COLLAPSED_SIGNALS)} signals decayed)")

    overall = v1 and v2 and v4
    if overall:
        print(f"\n  {PASS}: Partial observability is recoverable")
    else:
        findings = []
        if not v1:
            findings.append(f"permanent decay in {permanently_decayed}")
        if not v2:
            findings.append(f"MSE didn't recover ({mse_recovery:.2f}x)")
        if not v4:
            findings.append(f"collateral damage to {damaged}")
        print(f"\n  {FAIL}: {findings}")
    print(f"  {'=' * 60}")

    return overall


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
