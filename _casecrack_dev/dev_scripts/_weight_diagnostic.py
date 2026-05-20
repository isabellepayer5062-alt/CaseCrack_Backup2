#!/usr/bin/env python3
"""Surgical diagnostic: trace WHERE the weight learning signal dies.

Creates a WeightTuner, feeds it known signal→reward patterns where
execute_score STRONGLY predicts success, and traces every suppression
layer to find the exact mathematical cancellation point.
"""

import sys
import os
import copy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CaseCrack"))

from dataclasses import dataclass
from tools.burp_enterprise.exploit_chains.weight_tuner import (
    WeightTuner,
    WeightObservation,
    SIGNAL_NAMES,
    STATIC_PRIORS,
    POLARITY,
    MIN_WEIGHT_MAGNITUDE,
    MAX_WEIGHT_MAGNITUDE,
    LOW_VARIANCE_EPSILON,
    LOW_VARIANCE_DECAY,
    STABILITY_DAMPEN_THRESHOLD,
    STABILITY_DAMPEN_FACTOR,
    STABILITY_WINDOW,
    BLEND_RATIO,
    RIDGE_LAMBDA,
    DECAY_FACTOR,
    MIN_OBSERVATIONS_FOR_CALIBRATION,
    _solve_linear_system,
    _compute_r_squared,
)

import time

# ── Synthetic observations: execute_score = STRONG predictor ─────────────
# Pattern: When execute_score is high → positive reward
#          When execute_score is low → negative reward
#          Other signals are random noise

import random
random.seed(42)


def make_observation(execute_high: bool, t: float) -> WeightObservation:
    """Create observation where execute_score predicts reward."""
    if execute_high:
        return WeightObservation(
            bypass_score=random.uniform(0.2, 0.8),
            execute_score=random.uniform(0.7, 1.0),  # HIGH
            impact_score=random.uniform(0.1, 0.5),
            chain_alignment=random.uniform(0.1, 0.5),
            hypothesis_boost=random.uniform(0.0, 0.3),
            campaign_boost=random.uniform(0.0, 0.2),
            detection_risk=random.uniform(0.1, 0.5),
            cost=random.uniform(0.1, 0.4),
            reward=random.uniform(0.5, 1.0),  # POSITIVE
            timestamp=t,
        )
    else:
        return WeightObservation(
            bypass_score=random.uniform(0.2, 0.8),
            execute_score=random.uniform(0.0, 0.3),  # LOW
            impact_score=random.uniform(0.1, 0.5),
            chain_alignment=random.uniform(0.1, 0.5),
            hypothesis_boost=random.uniform(0.0, 0.3),
            campaign_boost=random.uniform(0.0, 0.2),
            detection_risk=random.uniform(0.1, 0.5),
            cost=random.uniform(0.1, 0.4),
            reward=random.uniform(-1.0, -0.3),  # NEGATIVE
            timestamp=t,
        )


def trace_calibration(tuner: WeightTuner, label: str) -> dict:
    """Run _calibrate() manually with instrumentation at every step."""
    print(f"\n{'='*80}")
    print(f"  CALIBRATION TRACE: {label}")
    print(f"{'='*80}")

    with tuner._lock:
        n = len(tuner._observations)
        k = len(SIGNAL_NAMES)
        print(f"  Observations in window: {n}")
        print(f"  Total observations: {tuner._total_observations}")
        print(f"  Total calibrations so far: {tuner._total_calibrations}")

        if n < MIN_OBSERVATIONS_FOR_CALIBRATION:
            print("  ❌ Too few observations — calibration skipped")
            return {}

        # ── STEP A: Build matrices ─────────────────────────────────────
        X = []
        y = []
        d = []
        now = tuner._observations[-1].timestamp
        for obs in tuner._observations:
            X.append(list(obs.signal_vector()))
            y.append(obs.reward)
            age = max(0.0, now - obs.timestamp)
            d.append(DECAY_FACTOR ** age)

        y_mean = sum(y) / len(y)
        y_var = sum((v - y_mean) ** 2 for v in y) / len(y)
        print(f"\n  STEP A — Data matrix")
        print(f"    reward mean = {y_mean:.4f}, variance = {y_var:.4f}")
        for col_idx, name in enumerate(SIGNAL_NAMES):
            col = [X[t][col_idx] for t in range(n)]
            c_mean = sum(col) / len(col)
            c_var = sum((v - c_mean) ** 2 for v in col) / len(col)
            # Signal-reward correlation
            cov = sum((col[t] - c_mean) * (y[t] - y_mean) for t in range(n)) / n
            corr = cov / (c_var ** 0.5 * y_var ** 0.5 + 1e-12)
            print(f"    {name:20s}: mean={c_mean:.4f} var={c_var:.6f} corr(signal,reward)={corr:+.4f}")

        # ── STEP B: Solve ridge regression ─────────────────────────────
        XtDX = [[0.0] * k for _ in range(k)]
        for t in range(n):
            for i in range(k):
                for j in range(k):
                    XtDX[i][j] += d[t] * X[t][i] * X[t][j]
        for i in range(k):
            XtDX[i][i] += tuner._ridge

        XtDy = [0.0] * k
        for t in range(n):
            for i in range(k):
                XtDy[i] += d[t] * X[t][i] * y[t]

        learned = _solve_linear_system(XtDX, XtDy)
        if learned is None:
            print("  ❌ Singular matrix — no solution")
            return {}

        print(f"\n  STEP B — Ridge regression (raw learned coefficients)")
        for i, name in enumerate(SIGNAL_NAMES):
            print(f"    {name:20s}: learned = {learned[i]:+.6f}  (prior = {STATIC_PRIORS[name]:+.4f})")

        # ── STEP C: Blend with priors ──────────────────────────────────
        blended = {}
        for i, name in enumerate(SIGNAL_NAMES):
            prior = STATIC_PRIORS[name]
            raw = (1.0 - tuner._blend) * prior + tuner._blend * learned[i]
            blended[name] = raw
        
        print(f"\n  STEP C — After blend (60% prior + 40% learned)")
        for name in SIGNAL_NAMES:
            delta = blended[name] - STATIC_PRIORS[name]
            print(f"    {name:20s}: blended = {blended[name]:+.6f}  delta_from_prior = {delta:+.6f}")

        step_c = dict(blended)

        # ── STEP D: Polarity constraints ───────────────────────────────
        for name, pol in POLARITY.items():
            if pol > 0:
                blended[name] = max(MIN_WEIGHT_MAGNITUDE, blended[name])
            else:
                blended[name] = min(-MIN_WEIGHT_MAGNITUDE, blended[name])

        changes_d = {sn: blended[sn] - step_c[sn] for sn in SIGNAL_NAMES if abs(blended[sn] - step_c[sn]) > 1e-9}
        if changes_d:
            print(f"\n  STEP D — Polarity constraints (changes: {len(changes_d)})")
            for sn, delta in changes_d.items():
                print(f"    {sn:20s}: adjusted by {delta:+.6f}")
        else:
            print(f"\n  STEP D — Polarity constraints: no changes")

        step_d = dict(blended)

        # ── STEP E: Clamp magnitudes ───────────────────────────────────
        for name in SIGNAL_NAMES:
            mag = abs(blended[name])
            if mag > MAX_WEIGHT_MAGNITUDE:
                blended[name] = MAX_WEIGHT_MAGNITUDE * (1 if blended[name] > 0 else -1)

        changes_e = {sn: blended[sn] - step_d[sn] for sn in SIGNAL_NAMES if abs(blended[sn] - step_d[sn]) > 1e-9}
        if changes_e:
            print(f"\n  STEP E — Magnitude clamp (max={MAX_WEIGHT_MAGNITUDE}): {len(changes_e)} clamped")
            for sn, delta in changes_e.items():
                print(f"    {sn:20s}: clamped by {delta:+.6f}")
        else:
            print(f"\n  STEP E — Magnitude clamp: no changes")

        step_e = dict(blended)

        # ── STEP F: Negative-correlation dampening ─────────────────────
        correlations = tuner.get_signal_correlations()
        for name in SIGNAL_NAMES:
            corr = correlations.get(name, 0.0)
            if POLARITY.get(name, 1) > 0 and corr < -0.05:
                blended[name] *= 0.5

        changes_f = {sn: blended[sn] - step_e[sn] for sn in SIGNAL_NAMES if abs(blended[sn] - step_e[sn]) > 1e-9}
        print(f"\n  STEP F — Negative-correlation dampening")
        print(f"    Signal correlations (EMA): {', '.join(f'{sn}={correlations.get(sn,0):.4f}' for sn in SIGNAL_NAMES)}")
        if changes_f:
            print(f"    Dampened {len(changes_f)} signals:")
            for sn, delta in changes_f.items():
                print(f"      {sn:20s}: halved (delta = {delta:+.6f})")
        else:
            print(f"    No signals dampened")

        step_f = dict(blended)

        # ── STEP G: Low-variance decay ─────────────────────────────────
        print(f"\n  STEP G — Low-variance decay (threshold={LOW_VARIANCE_EPSILON}, factor={LOW_VARIANCE_DECAY})")
        lv_count = 0
        for col_idx, sname in enumerate(SIGNAL_NAMES):
            name = sname
            col_vals = [X[ti][col_idx] for ti in range(n)]
            col_mean = sum(col_vals) / len(col_vals)
            col_var = sum((v - col_mean) ** 2 for v in col_vals) / len(col_vals)
            if col_var < LOW_VARIANCE_EPSILON:
                before = blended[name]
                blended[name] *= LOW_VARIANCE_DECAY
                lv_count += 1
                print(f"    {name:20s}: var={col_var:.6f} < ε → decayed {before:+.6f} → {blended[name]:+.6f}")
        if lv_count == 0:
            print(f"    No signals have low variance")

        step_g = dict(blended)

        # ── STEP H: Stability dampening ────────────────────────────────
        print(f"\n  STEP H — Stability dampening (threshold={STABILITY_DAMPEN_THRESHOLD})")
        stab_count = 0
        for name in SIGNAL_NAMES:
            hist = tuner._weight_history.get(name, [])
            if len(hist) >= 3:
                recent = hist[-STABILITY_WINDOW:]
                h_mean = sum(recent) / len(recent)
                h_var = sum((v - h_mean) ** 2 for v in recent) / len(recent)
                if h_var > STABILITY_DAMPEN_THRESHOLD:
                    old_w = hist[-1]
                    new_w = blended[name]
                    blended[name] = STABILITY_DAMPEN_FACTOR * old_w + (1.0 - STABILITY_DAMPEN_FACTOR) * new_w
                    stab_count += 1
                    print(f"    {name:20s}: hist_var={h_var:.6f} > threshold → dampened {new_w:+.6f} → {blended[name]:+.6f}")
        if stab_count == 0:
            print(f"    No signals oscillating")

        step_h = dict(blended)

        # ── STEP I: Normalization (Σ|W| = 1.0) ────────────────────────
        pre_norm = dict(blended)
        total = sum(abs(v) for v in blended.values())
        if total > 0:
            for name in SIGNAL_NAMES:
                blended[name] /= total

        print(f"\n  STEP I — Normalization (Σ|W| = 1.0)")
        print(f"    Pre-norm total = {total:.6f}")
        for name in SIGNAL_NAMES:
            delta_from_prior = blended[name] - STATIC_PRIORS[name]
            print(f"    {name:20s}: {pre_norm[name]:+.6f} → {blended[name]:+.6f}  (Δ from prior: {delta_from_prior:+.6f})")

        step_i = dict(blended)

        # ── STEP J: Min-magnitude re-enforcement ──────────────────────
        needs_renorm = False
        for name in SIGNAL_NAMES:
            if abs(blended[name]) < MIN_WEIGHT_MAGNITUDE:
                sign = 1 if POLARITY.get(name, 1) > 0 else -1
                blended[name] = sign * MIN_WEIGHT_MAGNITUDE
                needs_renorm = True
        if needs_renorm:
            total2 = sum(abs(v) for v in blended.values())
            if total2 > 0:
                for name in SIGNAL_NAMES:
                    blended[name] /= total2

        changes_j = {sn: blended[sn] - step_i[sn] for sn in SIGNAL_NAMES if abs(blended[sn] - step_i[sn]) > 1e-9}
        if changes_j:
            print(f"\n  STEP J — Min-magnitude re-enforcement: {len(changes_j)} signals lifted")
            for sn, delta in changes_j.items():
                print(f"    {sn:20s}: adjusted by {delta:+.6f}")
        else:
            print(f"\n  STEP J — Min-magnitude re-enforcement: no changes needed")

        # ── FINAL RESULT ───────────────────────────────────────────────
        print(f"\n  ═══ FINAL WEIGHTS vs STATIC PRIORS ═══")
        total_drift = 0.0
        for name in SIGNAL_NAMES:
            drift = blended[name] - STATIC_PRIORS[name]
            total_drift += abs(drift)
            marker = "✅ MOVED" if abs(drift) > 0.001 else "❌ FROZEN" if abs(drift) < 0.0001 else "⚠️  TINY"
            print(f"    {name:20s}: prior={STATIC_PRIORS[name]:+.4f}  final={blended[name]:+.6f}  drift={drift:+.6f}  {marker}")

        print(f"\n    TOTAL absolute drift = {total_drift:.6f}")
        if total_drift < 0.001:
            print(f"    🔴 VERDICT: Weights are effectively FROZEN")
        elif total_drift < 0.01:
            print(f"    🟡 VERDICT: Minimal weight movement")
        else:
            print(f"    🟢 VERDICT: Weights are learning")

        return blended


def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  WEIGHT LEARNING DIAGNOSTIC — Finding the Kill Point   ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # ── Phase 1: Feed known pattern and trace first calibration ────────
    tuner = WeightTuner()
    t = time.monotonic()

    print("\n\n📍 PHASE 1: Feed 50 observations (execute_score → reward)")
    print("   Pattern: high execute_score → positive reward, low → negative")
    for i in range(50):
        is_success = random.random() < 0.5
        obs = make_observation(execute_high=is_success, t=t + i * 0.1)
        tuner._observations.append(obs)
        tuner._total_observations += 1

        # Update EMAs
        alpha = 0.05
        for j, name in enumerate(SIGNAL_NAMES):
            sig_val = obs.signal_vector()[j]
            tuner._signal_reward_ema[name] += alpha * (
                sig_val * obs.reward - tuner._signal_reward_ema[name]
            )
            tuner._signal_abs_ema[name] += alpha * (
                abs(sig_val) - tuner._signal_abs_ema[name]
            )

    # Trace the calibration
    result1 = trace_calibration(tuner, "FIRST calibration (50 obs)")

    # ── Phase 2: Feed 200 more and trace multiple calibrations ─────────
    print("\n\n📍 PHASE 2: Feed 200 more observations + trace 4 calibrations")
    for i in range(200):
        is_success = random.random() < 0.5
        obs = make_observation(execute_high=is_success, t=t + (50 + i) * 0.1)
        tuner._observations.append(obs)
        tuner._total_observations += 1

        alpha = 0.05
        for j, name in enumerate(SIGNAL_NAMES):
            sig_val = obs.signal_vector()[j]
            tuner._signal_reward_ema[name] += alpha * (
                sig_val * obs.reward - tuner._signal_reward_ema[name]
            )
            tuner._signal_abs_ema[name] += alpha * (
                abs(sig_val) - tuner._signal_abs_ema[name]
            )

        # Run calibration at actual intervals to build weight history
        if tuner._total_observations % tuner._interval == 0:
            tuner._calibrate()

    # Trace final calibration with history
    result2 = trace_calibration(tuner, "AFTER 250 total obs (with weight history)")

    # ── Phase 3: Same test but with guards DISABLED ────────────────────
    print("\n\n📍 PHASE 3: GUARDS DISABLED — pure learning, no suppression")
    tuner3 = WeightTuner(blend_ratio=1.0, ridge_lambda=0.01)  # 100% learned, minimal ridge

    random.seed(42)  # Same seed as Phase 1 for fair comparison
    for i in range(250):
        is_success = random.random() < 0.5
        obs = make_observation(execute_high=is_success, t=t + i * 0.1)
        tuner3._observations.append(obs)
        tuner3._total_observations += 1

        alpha = 0.05
        for j, name in enumerate(SIGNAL_NAMES):
            sig_val = obs.signal_vector()[j]
            tuner3._signal_reward_ema[name] += alpha * (
                sig_val * obs.reward - tuner3._signal_reward_ema[name]
            )
            tuner3._signal_abs_ema[name] += alpha * (
                abs(sig_val) - tuner3._signal_abs_ema[name]
            )

    # Manually trace without any suppression layers
    print(f"\n{'='*80}")
    print(f"  CALIBRATION TRACE: GUARDS DISABLED")
    print(f"{'='*80}")

    with tuner3._lock:
        n = len(tuner3._observations)
        k = len(SIGNAL_NAMES)

        X = []
        y = []
        d = []
        now = tuner3._observations[-1].timestamp
        for obs in tuner3._observations:
            X.append(list(obs.signal_vector()))
            y.append(obs.reward)
            age = max(0.0, now - obs.timestamp)
            d.append(DECAY_FACTOR ** age)

        XtDX = [[0.0] * k for _ in range(k)]
        for t_idx in range(n):
            for i in range(k):
                for j in range(k):
                    XtDX[i][j] += d[t_idx] * X[t_idx][i] * X[t_idx][j]
        for i in range(k):
            XtDX[i][i] += 0.01  # minimal ridge

        XtDy = [0.0] * k
        for t_idx in range(n):
            for i in range(k):
                XtDy[i] += d[t_idx] * X[t_idx][i] * y[t_idx]

        learned = _solve_linear_system(XtDX, XtDy)

        print(f"\n  Raw learned (100% weight, ridge=0.01):")
        for i, name in enumerate(SIGNAL_NAMES):
            print(f"    {name:20s}: {learned[i]:+.6f}")

        # Skip blend — use learned directly
        blended = {SIGNAL_NAMES[i]: learned[i] for i in range(k)}

        # Skip all guards — just normalize
        total = sum(abs(v) for v in blended.values())
        if total > 0:
            for name in SIGNAL_NAMES:
                blended[name] /= total

        print(f"\n  After normalization only:")
        total_drift = 0.0
        for name in SIGNAL_NAMES:
            drift = blended[name] - STATIC_PRIORS[name]
            total_drift += abs(drift)
            marker = "✅ MOVED" if abs(drift) > 0.001 else "❌ FROZEN"
            print(f"    {name:20s}: final={blended[name]:+.6f}  drift={drift:+.6f}  {marker}")
        print(f"\n    TOTAL absolute drift = {total_drift:.6f}")
        if total_drift > 0.01:
            print(f"    🟢 Learning works when guards are disabled!")
        else:
            print(f"    🔴 Problem is deeper than guards")

    # ── Phase 4: Identify the killer layer ─────────────────────────────
    print("\n\n📍 PHASE 4: LAYER-BY-LAYER ABLATION — which guard kills learning?")

    # Re-use the same data
    random.seed(42)
    observations = []
    for i in range(250):
        is_success = random.random() < 0.5
        observations.append(make_observation(execute_high=is_success, t=t + i * 0.1))

    configs = [
        ("Full guards (production)",     {"blend": 0.40, "skip_corr_damp": False, "skip_lv_decay": False, "skip_stab_damp": False, "skip_norm": False}),
        ("No blend (100% learned)",      {"blend": 1.00, "skip_corr_damp": False, "skip_lv_decay": False, "skip_stab_damp": False, "skip_norm": False}),
        ("No normalization",             {"blend": 0.40, "skip_corr_damp": False, "skip_lv_decay": False, "skip_stab_damp": False, "skip_norm": True}),
        ("No corr dampening",            {"blend": 0.40, "skip_corr_damp": True,  "skip_lv_decay": False, "skip_stab_damp": False, "skip_norm": False}),
        ("No low-var decay",             {"blend": 0.40, "skip_corr_damp": False, "skip_lv_decay": True,  "skip_stab_damp": False, "skip_norm": False}),
        ("No stability dampening",       {"blend": 0.40, "skip_corr_damp": False, "skip_lv_decay": False, "skip_stab_damp": True,  "skip_norm": False}),
        ("No blend + no norm",           {"blend": 1.00, "skip_corr_damp": False, "skip_lv_decay": False, "skip_stab_damp": False, "skip_norm": True}),
        ("All guards disabled",          {"blend": 1.00, "skip_corr_damp": True,  "skip_lv_decay": True,  "skip_stab_damp": True,  "skip_norm": True}),
    ]

    print(f"\n  {'Config':<35s} {'Total Drift':>12s} {'execute_score drift':>20s} {'Verdict':<15s}")
    print(f"  {'-'*35} {'-'*12} {'-'*20} {'-'*15}")

    for config_name, cfg in configs:
        # Build fresh tuner
        t4 = WeightTuner(blend_ratio=cfg["blend"], ridge_lambda=0.01 if cfg["blend"] >= 0.99 else RIDGE_LAMBDA)
        for obs in observations:
            t4._observations.append(obs)
            t4._total_observations += 1
            alpha = 0.05
            for j, name in enumerate(SIGNAL_NAMES):
                sig_val = obs.signal_vector()[j]
                t4._signal_reward_ema[name] += alpha * (sig_val * obs.reward - t4._signal_reward_ema[name])
                t4._signal_abs_ema[name] += alpha * (abs(sig_val) - t4._signal_abs_ema[name])

        with t4._lock:
            nn = len(t4._observations)
            kk = 8
            X4 = [list(o.signal_vector()) for o in t4._observations]
            y4 = [o.reward for o in t4._observations]
            now4 = t4._observations[-1].timestamp
            d4 = [DECAY_FACTOR ** max(0, now4 - o.timestamp) for o in t4._observations]

            XtDX4 = [[0.0]*kk for _ in range(kk)]
            for ti in range(nn):
                for ii in range(kk):
                    for jj in range(kk):
                        XtDX4[ii][jj] += d4[ti] * X4[ti][ii] * X4[ti][jj]
            for ii in range(kk):
                XtDX4[ii][ii] += t4._ridge

            XtDy4 = [0.0]*kk
            for ti in range(nn):
                for ii in range(kk):
                    XtDy4[ii] += d4[ti] * X4[ti][ii] * y4[ti]

            learned4 = _solve_linear_system(XtDX4, XtDy4)
            if learned4 is None:
                print(f"  {config_name:<35s} SINGULAR")
                continue

            # Blend
            bl4 = {}
            for i, name in enumerate(SIGNAL_NAMES):
                prior = STATIC_PRIORS[name]
                bl4[name] = (1.0 - cfg["blend"]) * prior + cfg["blend"] * learned4[i]

            # Polarity
            for name, pol in POLARITY.items():
                if pol > 0:
                    bl4[name] = max(MIN_WEIGHT_MAGNITUDE, bl4[name])
                else:
                    bl4[name] = min(-MIN_WEIGHT_MAGNITUDE, bl4[name])

            # Magnitude clamp
            for name in SIGNAL_NAMES:
                mag = abs(bl4[name])
                if mag > MAX_WEIGHT_MAGNITUDE:
                    bl4[name] = MAX_WEIGHT_MAGNITUDE * (1 if bl4[name] > 0 else -1)

            # Corr dampening
            if not cfg["skip_corr_damp"]:
                correlations = t4.get_signal_correlations()
                for name in SIGNAL_NAMES:
                    corr = correlations.get(name, 0.0)
                    if POLARITY.get(name, 1) > 0 and corr < -0.05:
                        bl4[name] *= 0.5

            # Low-var decay
            if not cfg["skip_lv_decay"]:
                for col_idx, name in enumerate(SIGNAL_NAMES):
                    col_vals = [X4[ti][col_idx] for ti in range(nn)]
                    c_mean = sum(col_vals) / len(col_vals)
                    c_var = sum((v - c_mean)**2 for v in col_vals) / len(col_vals)
                    if c_var < LOW_VARIANCE_EPSILON:
                        bl4[name] *= LOW_VARIANCE_DECAY

            # Stability dampening (fresh tuner, no history to trigger)

            # Normalization
            if not cfg["skip_norm"]:
                total4 = sum(abs(v) for v in bl4.values())
                if total4 > 0:
                    for name in SIGNAL_NAMES:
                        bl4[name] /= total4
                # Min-magnitude re-enforcement
                needs = False
                for name in SIGNAL_NAMES:
                    if abs(bl4[name]) < MIN_WEIGHT_MAGNITUDE:
                        sign = 1 if POLARITY.get(name, 1) > 0 else -1
                        bl4[name] = sign * MIN_WEIGHT_MAGNITUDE
                        needs = True
                if needs:
                    total4 = sum(abs(v) for v in bl4.values())
                    if total4 > 0:
                        for name in SIGNAL_NAMES:
                            bl4[name] /= total4

            td = sum(abs(bl4[sn] - STATIC_PRIORS[sn]) for sn in SIGNAL_NAMES)
            ed = bl4["execute_score"] - STATIC_PRIORS["execute_score"]
            verdict = "🟢 LEARNING" if td > 0.01 else "🟡 minimal" if td > 0.001 else "🔴 FROZEN"
            print(f"  {config_name:<35s} {td:>12.6f} {ed:>+20.6f} {verdict}")

    print("\n\n📍 SUMMARY")
    print("━"*60)
    print("Compare 'Full guards' vs each disabled variant.")
    print("The variant(s) that show the biggest drift jump")
    print("identify the killer suppression layer(s).")


if __name__ == "__main__":
    main()
