#!/usr/bin/env python3
"""Surgical probe: What does WeightTuner actually SEE during harness runs?

Monkey-patches WeightTuner.observe() to capture every observation,
runs ONE harness scenario, then dumps the signal vectors and rewards.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CaseCrack"))

# ── Monkey-patch WeightTuner to capture observations ──────────────────
captured_observations = []
calibration_calls = []

import tools.burp_enterprise.exploit_chains.weight_tuner as wt_mod

_original_observe = wt_mod.WeightTuner.observe
_original_calibrate = wt_mod.WeightTuner._calibrate


def instrumented_observe(self, event):
    """Capture what observe() receives."""
    payload = event.payload
    vec = {
        "bypass_score": payload.bypass_score,
        "execute_score": payload.execute_score,
        "impact_score": payload.impact_score,
        "chain_alignment": payload.chain_alignment,
        "hypothesis_boost": payload.hypothesis_boost,
        "campaign_boost": payload.campaign_boost,
        "detection_risk": payload.detection_risk,
        "cost": payload.cost,
    }
    captured_observations.append({
        "signal_vector": vec,
        "reward": event.reward_signal,
        "feedback_type": event.feedback_type.value if hasattr(event.feedback_type, 'value') else str(event.feedback_type),
        "payload_preview": payload.payload[:60] if payload.payload else "<empty>",
        "engine": payload.engine.value if hasattr(payload.engine, 'value') else str(payload.engine),
    })
    return _original_observe(self, event)


def instrumented_calibrate(self):
    """Capture calibration trigger."""
    before_weights = dict(self._current_weights)
    result = _original_calibrate(self)
    after_weights = dict(self._current_weights)
    calibration_calls.append({
        "obs_count": len(self._observations),
        "total_obs": self._total_observations,
        "calibration_number": self._total_calibrations,
        "before": before_weights,
        "after": after_weights,
    })
    return result


wt_mod.WeightTuner.observe = instrumented_observe
wt_mod.WeightTuner._calibrate = instrumented_calibrate


# ── Now import and run the harness ────────────────────────────────────
from tools.burp_enterprise.exploit_chains.system_audit_harness import (
    HarnessRunner,
    ScenarioGenerator,
)

import logging
logging.basicConfig(level=logging.WARNING)


def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   PROBE: What WeightTuner SEES during harness runs     ║")
    print("╚══════════════════════════════════════════════════════════╝")

    runner = HarnessRunner(seed=42)

    # Run Scenario B (single_signal_dominance) — 30 cycles
    scenario = ScenarioGenerator.single_signal_dominance(seed=42)
    print(f"\n▶ Running scenario: {scenario.name} ({scenario.cycles} cycles)...")
    run_result = runner.execute(scenario)

    print(f"\n✅ Scenario B complete")
    print(f"   Observations captured: {len(captured_observations)}")
    print(f"   Calibrations triggered: {len(calibration_calls)}")

    if not captured_observations:
        print("\n🔴 ZERO observations captured!")
        print("   → WeightTuner.observe() was NEVER CALLED")
        print("   → Feedback loop is BROKEN before reaching tuner")
        return

    # ── Analyze observations ──────────────────────────────────────────
    print(f"\n{'='*72}")
    print("  OBSERVATION ANALYSIS")
    print(f"{'='*72}")

    # Check if signal vectors are all zeros
    all_zero_count = 0
    nonzero_count = 0
    for obs in captured_observations:
        vec = obs["signal_vector"]
        if all(abs(v) < 1e-9 for v in vec.values()):
            all_zero_count += 1
        else:
            nonzero_count += 1

    print(f"\n  All-zero signal vectors: {all_zero_count} / {len(captured_observations)}")
    print(f"  Non-zero signal vectors: {nonzero_count} / {len(captured_observations)}")

    if all_zero_count == len(captured_observations):
        print("\n  🔴 ALL signal vectors are zero!")
        print("     → Payloads were NEVER scored by PayloadArbiter")
        print("     → WeightTuner gets [0,0,0,0,0,0,0,0] → Ridge gives 0 → drift=0")
    elif all_zero_count > 0:
        print(f"\n  ⚠️  {all_zero_count} observations have zero vectors (possible arbiter skip)")

    # Show first 5 observations
    print(f"\n  First 5 observations:")
    for i, obs in enumerate(captured_observations[:5]):
        vec = obs["signal_vector"]
        print(f"    #{i+1}: reward={obs['reward']:+.2f}  feedback={obs['feedback_type']}")
        print(f"         engine={obs['engine']}  payload={obs['payload_preview']}")
        for sig, val in vec.items():
            marker = "✅" if abs(val) > 0.01 else "❌=0"
            print(f"           {sig:20s}: {val:.4f}  {marker}")
        print()

    # Signal value statistics
    print(f"\n  Signal statistics across ALL {len(captured_observations)} observations:")
    from tools.burp_enterprise.exploit_chains.weight_tuner import SIGNAL_NAMES
    for sig in SIGNAL_NAMES:
        vals = [o["signal_vector"][sig] for o in captured_observations]
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        mn, mx = min(vals), max(vals)
        print(f"    {sig:20s}: mean={mean:.4f}  var={var:.6f}  range=[{mn:.4f}, {mx:.4f}]")

    # Reward statistics
    rewards = [o["reward"] for o in captured_observations]
    r_mean = sum(rewards) / len(rewards)
    r_var = sum((v - r_mean) ** 2 for v in rewards) / len(rewards)
    print(f"\n  Reward stats: mean={r_mean:.4f}  var={r_var:.6f}  range=[{min(rewards):.2f}, {max(rewards):.2f}]")

    # Feedback type distribution
    from collections import Counter
    fb_dist = Counter(o["feedback_type"] for o in captured_observations)
    print(f"\n  Feedback type distribution:")
    for fb, count in fb_dist.most_common():
        print(f"    {fb:30s}: {count}")

    # ── Analyze calibrations ──────────────────────────────────────────
    if calibration_calls:
        print(f"\n{'='*72}")
        print("  CALIBRATION ANALYSIS")
        print(f"{'='*72}")
        for i, cal in enumerate(calibration_calls):
            print(f"\n  Calibration #{cal['calibration_number']} (after {cal['total_obs']} obs, window={cal['obs_count']}):")
            for sig in SIGNAL_NAMES:
                before = cal['before'].get(sig, 0)
                after = cal['after'].get(sig, 0)
                delta = after - before
                marker = "MOVED" if abs(delta) > 0.001 else "frozen"
                print(f"    {sig:20s}: {before:+.6f} → {after:+.6f}  (Δ={delta:+.6f})  {marker}")
    else:
        print(f"\n  🔴 No calibrations triggered!")
        print(f"     Observations: {len(captured_observations)}, Interval: {wt_mod.CALIBRATION_INTERVAL}")
        print(f"     Need % interval == 0 AND >= {wt_mod.MIN_OBSERVATIONS_FOR_CALIBRATION} in window")


if __name__ == "__main__":
    main()
