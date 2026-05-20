#!/usr/bin/env python3
"""Strategic Misgeneralization Audits — PhD-level failure modes.

Test 1: Context Transfer
  Train on XSS-heavy environment → switch to SQLi-heavy environment.
  Does the system relearn cleanly, or carry stale XSS priors?

Test 2: Feature Aliasing
  Create two signals with identical distributions, but only one is causal.
  Does the system separate them over time, or shortcut statistically?

Run:
    .venv/Scripts/python.exe _audit_misgeneralization.py
"""
from __future__ import annotations

import copy
import math
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "CaseCrack"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.burp_enterprise.exploit_chains.synthesis_context import (
    RankedPayload,
    SynthesisContext,
    SynthesisEngine,
    VulnType,
)
from tools.burp_enterprise.exploit_chains.synthesis_feedback import (
    FeedbackEvent,
    FeedbackType,
)
from tools.burp_enterprise.exploit_chains.weight_tuner import (
    SIGNAL_NAMES,
    STATIC_PRIORS,
    WeightTuner,
)

PASS = "✔"
FAIL = "✘"
WARN = "⚠"
random.seed(42)


# =====================================================================
#  Helpers
# =====================================================================

def _p(text: str, **kw) -> RankedPayload:
    """Quick payload builder with explicit signal values."""
    return RankedPayload(
        payload=text,
        engine=kw.get("engine", SynthesisEngine.GRAMMAR),
        vuln_type=kw.get("vuln_type", VulnType.XSS),
        confidence=kw.get("confidence", 0.80),
        bypass_score=kw.get("bypass_score", 0.0),
        execute_score=kw.get("execute_score", 0.0),
        impact_score=kw.get("impact_score", 0.0),
        chain_alignment=kw.get("chain_alignment", 0.0),
        hypothesis_boost=kw.get("hypothesis_boost", 0.0),
        environment_fit=kw.get("environment_fit", 0.0),
        campaign_boost=kw.get("campaign_boost", 0.0),
        stealth_score=kw.get("stealth_score", 0.0),
        temporal_relevance=kw.get("temporal_relevance", 0.0),
        novelty_score=kw.get("novelty_score", 0.0),
        chain_momentum=kw.get("chain_momentum", 0.0),
        detection_risk=kw.get("detection_risk", 0.0),
        cost=kw.get("cost", 0.0),
    )


def _ctx(**kw) -> SynthesisContext:
    return SynthesisContext(
        target_url=kw.get("target_url", "https://target.example.com/test"),
        vuln_type=kw.get("vuln_type", VulnType.XSS),
        hypothesis_multiplier=kw.get("hypothesis_multiplier", 1.0),
        chain_goal=kw.get("chain_goal", ""),
        waf_vendor=kw.get("waf_vendor", ""),
        cross_target_signals=kw.get("cross_target_signals", []),
        safety_level="aggressive",
    )


def _feed(tuner: WeightTuner, payload: RankedPayload,
          ctx: SynthesisContext, ft: FeedbackType) -> None:
    tuner.observe(FeedbackEvent(payload=payload, context=ctx, feedback_type=ft))


def _w(tuner: WeightTuner) -> dict[str, float]:
    return tuner.get_current_weights()


def _section(title: str) -> None:
    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print(f"{'=' * 72}")


def _print_weights(label: str, weights: dict[str, float],
                   highlight: list[str] | None = None) -> None:
    print(f"  {label}:")
    for s in SIGNAL_NAMES:
        mark = " ◀" if highlight and s in highlight else ""
        print(f"    {s:20s}: {weights[s]:+.4f}{mark}")


# =====================================================================
#  TEST 1: Context Transfer
# =====================================================================

def test_1_context_transfer() -> list[str]:
    """Train XSS regime → switch to SQLi regime → check clean relearning."""

    _section("TEST 1: Context Transfer (XSS → SQLi)")
    issues = []

    tuner = WeightTuner(calibration_interval=5)

    # ── Phase A: XSS regime ────────────────────────────────────────
    # In XSS: bypass_score is king (WAF evasion dominates success).
    # execute_score matters less.  detection_risk is critical.
    print("\n  Phase A: Training on XSS-heavy regime (80 events)...")
    print("    Rule: high bypass + low detection → success")

    xss_good = _p(
        '<img/src=x onerror="alert(1)">',
        engine=SynthesisEngine.GRAMMAR,
        vuln_type=VulnType.XSS,
        bypass_score=0.90,
        execute_score=0.40,
        impact_score=0.50,
        detection_risk=0.10,
        cost=0.15,
    )
    xss_bad = _p(
        "<script>alert(document.cookie)</script>",
        engine=SynthesisEngine.LLM,
        vuln_type=VulnType.XSS,
        bypass_score=0.20,
        execute_score=0.70,
        impact_score=0.60,
        detection_risk=0.80,
        cost=0.10,
    )
    xss_ctx = _ctx(vuln_type=VulnType.XSS, waf_vendor="cloudflare")

    for _ in range(40):
        _feed(tuner, xss_good, xss_ctx, FeedbackType.EXECUTED_SUCCESSFULLY)
        _feed(tuner, xss_bad, xss_ctx, FeedbackType.BLOCKED_BY_WAF)

    xss_weights = _w(tuner)
    xss_corrs = tuner.get_signal_correlations()
    _print_weights("XSS-trained weights", xss_weights,
                   highlight=["bypass_score", "detection_risk"])

    # Verify XSS regime learned correctly
    print(f"\n    bypass correlation:   {xss_corrs['bypass_score']:+.4f}")
    print(f"    detection correlation: {xss_corrs['detection_risk']:+.4f}")

    if xss_weights["bypass_score"] > xss_weights["execute_score"]:
        print(f"    {PASS} XSS regime: bypass > execute (correct)")
    else:
        print(f"    {WARN} XSS regime: bypass ≤ execute (unexpected)")

    # Record the XSS "fingerprint" — which signals are dominant
    xss_top = sorted(SIGNAL_NAMES, key=lambda s: abs(xss_weights[s]), reverse=True)[:3]
    print(f"    XSS top signals: {xss_top}")

    # ── Phase B: Switch to SQLi regime ────────────────────────────
    # In SQLi: execute_score is king (query execution matters most).
    # bypass_score matters much less.  impact_score matters (data exfil).
    print(f"\n  Phase B: Switching to SQLi-heavy regime...")
    print("    Rule: high execute + high impact → success")
    print("    (bypass is now irrelevant)")

    sqli_good = _p(
        "' UNION SELECT username,password FROM users--",
        engine=SynthesisEngine.GENETIC_FORGE,
        vuln_type=VulnType.SQLI,
        bypass_score=0.30,
        execute_score=0.90,
        impact_score=0.85,
        detection_risk=0.20,
        cost=0.10,
    )
    sqli_bad = _p(
        "1 OR 1=1",
        engine=SynthesisEngine.GRAMMAR,
        vuln_type=VulnType.SQLI,
        bypass_score=0.80,
        execute_score=0.20,
        impact_score=0.30,
        detection_risk=0.15,
        cost=0.05,
    )
    sqli_ctx = _ctx(vuln_type=VulnType.SQLI, waf_vendor="modsecurity")

    # Track relearning trajectory
    trajectory: list[dict[str, float]] = [copy.deepcopy(xss_weights)]
    cal_start = tuner.get_metrics()["total_calibrations"]

    SQLI_EVENTS = 120  # enough for the system to relearn
    BATCH = 10
    for batch_idx in range(SQLI_EVENTS // BATCH):
        for _ in range(BATCH // 2):
            _feed(tuner, sqli_good, sqli_ctx, FeedbackType.EXECUTED_SUCCESSFULLY)
            _feed(tuner, sqli_bad, sqli_ctx, FeedbackType.BLOCKED_BY_WAF)
        trajectory.append(copy.deepcopy(_w(tuner)))

    cal_end = tuner.get_metrics()["total_calibrations"]
    sqli_weights = _w(tuner)
    sqli_corrs = tuner.get_signal_correlations()

    _print_weights("SQLi-trained weights", sqli_weights,
                   highlight=["execute_score", "impact_score"])

    print(f"\n    Calibrations during SQLi phase: {cal_end - cal_start}")
    print(f"    execute correlation: {sqli_corrs['execute_score']:+.4f}")
    print(f"    bypass correlation:  {sqli_corrs['bypass_score']:+.4f}")

    # ── Phase C: Evaluate transfer quality ────────────────────────

    print(f"\n  Phase C: Transfer evaluation...")

    # C1: Did execute overtake bypass?
    if sqli_weights["execute_score"] > sqli_weights["bypass_score"]:
        print(f"    {PASS} C1. execute ({sqli_weights['execute_score']:.4f}) > "
              f"bypass ({sqli_weights['bypass_score']:.4f}): "
              f"correct SQLi priority learned")
    else:
        msg = (f"C1. Stale XSS prior: bypass ({sqli_weights['bypass_score']:.4f}) "
               f"still > execute ({sqli_weights['execute_score']:.4f})")
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # C2: Did impact increase? (important in SQLi, less so in XSS)
    impact_delta = sqli_weights["impact_score"] - xss_weights["impact_score"]
    if impact_delta > 0:
        print(f"    {PASS} C2. impact increased by {impact_delta:+.4f}: SQLi context learned")
    else:
        msg = f"C2. impact did not increase ({impact_delta:+.4f}): incomplete context transfer"
        print(f"    {WARN} {msg}")

    # C3: How quickly did execute overtake bypass? (batch index)
    crossover_batch = None
    for i, w in enumerate(trajectory[1:], 1):
        if w["execute_score"] > w["bypass_score"]:
            crossover_batch = i
            break

    if crossover_batch is not None:
        crossover_events = crossover_batch * BATCH
        print(f"    {PASS} C3. Crossover at batch {crossover_batch} "
              f"({crossover_events} events): clean relearning")
    else:
        msg = "C3. execute never overtook bypass — stale prior persists"
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # C4: Check for "ghost priors" — are XSS-specific correlations still lingering?
    # In the new regime, bypass should NOT still have strong positive correlation
    bypass_corr_in_sqli = sqli_corrs.get("bypass_score", 0.0)
    if bypass_corr_in_sqli < 0.10:
        print(f"    {PASS} C4. bypass correlation reset ({bypass_corr_in_sqli:+.4f} < 0.10): "
              f"no ghost priors")
    elif bypass_corr_in_sqli < 0.30:
        print(f"    {WARN} C4. bypass correlation partially lingering "
              f"({bypass_corr_in_sqli:+.4f}): slow decay")
    else:
        msg = f"C4. Ghost prior: bypass correlation still {bypass_corr_in_sqli:+.4f} in SQLi regime"
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # C5: Print trajectory
    print(f"\n    Relearning trajectory (bypass vs execute vs impact):")
    print(f"    {'Batch':>6s}  {'bypass':>8s}  {'execute':>8s}  {'impact':>8s}  {'note':s}")
    for i, w in enumerate(trajectory):
        note = ""
        if i == 0:
            note = "← end of XSS"
        elif crossover_batch and i == crossover_batch:
            note = "← CROSSOVER"
        elif i == len(trajectory) - 1:
            note = "← final"
        print(f"    {i:6d}  {w['bypass_score']:8.4f}  "
              f"{w['execute_score']:8.4f}  {w['impact_score']:8.4f}  {note}")

    return issues


# =====================================================================
#  TEST 2: Feature Aliasing
# =====================================================================

def test_2_feature_aliasing() -> list[str]:
    """Two signals with identical distributions; only one is causal.
    Does the system separate them or split the credit?

    Setup:
      - hypothesis_boost and campaign_boost will be given IDENTICAL values
        on every payload.
      - But ONLY hypothesis_boost is actually correlated with reward.
      - campaign_boost is a pure confounder — same distribution, no causality.

    How: payloads where hypothesis_boost = campaign_boost, but reward is
    determined solely by hypothesis_boost (high hyp → success, low → fail).
    The aliased signal (campaign) rides along for free.

    The system must eventually give more weight to hypothesis than campaign.
    If it just splits 50/50, that's statistical shortcutting.
    """

    _section("TEST 2: Feature Aliasing (hypothesis vs campaign)")
    issues = []

    tuner = WeightTuner(calibration_interval=5)
    baseline = _w(tuner)

    print(f"\n  Setup: hypothesis_boost = campaign_boost on every payload")
    print(f"  But ONLY hypothesis_boost determines success.")
    print(f"  Campaign is a pure confounder.\n")

    # ── Phase A: Aliased training ─────────────────────────────────
    # Both signals identical, but only hypothesis determines reward.
    print("  Phase A: Training with aliased signals (200 events)...")

    EVENTS = 200
    for i in range(EVENTS):
        # Generate a random pair of identical signal values
        sig_val = random.uniform(0.3, 0.9)

        payload_text = f"test_payload_{i}_{sig_val:.4f}"
        payload = _p(
            payload_text,
            engine=[SynthesisEngine.GRAMMAR, SynthesisEngine.LLM,
                    SynthesisEngine.GENETIC_FORGE][i % 3],
            vuln_type=VulnType.XSS,
            bypass_score=random.uniform(0.3, 0.7),
            execute_score=random.uniform(0.3, 0.7),
            impact_score=random.uniform(0.3, 0.7),
            hypothesis_boost=sig_val,       # CAUSAL: determines reward
            campaign_boost=sig_val,         # ALIASED: same value, NOT causal
            detection_risk=random.uniform(0.1, 0.3),
            cost=random.uniform(0.05, 0.20),
        )
        ctx = _ctx(vuln_type=VulnType.XSS)

        # Reward is determined by hypothesis_boost ONLY
        # High hypothesis → success, low → failure
        # (campaign has the same value but should NOT get credit)
        if sig_val > 0.6:
            _feed(tuner, payload, ctx, FeedbackType.EXECUTED_SUCCESSFULLY)
        else:
            _feed(tuner, payload, ctx, FeedbackType.BLOCKED_BY_WAF)

    aliased_weights = _w(tuner)
    aliased_corrs = tuner.get_signal_correlations()

    hyp_w = aliased_weights["hypothesis_boost"]
    camp_w = aliased_weights["campaign_boost"]

    print(f"\n  After aliased training:")
    print(f"    hypothesis_boost weight: {hyp_w:.4f}")
    print(f"    campaign_boost weight:   {camp_w:.4f}")
    print(f"    ratio (hyp/camp):        {hyp_w / camp_w:.2f}x" if camp_w > 0.001
          else f"    ratio: campaign near zero")

    hyp_corr = aliased_corrs.get("hypothesis_boost", 0.0)
    camp_corr = aliased_corrs.get("campaign_boost", 0.0)
    print(f"    hypothesis correlation:  {hyp_corr:+.4f}")
    print(f"    campaign correlation:    {camp_corr:+.4f}")

    # ── Phase B: Break the alias ──────────────────────────────────
    # Now feed events where hypothesis != campaign to test separation.
    # High hypothesis + LOW campaign → success
    # LOW hypothesis + high campaign → failure
    # This should break the tie and prove which is causal.

    print(f"\n  Phase B: Breaking the alias (100 events)...")
    print(f"    Rule: high hypothesis + LOW campaign → success")
    print(f"    Rule: LOW hypothesis + high campaign → failure")

    BREAK_EVENTS = 100
    for i in range(BREAK_EVENTS):
        payload_text = f"alias_break_{i}"
        if i % 2 == 0:
            # Causal: hypothesis high, confounder low → success
            payload = _p(
                payload_text + "_hyp_high",
                engine=SynthesisEngine.GRAMMAR,
                bypass_score=random.uniform(0.4, 0.6),
                execute_score=random.uniform(0.4, 0.6),
                impact_score=random.uniform(0.3, 0.6),
                hypothesis_boost=0.85,
                campaign_boost=0.15,
                detection_risk=0.15,
                cost=0.10,
            )
            _feed(tuner, payload, _ctx(), FeedbackType.EXECUTED_SUCCESSFULLY)
        else:
            # Anti-causal: hypothesis low, confounder high → failure
            payload = _p(
                payload_text + "_camp_high",
                engine=SynthesisEngine.LLM,
                bypass_score=random.uniform(0.4, 0.6),
                execute_score=random.uniform(0.4, 0.6),
                impact_score=random.uniform(0.3, 0.6),
                hypothesis_boost=0.15,
                campaign_boost=0.85,
                detection_risk=0.15,
                cost=0.10,
            )
            _feed(tuner, payload, _ctx(), FeedbackType.BLOCKED_BY_WAF)

    separated_weights = _w(tuner)
    separated_corrs = tuner.get_signal_correlations()

    hyp_w2 = separated_weights["hypothesis_boost"]
    camp_w2 = separated_weights["campaign_boost"]

    print(f"\n  After alias-breaking:")
    print(f"    hypothesis_boost weight: {hyp_w:.4f} → {hyp_w2:.4f}")
    print(f"    campaign_boost weight:   {camp_w:.4f} → {camp_w2:.4f}")

    hyp_corr2 = separated_corrs.get("hypothesis_boost", 0.0)
    camp_corr2 = separated_corrs.get("campaign_boost", 0.0)
    print(f"    hypothesis correlation:  {hyp_corr:+.4f} → {hyp_corr2:+.4f}")
    print(f"    campaign correlation:    {camp_corr:+.4f} → {camp_corr2:+.4f}")

    # ── Phase C: Evaluate separation quality ──────────────────────

    print(f"\n  Phase C: Separation evaluation...")

    # C1: After alias breaking, hypothesis must outweigh campaign
    if hyp_w2 > camp_w2:
        ratio = hyp_w2 / camp_w2 if camp_w2 > 0.001 else float("inf")
        print(f"    {PASS} C1. hypothesis ({hyp_w2:.4f}) > campaign ({camp_w2:.4f})"
              f" — ratio {ratio:.1f}x: causal signal identified")
    else:
        msg = (f"C1. Failed to separate: hypothesis ({hyp_w2:.4f}) "
               f"≤ campaign ({camp_w2:.4f})")
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # C2: Hypothesis correlation should be positive, campaign negative
    if hyp_corr2 > 0:
        print(f"    {PASS} C2. hypothesis correlation positive ({hyp_corr2:+.4f})")
    else:
        msg = f"C2. hypothesis correlation not positive ({hyp_corr2:+.4f})"
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    if camp_corr2 < 0:
        print(f"    {PASS} C3. campaign correlation negative ({camp_corr2:+.4f}): "
              f"confounder correctly penalised")
    elif camp_corr2 < hyp_corr2:
        print(f"    {WARN} C3. campaign correlation ({camp_corr2:+.4f}) < hypothesis "
              f"({hyp_corr2:+.4f}): partial separation")
    else:
        msg = (f"C3. campaign correlation ({camp_corr2:+.4f}) ≥ hypothesis "
               f"({hyp_corr2:+.4f}): no separation")
        print(f"    {FAIL} {msg}")
        issues.append(msg)

    # C4: Weight ratio should be at least 1.5x after separation
    if camp_w2 > 0.001:
        ratio = hyp_w2 / camp_w2
        if ratio >= 1.5:
            print(f"    {PASS} C4. Weight ratio {ratio:.1f}x (≥1.5): "
                  f"strong causal separation")
        elif ratio > 1.0:
            print(f"    {WARN} C4. Weight ratio {ratio:.1f}x (1.0-1.5): "
                  f"weak separation — more data may help")
        else:
            msg = f"C4. Weight ratio {ratio:.1f}x (<1.0): confounder dominates"
            print(f"    {FAIL} {msg}")
            issues.append(msg)
    else:
        print(f"    {PASS} C4. campaign weight near zero ({camp_w2:.4f}): "
              f"confounder eliminated")

    # C5: Was the system fooled during aliased phase?
    # (This is informational — being fooled initially is OK, recovery matters)
    print(f"\n    Phase A aliased state (informational):")
    if abs(hyp_w - camp_w) < 0.02:
        print(f"      During aliasing, weights were near-equal "
              f"(Δ={abs(hyp_w - camp_w):.4f}): expected statistical tie")
        print(f"      → This is the shortcut failure mode: equal credit to both")
    else:
        print(f"      During aliasing, weights already diverged "
              f"(Δ={abs(hyp_w - camp_w):.4f}): possible early separation")

    print(f"    Phase B recovery:")
    divergence = abs(hyp_w2 - camp_w2)
    print(f"      Final divergence: {divergence:.4f}")
    if divergence > 0.03:
        print(f"      {PASS} Strong separation achieved")
    elif divergence > 0.01:
        print(f"      {WARN} Moderate separation")
    else:
        print(f"      {FAIL} Insufficient separation — statistical shortcutting")
        issues.append("Insufficient divergence between causal and aliased signals")

    return issues


# =====================================================================
#  MAIN
# =====================================================================

def main() -> int:
    print("=" * 72)
    print("  STRATEGIC MISGENERALIZATION AUDITS")
    print("  PhD-level failure modes: context transfer + feature aliasing")
    print("=" * 72)

    all_issues: dict[str, list[str]] = {}

    all_issues["Test 1: Context Transfer"] = test_1_context_transfer()
    all_issues["Test 2: Feature Aliasing"] = test_2_feature_aliasing()

    # ── Summary ───────────────────────────────────────────────────
    _section("SUMMARY")
    total = 0
    for name, issues in all_issues.items():
        status = PASS if not issues else FAIL
        print(f"  {status}  {name}: {len(issues)} issues")
        for iss in issues:
            print(f"       → {iss}")
            total += 1

    print(f"\n  Total issues: {total}")
    if total == 0:
        print("\n  🟢 BOTH MISGENERALIZATION TESTS PASS")
        print("     System demonstrates true causal reasoning, not statistical shortcutting.")
    else:
        print(f"\n  🔴 {total} ISSUE(S) — strategic misgeneralization detected")

    return 1 if total > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
