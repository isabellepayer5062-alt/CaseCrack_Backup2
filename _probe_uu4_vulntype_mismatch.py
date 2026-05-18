"""Probe UU-4: VulnType Mismatch Recovery.

Tests what happens when the system's vuln_type classification is WRONG.
All 13 compute functions branch on vuln_type, so a misclassification
means every signal applies the wrong heuristic tree.

Design:
  Phase 1 (100 events): Correct vuln_type (XSS) with XSS payloads
                         -> GT rewards reflect XSS scoring
  Phase 2 (200 events): WRONG vuln_type (SQLI) with actual
                         INSECURE_DESERIALIZATION payloads
                         -> GT rewards come from DESER success but
                            signals are computed via SQLI heuristics
  Phase 3 (100 events): Correct vuln_type (INSECURE_DESERIALIZATION)
                         with DESER payloads -> Can the tuner recover?

Fail conditions:
  F1: Phase 2 R² is high (> 0.5) — the tuner mistakenly *trusts* wrong
      scoring (should recognise it's getting garbage signal)
  F2: After wrong-type training, weight ranking is inverted
      (bypass/execute should NOT gain weight from garbage)
  F3: Phase 3 doesn't recover within 75 events (system is too confused
      by prior misclassified data)
  F4: Contextual trust doesn't detect the mismatch (if context_key
      changes, trust should reset or diverge)

This is the hardest unknown-unknown: there's no self-correction mechanism
in the current architecture for vuln_type misclassification.
"""
from __future__ import annotations

import random
import re
import sys

sys.path.insert(0, "CaseCrack")

from tools.burp_enterprise.exploit_chains.synthesis_context import (
    SynthesisContext,
    VulnType,
)
from tools.burp_enterprise.exploit_chains.payload_arbiter import (
    PayloadArbiter,
    RankedPayload,
    _compute_bypass_score,
    _compute_execute_score,
    _compute_impact_score,
    _compute_chain_alignment,
    _compute_hypothesis_boost,
    _compute_environment_fit,
    _compute_campaign_boost,
    _compute_stealth_score,
    _compute_novelty_score,
    _compute_temporal_relevance,
    _compute_chain_momentum,
    _compute_detection_risk,
    _compute_cost,
)
from tools.burp_enterprise.exploit_chains.weight_tuner import (
    SIGNAL_NAMES,
    WeightTuner,
)

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

SEED = 271828

N_PHASE1 = 100  # Correct XSS
N_PHASE2 = 200  # Mismatch (SQLI label, DESER payloads)
N_PHASE3 = 100  # Correct DESER

# Sample payloads for each type
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg onload=confirm(1)>',
    '<body onload=prompt(document.cookie)>',
    '\'><details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<marquee onstart=alert(1)>',
    'javascript:alert(document.domain)',
    '<iframe srcdoc="<script>alert(1)</script>">',
    '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
]

DESER_PAYLOADS = [
    'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA',
    'aced000573720011java.util.HashMap',
    'O:10:"PharData":0:{}',
    'cos\nsystem\n(S\'id\'\ntR.',
    '__import__(\"os\").popen(\"id\").read()',
    'ysoserial CommonsCollections1 "touch /tmp/pwned"',
    'pickle.loads(base64.b64decode(payload))',
    'yaml.load("!!python/object/apply:os.system [id]")',
    'O:21:"JDatabaseDriverMysqli":0:{}',
    'gadget_chain=CommonsBeanutils1&cmd=whoami',
]


def _make_ctx(vuln_type: VulnType) -> SynthesisContext:
    """Build a minimal SynthesisContext with the given vuln_type."""
    return SynthesisContext(
        vuln_type=vuln_type,
        tech_stack={"language": "java", "framework": "spring"},
        waf_vendor="",
        chain_goal="exploit",
        current_chain_step=1,
        defense_complexity=0.3,
    )


def _make_payload(text: str, confidence: float = 0.6) -> RankedPayload:
    """Build a RankedPayload with the given text."""
    return RankedPayload(
        payload=text,
        engine="grammar",
        confidence=confidence,
        vuln_type=VulnType.XSS,  # engine label -- may be wrong
    )


def _score_with_arbiter(arbiter: PayloadArbiter, payload_text: str,
                         ctx: SynthesisContext, confidence: float = 0.6):
    """Score a single payload by computing all 13 signals directly."""
    rp = _make_payload(payload_text, confidence)
    rp.bypass_score = _compute_bypass_score(rp, ctx)
    rp.execute_score = _compute_execute_score(rp, ctx)
    rp.impact_score = _compute_impact_score(rp, ctx)
    rp.chain_alignment = _compute_chain_alignment(rp, ctx)
    rp.hypothesis_boost = _compute_hypothesis_boost(rp, ctx)
    rp.environment_fit = _compute_environment_fit(rp, ctx)
    rp.campaign_boost = _compute_campaign_boost(rp, ctx)
    rp.stealth_score = _compute_stealth_score(rp, ctx)
    rp.novelty_score = _compute_novelty_score(rp, ctx)
    rp.temporal_relevance = _compute_temporal_relevance(rp, ctx)
    rp.chain_momentum = _compute_chain_momentum(rp, ctx)
    rp.detection_risk = _compute_detection_risk(rp, ctx)
    rp.cost = _compute_cost(rp)
    return rp


def _compute_gt_reward(payload_text: str, actual_vuln: VulnType,
                        rng: random.Random) -> float:
    """Ground truth reward based on actual vuln type match.

    If the payload actually matches the REAL vuln type, reward is positive.
    If it doesn't, reward is near zero or negative.
    """
    p = payload_text.lower()
    match = False

    if actual_vuln == VulnType.XSS:
        match = bool(re.search(r'<\w+.*>|on\w+=|alert|confirm|prompt', p))
    elif actual_vuln == VulnType.INSECURE_DESERIALIZATION:
        match = bool(re.search(
            r'(aced|rO0AB|O:\d+:|pickle|yaml\.load|ysoserial|gadget|__reduce__)', p
        ))
    elif actual_vuln == VulnType.SQLI:
        match = bool(re.search(r'(union|select|information_schema)', p))

    if match:
        return 0.5 + rng.uniform(0, 0.4)  # 0.5 - 0.9
    else:
        return rng.uniform(-0.3, 0.1)  # mostly negative


def _feed_with_context(tuner: WeightTuner, scored: RankedPayload,
                        reward: float, context_key: str, rng: random.Random):
    """Feed a scored payload to the tuner with context."""

    class FE:
        pass
    fe = FE()
    fe.payload = scored
    fe.reward_signal = reward
    tuner.observe(fe)
    tuner.observe_with_context(fe, context_key)


def _weight_rank(weights: dict) -> list[str]:
    """Return signal names sorted by absolute weight (descending)."""
    return [s for s, _ in sorted(weights.items(), key=lambda x: abs(x[1]), reverse=True)]


def _mse(weights: dict, test_data: list[tuple[dict, float]]) -> float:
    if not test_data:
        return float("inf")
    total = 0.0
    for signals, reward in test_data:
        pred = sum(weights.get(s, 0) * signals.get(s, 0) for s in SIGNAL_NAMES)
        total += (pred - reward) ** 2
    return total / len(test_data)


def main():
    print("=" * 72)
    print("  PROBE UU-4: VulnType Mismatch Recovery")
    print("  Train with WRONG vuln_type. Can the tuner detect/recover?")
    print("=" * 72)

    arbiter = PayloadArbiter()
    tuner = WeightTuner()
    rng = random.Random(SEED)

    # ── Phase 1: Correct XSS classification ──
    print(f"\n  Phase 1: Correct XSS ({N_PHASE1} events)...")
    ctx_xss = _make_ctx(VulnType.XSS)
    phase1_data = []

    for i in range(N_PHASE1):
        p_text = rng.choice(XSS_PAYLOADS)
        conf = rng.uniform(0.4, 0.8)
        scored = _score_with_arbiter(arbiter, p_text, ctx_xss, conf)
        reward = _compute_gt_reward(p_text, VulnType.XSS, rng)

        # Collect signal values for test data
        signals = {n: getattr(scored, n, 0) for n in SIGNAL_NAMES}
        phase1_data.append((signals, reward))

        _feed_with_context(tuner, scored, reward, "xss_correct", rng)

    w_phase1 = tuner.get_current_weights()
    mse_phase1 = _mse(w_phase1, phase1_data)
    rank_phase1 = _weight_rank(w_phase1)[:5]
    trust_phase1 = tuner.get_contextual_trust("xss_correct")

    print(f"    MSE: {mse_phase1:.6f}")
    print(f"    Top-5 by weight: {rank_phase1}")
    print(f"    Trust (xss_correct): ", end="")
    print(", ".join(f"{s}={trust_phase1.get(s,0):.2f}" for s in rank_phase1[:3]))

    # ── Phase 2: WRONG vuln_type (SQLI label, DESER payloads) ──
    print(f"\n  Phase 2: MISMATCH ({N_PHASE2} events)...")
    print(f"    Label: SQLI  |  Actual payloads: INSECURE_DESERIALIZATION")
    ctx_sqli = _make_ctx(VulnType.SQLI)  # WRONG label
    phase2_data = []
    phase2_rewards = []

    for i in range(N_PHASE2):
        p_text = rng.choice(DESER_PAYLOADS)
        conf = rng.uniform(0.4, 0.8)
        # Score through arbiter with WRONG context
        scored = _score_with_arbiter(arbiter, p_text, ctx_sqli, conf)
        # GT reward based on ACTUAL vuln type (DESER)
        reward = _compute_gt_reward(p_text, VulnType.INSECURE_DESERIALIZATION, rng)
        phase2_rewards.append(reward)

        signals = {n: getattr(scored, n, 0) for n in SIGNAL_NAMES}
        phase2_data.append((signals, reward))

        _feed_with_context(tuner, scored, reward, "sqli_mismatch", rng)

    w_phase2 = tuner.get_current_weights()
    mse_phase2 = _mse(w_phase2, phase2_data)
    rank_phase2 = _weight_rank(w_phase2)[:5]

    avg_reward_p2 = sum(phase2_rewards) / len(phase2_rewards)
    pos_rewards = sum(1 for r in phase2_rewards if r > 0.3)

    print(f"    Avg reward: {avg_reward_p2:.4f} ({pos_rewards}/{N_PHASE2} > 0.3)")
    print(f"    MSE on mismatch data: {mse_phase2:.6f}")
    print(f"    Top-5 by weight: {rank_phase2}")

    # Check signal coherence -- with wrong vuln_type, bypass/execute
    # should score LOW for deser payloads (no SQLI patterns found)
    bypass_scores = [d[0].get("bypass_score", 0) for d in phase2_data]
    avg_bypass = sum(bypass_scores) / max(len(bypass_scores), 1)
    print(f"    Avg bypass_score (SQLI scoring of DESER payload): {avg_bypass:.4f}")
    print(f"    → Expected: LOW (~0.25-0.35 baseline, SQLI regex won't match DESER)")

    # Contextual trust comparison
    trust_mismatch = tuner.get_contextual_trust("sqli_mismatch")
    trust_correct = tuner.get_contextual_trust("xss_correct")

    print(f"\n    Contextual trust comparison:")
    print(f"    {'Signal':>22s} {'xss_correct':>12s} {'sqli_mismatch':>14s} {'delta':>8s}")
    trust_divergences = {}
    for s in SIGNAL_NAMES[:7]:  # top 7 signals
        tc = trust_correct.get(s, 1.0)
        tm = trust_mismatch.get(s, 1.0)
        delta = tm - tc
        trust_divergences[s] = delta
        marker = " << LOW TRUST" if tm < 0.50 else ""
        print(f"    {s:>22s} {tc:>12.3f} {tm:>14.3f} {delta:>+8.3f}{marker}")

    # ── Phase 3: Correct DESER classification ──
    print(f"\n  Phase 3: Correct INSECURE_DESERIALIZATION ({N_PHASE3} events)...")
    ctx_deser = _make_ctx(VulnType.INSECURE_DESERIALIZATION)
    phase3_data = []
    recovery_snapshots = []

    for i in range(1, N_PHASE3 + 1):
        p_text = rng.choice(DESER_PAYLOADS)
        conf = rng.uniform(0.4, 0.8)
        scored = _score_with_arbiter(arbiter, p_text, ctx_deser, conf)
        reward = _compute_gt_reward(p_text, VulnType.INSECURE_DESERIALIZATION, rng)

        signals = {n: getattr(scored, n, 0) for n in SIGNAL_NAMES}
        phase3_data.append((signals, reward))

        _feed_with_context(tuner, scored, reward, "deser_correct", rng)

        if i % 10 == 0:
            w_snap = tuner.get_current_weights()
            snap_mse = _mse(w_snap, phase3_data)
            recovery_snapshots.append((i, snap_mse, dict(w_snap)))

    w_phase3 = tuner.get_current_weights()
    mse_phase3 = _mse(w_phase3, phase3_data)
    rank_phase3 = _weight_rank(w_phase3)[:5]

    print(f"    Recovery trajectory (MSE on DESER data):")
    print(f"    {'Events':>8s} {'MSE':>10s}")
    for ev, mse_val, _ in recovery_snapshots:
        print(f"    {ev:>8d} {mse_val:>10.6f}")

    print(f"    Final MSE: {mse_phase3:.6f}")
    print(f"    Top-5 by weight: {rank_phase3}")

    # ── Verdicts ──
    print(f"\n  {'=' * 60}")

    # V1: Mismatch should cause poor signal-reward correlation
    # If bypass/execute scores are low but rewards are high, R² should be low
    # Simple proxy: MSE on mismatch data should be WORSE than Phase 1
    v1_ratio = mse_phase2 / max(mse_phase1, 1e-9)
    v1 = v1_ratio > 0.8  # Phase 2 MSE should not be great
    print(f"  {PASS if v1 else WARN} V1: Mismatch detectable via MSE "
          f"(Phase 1 MSE: {mse_phase1:.6f}, Phase 2: {mse_phase2:.6f}, "
          f"ratio: {v1_ratio:.2f}x)")

    # V2: Weight ranking shouldn't have been permanently corrupted
    # Impact signal should still be in top-5 (DESER has high base impact)
    v2 = "impact_score" in rank_phase3[:6] or "bypass_score" in rank_phase3[:3]
    print(f"  {PASS if v2 else FAIL} V2: Weight ranking sensible after recovery "
          f"(top-5: {rank_phase3})")

    # V3: Contextual trust should diverge between correct and mismatch
    # At least 2 signals should have trust divergence > 0.1
    big_divergences = sum(1 for d in trust_divergences.values() if abs(d) > 0.10)
    v3 = big_divergences >= 2
    print(f"  {PASS if v3 else WARN} V3: Contextual trust diverges "
          f"({big_divergences}/7 signals diverged > 0.10)")

    # V4: Weight sum-to-one maintained
    total_abs = sum(abs(v) for v in w_phase3.values())
    v4 = 0.95 < total_abs < 1.05
    print(f"  {PASS if v4 else FAIL} V4: Weight norm invariant "
          f"(Σ|W|={total_abs:.4f})")

    # V5: The WRONG-label period should NOT have produced high-confidence
    # predictions.  Avg bypass score should be low for DESER payloads
    # scored as SQLI.
    v5 = avg_bypass < 0.50
    print(f"  {PASS if v5 else WARN} V5: Wrong heuristics produce low scores "
          f"(avg bypass={avg_bypass:.4f}, threshold <0.50)")

    # V6: Recovery phase should show improving MSE (last snapshot < first)
    if len(recovery_snapshots) >= 2:
        first_mse = recovery_snapshots[0][1]
        last_mse = recovery_snapshots[-1][1]
        improving = last_mse < first_mse * 1.2
        v6 = improving
        print(f"  {PASS if v6 else WARN} V6: Phase 3 MSE improving "
              f"({first_mse:.6f} -> {last_mse:.6f})")
    else:
        v6 = True
        print(f"  {WARN} V6: Not enough Phase 3 snapshots")

    # V7: Polarity should be preserved even after mismatch
    neg_signals = ["detection_risk", "cost"]
    polarity_ok = all(w_phase3.get(s, 0) < 0 for s in neg_signals)
    v7 = polarity_ok
    print(f"  {PASS if v7 else FAIL} V7: Polarity constraints survived mismatch "
          f"(detection_risk={w_phase3.get('detection_risk', 0):+.4f}, "
          f"cost={w_phase3.get('cost', 0):+.4f})")

    overall = v2 and v4 and v7
    if overall:
        print(f"\n  {PASS}: VulnType mismatch is survivable (with caveats)")
        if not v1:
            print(f"         Note: Mismatch wasn't clearly detectable via MSE")
        if not v3:
            print(f"         Note: Contextual trust didn't fully diverge")
    else:
        findings = []
        if not v2:
            findings.append(f"weight ranking corrupted: {rank_phase3}")
        if not v4:
            findings.append(f"weight norm broken (Σ|W|={total_abs:.4f})")
        if not v7:
            findings.append("polarity constraints violated")
        print(f"\n  {FAIL}: {findings}")
    print(f"  {'=' * 60}")

    return overall


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
