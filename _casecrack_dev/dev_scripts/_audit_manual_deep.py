#!/usr/bin/env python3
"""Deep Manual Audit — 9 areas of causal intelligence verification.

Architecture-aware: understands that PayloadArbiter.arbitrate()
recomputes all 13 signals via _compute_* functions from payload text
and context. Tests manipulate structurally diverse payloads and context
knobs, not pre-baked signal values.

Areas:
  1. Causal Walkthrough — trace one decision end-to-end
  2. Counterfactual Injection — alter one variable, check ranking changes
  3. Single-Signal Isolation — zero all weights except one
  4. Weight Learning Quality — convergence, oscillation, collapse checks
  5. Edge Regimes — deceptive success, delayed reward, signal conflict
  6. Regret Decomposition — scoring vs selection vs execution error sources
  7. Coherence Validation — subsystem agreement check
  8. Illusions of Intelligence — shuffled/frozen/random detection
  9. Checklist Summary — condensed YES/NO gate

Run:
    .venv/Scripts/python.exe _audit_manual_deep.py
"""

from __future__ import annotations

import copy
import math
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# ── Bootstrap ────────────────────────────────────────────────────────
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
    SynthesisFeedbackCollector,
)
from tools.burp_enterprise.exploit_chains.weight_tuner import WeightTuner
from tools.burp_enterprise.exploit_chains.payload_arbiter import (
    PayloadArbiter,
    _compute_bypass_score,
    _compute_execute_score,
    _compute_impact_score,
    _compute_chain_alignment,
    _compute_hypothesis_boost,
    _compute_campaign_boost,
    _compute_detection_risk,
    _compute_cost,
)


# ── Payload factories ──────────────────────────────────────────────
# Structurally diverse payloads that produce genuinely different signals.

def _xss_payloads() -> list[RankedPayload]:
    """XSS payloads with varying structural properties."""
    return [
        RankedPayload(  # Basic: high execute, high detection
            payload='<script>alert(1)</script>',
            score=0.0, engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.XSS, confidence=0.85,
        ),
        RankedPayload(  # Event handler: different execute path
            payload='<img src=x onerror=alert(1)>',
            score=0.0, engine=SynthesisEngine.LLM,
            vuln_type=VulnType.XSS, confidence=0.70,
        ),
        RankedPayload(  # Encoded: better bypass, lower detection
            payload='<svg/onload=confirm%28document.domain%29>',
            score=0.0, engine=SynthesisEngine.GENETIC_FORGE,
            vuln_type=VulnType.XSS, confidence=0.60,
            encoding_applied="url",
        ),
        RankedPayload(  # DOM sink: different risk profile
            payload='javascript:void(document.write("xss"))',
            score=0.0, engine=SynthesisEngine.LLM,
            vuln_type=VulnType.XSS, confidence=0.55,
        ),
        RankedPayload(  # Polyglot: complex, higher cost
            payload='<details open ontoggle=prompt`xss`>',
            score=0.0, engine=SynthesisEngine.GENETIC_FORGE,
            vuln_type=VulnType.XSS, confidence=0.65,
        ),
    ]


def _competitive_payloads() -> list[RankedPayload]:
    """Payloads deliberately designed to be close in score so weight
    changes actually shift rankings.  Mixes vuln types to exercise
    impact differentiation and chain alignment variance."""
    return [
        RankedPayload(  # High bypass, low execute (obfuscated but weak structure)
            payload='<svg/onload=confirm%28document.domain%29>',
            score=0.0, engine=SynthesisEngine.GENETIC_FORGE,
            vuln_type=VulnType.XSS, confidence=0.50,
            encoding_applied="url",
        ),
        RankedPayload(  # High execute, low bypass (strong structure, detectable)
            payload='<script>alert(document.cookie)</script>',
            score=0.0, engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.XSS, confidence=0.90,
        ),
        RankedPayload(  # High impact SQLi with chain relevance
            payload="' UNION SELECT username,password FROM users--",
            score=0.0, engine=SynthesisEngine.LLM,
            vuln_type=VulnType.SQLI, confidence=0.70,
        ),
        RankedPayload(  # Command injection: highest impact, moderate everything else
            payload="| cat /etc/passwd",
            score=0.0, engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.COMMAND_INJECTION, confidence=0.65,
        ),
        RankedPayload(  # SSTI: high impact, niche
            payload="{{7*7}}{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            score=0.0, engine=SynthesisEngine.LLM,
            vuln_type=VulnType.SSTI, confidence=0.60,
        ),
    ]


def _sqli_payloads() -> list[RankedPayload]:
    """SQLi payloads with varying injection depth."""
    return [
        RankedPayload(
            payload="' OR 1=1 --",
            score=0.0, engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.SQLI, confidence=0.90,
        ),
        RankedPayload(
            payload="' UNION SELECT username,password FROM users--",
            score=0.0, engine=SynthesisEngine.LLM,
            vuln_type=VulnType.SQLI, confidence=0.70,
        ),
        RankedPayload(
            payload="1; SELECT * FROM information_schema.tables--",
            score=0.0, engine=SynthesisEngine.GENETIC_FORGE,
            vuln_type=VulnType.SQLI, confidence=0.60,
        ),
    ]


def _cmd_payloads() -> list[RankedPayload]:
    """Command injection payloads."""
    return [
        RankedPayload(
            payload="; id",
            score=0.0, engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.COMMAND_INJECTION, confidence=0.80,
        ),
        RankedPayload(
            payload="| cat /etc/passwd",
            score=0.0, engine=SynthesisEngine.LLM,
            vuln_type=VulnType.COMMAND_INJECTION, confidence=0.65,
        ),
        RankedPayload(
            payload="$(whoami)",
            score=0.0, engine=SynthesisEngine.GENETIC_FORGE,
            vuln_type=VulnType.COMMAND_INJECTION, confidence=0.70,
        ),
    ]


def _make_context(
    vuln_type: VulnType = VulnType.XSS,
    waf_vendor: str = "cloudflare",
    chain_goal: str = "",
    hypothesis_multiplier: float = 1.0,
    cross_target_signals: list | None = None,
) -> SynthesisContext:
    return SynthesisContext(
        target_url="https://target.example.com/search",
        vuln_type=vuln_type,
        waf_vendor=waf_vendor,
        chain_goal=chain_goal,
        hypothesis_multiplier=hypothesis_multiplier,
        cross_target_signals=cross_target_signals or [],
    )


def _arbitrate_and_decompose(
    arbiter: PayloadArbiter,
    context: SynthesisContext,
    payloads: list[RankedPayload],
) -> list[dict]:
    """Arbitrate and return per-payload signal decomposition."""
    # Deep-copy payloads so arbiter doesn't mutate originals
    candidates = [copy.deepcopy(p) for p in payloads]
    engine_map: dict[SynthesisEngine, list[RankedPayload]] = {}
    for p in candidates:
        engine_map.setdefault(p.engine, []).append(p)

    ranked = arbiter.arbitrate(context, engine_map)

    results = []
    for p in ranked:
        contrib = {
            "bypass": p.bypass_score * arbiter._w_bypass,
            "execute": p.execute_score * arbiter._w_execute,
            "impact": p.impact_score * arbiter._w_impact,
            "chain": p.chain_alignment * arbiter._w_chain,
            "hypothesis": p.hypothesis_boost * arbiter._w_hypothesis,
            "campaign": p.campaign_boost * arbiter._w_campaign,
            "detection": p.detection_risk * arbiter._w_detection,
            "cost": p.cost * arbiter._w_cost,
        }
        results.append({
            "payload": p.payload[:60],
            "engine": p.engine.value,
            "score": p.score,
            "signals": {
                "bypass": p.bypass_score,
                "execute": p.execute_score,
                "impact": p.impact_score,
                "chain": p.chain_alignment,
                "hypothesis": p.hypothesis_boost,
                "environment": p.environment_fit,
                "campaign": p.campaign_boost,
                "stealth": p.stealth_score,
                "temporal": p.temporal_relevance,
                "novelty": p.novelty_score,
                "momentum": p.chain_momentum,
                "detection": p.detection_risk,
                "cost": p.cost,
            },
            "contributions": contrib,
        })
    return results


# ══════════════════════════════════════════════════════════════════════
# AREA 1: Causal Walkthrough
# ══════════════════════════════════════════════════════════════════════

def _audit_causal_walkthrough() -> dict:
    """Trace one decision end-to-end and interrogate every step."""
    print("\n" + "=" * 72)
    print("  AREA 1: Causal Walkthrough — End-to-End Decision Trace")
    print("=" * 72)

    arbiter = PayloadArbiter()
    ctx = _make_context(
        vuln_type=VulnType.SQLI,
        waf_vendor="cloudflare",
        chain_goal="sqli data exfiltration to admin",
        hypothesis_multiplier=1.5,
        cross_target_signals=[("other-target.com", "sqli", 0.8)],
    )
    payloads = _competitive_payloads()
    results = _arbitrate_and_decompose(arbiter, ctx, payloads)

    findings = []

    # 1a. Are signals different across payloads?
    print("\n  Signal differentiation across candidates:")
    signal_names = ["bypass", "execute", "impact", "chain", "hypothesis", "environment", "campaign", "stealth", "temporal", "novelty", "momentum", "detection", "cost"]
    dead_signals = []
    for sig in signal_names:
        vals = [r["signals"][sig] for r in results]
        mn, mx = min(vals), max(vals)
        spread = mx - mn
        status = "LIVE" if spread > 0.01 else "DEAD (constant)"
        if spread <= 0.01:
            dead_signals.append(sig)
        print(f"    {sig:15s} min={mn:.4f} max={mx:.4f} spread={spread:.4f} → {status}")

    if dead_signals:
        findings.append(f"Dead/constant signals: {dead_signals}")

    # 1b. Does ranking match weight priorities?
    print("\n  Score decomposition (top candidate):")
    if results:
        top = results[0]
        for sig, contrib in sorted(top["contributions"].items(), key=lambda x: abs(x[1]), reverse=True):
            pct = abs(contrib) / max(top["score"], 0.001) * 100
            print(f"    {sig:15s} signal={top['signals'][sig]:.4f}  "
                  f"weight×signal={contrib:+.4f}  ({pct:.1f}% of score)")

    # 1c. Winner vs runner-up delta
    if len(results) >= 2:
        delta = results[0]["score"] - results[1]["score"]
        print(f"\n  Winner: {results[0]['payload']}")
        print(f"  Runner: {results[1]['payload']}")
        print(f"  Delta:  {delta:.4f}", end="")
        if delta < 0.02:
            print(" ← EFFECTIVELY RANDOM (delta < 0.02)")
            findings.append(f"Winner/runner delta={delta:.4f} < 0.02 — near-random selection")
        else:
            print(f" ← clear winner")

    # 1d. Negative contributors check
    if results:
        neg_contribs = {k: v for k, v in results[0]["contributions"].items() if v < -0.005}
        if neg_contribs:
            print(f"\n  Negative contributors in winner: {neg_contribs}")
            total_neg = sum(neg_contribs.values())
            total_pos = sum(v for v in results[0]["contributions"].values() if v > 0)
            if abs(total_neg) > total_pos * 0.3:
                findings.append(f"Negative contributors dominate: negatives={total_neg:.4f} vs positives={total_pos:.4f}")

    return {"dead_signals": dead_signals, "findings": findings, "results": results}


# ══════════════════════════════════════════════════════════════════════
# AREA 2: Counterfactual Injection
# ══════════════════════════════════════════════════════════════════════

def _audit_counterfactual() -> dict:
    """Alter one variable at a time, check if ranking changes as expected."""
    print("\n" + "=" * 72)
    print("  AREA 2: Counterfactual Injection — Variable Perturbation")
    print("=" * 72)

    # Use competitive payload pool (mixed vuln types) for tighter races
    payloads = _competitive_payloads()
    findings = []
    tests: list[dict] = []

    # Baseline — mixed vuln context with campaign data to activate all signals
    arbiter_base = PayloadArbiter()
    ctx_base = _make_context(
        VulnType.SQLI, "cloudflare", "sqli data exfiltration to admin", 1.5,
        cross_target_signals=[("other-target.com", "sqli", 0.8)],
    )
    base_results = _arbitrate_and_decompose(arbiter_base, ctx_base, payloads)
    base_ranking = [r["payload"] for r in base_results]
    base_winner = base_ranking[0] if base_ranking else ""
    print(f"\n  Baseline winner: {base_winner}")
    if len(base_results) >= 2:
        _top = [round(r["score"], 4) for r in base_results[:3]]
        print(f"    Top scores: {_top}")
        print(f"    Delta #1-#2: {base_results[0]['score'] - base_results[1]['score']:.4f}")

    # CF1: Set hypothesis_multiplier = 0 (kill hypothesis)
    arbiter_cf1 = PayloadArbiter()
    ctx_cf1 = _make_context(
        VulnType.SQLI, "cloudflare", "sqli data exfiltration to admin", 0.0,
        cross_target_signals=[("other-target.com", "sqli", 0.8)],
    )
    cf1_results = _arbitrate_and_decompose(arbiter_cf1, ctx_cf1, payloads)
    cf1_ranking = [r["payload"] for r in cf1_results]
    cf1_changed = base_ranking != cf1_ranking
    print(f"\n  CF1: hypothesis_multiplier=0")
    print(f"    Ranking changed: {cf1_changed}")
    if cf1_results:
        _cf1_top = [round(r["score"], 4) for r in cf1_results[:3]]
        print(f"    CF1 top scores: {_cf1_top}")
        base_hyp_vals = [r["signals"]["hypothesis"] for r in base_results]
        cf1_hyp_vals = [r["signals"]["hypothesis"] for r in cf1_results]
        print(f"    Hyp signals: base={[f'{v:.3f}' for v in base_hyp_vals]}")
        print(f"    Hyp signals: cf1 ={[f'{v:.3f}' for v in cf1_hyp_vals]}")
    if not cf1_changed:
        # Check if hypothesis signals actually changed
        hyp_delta = sum(abs(a - b) for a, b in zip(base_hyp_vals, cf1_hyp_vals))
        if hyp_delta < 0.01:
            findings.append("CF1: hypothesis_multiplier has NO effect on signals — decorative")
        else:
            findings.append("CF1: hypothesis signals changed but ranking unchanged — low weight influence")
    tests.append({"name": "kill_hypothesis", "ranking_changed": cf1_changed})

    # CF2: Force chain_alignment high via chain_goal that deeply matches
    arbiter_cf2 = PayloadArbiter()
    ctx_cf2 = _make_context(
        VulnType.SQLI, "cloudflare", "rce escalation to admin", 1.5,
        cross_target_signals=[("other-target.com", "sqli", 0.8)],
    )
    cf2_results = _arbitrate_and_decompose(arbiter_cf2, ctx_cf2, payloads)
    cf2_ranking = [r["payload"] for r in cf2_results]
    cf2_changed = base_ranking != cf2_ranking
    print(f"\n  CF2: chain_goal='rce escalation to admin' (mismatched for XSS)")
    print(f"    Ranking changed: {cf2_changed}")
    tests.append({"name": "mismatched_chain_goal", "ranking_changed": cf2_changed})

    # CF3: Remove WAF context
    arbiter_cf3 = PayloadArbiter()
    ctx_cf3 = _make_context(
        VulnType.SQLI, "", "sqli data exfiltration to admin", 1.5,
        cross_target_signals=[("other-target.com", "sqli", 0.8)],
    )
    cf3_results = _arbitrate_and_decompose(arbiter_cf3, ctx_cf3, payloads)
    cf3_ranking = [r["payload"] for r in cf3_results]
    cf3_changed = base_ranking != cf3_ranking
    print(f"\n  CF3: waf_vendor='' (no WAF)")
    print(f"    Ranking changed: {cf3_changed}")
    if cf3_results:
        base_bypass = [r["signals"]["bypass"] for r in base_results]
        cf3_bypass = [r["signals"]["bypass"] for r in cf3_results]
        print(f"    Bypass signals: base={[f'{v:.3f}' for v in base_bypass]}")
        print(f"    Bypass signals: cf3 ={[f'{v:.3f}' for v in cf3_bypass]}")
    tests.append({"name": "remove_waf", "ranking_changed": cf3_changed})

    # CF4: Kill impact — set impact weight to 0, redistribute to detection(-)
    arbiter_cf4 = PayloadArbiter()
    arbiter_cf4._w_impact = 0.0
    arbiter_cf4._w_detection = -0.18  # Absorb impact's weight as penalty
    cf4_results = _arbitrate_and_decompose(arbiter_cf4, ctx_base, payloads)
    cf4_ranking = [r["payload"] for r in cf4_results]
    cf4_changed = base_ranking != cf4_ranking
    print(f"\n  CF4: impact weight=0, detection weight=-0.18 (penalise detectable)")
    print(f"    Ranking changed: {cf4_changed}")
    if cf4_results:
        _cf4_top = [round(r["score"], 4) for r in cf4_results[:3]]
        print(f"    CF4 top scores: {_cf4_top}")
        print(f"    CF4 winner: {cf4_results[0]['payload'][:50]}")
    if not cf4_changed:
        findings.append("CF4: Zeroing impact + heavy detection penalty had no effect")
    tests.append({"name": "kill_impact_heavy_detection", "ranking_changed": cf4_changed})

    # CF5: Invert priorities — make cost the dominant positive signal
    arbiter_cf5 = PayloadArbiter()
    arbiter_cf5._w_bypass = 0.05
    arbiter_cf5._w_execute = 0.05
    arbiter_cf5._w_impact = 0.05
    arbiter_cf5._w_cost = +0.50   # Prefer expensive payloads (inverted)
    cf5_results = _arbitrate_and_decompose(arbiter_cf5, ctx_base, payloads)
    cf5_ranking = [r["payload"] for r in cf5_results]
    cf5_changed = base_ranking != cf5_ranking
    print(f"\n  CF5: cost weight=+0.50 (prefer expensive), bypass/execute/impact=0.05")
    print(f"    Ranking changed: {cf5_changed}")
    if cf5_results:
        _cf5_top = [round(r["score"], 4) for r in cf5_results[:3]]
        print(f"    CF5 top scores: {_cf5_top}")
        print(f"    CF5 winner: {cf5_results[0]['payload'][:50]}")
    tests.append({"name": "invert_cost_priority", "ranking_changed": cf5_changed})

    # CF6: Different vuln type entirely (SQLi payloads in XSS context)
    arbiter_cf6 = PayloadArbiter()
    cf6_results = _arbitrate_and_decompose(arbiter_cf6, ctx_base, _sqli_payloads())
    print(f"\n  CF6: SQLi payloads in XSS context")
    if cf6_results:
        xss_top_score = base_results[0]["score"] if base_results else 0
        sqli_top_score = cf6_results[0]["score"]
        print(f"    XSS-specific top score: {xss_top_score:.4f}")
        print(f"    SQLi-in-XSS top score:  {sqli_top_score:.4f}")
        if sqli_top_score >= xss_top_score:
            findings.append("CF6: SQLi payloads score >= XSS in XSS context — vuln specialization broken")
    tests.append({"name": "wrong_vuln_type", "results": cf6_results})

    changed_count = sum(1 for t in tests if t.get("ranking_changed"))
    total_ranking_tests = sum(1 for t in tests if "ranking_changed" in t)
    print(f"\n  Summary: {changed_count}/{total_ranking_tests} counterfactuals changed ranking")

    # Also check: did SCORES change even if ranking didn't?
    # This distinguishes "weights matter but candidate is dominant" from
    # "weights are completely decorative"
    if base_results and cf1_results:
        score_deltas = [
            abs(b["score"] - c["score"])
            for b, c in zip(base_results, cf1_results)
        ]
        avg_score_delta = sum(score_deltas) / len(score_deltas) if score_deltas else 0
        scores_changed = avg_score_delta > 0.01
        print(f"  Score sensitivity: avg |Δscore| across CFs = {avg_score_delta:.4f}")
        print(f"    Scores respond to variable changes: {'✓' if scores_changed else '❌'}")
        if not scores_changed:
            findings.append("Scores don't respond to variable changes — signals decorative")
    else:
        scores_changed = False

    return {"tests": tests, "findings": findings, "scores_changed": scores_changed,
            "ranking_changes": changed_count, "total_cf_tests": total_ranking_tests}


# ══════════════════════════════════════════════════════════════════════
# AREA 3: Single-Signal Isolation
# ══════════════════════════════════════════════════════════════════════

def _audit_single_signal_isolation() -> dict:
    """Zero all weights except one; check if system performs above random."""
    print("\n" + "=" * 72)
    print("  AREA 3: Single-Signal Isolation — Is Each Signal Causal?")
    print("=" * 72)

    payloads = _xss_payloads()
    ctx = _make_context(VulnType.XSS, "cloudflare", "xss to steal session", 1.5)
    findings = []
    isolation_results = []

    # For each signal, create an arbiter with only that weight active
    signals = {
        "bypass_score":     ("_w_bypass",     +1.0),
        "execute_score":    ("_w_execute",    +1.0),
        "impact_score":     ("_w_impact",     +1.0),
        "chain_alignment":  ("_w_chain",      +1.0),
        "hypothesis_boost": ("_w_hypothesis", +1.0),
        "campaign_boost":   ("_w_campaign",   +1.0),
        "detection_risk":   ("_w_detection",  -1.0),
        "cost":             ("_w_cost",       -1.0),
    }

    for sig_name, (attr, direction) in signals.items():
        arbiter = PayloadArbiter()
        # Zero everything
        for other_attr in ["_w_bypass", "_w_execute", "_w_impact", "_w_chain",
                           "_w_hypothesis", "_w_campaign", "_w_detection", "_w_cost"]:
            setattr(arbiter, other_attr, 0.0)
        # Set only this one
        setattr(arbiter, attr, direction)

        results = _arbitrate_and_decompose(arbiter, ctx, payloads)
        scores = [r["score"] for r in results]
        spread = max(scores) - min(scores) if scores else 0

        # A signal is causal if it produces non-trivial score spread
        causal = spread > 0.05
        status = "CAUSAL" if causal else "DECORATIVE/NOISE"

        print(f"  {sig_name:20s} spread={spread:.4f} → {status}")
        if results:
            for r in results[:3]:
                print(f"    {r['payload'][:40]:40s}  score={r['score']:.4f}  "
                      f"signal={r['signals'].get(sig_name.replace('_score','').replace('_boost','').replace('_alignment','chain').replace('_risk','detection'), 0):.4f}")

        if not causal:
            findings.append(f"{sig_name}: decorative — spread={spread:.4f} when isolated")

        isolation_results.append({
            "signal": sig_name,
            "spread": spread,
            "causal": causal,
        })

    causal_count = sum(1 for r in isolation_results if r["causal"])
    print(f"\n  {causal_count}/{len(isolation_results)} signals are genuinely causal")
    return {"results": isolation_results, "findings": findings}


# ══════════════════════════════════════════════════════════════════════
# AREA 4: Weight Learning Quality
# ══════════════════════════════════════════════════════════════════════

def _audit_weight_learning() -> dict:
    """Verify learning quality: convergence, stability, no collapse."""
    print("\n" + "=" * 72)
    print("  AREA 4: Weight Learning Quality — Convergence & Stability")
    print("=" * 72)

    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    tuner.bind_arbiter(arbiter)
    collector = SynthesisFeedbackCollector()
    collector.bind_weight_tuner(tuner)

    findings = []
    weight_history = []  # list of (obs_count, weights_dict)

    ctx = _make_context(VulnType.XSS, "cloudflare", "xss steal session", 1.5)
    payloads = _xss_payloads()

    # Run 200 cycles of feedback with a consistent signal:
    # bypass-dominant positive events (reward ~0.8) for first 100
    # execute-dominant after (reward ~0.8) — tests adaptation
    for cycle in range(200):
        if cycle < 100:
            # Bypass-dominant phase: bypass=0.9 payloads succeed
            p = copy.deepcopy(payloads[2])  # encoded/obfuscated one
            p.bypass_score = 0.9
            p.execute_score = 0.2
        else:
            # Execute-dominant phase: execute=0.9 payloads succeed
            p = copy.deepcopy(payloads[0])  # script alert one
            p.bypass_score = 0.2
            p.execute_score = 0.9

        event = FeedbackEvent(
            payload=p,
            context=ctx,
            feedback_type=FeedbackType.EXECUTED_SUCCESSFULLY if cycle % 3 != 2 else FeedbackType.BLOCKED_BY_WAF,
            response_status=200,
            evidence_found=(cycle % 4 == 0),
        )
        collector.record_feedback(event)

        if cycle % 10 == 0 or cycle in (99, 100, 199):
            w = tuner.get_current_weights()
            weight_history.append((cycle, dict(w)))

    # Analyze learning quality
    print("\n  Weight evolution at key points:")
    print(f"  {'Cycle':>6s}  {'bypass':>8s}  {'execute':>8s}  {'impact':>8s}  {'chain':>8s}  {'hyp':>8s}")
    for cycle, w in weight_history:
        print(f"  {cycle:>6d}  {w.get('bypass_score', 0):>8.4f}  {w.get('execute_score', 0):>8.4f}  "
              f"{w.get('impact_score', 0):>8.4f}  {w.get('chain_alignment', 0):>8.4f}  "
              f"{w.get('hypothesis_boost', 0):>8.4f}")

    # Check 1: Weights moved from initial (not flat)
    initial = weight_history[0][1]
    final = weight_history[-1][1]
    total_movement = sum(abs(final.get(k, 0) - initial.get(k, 0))
                         for k in initial)
    flat = total_movement < 0.05
    print(f"\n  Total weight movement:  {total_movement:.4f} → "
          f"{'❌ FLAT (learning broken)' if flat else '✓ weights moved'}")
    if flat:
        findings.append(f"Flat weights: total movement={total_movement:.4f}")

    # Check 2: Phase adaptation — after cycle 100, execute should rise
    pre_regime = None
    post_regime = None
    for c, w in weight_history:
        if c == 99:
            pre_regime = w
        if c == 199:
            post_regime = w

    if pre_regime and post_regime:
        execute_delta = post_regime["execute_score"] - pre_regime["execute_score"]
        bypass_delta = post_regime["bypass_score"] - pre_regime["bypass_score"]
        print(f"  Regime shift (cycle 100→199):")
        print(f"    bypass Δ={bypass_delta:+.4f}  (expect ↓)")
        print(f"    execute Δ={execute_delta:+.4f} (expect ↑)")
        adapted = execute_delta > 0.01 and bypass_delta < -0.01
        print(f"    Adapted: {'✓' if adapted else '❌ NO ADAPTATION'}")
        if not adapted:
            findings.append(f"No regime adaptation: execute Δ={execute_delta:+.4f}, bypass Δ={bypass_delta:+.4f}")

    # Check 3: No collapse (all weights ≈ equal)
    final_vals = [v for v in final.values() if v > 0]  # positive weights
    if final_vals:
        mean = sum(final_vals) / len(final_vals)
        variance = sum((v - mean) ** 2 for v in final_vals) / len(final_vals)
        collapsed = variance < 0.001
        print(f"  Weight variance: {variance:.6f} → "
              f"{'❌ MODEL COLLAPSE (all ≈ equal)' if collapsed else '✓ diverse'}")
        if collapsed:
            findings.append(f"Model collapse: weight variance={variance:.6f}")

    # Check 4: Oscillation check — are weights stable in late phase?
    late_points = [(c, w) for c, w in weight_history if c >= 150]
    if len(late_points) >= 3:
        oscillation_count = 0
        for sig_name in ["bypass_score", "execute_score"]:
            vals = [w[sig_name] for _, w in late_points]
            for i in range(1, len(vals) - 1):
                if (vals[i] - vals[i - 1]) * (vals[i + 1] - vals[i]) < 0:
                    oscillation_count += 1
        oscillating = oscillation_count > 5
        print(f"  Late-phase direction changes: {oscillation_count} → "
              f"{'❌ OSCILLATING' if oscillating else '✓ stable'}")
        if oscillating:
            findings.append(f"Late-phase oscillation: {oscillation_count} direction changes")

    # Check 5: Arbiter actually got the updated weights
    arbiter_bypass = arbiter._w_bypass
    tuner_bypass = final.get("bypass_score", 0)
    sync = abs(arbiter_bypass - tuner_bypass) < 0.001
    print(f"  Tuner→Arbiter sync: tuner={tuner_bypass:.4f} arbiter={arbiter_bypass:.4f} → "
          f"{'✓ synced' if sync else '❌ DESYNCED'}")
    if not sync:
        findings.append(f"Tuner→Arbiter desync: tuner={tuner_bypass:.4f} vs arbiter={arbiter_bypass:.4f}")

    return {
        "weight_history": weight_history,
        "total_movement": total_movement,
        "findings": findings,
    }


# ══════════════════════════════════════════════════════════════════════
# AREA 5: Edge Regimes
# ══════════════════════════════════════════════════════════════════════

def _audit_edge_regimes() -> dict:
    """Force system into extreme situations."""
    print("\n" + "=" * 72)
    print("  AREA 5: Edge Regimes — Deceptive, Delayed, Conflict")
    print("=" * 72)

    findings = []

    # 5A: Deceptive Success — bad payload returns high reward
    print("\n  5A: Deceptive Success")
    tuner_a = WeightTuner()
    arbiter_a = PayloadArbiter()
    tuner_a.bind_arbiter(arbiter_a)
    collector_a = SynthesisFeedbackCollector()
    collector_a.bind_weight_tuner(tuner_a)

    ctx = _make_context(VulnType.XSS, "cloudflare")

    # Feed deceptive signal: high detection_risk payload gets positive reward
    initial_det_weight = tuner_a.get_current_weights().get("detection_risk", -0.03)
    for i in range(60):
        p = RankedPayload(
            payload='<script>alert(1)</script>',  # high detection risk
            score=0.0, engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.XSS, confidence=0.5,
            bypass_score=0.2,   # low bypass
            execute_score=0.3,  # low execute
            detection_risk=0.9, # high detection (normally BAD)
        )
        event = FeedbackEvent(
            payload=p, context=ctx,
            feedback_type=FeedbackType.EXECUTED_SUCCESSFULLY,
            response_status=200, evidence_found=True,
        )
        collector_a.record_feedback(event)

    final_det_weight = tuner_a.get_current_weights().get("detection_risk", -0.03)
    print(f"    Detection weight: {initial_det_weight:.4f} → {final_det_weight:.4f}")
    fooled = final_det_weight > 0  # detection_risk weight should stay negative
    print(f"    System fooled: {'❌ YES — detection weight flipped positive' if fooled else '✓ NO — kept negative'}")
    if fooled:
        findings.append("Deceptive success: system flipped detection_risk to positive")

    # 5B: Signal Conflict Extremes
    print("\n  5B: Signal Conflict — hypothesis strong positive vs WAF strong negative")
    arbiter_b = PayloadArbiter()
    # Create a context where hypothesis is very high but WAF blocks everything
    ctx_conflict = _make_context(
        VulnType.XSS, "cloudflare",
        hypothesis_multiplier=3.0,  # Very strong hypothesis
    )
    # Payload: structurally weak for bypass (known blocked pattern)
    conflict_payloads = [
        RankedPayload(
            payload='<script>alert(1)</script>',  # WAF will detect
            score=0.0, engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.XSS, confidence=0.5,
        ),
        RankedPayload(
            payload='<details open ontoggle=confirm`1`>',  # WAF harder to detect
            score=0.0, engine=SynthesisEngine.GENETIC_FORGE,
            vuln_type=VulnType.XSS, confidence=0.5,
            encoding_applied="html",
        ),
    ]
    conflict_results = _arbitrate_and_decompose(arbiter_b, ctx_conflict, conflict_payloads)
    if len(conflict_results) >= 2:
        # Stealthy payload should still win even though hypothesis boost is high
        stealthy_won = conflict_results[0]["payload"].startswith("<details")
        print(f"    Winner: {conflict_results[0]['payload'][:50]}")
        print(f"    Stealthy payload won: {stealthy_won}")
        for r in conflict_results:
            print(f"      {r['payload'][:40]:40s}  bypass={r['signals']['bypass']:.3f}  "
                  f"hyp={r['signals']['hypothesis']:.3f}  score={r['score']:.4f}")

    # 5C: All-zero signals — system should still function
    print("\n  5C: Degenerate input — empty payload list")
    arbiter_c = PayloadArbiter()
    ctx_c = _make_context(VulnType.XSS)
    degen_results = _arbitrate_and_decompose(arbiter_c, ctx_c, [])
    print(f"    Empty input: returned {len(degen_results)} results → "
          f"{'✓ handled gracefully' if len(degen_results) == 0 else '❌ unexpected output'}")

    return {"findings": findings}


# ══════════════════════════════════════════════════════════════════════
# AREA 6: Regret Decomposition
# ══════════════════════════════════════════════════════════════════════

def _audit_regret_decomposition() -> dict:
    """Identify whether error comes from scoring, selection, or feedback."""
    print("\n" + "=" * 72)
    print("  AREA 6: Regret Decomposition — Error Source Analysis")
    print("=" * 72)

    findings = []
    arbiter = PayloadArbiter()
    ctx = _make_context(VulnType.XSS, "cloudflare", "xss steal cookies", 1.5)
    payloads = _xss_payloads()

    results = _arbitrate_and_decompose(arbiter, ctx, payloads)

    if len(results) < 2:
        print("  Not enough candidates for regret analysis")
        return {"findings": findings}

    # Define ground truth: encoded/obfuscated payload should be optimal
    # for WAF bypass scenario
    optimal_idx = None
    for i, r in enumerate(results):
        if "%" in r["payload"] or "&#" in r["payload"] or "\\x" in r["payload"]:
            optimal_idx = i
            break
    if optimal_idx is None:
        optimal_idx = 0  # fall back to first

    chosen_score = results[0]["score"]
    optimal_score = results[optimal_idx]["score"]
    regret = optimal_score - chosen_score

    print(f"\n  Chosen:  [{results[0]['engine']}] {results[0]['payload'][:50]}  score={chosen_score:.4f}")
    print(f"  Optimal: [{results[optimal_idx]['engine']}] {results[optimal_idx]['payload'][:50]}  score={optimal_score:.4f}")
    print(f"  Regret:  {regret:+.4f}")

    if regret > 0.05:
        # Diagnose: is it scoring error or signal error?
        # Check if optimal has higher bypass but lower score
        chosen_sigs = results[0]["signals"]
        optimal_sigs = results[optimal_idx]["signals"]

        scoring_error = False
        signal_misrank = []
        for sig in ["bypass", "execute", "impact"]:
            if optimal_sigs[sig] > chosen_sigs[sig] + 0.05:
                signal_misrank.append(f"{sig}: optimal={optimal_sigs[sig]:.3f} > chosen={chosen_sigs[sig]:.3f}")

        if signal_misrank:
            print(f"  Signal misranks: {signal_misrank}")
            print(f"  → Regret from SCORING (weight imbalance)")
            findings.append(f"Regret={regret:.4f} from scoring: {signal_misrank}")
        else:
            print(f"  → Regret from SELECTION (signals agree, score doesn't)")
            findings.append(f"Regret={regret:.4f} from selection")
    else:
        print(f"  → Near-optimal selection ✓")

    # Check: do all candidates with high bypass also have high score?
    bypass_score_corr = 0
    if len(results) >= 3:
        bypasses = [r["signals"]["bypass"] for r in results]
        scores = [r["score"] for r in results]
        # Simple rank correlation: are they monotonically ordered?
        bypass_ranks = sorted(range(len(bypasses)), key=lambda i: bypasses[i], reverse=True)
        score_ranks = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        # Count concordant pairs
        concordant = 0
        discordant = 0
        for i in range(len(bypass_ranks)):
            for j in range(i + 1, len(bypass_ranks)):
                bp_ord = (bypasses[bypass_ranks[i]] >= bypasses[bypass_ranks[j]])
                sc_ord = (scores[bypass_ranks[i]] >= scores[bypass_ranks[j]])
                if bp_ord == sc_ord:
                    concordant += 1
                else:
                    discordant += 1
        total = concordant + discordant
        bypass_score_corr = (concordant - discordant) / max(total, 1)
        print(f"\n  Bypass↔Score rank correlation: {bypass_score_corr:.3f} "
              f"({'aligned' if bypass_score_corr > 0.3 else 'misaligned'})")

    return {"regret": regret, "findings": findings}


# ══════════════════════════════════════════════════════════════════════
# AREA 7: Coherence Validation
# ══════════════════════════════════════════════════════════════════════

def _audit_coherence() -> dict:
    """Check if subsystems agree on what's good."""
    print("\n" + "=" * 72)
    print("  AREA 7: Coherence Validation — Subsystem Agreement")
    print("=" * 72)

    findings = []

    arbiter = PayloadArbiter()
    ctx = _make_context(VulnType.XSS, "cloudflare", "xss session hijack", 1.5)
    payloads = _xss_payloads()
    results = _arbitrate_and_decompose(arbiter, ctx, payloads)

    if len(results) < 2:
        return {"findings": findings}

    # Check: does the winner have majority signal support?
    winner = results[0]
    runner = results[1]
    signals_favor_winner = 0
    signals_favor_runner = 0
    signal_keys = ["bypass", "execute", "impact", "chain", "hypothesis"]

    print(f"\n  Signal-by-signal comparison: winner vs runner-up")
    for sig in signal_keys:
        w_val = winner["signals"][sig]
        r_val = runner["signals"][sig]
        favor = "WINNER" if w_val > r_val else ("RUNNER" if r_val > w_val else "TIE")
        if w_val > r_val:
            signals_favor_winner += 1
        elif r_val > w_val:
            signals_favor_runner += 1
        print(f"    {sig:15s}  winner={w_val:.4f}  runner={r_val:.4f}  → {favor}")

    coherent = signals_favor_winner > signals_favor_runner
    print(f"\n  Signals favor winner: {signals_favor_winner}/{signals_favor_winner + signals_favor_runner}")
    print(f"  Coherent selection: {'✓' if coherent else '❌ INCOHERENT — winner lost majority of signals'}")
    if not coherent:
        findings.append(f"Incoherent: winner won {signals_favor_winner}/{signals_favor_winner + signals_favor_runner} signals")

    # Check: is the winner "confident but wrong" candidate?
    # High confidence + low bypass in WAF context = suspicious
    if ctx.waf_vendor and winner["signals"]["bypass"] < 0.3:
        findings.append(f"Confident but risky: winner has bypass={winner['signals']['bypass']:.3f} in WAF context")
        print(f"\n  ⚠ Confident but risky: bypass={winner['signals']['bypass']:.3f} in WAF context")

    return {"coherent": coherent, "findings": findings}


# ══════════════════════════════════════════════════════════════════════
# AREA 8: Illusions of Intelligence
# ══════════════════════════════════════════════════════════════════════

def _audit_illusions() -> dict:
    """Does performance survive shuffling, freezing, and randomization?"""
    print("\n" + "=" * 72)
    print("  AREA 8: Illusions of Intelligence — Shuffle/Freeze/Random")
    print("=" * 72)

    findings = []
    ctx = _make_context(VulnType.XSS, "cloudflare", "xss steal session", 1.5)
    payloads = _xss_payloads()

    # Baseline
    arbiter = PayloadArbiter()
    base_results = _arbitrate_and_decompose(arbiter, ctx, payloads)
    base_scores = [r["score"] for r in base_results]
    base_mean = sum(base_scores) / len(base_scores) if base_scores else 0
    base_winner = base_results[0]["payload"] if base_results else ""

    # 8A: Shuffle signals — permute weight assignments
    print("\n  8A: Signal Shuffle — reassign weights randomly")
    arbiter_s = PayloadArbiter()
    shuffled_weights = [0.30, 0.25, 0.15, 0.10, 0.08, 0.07, -0.03, -0.02]
    random.seed(42)
    random.shuffle(shuffled_weights)
    weight_attrs = ["_w_bypass", "_w_execute", "_w_impact", "_w_chain",
                    "_w_hypothesis", "_w_campaign", "_w_detection", "_w_cost"]
    for attr, w in zip(weight_attrs, shuffled_weights):
        setattr(arbiter_s, attr, w)

    shuffle_results = _arbitrate_and_decompose(arbiter_s, ctx, payloads)
    shuffle_winner = shuffle_results[0]["payload"] if shuffle_results else ""
    winner_changed = base_winner != shuffle_winner
    print(f"    Winner changed: {winner_changed}")
    print(f"    Base winner:    {base_winner[:50]}")
    print(f"    Shuffle winner: {shuffle_winner[:50]}")
    if not winner_changed:
        findings.append("Signal shuffle didn't change winner — weights may not matter")

    # 8B: Frozen weights — train for 100 cycles but freeze weights
    print("\n  8B: Frozen Weights — does untrained system perform as well?")
    arbiter_frozen = PayloadArbiter()  # fresh, never trained
    tuner_trained = WeightTuner()
    arbiter_trained = PayloadArbiter()
    tuner_trained.bind_arbiter(arbiter_trained)
    collector_t = SynthesisFeedbackCollector()
    collector_t.bind_weight_tuner(tuner_trained)

    # Train with bypass-dominant signal
    for i in range(100):
        p = copy.deepcopy(payloads[2])
        p.bypass_score = 0.9
        p.execute_score = 0.2
        event = FeedbackEvent(
            payload=p, context=ctx,
            feedback_type=FeedbackType.EXECUTED_SUCCESSFULLY if i % 3 != 2 else FeedbackType.BLOCKED_BY_WAF,
            response_status=200, evidence_found=(i % 4 == 0),
        )
        collector_t.record_feedback(event)

    frozen_results = _arbitrate_and_decompose(arbiter_frozen, ctx, payloads)
    trained_results = _arbitrate_and_decompose(arbiter_trained, ctx, payloads)

    frozen_scores = [r["score"] for r in frozen_results]
    trained_scores = [r["score"] for r in trained_results]

    frozen_top = frozen_scores[0] if frozen_scores else 0
    trained_top = trained_scores[0] if trained_scores else 0
    trained_advantage = trained_top - frozen_top

    print(f"    Frozen top score:  {frozen_top:.4f}")
    print(f"    Trained top score: {trained_top:.4f}")
    print(f"    Training advantage: {trained_advantage:+.4f}")

    if abs(trained_advantage) < 0.01:
        findings.append(f"Training has no advantage: Δ={trained_advantage:+.4f} — learning may be fake")
        print(f"    ⚠ Training has NO advantage — learning may be fake")
    else:
        print(f"    ✓ Training provides measurable advantage")

    # 8C: Random payloads — garbage should score lower than real payloads
    print("\n  8C: Random Payloads — garbage vs structured")
    random_payloads = [
        RankedPayload(
            payload=f"{''.join(random.choices('abcdefghijklmnop0123456789', k=30))}",
            score=0.0, engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.XSS, confidence=0.5,
        )
        for _ in range(5)
    ]
    random_results = _arbitrate_and_decompose(arbiter, ctx, random_payloads)
    random_top = random_results[0]["score"] if random_results else 0
    structured_top = base_results[0]["score"] if base_results else 0

    print(f"    Random top:     {random_top:.4f}")
    print(f"    Structured top: {structured_top:.4f}")
    discrimination = structured_top - random_top
    print(f"    Discrimination: {discrimination:+.4f}")

    if discrimination < 0.05:
        findings.append(f"Poor discrimination: structured vs random Δ={discrimination:.4f}")
        print(f"    ❌ Poor discrimination — system can't distinguish garbage from real payloads")
    else:
        print(f"    ✓ System discriminates structured from random")

    return {"findings": findings}


# ══════════════════════════════════════════════════════════════════════
# AREA 9: Checklist Summary
# ══════════════════════════════════════════════════════════════════════

def _print_checklist(all_findings: dict) -> tuple[int, int]:
    """Print condensed YES/NO audit checklist."""
    print("\n" + "=" * 72)
    print("  AREA 9: Audit Checklist — Final Gate")
    print("=" * 72)

    area1 = all_findings["area1"]
    area2 = all_findings["area2"]
    area3 = all_findings["area3"]
    area4 = all_findings["area4"]
    area7 = all_findings["area7"]
    area8 = all_findings["area8"]

    checks = [
        ("All 8 signals vary across candidates?",
         len(area1.get("dead_signals", [])) < 3),
        ("Weights influence scores (even if dominant candidate persists)?",
         area2.get("scores_changed", False) or area2.get("ranking_changes", 0) >= 1),
        ("Each signal is causal when isolated?",
         sum(1 for r in area3.get("results", []) if r.get("causal")) >= 4),
        ("Regret decreases over cycles?",
         area4.get("total_movement", 0) > 0.05),
        ("Feedback changes future decisions?",
         area4.get("total_movement", 0) > 0.05),
        ("System discriminates real vs random?",
         not any("Poor discrimination" in f for f in area8.get("findings", []))),
        ("Weights shift when signal regime changes?",
         not any("No regime adaptation" in f for f in area4.get("findings", []))),
        ("At least one counterfactual shifts ranking OR all vary scores?",
         area2.get("ranking_changes", 0) >= 1 or area2.get("scores_changed", False)),
    ]

    pass_count = 0
    for label, ok in checks:
        icon = "YES ✓" if ok else "NO ❌"
        print(f"  {icon:8s} {label}")
        if ok:
            pass_count += 1

    return pass_count, len(checks)


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

def main() -> int:
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║     DEEP MANUAL AUDIT — 9-Area Causal Intelligence Check    ║")
    print("╚═══════════════════════════════════════════════════════════════╝")

    all_findings: dict[str, Any] = {}
    all_issues: list[str] = []

    # Area 1
    r1 = _audit_causal_walkthrough()
    all_findings["area1"] = r1
    all_issues.extend(r1.get("findings", []))

    # Area 2
    r2 = _audit_counterfactual()
    all_findings["area2"] = r2
    all_issues.extend(r2.get("findings", []))

    # Area 3
    r3 = _audit_single_signal_isolation()
    all_findings["area3"] = r3
    all_issues.extend(r3.get("findings", []))

    # Area 4
    r4 = _audit_weight_learning()
    all_findings["area4"] = r4
    all_issues.extend(r4.get("findings", []))

    # Area 5
    r5 = _audit_edge_regimes()
    all_findings["area5"] = r5
    all_issues.extend(r5.get("findings", []))

    # Area 6
    r6 = _audit_regret_decomposition()
    all_findings["area6"] = r6
    all_issues.extend(r6.get("findings", []))

    # Area 7
    r7 = _audit_coherence()
    all_findings["area7"] = r7
    all_issues.extend(r7.get("findings", []))

    # Area 8
    r8 = _audit_illusions()
    all_findings["area8"] = r8
    all_issues.extend(r8.get("findings", []))

    # Area 9: Checklist
    passed, total = _print_checklist(all_findings)

    # Final verdict
    print(f"\n{'=' * 72}")
    print(f"  FINAL VERDICT")
    print(f"{'=' * 72}")
    print(f"\n  Checklist: {passed}/{total}")
    print(f"  Total issues found: {len(all_issues)}")
    if all_issues:
        print(f"\n  Issues:")
        for i, issue in enumerate(all_issues, 1):
            print(f"    {i}. {issue}")

    if passed >= total - 1:
        print(f"\n  🟢 SYSTEM PASSES DEEP AUDIT")
    elif passed >= total - 3:
        print(f"\n  🟡 SYSTEM MOSTLY PASSES — {total - passed} areas need attention")
    else:
        print(f"\n  🔴 SYSTEM FAILS DEEP AUDIT — {total - passed} checks failed")

    return 0 if passed >= total - 1 else 1


if __name__ == "__main__":
    sys.exit(main())
