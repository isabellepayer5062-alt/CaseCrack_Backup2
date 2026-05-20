#!/usr/bin/env python3
"""Probe 14: Delayed Subsystem Activation — Causal Influence Test.

Proves that the feedback loop is not just CONNECTED but CAUSALLY
INFLUENCING outcomes.

Protocol:
  Phase A — "Deaf" (50 cycles, feedback DISABLED):
    - Feed events with strong signal (bypass=0.9, execute=0.1)
    - Record weight movement, hypothesis state, arbiter scores
    
  Phase B — "Alive" (50 cycles, feedback ENABLED):
    - Feed identical events
    - Record same metrics
    
  Assertions:
    1. Phase A: weights are STATIC (no learning)
    2. Phase B: weights MOVE toward signal (bypass ↑, execute ↓)
    3. Hypothesis engine metrics non-zero only in Phase B
    4. Performance jump: Phase B arbiter scores diverge from Phase A

This is the definitive test: if it passes, the feedback loop is
causally influencing system behavior, not just connected.

Run:
    .venv/Scripts/python.exe _probe_delayed_activation.py
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
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
from tools.burp_enterprise.exploit_chains.payload_arbiter import PayloadArbiter
from tools.burp_enterprise.hypothesis_engine import HypothesisEngine


# ── Helpers ──────────────────────────────────────────────────────────

def _make_signal_event(
    feedback_type: FeedbackType,
    *,
    bypass: float = 0.9,
    execute: float = 0.1,
    evidence: bool = False,
    vuln: VulnType = VulnType.XSS,
) -> FeedbackEvent:
    """Build a feedback event with controlled signal strengths."""
    payload = RankedPayload(
        payload="<script>alert(1)</script>",
        score=0.85,
        engine=SynthesisEngine.GRAMMAR,
        vuln_type=vuln,
        confidence=0.9,
        bypass_score=bypass,
        execute_score=execute,
        impact_score=0.5,
        chain_alignment=0.3,
        hypothesis_boost=0.1,
        campaign_boost=0.05,
        stealth_score=0.2,
        novelty_score=0.3,
        environment_fit=0.4,
        temporal_relevance=0.3,
        chain_momentum=0.15,
        detection_risk=0.02,
        cost=0.01,
    )
    context = SynthesisContext(
        target_url="https://target.example.com/search",
        vuln_type=vuln,
    )
    return FeedbackEvent(
        payload=payload,
        context=context,
        feedback_type=feedback_type,
        response_status=200,
        evidence_found=evidence,
    )


@dataclass
class PhaseMetrics:
    """Captured metrics for one phase."""
    bypass_weight: float
    execute_weight: float
    hypothesis_signals: int
    hypothesis_penalties: int
    observations: int
    arbiter_bypass: float
    arbiter_execute: float
    elapsed_ms: float


def _snapshot_weights(tuner: WeightTuner) -> dict[str, float]:
    """Get current weights from tuner."""
    return tuner.get_current_weights()


def _run_phase(
    collector: SynthesisFeedbackCollector | None,
    tuner: WeightTuner,
    arbiter: PayloadArbiter,
    hyp: HypothesisEngine,
    n_cycles: int,
    *,
    label: str,
) -> PhaseMetrics:
    """Run n_cycles of feedback events and capture metrics."""
    start = time.monotonic()

    initial_obs = tuner._total_observations
    initial_signals = hyp.get_metrics().get("signals_received", 0)
    initial_penalties = hyp.get_metrics().get("penalties_applied", 0)

    for i in range(n_cycles):
        # Alternate 80% positive (bypass-dominant) + 20% negative
        if i % 5 < 4:
            ft = FeedbackType.EXECUTED_SUCCESSFULLY
            evidence = (i % 3 == 0)  # ~33% evidence
        else:
            ft = FeedbackType.BLOCKED_BY_WAF
            evidence = False

        event = _make_signal_event(ft, bypass=0.9, execute=0.1, evidence=evidence)

        if collector is not None:
            collector.record_feedback(event)
        # If collector is None (deaf phase), we just skip — nothing propagates

    elapsed = (time.monotonic() - start) * 1000
    weights = _snapshot_weights(tuner)
    metrics = hyp.get_metrics()

    return PhaseMetrics(
        bypass_weight=weights.get("bypass_score", 0.0),
        execute_weight=weights.get("execute_score", 0.0),
        hypothesis_signals=metrics.get("signals_received", 0) - initial_signals,
        hypothesis_penalties=metrics.get("penalties_applied", 0) - initial_penalties,
        observations=tuner._total_observations - initial_obs,
        arbiter_bypass=arbiter._w_bypass,
        arbiter_execute=arbiter._w_execute,
        elapsed_ms=elapsed,
    )


# ── Main ─────────────────────────────────────────────────────────────

def main() -> int:
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║   PROBE 14: Delayed Subsystem Activation — Causal Test      ║")
    print("╚═══════════════════════════════════════════════════════════════╝")

    N_CYCLES = 50
    findings: list[str] = []

    # ── Setup ────────────────────────────────────────────────────
    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    hyp = HypothesisEngine()

    # WeightTuner pushes learned weights → arbiter via bind_arbiter
    tuner.bind_arbiter(arbiter)

    collector = SynthesisFeedbackCollector()
    collector.bind_weight_tuner(tuner)
    collector.bind_hypothesis_engine(hyp)

    initial_weights = _snapshot_weights(tuner)
    print(f"\n  Initial weights: bypass={initial_weights.get('bypass_score', 0):.4f}, "
          f"execute={initial_weights.get('execute_score', 0):.4f}")
    print(f"  Initial arbiter: bypass={arbiter._w_bypass:.4f}, execute={arbiter._w_execute:.4f}")

    # ══════════════════════════════════════════════════════════════
    # PHASE A — "DEAF" (feedback disabled, 50 cycles)
    # ══════════════════════════════════════════════════════════════
    print(f"\n{'='*72}")
    print(f"  PHASE A: Deaf — {N_CYCLES} cycles, feedback DISABLED")
    print(f"{'='*72}\n")

    # Run events WITHOUT the collector (no propagation)
    phase_a = _run_phase(
        collector=None,  # DISABLED
        tuner=tuner,
        arbiter=arbiter,
        hyp=hyp,
        n_cycles=N_CYCLES,
        label="deaf",
    )

    print(f"  Observations:      {phase_a.observations}")
    print(f"  Hypothesis signals: +{phase_a.hypothesis_signals}")
    print(f"  Hypothesis penalties: +{phase_a.hypothesis_penalties}")
    print(f"  Bypass weight:     {phase_a.bypass_weight:.4f}")
    print(f"  Execute weight:    {phase_a.execute_weight:.4f}")
    print(f"  Arbiter bypass:    {phase_a.arbiter_bypass:.4f}")
    print(f"  Arbiter execute:   {phase_a.arbiter_execute:.4f}")
    print(f"  Elapsed:           {phase_a.elapsed_ms:.1f}ms")

    # ══════════════════════════════════════════════════════════════
    # PHASE B — "ALIVE" (feedback enabled, 50 cycles)
    # ══════════════════════════════════════════════════════════════
    print(f"\n{'='*72}")
    print(f"  PHASE B: Alive — {N_CYCLES} cycles, feedback ENABLED")
    print(f"{'='*72}\n")

    phase_b = _run_phase(
        collector=collector,  # ENABLED
        tuner=tuner,
        arbiter=arbiter,
        hyp=hyp,
        n_cycles=N_CYCLES,
        label="alive",
    )

    print(f"  Observations:      {phase_b.observations}")
    print(f"  Hypothesis signals: +{phase_b.hypothesis_signals}")
    print(f"  Hypothesis penalties: +{phase_b.hypothesis_penalties}")
    print(f"  Bypass weight:     {phase_b.bypass_weight:.4f}")
    print(f"  Execute weight:    {phase_b.execute_weight:.4f}")
    print(f"  Arbiter bypass:    {phase_b.arbiter_bypass:.4f}")
    print(f"  Arbiter execute:   {phase_b.arbiter_execute:.4f}")
    print(f"  Elapsed:           {phase_b.elapsed_ms:.1f}ms")

    # ══════════════════════════════════════════════════════════════
    # ASSERTIONS
    # ══════════════════════════════════════════════════════════════
    print(f"\n{'='*72}")
    print(f"  ASSERTIONS")
    print(f"{'='*72}\n")

    checks: list[tuple[str, bool]] = []

    # A1: Phase A had ZERO observations (feedback disabled)
    a1 = phase_a.observations == 0
    checks.append(("Phase A: zero observations", a1))
    if not a1:
        findings.append(f"Phase A had {phase_a.observations} observations (expected 0)")
    print(f"  A1 Zero observations in deaf phase: {'✓' if a1 else '✗'} ({phase_a.observations})")

    # A2: Phase A hypothesis engine untouched
    a2 = phase_a.hypothesis_signals == 0 and phase_a.hypothesis_penalties == 0
    checks.append(("Phase A: hypothesis silent", a2))
    if not a2:
        findings.append(f"Phase A hypothesis: signals={phase_a.hypothesis_signals}, penalties={phase_a.hypothesis_penalties}")
    print(f"  A2 Hypothesis silent in deaf phase: {'✓' if a2 else '✗'} "
          f"(signals={phase_a.hypothesis_signals}, penalties={phase_a.hypothesis_penalties})")

    # A3: Phase A weights unchanged
    a3_bypass = abs(phase_a.bypass_weight - initial_weights.get("bypass_score", 0)) < 0.001
    a3_execute = abs(phase_a.execute_weight - initial_weights.get("execute_score", 0)) < 0.001
    a3 = a3_bypass and a3_execute
    checks.append(("Phase A: weights static", a3))
    if not a3:
        findings.append(f"Phase A weights moved: bypass Δ={phase_a.bypass_weight - initial_weights.get('bypass_score', 0):.4f}")
    print(f"  A3 Weights static in deaf phase: {'✓' if a3 else '✗'}")

    # B1: Phase B had observations
    b1 = phase_b.observations >= N_CYCLES * 0.9  # Allow some margin
    checks.append(("Phase B: observations recorded", b1))
    if not b1:
        findings.append(f"Phase B only {phase_b.observations} observations (expected ~{N_CYCLES})")
    print(f"  B1 Observations in alive phase: {'✓' if b1 else '✗'} ({phase_b.observations})")

    # B2: Phase B hypothesis engine activated
    b2 = phase_b.hypothesis_signals > 0 or phase_b.hypothesis_penalties > 0
    checks.append(("Phase B: hypothesis activated", b2))
    if not b2:
        findings.append("Phase B hypothesis engine still silent")
    print(f"  B2 Hypothesis active in alive phase: {'✓' if b2 else '✗'} "
          f"(signals={phase_b.hypothesis_signals}, penalties={phase_b.hypothesis_penalties})")

    # B3: Phase B weights MOVED toward signal
    bypass_delta = phase_b.bypass_weight - initial_weights.get("bypass_score", 0)
    execute_delta = phase_b.execute_weight - initial_weights.get("execute_score", 0)
    b3_bypass = bypass_delta > 0.01  # bypass should increase (signal = 0.9)
    b3_execute = execute_delta < -0.01  # execute should decrease (signal = 0.1)
    b3 = b3_bypass and b3_execute
    checks.append(("Phase B: weights moved correctly", b3))
    if not b3:
        findings.append(f"Phase B weight movement: bypass Δ={bypass_delta:+.4f}, execute Δ={execute_delta:+.4f}")
    print(f"  B3 Weights moved toward signal: {'✓' if b3 else '✗'} "
          f"(bypass Δ={bypass_delta:+.4f}, execute Δ={execute_delta:+.4f})")

    # B4: Arbiter weights also moved (hot-update working)
    arbiter_bypass_delta = phase_b.arbiter_bypass - initial_weights.get("bypass_score", 0.3)
    arbiter_execute_delta = phase_b.arbiter_execute - initial_weights.get("execute_score", 0.25)
    b4 = abs(arbiter_bypass_delta) > 0.005 or abs(arbiter_execute_delta) > 0.005
    checks.append(("Phase B: arbiter weights updated", b4))
    if not b4:
        findings.append(f"Arbiter didn't update: bypass Δ={arbiter_bypass_delta:+.4f}, execute Δ={arbiter_execute_delta:+.4f}")
    print(f"  B4 Arbiter hot-updated: {'✓' if b4 else '✗'} "
          f"(bypass Δ={arbiter_bypass_delta:+.4f}, execute Δ={arbiter_execute_delta:+.4f})")

    # B5: CAUSAL JUMP — Phase B metrics must be strictly greater than Phase A
    causal_obs = phase_b.observations > phase_a.observations
    causal_hyp = (phase_b.hypothesis_signals + phase_b.hypothesis_penalties) > (
        phase_a.hypothesis_signals + phase_a.hypothesis_penalties
    )
    causal_weight = abs(bypass_delta) > abs(
        phase_a.bypass_weight - initial_weights.get("bypass_score", 0)
    )
    b5 = causal_obs and causal_hyp and causal_weight
    checks.append(("Phase B: causal jump detected", b5))
    if not b5:
        findings.append("No causal jump between deaf and alive phases")
    print(f"  B5 Causal jump: {'✓' if b5 else '✗'} "
          f"(obs: {phase_a.observations}→{phase_b.observations}, "
          f"hyp: {phase_a.hypothesis_signals + phase_a.hypothesis_penalties}"
          f"→{phase_b.hypothesis_signals + phase_b.hypothesis_penalties})")

    # ═══════════════════════════════════════════════════════════════
    # DELTA SUMMARY TABLE
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'='*72}")
    print(f"  DELTA SUMMARY")
    print(f"{'='*72}\n")
    print(f"  {'Metric':<25} {'Phase A (deaf)':>15} {'Phase B (alive)':>15} {'Δ':>10}")
    print(f"  {'─'*25} {'─'*15} {'─'*15} {'─'*10}")
    print(f"  {'Observations':<25} {phase_a.observations:>15} {phase_b.observations:>15} {phase_b.observations - phase_a.observations:>+10}")
    print(f"  {'Hypothesis signals':<25} {phase_a.hypothesis_signals:>15} {phase_b.hypothesis_signals:>15} {phase_b.hypothesis_signals - phase_a.hypothesis_signals:>+10}")
    print(f"  {'Hypothesis penalties':<25} {phase_a.hypothesis_penalties:>15} {phase_b.hypothesis_penalties:>15} {phase_b.hypothesis_penalties - phase_a.hypothesis_penalties:>+10}")
    print(f"  {'Bypass weight':<25} {phase_a.bypass_weight:>15.4f} {phase_b.bypass_weight:>15.4f} {phase_b.bypass_weight - phase_a.bypass_weight:>+10.4f}")
    print(f"  {'Execute weight':<25} {phase_a.execute_weight:>15.4f} {phase_b.execute_weight:>15.4f} {phase_b.execute_weight - phase_a.execute_weight:>+10.4f}")
    print(f"  {'Arbiter bypass':<25} {phase_a.arbiter_bypass:>15.4f} {phase_b.arbiter_bypass:>15.4f} {phase_b.arbiter_bypass - phase_a.arbiter_bypass:>+10.4f}")
    print(f"  {'Arbiter execute':<25} {phase_a.arbiter_execute:>15.4f} {phase_b.arbiter_execute:>15.4f} {phase_b.arbiter_execute - phase_a.arbiter_execute:>+10.4f}")

    # ═══════════════════════════════════════════════════════════════
    # VERDICT
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'='*72}")
    print(f"  VERDICT")
    print(f"{'='*72}\n")

    passed_count = sum(1 for _, p in checks if p)
    total_count = len(checks)
    all_pass = passed_count == total_count

    for label, ok in checks:
        icon = "✓" if ok else "✗"
        print(f"  {icon} {label}")

    if all_pass:
        print(f"\n  🟢 PASS: Feedback loop CAUSALLY INFLUENCES outcomes")
        print(f"           Deaf phase: static. Alive phase: learning.")
        print(f"           {phase_b.observations} observations, "
              f"{phase_b.hypothesis_signals} signals, "
              f"bypass Δ={bypass_delta:+.4f}")
    else:
        print(f"\n  🔴 FAIL: {total_count - passed_count} checks failed")
        for f in findings:
            print(f"         └─ {f}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
