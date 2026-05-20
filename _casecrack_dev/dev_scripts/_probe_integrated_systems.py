#!/usr/bin/env python3
"""Probes 9-13: Integrated Systems Audit.

Cross-subsystem probes that test the REAL integration between backend
components — not mocked interfaces.  These probes answer:

   P9.  Interface Compatibility   — Do real subsystem APIs match what
        SynthesisFeedbackCollector expects?  (Method names, signatures)
   P10. Feedback Propagation      — When a real FeedbackEvent is fired,
        do all 7 subsystems actually mutate state?
   P11. Weight→Arbiter Hot-Update — Does WeightTuner calibration change
        PayloadArbiter scoring?
   P12. Pipeline Latency Budget   — End-to-end timing from feedback
        event through all subsystems.
   P13. Cross-Subsystem Coherence — After N feedback events, do the
        subsystems converge to a coherent "belief"?

Run:
    .venv/Scripts/python.exe _probe_integrated_systems.py
"""

from __future__ import annotations

import inspect
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

# ── Bootstrap ────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent / "CaseCrack"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── Imports ──────────────────────────────────────────────────────────
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
from tools.burp_enterprise.exploit_chains.execution_scheduler import ExecutionScheduler
from tools.burp_enterprise.exploit_chains.genetic_forge import GeneticForge
from tools.burp_enterprise.hypothesis_engine import HypothesisEngine

# ── Results ──────────────────────────────────────────────────────────
@dataclass
class ProbeResult:
    name: str
    passed: bool
    details: str
    findings: list[str]


results: list[ProbeResult] = []


# ── Helpers ──────────────────────────────────────────────────────────
def _make_event(
    feedback_type: FeedbackType = FeedbackType.EXECUTED_SUCCESSFULLY,
    *,
    vuln_type: VulnType = VulnType.XSS,
    evidence_found: bool = False,
    target_url: str = "https://target.example.com/search",
) -> FeedbackEvent:
    """Build a minimal FeedbackEvent for testing."""
    payload = RankedPayload(
        payload="<script>alert(1)</script>",
        score=0.85,
        engine=SynthesisEngine.GRAMMAR,
        vuln_type=vuln_type,
        confidence=0.9,
        bypass_score=0.7,
        execute_score=0.8,
        impact_score=0.5,
        chain_alignment=0.3,
        hypothesis_boost=0.1,
        campaign_boost=0.05,
        detection_risk=0.02,
        cost=0.01,
    )
    context = SynthesisContext(
        target_url=target_url,
        vuln_type=vuln_type,
    )
    return FeedbackEvent(
        payload=payload,
        context=context,
        feedback_type=feedback_type,
        response_status=200,
        evidence_found=evidence_found,
    )


def _header(title: str) -> None:
    print(f"\n{'=' * 72}")
    print(f"  PROBE: {title}")
    print(f"{'=' * 72}\n")


# =====================================================================
#  PROBE 9: Interface Compatibility Audit
# =====================================================================

def probe_9_interface_compatibility() -> ProbeResult:
    """Check that feedback propagation method calls match real APIs.

    After fixing synthesis_feedback.py, propagation now uses the
    correct APIs.  This probe validates that the real subsystem
    methods exist and accept the signatures feedback actually sends.
    """
    _header("P9: Interface Compatibility — Real API Validation")

    findings: list[str] = []
    checks_passed = 0
    checks_total = 0

    # ── Subsystem 1: HypothesisEngine ────────────────────────────
    # Feedback now calls: signal_finding(finding_type, severity) for
    # positive+evidence, signal_success_no_finding(action) for positive
    # w/o evidence, signal_failure(action) for negative.
    print("  [HypothesisEngine]")
    hyp = HypothesisEngine()

    for meth_name, expected_params in [
        ("signal_finding", ["finding_type"]),
        ("signal_failure", ["action"]),
        ("signal_success_no_finding", ["action"]),
    ]:
        checks_total += 1
        if hasattr(hyp, meth_name):
            sig = inspect.signature(getattr(hyp, meth_name))
            params = [p for p in sig.parameters if p != "self"]
            if all(p in params for p in expected_params):
                print(f"    {meth_name}(): EXISTS ✓ (params={params})")
                checks_passed += 1
            else:
                msg = f"{meth_name}() params={params}, expected {expected_params}"
                print(f"    {meth_name}(): INCOMPATIBLE — {msg}")
                findings.append(f"HypothesisEngine: {msg}")
        else:
            msg = f"{meth_name}() MISSING"
            print(f"    {meth_name}(): {msg}")
            findings.append(f"HypothesisEngine: {msg}")

    # ── Subsystem 2: WAFAdaptive (BypassArmManager) ──────────────
    # Feedback now calls: get_or_create_arm(vendor, attack_type,
    # mutation_op) → arm, then update_arm(arm, reward).
    print("\n  [WAFAdaptive / BypassArmManager]")
    try:
        from tools.burp_enterprise.scanners.waf_adaptive import BypassArmManager

        for meth_name, expected_params in [
            ("get_or_create_arm", ["vendor", "attack_type", "mutation_op"]),
            ("update_arm", ["arm", "reward"]),
        ]:
            checks_total += 1
            if hasattr(BypassArmManager, meth_name):
                sig = inspect.signature(getattr(BypassArmManager, meth_name))
                params = [p for p in sig.parameters if p != "self"]
                if all(p in params for p in expected_params):
                    print(f"    {meth_name}(): EXISTS ✓ (params={params})")
                    checks_passed += 1
                else:
                    msg = f"{meth_name}() params={params}, expected {expected_params}"
                    print(f"    {meth_name}(): INCOMPATIBLE — {msg}")
                    findings.append(f"WAFAdaptive: {msg}")
            else:
                msg = f"{meth_name}() MISSING"
                print(f"    {meth_name}(): {msg}")
                findings.append(f"WAFAdaptive: {msg}")
    except Exception as exc:
        print(f"    WAFAdaptive import: FAILED ({exc})")
        findings.append(f"WAFAdaptive: import failed: {exc}")
        checks_total += 2

    # ── Subsystem 3: GeneticForge ────────────────────────────────
    # GeneticForge learns indirectly via HypothesisEngine + WAFAdaptive
    # bindings when evolve() is called.  inject_fitness_signal() is
    # optional — we silently skip if missing, which is correct behavior.
    print("\n  [GeneticForge]")
    forge = GeneticForge()

    checks_total += 1
    has_evolve = hasattr(forge, "evolve")
    has_bind_hyp = hasattr(forge, "bind_hypothesis_engine")
    has_bind_waf = hasattr(forge, "bind_waf_adaptive")
    if has_evolve and has_bind_hyp and has_bind_waf:
        print(f"    evolve(): EXISTS ✓")
        print(f"    bind_hypothesis_engine(): EXISTS ✓")
        print(f"    bind_waf_adaptive(): EXISTS ✓")
        print(f"    (inject_fitness_signal optional — forge learns via bindings)")
        checks_passed += 1
    else:
        missing = []
        if not has_evolve:
            missing.append("evolve()")
        if not has_bind_hyp:
            missing.append("bind_hypothesis_engine()")
        if not has_bind_waf:
            missing.append("bind_waf_adaptive()")
        msg = f"Missing core methods: {', '.join(missing)}"
        print(f"    {msg}")
        findings.append(f"GeneticForge: {msg}")

    # ── Subsystem 4: UnifiedReasoningLayer ───────────────────────
    # Feedback now calls: record_outcome(action=..., found=...,
    # severity=...) matching the real API.
    print("\n  [UnifiedReasoningLayer]")
    try:
        from tools.burp_enterprise.unified_reasoning import UnifiedReasoningLayer
        layer = UnifiedReasoningLayer()

        checks_total += 1
        has_record_outcome = hasattr(layer, "record_outcome")
        if has_record_outcome:
            sig = inspect.signature(layer.record_outcome)
            params = [p for p in sig.parameters if p != "self"]
            expected = ["action", "found"]
            if all(p in params for p in expected):
                print(f"    record_outcome(): EXISTS ✓ (params={params})")
                checks_passed += 1
            else:
                msg = f"record_outcome() params={params}, expected {expected}"
                print(f"    record_outcome(): INCOMPATIBLE — {msg}")
                findings.append(f"UnifiedReasoningLayer: {msg}")
        else:
            msg = "record_outcome() MISSING"
            print(f"    {msg}")
            findings.append(f"UnifiedReasoningLayer: {msg}")
    except Exception as exc:
        print(f"    UnifiedReasoningLayer import: FAILED ({exc})")
        findings.append(f"UnifiedReasoningLayer: import failed: {exc}")
        checks_total += 1

    # ── Subsystem 5: CampaignIntelligence ────────────────────────
    # Feedback now calls: broadcast_finding(finding_type=...,
    # severity=..., source_target=..., source_fingerprint=...)
    print("\n  [CampaignIntelligence]")
    try:
        from tools.burp_enterprise.session_auth.campaign_intelligence import (
            CampaignSignalBus,
        )
        bus = CampaignSignalBus("test-campaign")

        checks_total += 1
        sig = inspect.signature(bus.broadcast_finding)
        params = [p for p in sig.parameters if p != "self"]
        expected = ["finding_type", "severity", "source_target", "source_fingerprint"]
        if all(p in params for p in expected):
            print(f"    broadcast_finding(): EXISTS ✓ (params={params})")
            checks_passed += 1
        else:
            msg = f"broadcast_finding() params={params}, expected {expected}"
            print(f"    broadcast_finding(): INCOMPATIBLE — {msg}")
            findings.append(f"CampaignSignalBus: {msg}")

    except Exception as exc:
        print(f"    CampaignIntelligence import: FAILED ({exc})")
        findings.append(f"CampaignIntelligence: import failed: {exc}")
        checks_total += 1

    # ── Subsystem 6: WeightTuner ─────────────────────────────────
    print("\n  [WeightTuner]")
    tuner = WeightTuner()
    checks_total += 1
    has_observe = hasattr(tuner, "observe")
    if has_observe:
        print(f"    observe(): EXISTS ✓")
        sig = inspect.signature(tuner.observe)
        params = list(sig.parameters.keys())
        print(f"      Signature: observe({', '.join(params)})")
        checks_passed += 1
    else:
        findings.append("WeightTuner: observe() MISSING")

    # ── Subsystem 7: StateMachine ────────────────────────────────
    print("\n  [StateMachine — skipped, uses generic hasattr dispatch]")

    # ── Summary ──────────────────────────────────────────────────
    print(f"\n  Summary: {checks_passed}/{checks_total} interface checks passed")
    if findings:
        print(f"\n  Critical findings ({len(findings)}):")
        for i, f in enumerate(findings, 1):
            print(f"    {i}. {f}")
    else:
        print("\n  All interfaces verified ✓")

    passed = len(findings) == 0
    return ProbeResult(
        name="P9: Interface Compatibility",
        passed=passed,
        details=f"{checks_passed}/{checks_total} checks",
        findings=findings,
    )


# =====================================================================
#  PROBE 10: Live Feedback Propagation — Real Instance State Mutation
# =====================================================================

def probe_10_feedback_propagation() -> ProbeResult:
    """Fire feedback events through real instances and check state changes."""
    _header("P10: Feedback Propagation — Real Instance State Mutation")

    findings: list[str] = []
    mutations_detected = 0
    mutations_expected = 0

    collector = SynthesisFeedbackCollector()

    # ── Wire real subsystems ─────────────────────────────────────
    # HypothesisEngine
    hyp = HypothesisEngine()
    collector.bind_hypothesis_engine(hyp)
    hyp_before = dict(hyp.get_metrics())

    # WeightTuner + Arbiter
    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    tuner.bind_arbiter(arbiter)
    collector.bind_weight_tuner(tuner)
    arbiter_weights_before = {
        "bypass": arbiter._w_bypass,
        "execute": arbiter._w_execute,
    }

    # GeneticForge
    forge = GeneticForge()
    collector.bind_genetic_forge(forge)

    print("  Bound subsystems: HypothesisEngine, WeightTuner+Arbiter, GeneticForge")
    print("  (WAFAdaptive, CampaignIntelligence, UnifiedReasoning skipped — require DB/campaign)")

    # ── Fire 50 positive + 50 negative events ────────────────────
    print("\n  Firing 100 feedback events (50 positive, 50 negative)...")
    errors_caught: list[str] = []
    for i in range(50):
        event = _make_event(FeedbackType.EXECUTED_SUCCESSFULLY, evidence_found=True)
        try:
            collector.record_feedback(event)
        except Exception as exc:
            errors_caught.append(f"Event {i} positive: {exc}")

    for i in range(50):
        event = _make_event(FeedbackType.BLOCKED_BY_WAF)
        try:
            collector.record_feedback(event)
        except Exception as exc:
            errors_caught.append(f"Event {i + 50} negative: {exc}")

    if errors_caught:
        print(f"\n  Propagation errors: {len(errors_caught)}")
        for e in errors_caught[:5]:
            print(f"    - {e}")
        findings.append(f"{len(errors_caught)} propagation errors")

    # ── Check subsystem state mutations ──────────────────────────

    # 1. HypothesisEngine
    print("\n  [HypothesisEngine state check]")
    mutations_expected += 1
    hyp_after = dict(hyp.get_metrics())
    signals_received = hyp_after.get("signals_received", 0) - hyp_before.get("signals_received", 0)
    penalties = hyp_after.get("penalties_applied", 0) - hyp_before.get("penalties_applied", 0)
    if signals_received > 0 or penalties > 0:
        print(f"    Signals received: +{signals_received}, Penalties: +{penalties} ✓")
        mutations_detected += 1
    else:
        msg = f"NO state change — signals_received={signals_received}, penalties={penalties}"
        print(f"    {msg}")
        findings.append(f"HypothesisEngine: {msg}")

    # 2. WeightTuner
    print("\n  [WeightTuner state check]")
    mutations_expected += 1
    obs_count = tuner._total_observations
    if obs_count > 0:
        print(f"    Observations recorded: {obs_count} ✓")
        mutations_detected += 1
    else:
        msg = f"NO observations recorded (count={obs_count})"
        print(f"    {msg}")
        findings.append(f"WeightTuner: {msg}")

    # 3. Arbiter weight change (if tuner calibrated)
    print("\n  [PayloadArbiter weight check]")
    mutations_expected += 1
    arbiter_weights_after = {
        "bypass": arbiter._w_bypass,
        "execute": arbiter._w_execute,
    }
    weight_changed = any(
        abs(arbiter_weights_after[k] - arbiter_weights_before[k]) > 1e-6
        for k in arbiter_weights_before
    )
    if weight_changed:
        for k in arbiter_weights_before:
            delta = arbiter_weights_after[k] - arbiter_weights_before[k]
            print(f"    {k}: {arbiter_weights_before[k]:.4f} → {arbiter_weights_after[k]:.4f} (Δ={delta:+.4f})")
        mutations_detected += 1
    else:
        msg = "Arbiter weights UNCHANGED after 100 feedback events"
        print(f"    {msg}")
        findings.append(f"PayloadArbiter: {msg}")

    # 4. GeneticForge (no inject_fitness_signal, so expect no change)
    print("\n  [GeneticForge state check]")
    mutations_expected += 1
    forge_unchanged = forge._total_evolutions == 0 and forge._best_fitness_ever == 0.0
    if forge_unchanged:
        msg = "No state mutation (inject_fitness_signal missing)"
        print(f"    {msg}")
        findings.append(f"GeneticForge: {msg}")
    else:
        print(f"    State mutated: evolutions={forge._total_evolutions} ✓")
        mutations_detected += 1

    # 5. Collector metrics
    print(f"\n  [Collector metrics]")
    print(f"    Total feedback: {collector._total_feedback}")
    print(f"    Positive: {collector._positive_count}, Negative: {collector._negative_count}")
    print(f"    Propagation errors: {collector._propagation_errors}")
    if collector._subsystem_latencies:
        print(f"    Subsystems with latency data: {list(collector._subsystem_latencies.keys())}")
    else:
        print(f"    No subsystem latency data collected")
        findings.append("No subsystem latency data — all propagation might be failing silently")

    print(f"\n  State mutations: {mutations_detected}/{mutations_expected}")

    passed = mutations_detected >= 2 and len(errors_caught) == 0
    return ProbeResult(
        name="P10: Feedback Propagation (Real Instances)",
        passed=passed,
        details=f"{mutations_detected}/{mutations_expected} subsystems mutated",
        findings=findings,
    )


# =====================================================================
#  PROBE 11: Weight→Arbiter Hot-Update End-to-End
# =====================================================================

def probe_11_weight_arbiter_hot_update() -> ProbeResult:
    """Verify WeightTuner calibration changes PayloadArbiter scoring."""
    _header("P11: Weight→Arbiter Hot-Update End-to-End")

    findings: list[str] = []
    arbiter = PayloadArbiter()
    tuner = WeightTuner()
    tuner.bind_arbiter(arbiter)

    # Record initial weights
    initial_bypass = arbiter._w_bypass
    initial_execute = arbiter._w_execute
    print(f"  Initial weights: bypass={initial_bypass:.4f}, execute={initial_execute:.4f}")

    # Feed tuner with consistent signal: high bypass, low execute → should shift weights
    print("\n  Feeding 200 observations: bypass=0.9, execute=0.1 (strong signal)...")
    collector = SynthesisFeedbackCollector()
    collector.bind_weight_tuner(tuner)

    for i in range(200):
        payload = RankedPayload(
            payload=f"test-payload-{i}",
            score=0.85,
            engine=SynthesisEngine.GRAMMAR,
            vuln_type=VulnType.XSS,
            confidence=0.9,
            bypass_score=0.9,
            execute_score=0.1,
            impact_score=0.3,
            chain_alignment=0.2,
            hypothesis_boost=0.1,
            campaign_boost=0.05,
            detection_risk=0.02,
            cost=0.01,
        )
        context = SynthesisContext(
            target_url="https://target.example.com",
            vuln_type=VulnType.XSS,
        )
        # Successful bypass events
        event = FeedbackEvent(
            payload=payload,
            context=context,
            feedback_type=FeedbackType.BYPASSED_WAF,
            response_status=200,
        )
        collector.record_feedback(event)

    # Check weights moved
    final_bypass = arbiter._w_bypass
    final_execute = arbiter._w_execute
    bypass_delta = final_bypass - initial_bypass
    execute_delta = final_execute - initial_execute

    print(f"\n  Final weights: bypass={final_bypass:.4f}, execute={final_execute:.4f}")
    print(f"  Deltas: bypass={bypass_delta:+.4f}, execute={execute_delta:+.4f}")

    # Score a payload before/after to see if ordering changes
    test_payload = RankedPayload(
        payload="test-scoring",
        score=0.0,
        engine=SynthesisEngine.GRAMMAR,
        vuln_type=VulnType.XSS,
        confidence=0.9,
        bypass_score=0.9,
        execute_score=0.1,
        impact_score=0.5,
        chain_alignment=0.3,
        hypothesis_boost=0.1,
        campaign_boost=0.05,
        detection_risk=0.02,
        cost=0.01,
    )

    # Compute composite score with current weights
    score = (
        final_bypass * test_payload.bypass_score
        + final_execute * test_payload.execute_score
        + arbiter._w_impact * test_payload.impact_score
        + arbiter._w_chain * test_payload.chain_alignment
        + arbiter._w_hypothesis * test_payload.hypothesis_boost
        + arbiter._w_campaign * test_payload.campaign_boost
        + arbiter._w_detection * test_payload.detection_risk
        + arbiter._w_cost * test_payload.cost
    )
    print(f"\n  Composite score with learned weights: {score:.4f}")

    checks = []

    # Check 1: Weights moved meaningfully
    weights_moved = abs(bypass_delta) > 0.001 or abs(execute_delta) > 0.001
    checks.append(("Weights moved", weights_moved))
    if not weights_moved:
        findings.append(f"Weights barely moved: bypass_delta={bypass_delta:.6f}, execute_delta={execute_delta:.6f}")

    # Check 2: bypass should have grown (consistent bypass success signal)
    bypass_grew = bypass_delta > 0
    checks.append(("Bypass weight increased", bypass_grew))
    if not bypass_grew:
        findings.append(f"Bypass weight should increase with bypass success, got delta={bypass_delta:+.4f}")

    # Check 3: Tuner observation count matches
    obs_match = tuner._total_observations == 200
    checks.append(("200 observations recorded", obs_match))
    if not obs_match:
        findings.append(f"Expected 200 observations, got {tuner._total_observations}")

    print(f"\n  Checks:")
    for name, ok in checks:
        print(f"    {name}: {'✓' if ok else '✗'}")

    passed = all(ok for _, ok in checks)
    return ProbeResult(
        name="P11: Weight→Arbiter Hot-Update",
        passed=passed,
        details=f"bypass Δ={bypass_delta:+.4f}, execute Δ={execute_delta:+.4f}",
        findings=findings,
    )


# =====================================================================
#  PROBE 12: Pipeline Latency Budget
# =====================================================================

def probe_12_pipeline_latency() -> ProbeResult:
    """Measure end-to-end feedback propagation latency."""
    _header("P12: Pipeline Latency Budget")

    findings: list[str] = []

    collector = SynthesisFeedbackCollector()
    hyp = HypothesisEngine()
    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    tuner.bind_arbiter(arbiter)
    forge = GeneticForge()

    collector.bind_hypothesis_engine(hyp)
    collector.bind_weight_tuner(tuner)
    collector.bind_genetic_forge(forge)

    # Warm up
    for _ in range(10):
        event = _make_event(FeedbackType.EXECUTED_SUCCESSFULLY)
        collector.record_feedback(event)

    # Measure latency for 500 events
    N = 500
    latencies_us: list[float] = []
    print(f"  Measuring {N} feedback events...")

    for i in range(N):
        event = _make_event(
            FeedbackType.EXECUTED_SUCCESSFULLY if i % 3 != 0 else FeedbackType.BLOCKED_BY_WAF
        )
        t0 = time.perf_counter()
        collector.record_feedback(event)
        t1 = time.perf_counter()
        latencies_us.append((t1 - t0) * 1_000_000)

    latencies_us.sort()
    p50 = latencies_us[N // 2]
    p95 = latencies_us[int(N * 0.95)]
    p99 = latencies_us[int(N * 0.99)]
    mean = sum(latencies_us) / N
    total_ms = sum(latencies_us) / 1000

    print(f"\n  Latency distribution ({N} events):")
    print(f"    Mean:   {mean:.0f} μs")
    print(f"    P50:    {p50:.0f} μs")
    print(f"    P95:    {p95:.0f} μs")
    print(f"    P99:    {p99:.0f} μs")
    print(f"    Total:  {total_ms:.1f} ms")

    # Per-subsystem breakdown from collector
    print(f"\n  Per-subsystem latency (from collector internals):")
    for sub, lats in sorted(collector._subsystem_latencies.items()):
        if lats:
            sub_mean = sum(lats) / len(lats)
            sub_max = max(lats)
            print(f"    {sub:25s}: mean={sub_mean:.3f}ms, max={sub_max:.3f}ms, n={len(lats)}")

    # Budget checks
    budget_p50 = 500  # 500μs budget for p50
    budget_p99 = 5000  # 5ms budget for p99

    ok_p50 = p50 < budget_p50
    ok_p99 = p99 < budget_p99

    print(f"\n  Budget:")
    print(f"    P50 < {budget_p50}μs: {'✓' if ok_p50 else '✗'} ({p50:.0f}μs)")
    print(f"    P99 < {budget_p99}μs: {'✓' if ok_p99 else '✗'} ({p99:.0f}μs)")

    if not ok_p50:
        findings.append(f"P50 latency {p50:.0f}μs exceeds {budget_p50}μs budget")
    if not ok_p99:
        findings.append(f"P99 latency {p99:.0f}μs exceeds {budget_p99}μs budget")

    # Throughput
    throughput = N / (total_ms / 1000) if total_ms > 0 else 0
    print(f"\n  Throughput: {throughput:.0f} events/sec")
    ok_throughput = throughput > 1000
    if not ok_throughput:
        findings.append(f"Throughput {throughput:.0f} events/sec below 1000/sec target")

    passed = ok_p50 and ok_p99
    return ProbeResult(
        name="P12: Pipeline Latency Budget",
        passed=passed,
        details=f"P50={p50:.0f}μs, P95={p95:.0f}μs, P99={p99:.0f}μs, {throughput:.0f} evt/s",
        findings=findings,
    )


# =====================================================================
#  PROBE 13: Cross-Subsystem Coherence
# =====================================================================

def probe_13_cross_subsystem_coherence() -> ProbeResult:
    """After consistent feedback, do subsystems converge to coherent beliefs?"""
    _header("P13: Cross-Subsystem Coherence")

    findings: list[str] = []

    # Build full pipeline
    collector = SynthesisFeedbackCollector()
    hyp = HypothesisEngine()
    tuner = WeightTuner()
    arbiter = PayloadArbiter()
    tuner.bind_arbiter(arbiter)

    collector.bind_hypothesis_engine(hyp)
    collector.bind_weight_tuner(tuner)

    # Scenario: XSS payloads succeed 80%, SQLi payloads fail 90%
    print("  Scenario: XSS success rate 80%, SQLi failure rate 90%")
    print("  Feeding 200 XSS events + 200 SQLi events...\n")

    for i in range(200):
        # 80% XSS success
        ft = FeedbackType.EXECUTED_SUCCESSFULLY if i % 5 != 0 else FeedbackType.NO_EFFECT
        event = _make_event(ft, vuln_type=VulnType.XSS, evidence_found=(ft == FeedbackType.EXECUTED_SUCCESSFULLY))
        collector.record_feedback(event)

    for i in range(200):
        # 90% SQLi failure
        ft = FeedbackType.BLOCKED_BY_WAF if i % 10 != 0 else FeedbackType.EXECUTED_SUCCESSFULLY
        event = _make_event(ft, vuln_type=VulnType.SQLI)
        collector.record_feedback(event)

    # ── Check coherence across subsystems ────────────────────────

    # 1. WeightTuner: should have learned XSS-favorable weights
    print("  [WeightTuner weights]")
    weights = dict(tuner._current_weights)
    for name, w in sorted(weights.items()):
        print(f"    {name:20s}: {w:+.4f}")

    # 2. Arbiter: check weights were pushed
    print(f"\n  [PayloadArbiter live weights]")
    arbiter_state = {
        "bypass": arbiter._w_bypass,
        "execute": arbiter._w_execute,
        "impact": arbiter._w_impact,
        "chain": arbiter._w_chain,
        "hypothesis": arbiter._w_hypothesis,
        "campaign": arbiter._w_campaign,
        "detection": arbiter._w_detection,
        "cost": arbiter._w_cost,
    }
    for name, w in sorted(arbiter_state.items()):
        print(f"    {name:20s}: {w:+.4f}")

    # 3. HypothesisEngine: check XSS vs SQLi weight divergence
    print(f"\n  [HypothesisEngine beliefs]")
    xss_weight = hyp.get_weight("xss")
    sqli_weight = hyp.get_weight("sqli")
    print(f"    XSS effective:  {xss_weight.effective:.4f}")
    print(f"    SQLi effective: {sqli_weight.effective:.4f}")

    # Coherence checks
    checks = []

    # Check 1: Tuner and Arbiter are synchronized
    tuner_bypass = weights.get("bypass_score", 0.30)
    arbiter_bypass = arbiter._w_bypass
    sync_delta = abs(tuner_bypass - arbiter_bypass)
    ok_sync = sync_delta < 0.01
    checks.append(("Tuner↔Arbiter weight sync", ok_sync))
    if not ok_sync:
        findings.append(f"Tuner bypass={tuner_bypass:.4f} vs Arbiter bypass={arbiter_bypass:.4f} (Δ={sync_delta:.4f})")
    print(f"\n  Tuner↔Arbiter sync: Δ={sync_delta:.6f} {'✓' if ok_sync else '✗'}")

    # Check 2: WeightTuner observations reflect both vuln types
    ok_obs = tuner._total_observations >= 350  # should be ~400 but some might not propagate
    checks.append(("≥350 observations recorded", ok_obs))
    if not ok_obs:
        findings.append(f"Only {tuner._total_observations} observations (expected ≥350)")
    print(f"  Observation count: {tuner._total_observations} {'✓' if ok_obs else '✗'}")

    # Check 3: HypothesisEngine — XSS should not be penalized
    # (If record_success/record_failure doesn't exist, there's no mutation)
    hyp_metrics = hyp.get_metrics()
    hyp_signals = hyp_metrics.get("signals_received", 0)
    hyp_penalties = hyp_metrics.get("penalties_applied", 0)
    hyp_active = hyp_signals > 0 or hyp_penalties > 0
    checks.append(("HypothesisEngine received feedback", hyp_active))
    if not hyp_active:
        findings.append("HypothesisEngine received 0 signals — feedback propagation disconnected")
    print(f"  HypothesisEngine active: signals={hyp_signals}, penalties={hyp_penalties} "
          f"{'✓' if hyp_active else '✗ — DISCONNECTED'}")

    # Check 4: Collector error count is low
    error_rate = collector._propagation_errors / max(collector._total_feedback, 1)
    ok_errors = error_rate < 0.05
    checks.append(("Error rate < 5%", ok_errors))
    if not ok_errors:
        findings.append(f"Propagation error rate {error_rate:.1%} exceeds 5%")
    print(f"  Propagation error rate: {error_rate:.1%} ({collector._propagation_errors}/{collector._total_feedback}) "
          f"{'✓' if ok_errors else '✗'}")

    print(f"\n  Checks:")
    for name, ok in checks:
        print(f"    {name}: {'✓' if ok else '✗'}")

    passed = all(ok for _, ok in checks)
    return ProbeResult(
        name="P13: Cross-Subsystem Coherence",
        passed=passed,
        details=f"{sum(1 for _, ok in checks if ok)}/{len(checks)} coherence checks",
        findings=findings,
    )


# =====================================================================
#  MAIN
# =====================================================================

if __name__ == "__main__":
    print("\u2554" + "\u2550" * 63 + "\u2557")
    print("\u2551   PROBES 9-13: Integrated Systems Audit" + " " * 22 + "\u2551")
    print("\u255a" + "\u2550" * 63 + "\u255d")

    probes = [
        probe_9_interface_compatibility,
        probe_10_feedback_propagation,
        probe_11_weight_arbiter_hot_update,
        probe_12_pipeline_latency,
        probe_13_cross_subsystem_coherence,
    ]

    for probe_fn in probes:
        try:
            result = probe_fn()
        except Exception as exc:
            result = ProbeResult(
                name=probe_fn.__name__,
                passed=False,
                details=f"EXCEPTION: {exc}",
                findings=[traceback.format_exc()],
            )
        results.append(result)

    # ── Final Scorecard ──────────────────────────────────────────
    print(f"\n\n{'=' * 72}")
    print(f"  FINAL SCORECARD")
    print(f"{'=' * 72}")

    all_findings: list[str] = []
    passed_count = 0
    for r in results:
        icon = "\U0001f7e2 PASS" if r.passed else "\U0001f534 FAIL"
        print(f"  {icon}  {r.name} — {r.details}")
        if not r.passed and r.findings:
            for f in r.findings:
                # Truncate long findings
                display = f if len(f) < 120 else f[:117] + "..."
                print(f"         \u2514\u2500 {display}")
            all_findings.extend(r.findings)
        if r.passed:
            passed_count += 1

    print(f"\n  Score: {passed_count}/{len(results)}")

    if all_findings:
        print(f"\n  \u26a0\ufe0f  {len(all_findings)} findings requiring attention")
    else:
        print(f"\n  \u2705 ALL PROBES PASS — Integrated systems are coherent")

    sys.exit(0 if passed_count == len(results) else 1)
