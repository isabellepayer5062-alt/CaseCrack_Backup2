"""Run the full Manual Audit Engine against tension-inducing scenarios.

Target: sugarrushed.ca
Scenarios:
    B — Conflicting Signals (hypothesis vs WAF)
    C — Chain Dependency (auth_bypass → IDOR → data_access)
    D — Adversarial Noise (30% false positive signals)
    E — Long-Run Stability (100 cycles, mid-run shift)

Audits:
    1. Signal vs Outcome Truth Check (corr with reward)
    2. Ablation Re-test (remove one signal at a time)
    3. WeightTuner Behavior Check (drift from priors)
    4. Long-Run Drift Test (hypothesis domination over time)

Usage:
    python -m _run_manual_audit
"""

from __future__ import annotations

import json
import sys
import time

# Ensure the project root is importable
sys.path.insert(0, ".")
sys.path.insert(0, "CaseCrack")

from tools.burp_enterprise.exploit_chains.system_audit_harness import (
    ScenarioGenerator,
)
from tools.burp_enterprise.exploit_chains.manual_audit_engine import (
    ManualAuditor,
    ManualAuditReport,
)

TARGET = "https://sugarrushed.ca"


def _patch_target(scenario, target_url: str):
    """Override the scenario target_url to the real target."""
    scenario.context_overrides["target_url"] = target_url
    return scenario


def _print_walked(report: ManualAuditReport) -> None:
    """Print detailed walked-decision explanations."""
    print("\n  ── WALKED DECISIONS (detailed) ──")
    for i, w in enumerate(report.walked, 1):
        snap = w.snapshot
        print(f"\n  Decision #{i} — cycle {snap.cycle} "
              f"[{w.interest_type.value}] ({w.interest_reason})")
        print(f"    Payload:    {snap.chosen_payload[:70]}")
        print(f"    Score:      {snap.chosen_score:.4f}  "
              f"(engine={snap.chosen_engine}, conf={snap.chosen_confidence:.3f})")
        print(f"    Margin:     {snap.margin:.4f} "
              f"(over runner-up {snap.runner_up_score:.4f})")
        print(f"    Candidates: {snap.candidate_count}")

        if snap.signal_breakdown:
            print("    Signal breakdown:")
            for sig, val in sorted(snap.signal_breakdown.items(),
                                   key=lambda kv: abs(kv[1]), reverse=True):
                weight = snap.weight_snapshot.get(sig, 0.0)
                contrib = val * weight
                print(f"      {sig:22s} signal={val:+.4f}  "
                      f"weight={weight:.4f}  contrib={contrib:+.4f}")

        print(f"    Dominant:   {snap.dominant_signal} "
              f"(contribution={snap.dominant_contribution:.4f})")

        if snap.ground_truth_result:
            gt = snap.ground_truth_result
            verdict = "✓ OPTIMAL" if gt.optimal else "✗ SUBOPTIMAL"
            print(f"    Ground truth: {verdict}  reward={gt.reward:.3f}  "
                  f"detection_risk={gt.detection_risk:.3f}")
            print(f"    Regret:     {snap.regret:.4f}  rank={snap.rank_in_pool}")
        else:
            print(f"    Feedback:   type={snap.feedback_type}  "
                  f"status={snap.response_status}  "
                  f"evidence={snap.evidence_found}")
            print(f"    Reward:     {snap.reward:.3f}")


def _print_failures(report: ManualAuditReport) -> None:
    """Print failure classification detail."""
    print("\n  ── FAILURE CLASSIFICATION ──")
    for label in report.failure_labels:
        if label.failure_type.value == "no_failure":
            continue
        icon = {"scoring_error": "🔴", "selection_error": "🟡",
                "execution_error": "🔵", "learning_error": "🟣"}.get(
                    label.failure_type.value, "⚪")
        print(f"    {icon} cycle {label.cycle}: {label.failure_type.value}")
        if label.description:
            print(f"       {label.description}")


def _print_counterfactuals(report: ManualAuditReport) -> None:
    """Print counterfactual analysis."""
    if not report.counterfactuals:
        print("\n  ── COUNTERFACTUALS: none (all decisions optimal) ──")
        return
    print(f"\n  ── COUNTERFACTUALS ({len(report.counterfactuals)}) ──")
    for cf in report.counterfactuals:
        print(f"    cycle {cf.cycle}: actual_reward={cf.actual_reward:.3f} → "
              f"could_have={cf.counterfactual_reward:.3f} "
              f"(Δ={cf.reward_delta:+.3f})")
        if cf.explanation:
            print(f"       {cf.explanation}")
        print(f"       was_available_in_pool={cf.was_available}")


def _print_influences(report: ManualAuditReport) -> None:
    """Print influence trace summaries."""
    print("\n  ── INFLUENCE TRACES ──")
    for inf in report.influence_reports:
        print(f"    cycle {inf.cycle}:")
        if inf.signals_that_shouldnt_matter:
            for s in inf.signals_that_shouldnt_matter:
                print(f"      ⚠️  SHOULDN'T MATTER: {s}")
        if inf.signals_that_should_matter:
            for s in inf.signals_that_should_matter:
                print(f"      ❌  SHOULD MATTER: {s}")
        if inf.phantom_influences:
            for s in inf.phantom_influences:
                print(f"      👻  PHANTOM: {s}")
        if (not inf.signals_that_shouldnt_matter
                and not inf.signals_that_should_matter
                and not inf.phantom_influences):
            print("      ✅  No anomalies detected")


def _print_red_flags(report: ManualAuditReport) -> None:
    """Print red flags."""
    if not report.red_flags:
        print("\n  ── RED FLAGS: none ──")
        return
    print(f"\n  ── RED FLAGS ({len(report.red_flags)}) ──")
    icons = {
        "false_intelligence": "🚨",
        "right_outcome_wrong_reason": "⚠️",
        "broken_feedback_loop": "🔁",
        "overreaction": "⚡",
        "ignored_signal": "👻",
    }
    for rf in report.red_flags:
        icon = icons.get(rf.flag_type.value, "❓")
        sev = rf.severity.upper()
        print(f"    {icon} [{sev}] cycle {rf.cycle}: "
              f"{rf.flag_type.value}")
        print(f"       {rf.description}")


def run_scenario(name: str, scenario, auditor: ManualAuditor) -> ManualAuditReport:
    """Run one scenario and print the full report."""
    print(f"\n{'='*70}")
    print(f"  SCENARIO: {name}")
    print(f"  Target:   {scenario.context_overrides.get('target_url', 'N/A')}")
    print(f"  Type:     {scenario.scenario_type.value}")
    print(f"  Cycles:   {scenario.cycles}")
    print(f"{'='*70}")

    t0 = time.perf_counter()
    report = auditor.audit(scenario, walk_n=5)
    elapsed = time.perf_counter() - t0

    # Summary header
    for line in report.summary_lines():
        print(f"  {line}")

    # Detailed sections
    _print_walked(report)
    _print_failures(report)
    _print_counterfactuals(report)
    _print_influences(report)
    _print_red_flags(report)

    print(f"\n  ⏱  Completed in {elapsed:.2f}s")
    print(f"{'='*70}\n")

    return report


def main() -> None:
    auditor = ManualAuditor(seed=42)
    reports: list[ManualAuditReport] = []

    # B — Conflicting Signals
    scenario_b = _patch_target(
        ScenarioGenerator.conflicting_signals(seed=42), TARGET,
    )
    reports.append(run_scenario("B: Conflicting Signals", scenario_b, auditor))

    # C — Chain Dependency
    scenario_c = _patch_target(
        ScenarioGenerator.chain_dependency(seed=42), TARGET,
    )
    reports.append(run_scenario("C: Chain Dependency", scenario_c, auditor))

    # D — Adversarial Noise (20 cycles)
    scenario_d = _patch_target(
        ScenarioGenerator.adversarial_noise(cycles=20, seed=42), TARGET,
    )
    reports.append(run_scenario("D: Adversarial Noise", scenario_d, auditor))

    # E — Long-Run Stability (100 cycles with mid-run shift)
    scenario_e = _patch_target(
        ScenarioGenerator.long_run_stability(cycles=100, seed=42), TARGET,
    )
    reports.append(run_scenario("E: Long-Run Stability", scenario_e, auditor))

    # ── Ablation test on Scenario D (has ground truth) ──
    print("\n" + "=" * 70)
    print("  ABLATION TEST — Scenario D (remove one signal at a time)")
    print("=" * 70)
    t0 = time.perf_counter()
    ablation_report = auditor.audit_with_ablation(scenario_d, walk_n=3)
    elapsed = time.perf_counter() - t0
    print(f"  Baseline %optimal: {ablation_report.baseline_pct_optimal:.1%}")
    if ablation_report.ablation_results:
        for sig, pct in sorted(
            ablation_report.ablation_results.items(),
            key=lambda kv: kv[1],
        ):
            delta = pct - ablation_report.baseline_pct_optimal
            flag = "← WIRED" if delta < -0.01 else "← NO EFFECT"
            print(f"    remove {sig:22s} → {pct:.1%}  (Δ={delta:+.1%})  {flag}")
    print(f"  ⏱  Ablation completed in {elapsed:.2f}s")
    print("=" * 70)

    # ── Cross-scenario summary ──
    print("\n" + "=" * 70)
    print("  CROSS-SCENARIO SUMMARY")
    print("=" * 70)
    total_flags = sum(len(r.red_flags) for r in reports)
    total_critical = sum(r.critical_count for r in reports)
    total_cycles = sum(r.total_cycles for r in reports)
    total_failures = sum(
        sum(1 for l in r.failure_labels
            if l.failure_type.value != "no_failure")
        for r in reports
    )
    avg_regret = (sum(r.avg_regret for r in reports) / len(reports)
                  if reports else 0.0)
    avg_optimal = (sum(r.pct_optimal for r in reports) / len(reports)
                   if reports else 0.0)

    print(f"  Scenarios:       {len(reports)}")
    print(f"  Total cycles:    {total_cycles}")
    print(f"  Total failures:  {total_failures}")
    print(f"  Total red flags: {total_flags} ({total_critical} critical)")
    print(f"  Avg regret:      {avg_regret:.4f}")
    print(f"  Avg % optimal:   {avg_optimal:.1%}")
    print("=" * 70)


if __name__ == "__main__":
    main()
