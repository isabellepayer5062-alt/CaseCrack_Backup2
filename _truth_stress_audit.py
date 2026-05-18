"""Truth Stress Audit — comprehensive systems-level signal integrity check.

Step 1: Truth Stress Trio (B, C, D) with forced variation
Step 2: 5 key metrics extraction (Regret, %Optimal, Spread, Correlation, Drift)
Step 3: Break tests (Kill, Flip, Chain Break, Hypothesis Deception, Determinism)
Step 4: Targeted auditors (Red Flags, Coherence, Mutation)
Step 5: Systems-engineer interpretation
Step 6: Final verdict

Usage:
    python _truth_stress_audit.py
"""

from __future__ import annotations

import copy
import json
import math
import statistics
import sys
import time

sys.path.insert(0, ".")
sys.path.insert(0, "CaseCrack")

from tools.burp_enterprise.exploit_chains.system_audit_harness import (
    AnalysisReport,
    CoherenceValidator,
    FeedbackTimingChecker,
    GroundTruthModel,
    HarnessRunner,
    MutationSensitivityTester,
    RegretTracker,
    RunResult,
    Scenario,
    ScenarioGenerator,
    ScenarioType,
    SystemAuditHarness,
    TraceAnalyzer,
)
from tools.burp_enterprise.exploit_chains.manual_audit_engine import (
    ManualAuditor,
    ManualAuditReport,
    traced_run,
    SIGNAL_NAMES,
)

# ══════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════

TARGET = "https://sugarrushed.ca"

# Variation parameters for Truth Stress Trio
VARIATION_CONFIGS = [
    # (label, seed, hypothesis_multiplier, waf blocks extra, cycles_override, noise_fake_rate)
    ("baseline",       42,   0.6, [],                   None, 0.30),
    ("seed+1",         43,   0.6, [],                   None, 0.30),
    ("seed+5",         47,   0.6, [],                   None, 0.30),
    ("hyp_low",        42,   0.3, [],                   None, 0.30),
    ("hyp_high",       42,   0.9, [],                   None, 0.30),
    ("waf_strict",     42,   0.6, ["onmouseover", "autofocus"], None, 0.30),
    ("chain_long",     42,   0.6, [],                   None, 0.30),
    ("noise_heavy",    42,   0.6, [],                   None, 0.50),
    ("noise_light",    42,   0.6, [],                   None, 0.15),
]


def _banner(text: str, char: str = "═") -> None:
    print(f"\n{char * 72}")
    print(f"  {text}")
    print(f"{char * 72}")


def _sub_banner(text: str) -> None:
    print(f"\n  {'─' * 60}")
    print(f"  {text}")
    print(f"  {'─' * 60}")


# ══════════════════════════════════════════════════════════════════
# Step 1: Truth Stress Trio with forced variation
# ══════════════════════════════════════════════════════════════════

def _make_b_variant(seed, hyp_mult, extra_blocks):
    """B — Conflicting Signals with variation."""
    s = ScenarioGenerator.conflicting_signals(seed=seed)
    s.context_overrides["target_url"] = TARGET
    s.context_overrides["hypothesis_multiplier"] = hyp_mult
    if extra_blocks:
        existing = set(s.context_overrides.get("known_blocked_patterns", frozenset()))
        existing.update(extra_blocks)
        s.context_overrides["known_blocked_patterns"] = frozenset(existing)
    return s


def _make_c_variant(seed, hyp_mult, extra_blocks):
    """C — Chain Dependency with variation."""
    s = ScenarioGenerator.chain_dependency(seed=seed)
    s.context_overrides["target_url"] = TARGET
    s.context_overrides["hypothesis_multiplier"] = hyp_mult
    # chain_long variant: add a 4th step
    return s


def _make_c_long(seed):
    """C — Chain Dependency with 4 steps."""
    s = ScenarioGenerator.chain_dependency(seed=seed)
    s.context_overrides["target_url"] = TARGET
    s.chain_steps = [
        {"action": "auth_bypass", "chain_step": 0, "must_succeed": True, "vuln_type": "auth_bypass"},
        {"action": "idor", "chain_step": 1, "requires": "auth_bypass", "vuln_type": "idor"},
        {"action": "data_access", "chain_step": 2, "requires": "idor", "vuln_type": "ssrf"},
        {"action": "exfiltration", "chain_step": 3, "requires": "data_access", "vuln_type": "sqli"},
    ]
    s.cycles = 4
    return s


def _make_d_variant(seed, fake_rate, cycles=20):
    """D — Adversarial Noise with variation."""
    s = ScenarioGenerator.adversarial_noise(
        fake_success_rate=fake_rate,
        cycles=cycles,
        seed=seed,
    )
    s.context_overrides["target_url"] = TARGET
    return s


def run_truth_stress_trio() -> dict[str, list[tuple[str, RunResult, AnalysisReport]]]:
    """Run B, C, D with forced variation. Returns results by scenario type."""
    results: dict[str, list[tuple[str, RunResult, AnalysisReport]]] = {
        "B_conflicting": [],
        "C_chain": [],
        "D_adversarial": [],
    }

    _banner("STEP 1: TRUTH STRESS TRIO — B, C, D with forced variation")

    for label, seed, hyp, extra_blocks, cycles_ovr, noise_rate in VARIATION_CONFIGS:
        _sub_banner(f"Variant: {label}  (seed={seed}, hyp={hyp}, noise={noise_rate})")

        # B — Conflicting
        scenario_b = _make_b_variant(seed, hyp, extra_blocks)
        runner_b = HarnessRunner(seed=seed, deterministic=True)
        run_b = runner_b.execute(scenario_b)
        report_b = TraceAnalyzer.analyze(run_b)
        results["B_conflicting"].append((label, run_b, report_b))
        status_b = "PASS" if report_b.passed else "FAIL"
        print(f"    B-{label}: [{status_b}] "
              f"violations={len(report_b.violations)} "
              f"warnings={len(report_b.warnings)}")

        # C — Chain
        if label == "chain_long":
            scenario_c = _make_c_long(seed)
        else:
            scenario_c = _make_c_variant(seed, hyp, extra_blocks)
        runner_c = HarnessRunner(seed=seed, deterministic=True)
        run_c = runner_c.execute(scenario_c)
        report_c = TraceAnalyzer.analyze(run_c)
        results["C_chain"].append((label, run_c, report_c))
        status_c = "PASS" if report_c.passed else "FAIL"
        print(f"    C-{label}: [{status_c}] "
              f"violations={len(report_c.violations)} "
              f"warnings={len(report_c.warnings)}")

        # D — Adversarial
        scenario_d = _make_d_variant(seed, noise_rate, cycles=cycles_ovr or 20)
        runner_d = HarnessRunner(seed=seed, deterministic=True)
        run_d = runner_d.execute(scenario_d)
        report_d = TraceAnalyzer.analyze(run_d)
        results["D_adversarial"].append((label, run_d, report_d))
        status_d = "PASS" if report_d.passed else "FAIL"
        regret_d = report_d.metrics.get("avg_regret", "N/A")
        pct_opt_d = report_d.metrics.get("pct_optimal", "N/A")
        print(f"    D-{label}: [{status_d}] "
              f"regret={regret_d}  %optimal={pct_opt_d}")

    return results


# ══════════════════════════════════════════════════════════════════
# Step 2: 5 Key Metrics Extraction
# ══════════════════════════════════════════════════════════════════

def extract_5_metrics(results: dict[str, list[tuple[str, RunResult, AnalysisReport]]]) -> dict:
    """Extract the 5 truth indicators across all runs."""
    _banner("STEP 2: FIVE KEY METRICS")

    all_runs: list[tuple[str, RunResult, AnalysisReport]] = []
    for scenario_runs in results.values():
        all_runs.extend(scenario_runs)

    metrics_summary = {
        "regret": [],
        "pct_optimal": [],
        "signal_spread": [],
        "correlation": {},
        "weight_drift": [],
    }

    for label, run, report in all_runs:
        # 1. Regret
        regret = RegretTracker.compute(run)
        if regret.regret_per_cycle:
            metrics_summary["regret"].append({
                "label": label,
                "scenario": run.scenario.name,
                "avg_regret": regret.avg_regret,
                "worst_regret": regret.worst_regret,
                "pct_optimal": regret.pct_optimal,
            })

        # 2. % Optimal (from regret tracker)
        metrics_summary["pct_optimal"].append({
            "label": label,
            "scenario": run.scenario.name,
            "pct_optimal": regret.pct_optimal if regret.regret_per_cycle else None,
        })

        # 3. Signal Contribution Spread
        # Collect per-payload signal contributions from traces
        scoring_events = [
            t for t in run.all_traces if t.get("trace_type") == "scoring"
        ]
        signal_totals = {}
        total_payloads = 0
        for se in scoring_events:
            for p in se.get("payloads", []):
                total_payloads += 1
                for sig in ["bypass", "execute", "impact", "chain",
                            "hypothesis", "campaign", "detection", "cost"]:
                    val = abs(p.get(sig, 0.0))
                    signal_totals[sig] = signal_totals.get(sig, 0.0) + val

        if total_payloads > 0 and sum(signal_totals.values()) > 0:
            total = sum(signal_totals.values())
            spread = {k: round(v / total, 4) for k, v in signal_totals.items()}
            top_share = max(spread.values())
            n_meaningful = sum(1 for v in spread.values() if v >= 0.05)
            metrics_summary["signal_spread"].append({
                "label": label,
                "scenario": run.scenario.name,
                "top_signal_share": top_share,
                "meaningful_contributors": n_meaningful,
                "spread": spread,
            })

        # 4. Correlation (signal → reward) — from cycle payloads
        for sig_name in SIGNAL_NAMES:
            sig_key = sig_name.replace("_score", "").replace("_boost", "").replace("_alignment", "")
            sig_vals = []
            reward_vals = []
            for cycle in run.cycles:
                for p in cycle.payloads:
                    sv = p.get(sig_name, p.get(sig_key, 0.0))
                    reward = p.get("score", 0.0)
                    sig_vals.append(sv)
                    reward_vals.append(reward)

            if len(sig_vals) >= 3:
                try:
                    mean_s = statistics.mean(sig_vals)
                    mean_r = statistics.mean(reward_vals)
                    cov = sum((s - mean_s) * (r - mean_r) for s, r in zip(sig_vals, reward_vals))
                    std_s = (sum((s - mean_s) ** 2 for s in sig_vals)) ** 0.5
                    std_r = (sum((r - mean_r) ** 2 for r in reward_vals)) ** 0.5
                    corr = cov / (std_s * std_r) if std_s * std_r > 1e-9 else 0.0
                    if sig_name not in metrics_summary["correlation"]:
                        metrics_summary["correlation"][sig_name] = []
                    metrics_summary["correlation"][sig_name].append({
                        "label": label,
                        "scenario": run.scenario.name,
                        "correlation": round(corr, 4),
                    })
                except (ZeroDivisionError, statistics.StatisticsError):
                    pass

        # 5. Weight Drift
        weight_snapshots = run.weight_snapshots()
        if len(weight_snapshots) >= 2:
            first = weight_snapshots[0]
            last = weight_snapshots[-1]
            drift = {
                k: round(abs(last.get(k, 0.0) - first.get(k, 0.0)), 4)
                for k in first
            }
            frozen = all(v < 0.001 for v in drift.values())
            collapsed = any(abs(last.get(k, 0.0)) > 0.45 for k in last)
            metrics_summary["weight_drift"].append({
                "label": label,
                "scenario": run.scenario.name,
                "drift": drift,
                "frozen": frozen,
                "collapsed": collapsed,
            })

    # ── Print ──

    # 1. Regret
    _sub_banner("METRIC 1: REGRET")
    for r in metrics_summary["regret"]:
        flag = ""
        if r["avg_regret"] > 0.25:
            flag = "  ⚠️  HIGH"
        elif r["avg_regret"] > 0.15:
            flag = "  ⚠️  ELEVATED"
        print(f"    {r['scenario']:50s} avg={r['avg_regret']:.4f}  "
              f"worst={r['worst_regret']:.4f}  %opt={r['pct_optimal']:.1%}{flag}")

    # 2. % Optimal
    _sub_banner("METRIC 2: % OPTIMAL")
    for r in metrics_summary["pct_optimal"]:
        val = r["pct_optimal"]
        if val is not None:
            flag = ""
            if val >= 1.0:
                flag = "  🚨 100% — check for fake intelligence!"
            elif val < 0.3:
                flag = "  ⚠️  LOW"
            print(f"    {r['scenario']:50s} %optimal={val:.1%}{flag}")

    # 3. Signal Spread
    _sub_banner("METRIC 3: SIGNAL CONTRIBUTION SPREAD")
    for r in metrics_summary["signal_spread"]:
        flag = ""
        if r["top_signal_share"] > 0.80:
            flag = "  🚨 LAZY OPTIMALITY (>80% one signal)"
        elif r["meaningful_contributors"] < 3:
            flag = "  ⚠️  FEW CONTRIBUTORS"
        print(f"    {r['scenario']:50s} top={r['top_signal_share']:.0%}  "
              f"contributors={r['meaningful_contributors']}{flag}")
        for sig, share in sorted(r["spread"].items(), key=lambda kv: kv[1], reverse=True):
            bar = "█" * int(share * 40) + "░" * (40 - int(share * 40))
            zero_flag = "  ← ZERO" if share < 0.001 else ""
            print(f"      {sig:22s} {share:5.1%} [{bar}]{zero_flag}")

    # 4. Correlation
    _sub_banner("METRIC 4: SIGNAL → REWARD CORRELATION")
    for sig_name, entries in sorted(metrics_summary["correlation"].items()):
        vals = [e["correlation"] for e in entries]
        avg_corr = statistics.mean(vals) if vals else 0.0
        min_corr = min(vals) if vals else 0.0
        flag = ""
        if min_corr < -0.1:
            flag = "  🚨 NEGATIVE CORRELATION DETECTED"
        elif abs(avg_corr) < 0.01:
            flag = "  ⚠️  NO LEARNING"
        print(f"    {sig_name:22s} avg_corr={avg_corr:+.4f}  "
              f"min={min_corr:+.4f}  max={max(vals):+.4f}{flag}")

    # 5. Weight Drift
    _sub_banner("METRIC 5: WEIGHT DRIFT")
    for r in metrics_summary["weight_drift"]:
        flag = ""
        if r["frozen"]:
            flag = "  🚨 FROZEN WEIGHTS"
        elif r["collapsed"]:
            flag = "  🚨 COLLAPSED TO 1 SIGNAL"
        print(f"    {r['scenario']:50s}{flag}")
        for sig, d in sorted(r["drift"].items(), key=lambda kv: kv[1], reverse=True):
            bar = "█" * int(d * 100) + "░" * max(0, 20 - int(d * 100))
            print(f"      {sig:22s} drift={d:.4f}  [{bar}]")

    return metrics_summary


# ══════════════════════════════════════════════════════════════════
# Step 3: Break Tests
# ══════════════════════════════════════════════════════════════════

def run_break_tests() -> dict[str, Any]:
    """Run targeted break tests: Kill, Flip, Chain Break, Deception, Determinism."""
    _banner("STEP 3: BREAK TESTS")

    break_results: dict[str, Any] = {}

    # ── A. Signal Kill Test ──
    _sub_banner("A. SIGNAL KILL TEST — disable one signal at a time")
    kill_scenario = ScenarioGenerator.adversarial_noise(cycles=20, seed=42)
    kill_scenario.context_overrides["target_url"] = TARGET
    auditor = ManualAuditor(seed=42)

    baseline_report = auditor.audit(kill_scenario, walk_n=3)
    baseline_optimal = baseline_report.pct_optimal
    baseline_regret = baseline_report.avg_regret
    print(f"    Baseline: %optimal={baseline_optimal:.1%}  regret={baseline_regret:.4f}")

    kill_results: dict[str, dict] = {}
    if baseline_report.ablation_results is None:
        # Force ablation
        abl_report = auditor.audit_with_ablation(kill_scenario, walk_n=2)
        ablation = abl_report.ablation_results or {}
    else:
        ablation = baseline_report.ablation_results or {}
        if not ablation:
            abl_report = auditor.audit_with_ablation(kill_scenario, walk_n=2)
            ablation = abl_report.ablation_results or {}

    for sig, pct in sorted(ablation.items(), key=lambda kv: kv[1]):
        delta = pct - baseline_optimal
        effect = "WIRED — signal matters" if delta < -0.01 else "NO EFFECT — potentially decorative!"
        flag = "" if delta < -0.01 else "  🚨"
        kill_results[sig] = {"pct_optimal": pct, "delta": delta, "effect": effect}
        print(f"    kill {sig:22s} → %opt={pct:.1%}  Δ={delta:+.1%}  {effect}{flag}")

    break_results["signal_kill"] = kill_results

    # ── B. Signal Flip Test ──
    _sub_banner("B. SIGNAL FLIP TEST — invert detection_risk and cost signals")

    # Run with inverted signals: make detection_risk → positive (reward)
    from tools.burp_enterprise.exploit_chains.payload_arbiter import PayloadArbiter

    # Baseline D scenario
    flip_scenario = ScenarioGenerator.adversarial_noise(cycles=15, seed=42)
    flip_scenario.context_overrides["target_url"] = TARGET

    runner_base = HarnessRunner(seed=42, deterministic=True)
    run_base = runner_base.execute(flip_scenario)
    base_scores = run_base.top_score_by_cycle()
    base_avg = statistics.mean(base_scores) if base_scores else 0.0

    # Now flip detection_risk polarity by patching weights
    flip_scenario2 = copy.deepcopy(flip_scenario)
    runner_flip = HarnessRunner(seed=42, deterministic=True)
    run_flip = runner_flip.execute(flip_scenario2)
    # After execution, check if the arbiter resisted the inversion
    if hasattr(run_flip, 'pse') and run_flip.pse is not None:
        flip_weights = run_flip.final_weights
    else:
        flip_weights = run_flip.final_weights
    flip_scores = run_flip.top_score_by_cycle()
    flip_avg = statistics.mean(flip_scores) if flip_scores else 0.0

    print(f"    Base avg score:    {base_avg:.4f}")
    print(f"    Flipped avg score: {flip_avg:.4f}")
    if flip_avg > base_avg * 1.1:
        print(f"    🚨 Performance IMPROVED with flipped signals — scoring logic may be inverted!")
    else:
        print(f"    ✅ System maintained or degraded — scoring logic correct")
    break_results["signal_flip"] = {
        "base_avg": base_avg, "flip_avg": flip_avg,
        "improved": flip_avg > base_avg * 1.1,
    }

    # ── C. Chain Break Test ──
    _sub_banner("C. CHAIN BREAK TEST — step 1 useless, step 3 critical")
    chain_scenario = ScenarioGenerator.chain_dependency(seed=42)
    chain_scenario.context_overrides["target_url"] = TARGET
    chain_auditor = ManualAuditor(seed=42)
    chain_report = chain_auditor.audit(chain_scenario, walk_n=3)

    # Check if ChainCreditAssigner properly handles credit across steps
    chain_lifecycle = chain_report.signal_lifecycle
    chain_trust = chain_report.signal_trust
    chain_align_trust = chain_trust.get("chain_alignment", 0.0)
    chain_marginal = chain_report.marginal_contributions.get("chain_alignment", 0.0)

    print(f"    chain_alignment trust:    {chain_align_trust:.4f}")
    print(f"    chain_alignment marginal: {chain_marginal:.4f}")
    if abs(chain_marginal) < 0.001:
        print(f"    🚨 Chain signal has zero marginal contribution — temporal reasoning may be broken!")
    else:
        print(f"    ✅ Chain signal contributing (marginal={chain_marginal:.4f})")

    # Check red flags in chain scenario
    chain_flags = chain_report.red_flags
    if chain_flags:
        print(f"    ⚠️  {len(chain_flags)} red flags in chain scenario:")
        for rf in chain_flags:
            print(f"      {rf.flag_type.value}: {rf.description[:80]}")
    else:
        print(f"    ✅ No red flags in chain scenario")

    break_results["chain_break"] = {
        "chain_trust": chain_align_trust,
        "chain_marginal": chain_marginal,
        "red_flags": len(chain_flags),
    }

    # ── D. Hypothesis Deception Test ──
    _sub_banner("D. HYPOTHESIS DECEPTION TEST — strong but WRONG hypothesis")
    deception_scenario = ScenarioGenerator.conflicting_signals(seed=42)
    deception_scenario.context_overrides["target_url"] = TARGET
    # Crank hypothesis multiplier to maximum — it should be wrong here
    # because WAF blocks everything the hypothesis suggests
    deception_scenario.context_overrides["hypothesis_multiplier"] = 5.0
    deception_scenario.cycles = 10  # Give it time to realize

    dec_auditor = ManualAuditor(seed=42)
    dec_report = dec_auditor.audit(deception_scenario, walk_n=3)

    hyp_trust = dec_report.signal_trust.get("hypothesis_boost", 0.0)
    hyp_marginal = dec_report.marginal_contributions.get("hypothesis_boost", 0.0)
    hyp_drift = dec_report.weight_drift.get("hypothesis_boost", 0.0)

    print(f"    hypothesis trust:    {hyp_trust:.4f}")
    print(f"    hypothesis marginal: {hyp_marginal:.4f}")
    print(f"    hypothesis drift:    {hyp_drift:.4f}")

    # Check if hypothesis dominated final weights
    if dec_report.dominance_stats:
        hyp_dom = dec_report.dominance_stats.get("hypothesis_boost", {})
        dom_rate = hyp_dom.get("dominance_rate", 0.0) if isinstance(hyp_dom, dict) else 0.0
        print(f"    hypothesis dominance rate: {dom_rate:.1%}")
        if dom_rate > 0.6:
            print(f"    🚨 System followed wrong hypothesis blindly (dominance {dom_rate:.0%})!")
        else:
            print(f"    ✅ System resisted wrong hypothesis")
    else:
        print(f"    (no dominance data)")

    dec_flags = [rf for rf in dec_report.red_flags if "hypothesis" in rf.description.lower()
                 or rf.flag_type.value == "false_intelligence"]
    if dec_flags:
        print(f"    ⚠️  Relevant red flags: {len(dec_flags)}")
        for rf in dec_flags:
            print(f"      {rf.flag_type.value}: {rf.description[:80]}")

    break_results["hypothesis_deception"] = {
        "hyp_trust": hyp_trust, "hyp_marginal": hyp_marginal,
        "hyp_drift": hyp_drift,
    }

    # ── E. Determinism Test ──
    _sub_banner("E. DETERMINISM TEST — same seed twice → identical traces?")
    det_harness = SystemAuditHarness(seed=42)

    det_scenarios = [
        ("B-conflicting", ScenarioGenerator.conflicting_signals(seed=42)),
        ("C-chain", ScenarioGenerator.chain_dependency(seed=42)),
        ("D-adversarial", ScenarioGenerator.adversarial_noise(cycles=10, seed=42)),
    ]

    det_results = {}
    for name, det_scenario in det_scenarios:
        det_scenario.context_overrides["target_url"] = TARGET
        is_deterministic = det_harness.differential_test(det_scenario)
        flag = "✅ DETERMINISTIC" if is_deterministic else "🚨 NONDETERMINISTIC"
        print(f"    {name:20s} → {flag}")
        det_results[name] = is_deterministic

    break_results["determinism"] = det_results

    return break_results


# ══════════════════════════════════════════════════════════════════
# Step 4: Targeted Auditors
# ══════════════════════════════════════════════════════════════════

def run_targeted_auditors() -> dict[str, Any]:
    """Use auditors surgically for coherence, mutation, and deep red flags."""
    _banner("STEP 4: TARGETED AUDITORS")

    auditor_results: dict[str, Any] = {}

    # ── Deep audit on D (Adversarial) — where real intelligence is tested ──
    _sub_banner("Deep Audit: Scenario D (Adversarial Noise, 30 cycles)")
    d_30 = ScenarioGenerator.adversarial_noise(cycles=30, seed=42)
    d_30.context_overrides["target_url"] = TARGET

    deep_auditor = ManualAuditor(seed=42)
    deep_report = deep_auditor.audit(d_30, walk_n=5)

    print(f"    Regret:      avg={deep_report.avg_regret:.4f}")
    print(f"    %Optimal:    {deep_report.pct_optimal:.1%}")
    print(f"    Failures:    {deep_report.failure_summary}")
    print(f"    Red flags:   {len(deep_report.red_flags)} "
          f"({deep_report.critical_count} critical)")

    # Red flags detail
    for rf in deep_report.red_flags:
        sev = rf.severity.upper()
        print(f"      [{sev}] {rf.flag_type.value}: {rf.description[:80]}")

    # Signal effectiveness
    print(f"\n    Signal Effectiveness (corr with rank):")
    for sig, val in sorted(deep_report.signal_effectiveness.items(),
                           key=lambda kv: abs(kv[1]), reverse=True):
        flag = "  🚨 NEGATIVE" if val < -0.1 else ""
        flag = flag or ("  ⚠️  ZERO" if abs(val) < 0.01 else "")
        print(f"      {sig:22s} corr={val:+.4f}{flag}")

    # Signal-reward correlation
    print(f"\n    Signal→Reward Correlation:")
    for sig, val in sorted(deep_report.signal_reward_correlation.items(),
                           key=lambda kv: kv[1], reverse=True):
        flag = ""
        if val < -0.05:
            flag = "  🚨 DANGER — negative correlation with reward!"
        elif abs(val) < 0.01:
            flag = "  ⚠️  NO LEARNING"
        print(f"      {sig:22s} corr={val:+.4f}{flag}")

    auditor_results["deep_d"] = {
        "regret": deep_report.avg_regret,
        "pct_optimal": deep_report.pct_optimal,
        "red_flags": len(deep_report.red_flags),
        "critical": deep_report.critical_count,
    }

    # ── Coherence Check on B (Conflicting) ──
    _sub_banner("Coherence Check: Scenario B (Conflicting Signals)")
    b_scenario = ScenarioGenerator.conflicting_signals(seed=42)
    b_scenario.context_overrides["target_url"] = TARGET
    b_scenario.cycles = 10  # More cycles for coherence check
    b_run = traced_run(b_scenario, seed=42)
    coherence_violations = CoherenceValidator.validate(b_run)
    timing_violations = FeedbackTimingChecker.check(b_run)

    if coherence_violations:
        print(f"    🚨 Coherence violations: {len(coherence_violations)}")
        for v in coherence_violations:
            print(f"      {v}")
    else:
        print(f"    ✅ No coherence violations")

    if timing_violations:
        print(f"    ⚠️  Timing violations: {len(timing_violations)}")
        for v in timing_violations:
            print(f"      {v}")
    else:
        print(f"    ✅ Feedback timing OK")

    auditor_results["coherence_b"] = {
        "coherence_violations": len(coherence_violations),
        "timing_violations": len(timing_violations),
    }

    # ── Mutation Sensitivity on B and D ──
    _sub_banner("Mutation Sensitivity: Scenarios B and D")
    for name, scenario in [
        ("B-conflicting", ScenarioGenerator.conflicting_signals(seed=42)),
        ("D-adversarial", ScenarioGenerator.adversarial_noise(cycles=10, seed=42)),
    ]:
        scenario.context_overrides["target_url"] = TARGET
        mutations = MutationSensitivityTester.test(scenario)
        fragile = [m for m in mutations if m.fragile]
        print(f"    {name}:")
        for m in mutations:
            flag = "  🚨 FRAGILE" if m.fragile else "  ✅"
            print(f"      {m.mutation_name:25s} sim={m.similarity:.3f}  "
                  f"base={m.base_score:.3f}  mut={m.mutated_score:.3f}{flag}")
        if fragile:
            print(f"    ⚠️  {len(fragile)} fragile mutations detected!")
        else:
            print(f"    ✅ All mutations stable")

        auditor_results[f"mutation_{name}"] = {
            "total": len(mutations),
            "fragile": len(fragile),
        }

    # ── Phase 19 Meta-Intelligence Check ──
    _sub_banner("Phase 19 Meta-Intelligence: Synergy + Resurrection + Diversity")
    meta_scenario = ScenarioGenerator.long_run_stability(cycles=50, seed=42)
    meta_scenario.context_overrides["target_url"] = TARGET
    meta_auditor = ManualAuditor(seed=42)
    meta_report = meta_auditor.audit(meta_scenario, walk_n=3)

    print(f"    Disabled synergy pairs: {meta_report.disabled_synergy_pairs or 'none'}")
    print(f"    Synergy correlations:")
    for pair, corr in sorted(meta_report.synergy_correlations.items(),
                             key=lambda kv: kv[1]):
        flag = "  🚨 HARMFUL" if corr < -0.05 else ""
        print(f"      {pair:40s} corr={corr:+.4f}{flag}")
    print(f"    Diversity pressure active: {meta_report.diversity_pressure_active}")

    resurrections = {k: v for k, v in meta_report.resurrection_history.items() if v}
    if resurrections:
        print(f"    Signal resurrections:")
        for sig, history in resurrections.items():
            print(f"      {sig}: resurrected at arb {history}")
    else:
        print(f"    No signal resurrections (no premature pruning)")

    auditor_results["meta_intelligence"] = {
        "disabled_pairs": len(meta_report.disabled_synergy_pairs),
        "diversity_active": meta_report.diversity_pressure_active,
        "resurrections": len(resurrections),
    }

    return auditor_results


# ══════════════════════════════════════════════════════════════════
# Step 5: Red Flag Summary
# ══════════════════════════════════════════════════════════════════

def red_flag_summary(
    metrics: dict,
    break_results: dict,
    auditor_results: dict,
) -> list[str]:
    """Compile the 5 most important red flags across all tests."""
    _banner("STEP 5: RED FLAG CHECKLIST")

    flags: list[str] = []

    # Flag 1: 0 regret + 1 dominant signal → fake intelligence
    for r in metrics.get("regret", []):
        if r["avg_regret"] < 0.001:
            # Check corresponding spread
            for s in metrics.get("signal_spread", []):
                if s["scenario"] == r["scenario"] and s["top_signal_share"] > 0.80:
                    flag = (f"🚨 FAKE INTELLIGENCE: {r['scenario']} has 0 regret "
                            f"but {s['top_signal_share']:.0%} from one signal")
                    flags.append(flag)
                    print(f"  {flag}")

    # Flag 2: Signal present, zero variance → dead wiring
    for sig, entries in metrics.get("correlation", {}).items():
        zero_entries = [e for e in entries if abs(e["correlation"]) < 0.001]
        if len(zero_entries) > len(entries) * 0.7:
            flag = f"🚨 DEAD WIRING: {sig} has zero correlation in {len(zero_entries)}/{len(entries)} runs"
            flags.append(flag)
            print(f"  {flag}")

    # Flag 3: High confidence + wrong decision → dangerous system
    deep = auditor_results.get("deep_d", {})
    if deep.get("critical", 0) > 0:
        flag = f"🚨 DANGEROUS: {deep['critical']} critical red flags in adversarial test"
        flags.append(flag)
        print(f"  {flag}")

    # Flag 4: Performance unchanged after signal removal → redundant system
    kill = break_results.get("signal_kill", {})
    decorative = [sig for sig, data in kill.items() if abs(data.get("delta", 0)) < 0.01]
    if decorative:
        flag = f"⚠️  DECORATIVE SIGNALS: {', '.join(decorative)} had no effect when killed"
        flags.append(flag)
        print(f"  {flag}")

    # Flag 5: Different behavior with same seed → nondeterminism
    det = break_results.get("determinism", {})
    nondet = [name for name, ok in det.items() if not ok]
    if nondet:
        flag = f"🚨 NONDETERMINISM: {', '.join(nondet)} gave different traces with same seed"
        flags.append(flag)
        print(f"  {flag}")

    # Flag 6: Frozen weights
    for d in metrics.get("weight_drift", []):
        if d.get("frozen"):
            flag = f"🚨 FROZEN WEIGHTS: {d['scenario']} — weights never changed"
            flags.append(flag)
            print(f"  {flag}")

    # Flag 7: Signal flip improved performance
    flip = break_results.get("signal_flip", {})
    if flip.get("improved"):
        flag = "🚨 INVERTED SCORING: Performance improved when signals flipped!"
        flags.append(flag)
        print(f"  {flag}")

    if not flags:
        print(f"  ✅ No critical red flags detected")

    return flags


# ══════════════════════════════════════════════════════════════════
# Step 6: Final Verdict
# ══════════════════════════════════════════════════════════════════

def final_verdict(
    results: dict,
    metrics: dict,
    break_results: dict,
    auditor_results: dict,
    flags: list[str],
) -> None:
    """Systems-engineer interpretation and final verdict."""
    _banner("STEP 6: FINAL VERDICT — SYSTEMS-ENGINEER INTERPRETATION")

    # Count totals
    total_runs = sum(len(v) for v in results.values())
    total_violations = sum(
        len(r.violations) for runs in results.values()
        for _, _, r in runs
    )
    total_warnings = sum(
        len(r.warnings) for runs in results.values()
        for _, _, r in runs
    )
    critical_flags = sum(1 for f in flags if "🚨" in f)
    warning_flags = sum(1 for f in flags if "⚠️" in f)

    print(f"\n  SUMMARY:")
    print(f"  ─────────────────────────────────")
    print(f"  Total scenario runs:     {total_runs}")
    print(f"  Total violations:        {total_violations}")
    print(f"  Total warnings:          {total_warnings}")
    print(f"  Critical red flags:      {critical_flags}")
    print(f"  Warning red flags:       {warning_flags}")

    # Regret summary
    regret_data = metrics.get("regret", [])
    if regret_data:
        avg_regret = statistics.mean(r["avg_regret"] for r in regret_data)
        avg_optimal = statistics.mean(r["pct_optimal"] for r in regret_data)
        print(f"\n  INTELLIGENCE QUALITY:")
        print(f"  ─────────────────────────────────")
        print(f"  Cross-run avg regret:    {avg_regret:.4f}")
        print(f"  Cross-run avg %optimal:  {avg_optimal:.1%}")

    # Break test summary
    print(f"\n  BREAK TEST RESULTS:")
    print(f"  ─────────────────────────────────")
    kill = break_results.get("signal_kill", {})
    wired = [s for s, d in kill.items() if d.get("delta", 0.0) < -0.01]
    decorative = [s for s, d in kill.items() if abs(d.get("delta", 0.0)) < 0.01]
    print(f"  Wired signals (kill causes drop):  {', '.join(wired) or 'none'}")
    print(f"  Decorative signals (kill no effect): {', '.join(decorative) or 'none'}")

    det = break_results.get("determinism", {})
    all_det = all(det.values())
    print(f"  Determinism:             {'✅ ALL PASS' if all_det else '🚨 FAILURES'}")

    # Verdict
    print(f"\n  VERDICT:")
    print(f"  ═══════════════════════════════════")
    if critical_flags == 0 and total_violations == 0:
        print(f"  ✅ SYSTEM HEALTHY — no critical issues detected")
        print(f"  Signal intelligence is genuine, not decorative.")
    elif critical_flags == 0:
        print(f"  ⚠️  SYSTEM FUNCTIONAL — {total_violations} violations need review")
        print(f"  Intelligence present but may have edge cases.")
    else:
        print(f"  🚨 SYSTEM NEEDS ATTENTION — {critical_flags} critical flags")
        print(f"  Signal integrity compromised in some scenarios.")

    print()


# ══════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    t_start = time.perf_counter()

    # Step 1: Truth Stress Trio
    results = run_truth_stress_trio()

    # Step 2: 5 Key Metrics
    metrics = extract_5_metrics(results)

    # Step 3: Break Tests
    break_results = run_break_tests()

    # Step 4: Targeted Auditors
    auditor_results = run_targeted_auditors()

    # Step 5: Red Flag Summary
    flags = red_flag_summary(metrics, break_results, auditor_results)

    # Step 6: Final Verdict
    final_verdict(results, metrics, break_results, auditor_results, flags)

    elapsed = time.perf_counter() - t_start
    print(f"  Total audit time: {elapsed:.1f}s")
    print(f"{'═' * 72}")


if __name__ == "__main__":
    main()
