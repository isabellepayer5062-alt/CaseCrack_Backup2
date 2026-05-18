#!/usr/bin/env python3
"""
PHASE 1 ENFORCEMENT VERIFICATION CHECKLIST
===========================================

Final gate before moving from development to staging.
Every checkbox must pass—no exceptions, no workarounds.

This is your sign-off document. Print it, attach to your PR/ticket.

================================================================================
PREREQUISITE: MCP SERVER PRODUCTION READINESS
================================================================================

Before ANY Phase 1 work begins:

□ MCP server is running on stable branch (ci/make-ci-green)
□ All MCP tests passing (pytest)
□ MCP authentication working (_mcp_auth.py)
□ MCP circuit breaker operational (_mcp_circuit_breaker.py)
□ MCP metrics collection working (_mcp_metrics.py)
□ MCP policy resolver functional (_mcp_policy.py)
□ Dashboard hooks working (recon_dashboard integration)
□ All critical fixes applied from recent audits

MCP Server Verification:
  Run: python -m pytest CaseCrack/tools/burp_enterprise/mcp/
  Expected: All tests pass
  If fails: Fix MCP issues before proceeding with Phase 1

================================================================================
RULE 1: READINESS AUDIT (Hard Gate)
================================================================================

□ Created _PHASE1_READINESS_AUDIT.py (non-negotiable gate)
□ Audit has 15 checks covering:
  □ Files exist (all _phase1*.py files)
  □ Imports working
  □ Tool definitions complete
  □ Parameter validators (edge cases)
  □ Policy enforcer
  □ Shadow runner
  □ Divergence detection
  □ Fail-safe mode
  □ Load test harness
  □ Latency overhead
  □ mcp_server integration
  □ Metrics collection
  □ Regression detection
  □ Dependencies traced
  □ Deployment config

□ Audit exit code = 0 (all checks pass)
□ Audit report generated and archived
□ No overrides or skips allowed

Verification:
  python _PHASE1_READINESS_AUDIT.py
  Expected: ✅ ALL CHECKS PASSED
  If fail: Fix issues and re-run

================================================================================
RULE 2: ZERO DIVERGENCE (Blocker)
================================================================================

□ Created _PHASE1_DIVERGENCE_DETECTION.py with:
  □ DivergenceDetector class
  □ EXACT_MATCH classification
  □ SEMANTIC_MATCH classification
  □ SOFT_DIVERGENCE classification (policy side-effects)
  □ DIVERGENCE classification (output mismatch)
  □ FATAL_DIVERGENCE classification (stop immediately)

□ Created _PHASE1_SEMANTIC_MATCH_SPEC.md defining:
  □ Allowed differences (ordering, timestamp ±5s, optional fields)
  □ NOT allowed differences (missing fields, changed values)
  □ Per-command specifications (run_burp_scan, list_targets, get_report)

□ Shadow runner validated to produce:
  □ 0 FATAL_DIVERGENCE in test runs
  □ 0 unresolved DIVERGENCE in test runs
  □ All SOFT_DIVERGENCE categorized and logged separately

□ Week 3 divergence threshold: ZERO unexplained divergences
  □ Any DIVERGENCE blocks progression
  □ Any FATAL_DIVERGENCE blocks immediately

Verification:
  python -c "from _phase1_divergence_detection import DivergenceDetector; d=DivergenceDetector(); print('✅ Divergence detector initialized')"
  Expected: ✅ Divergence detector initialized

================================================================================
RULE 3: FAIL-SAFE MODE (On at 10% Canary)
================================================================================

□ Created _phase1_safety_upgrades.py with FailSafeMode class:
  □ should_use_failsafe(command) → bool
  □ log_critical_divergence(command, error, passthrough_ok)
  □ get_critical_divergences() → list

□ FailSafeMode logic implemented:
  □ Enabled = True during 10% canary (MCP_PHASE1_FAILSAFE_ENABLED)
  □ When typed fails AND passthrough succeeds:
    □ Return passthrough result to user
    □ Log as CRITICAL divergence
    □ Record metric: failsafe_triggered += 1
  □ Disabled = False after 50% canary (after validation)

□ Integration with request dispatch:
  □ Check fail-safe before returning typed result
  □ Catch exceptions from typed implementation
  □ Fallback to passthrough when needed
  □ Log critical divergence for investigation

□ Monitoring:
  □ Alert if failsafe_triggered > 0 in 24h at 50%+
  □ Abort canary progression if failsafe triggered at 10%

Verification:
  python -c "from _phase1_safety_upgrades import FailSafeMode; fs=FailSafeMode(enabled=True); fs.log_critical_divergence('test', Exception('test'), True); print(f'✅ Fail-safe triggered: {len(fs.get_critical_divergences())} events')"
  Expected: ✅ Fail-safe triggered: 1 events

================================================================================
RULE 4: LOAD TEST (Peak + Buffer)
================================================================================

□ Created _phase1_load_test.py with LoadTestHarness:
  □ Measures latency at 10, 25, 50, 80, 100+ concurrency
  □ Detects queue buildup (p99 latency spike >50%)
  □ Calculates safe_concurrency_ceiling
  □ Tests 200+ requests per concurrency level

□ Load test parameters:
  □ Test concurrency = your_peak_spike + 20+ buffer
  □ p99 latency threshold = 2000ms (must pass all levels)
  □ Overhead threshold = <20% (must pass all levels)
  □ Queue buildup detection = enabled

□ Pre-staging data collection:
  □ Measured current production peak concurrency
  □ Documented in _PHASE1_LOAD_TEST_BASELINE.json
  □ Example: {real_peak: 80, test_levels: [10, 30, 50, 80, 100]}

□ Week 3 load test results:
  □ Max p99 latency < 2000ms
  □ Overhead < 20%
  □ No queue buildup detected
  □ Safe ceiling >= real_peak + buffer

Verification:
  python -c "from _phase1_load_test import LoadTestHarness; print('✅ Load test harness ready')"
  Expected: ✅ Load test harness ready

================================================================================
RULE 5: PASSTHROUGH REMOVAL (Regression Detection)
================================================================================

□ Created RegressionDetector in _phase1_safety_upgrades.py:
  □ mark_migration_complete() activates detection
  □ check_regression(command, request) immediately alerts
  □ get_regressions() returns all detected regressions

□ Week 5 decommissioning:
  □ Disable passthrough implementations for Phase 1 commands
  □ Mark migration complete: regression_detector.mark_migration_complete()
  □ Disable shadow runner: phase1.shadow_runner.enabled = False
  □ Alert threshold: passthrough_calls = zero tolerance

□ Post-Week 5 monitoring:
  □ Any Phase 1 passthrough call = CRITICAL alert
  □ Regression metrics dashboard active
  □ Weekly review: zero passthrough calls, zero divergences

□ Incident response:
  □ On-call team alerted for any passthrough call
  □ Investigation checklist documented
  □ Resolution procedures defined

Verification:
  python -c "from _phase1_safety_upgrades import RegressionDetector; r=RegressionDetector(); r.mark_migration_complete(); print('✅ Regression detection armed')"
  Expected: ✅ Regression detection armed

================================================================================
GAP 1: SEMANTIC MATCH (Explicit Definition)
================================================================================

□ Created _PHASE1_SEMANTIC_MATCH_SPEC.md with:
  □ run_burp_scan: Allowed differences (scan ID format, status case, timestamp ±5s)
  □ list_targets: Allowed differences (ordering, tag order, count metadata)
  □ get_report: Allowed differences (ID format, timestamp, distribution format)
  □ Blockers: Missing fields, changed values, different counts, failure mismatch

□ Implementation in DivergenceDetector:
  □ _is_semantic_match() method implemented per spec
  □ All allowed differences checked first
  □ All blockers checked before semantic pass
  □ Clear classification: EXACT_MATCH vs SEMANTIC_MATCH

□ Code review passed:
  □ Semantic match logic reviewed by: [tech lead]
  □ Sign-off date: [date]
  □ Any ambiguities resolved: [yes/no + details]

Verification:
  Review _PHASE1_SEMANTIC_MATCH_SPEC.md
  Expected: Clear, unambiguous definitions for each command

================================================================================
GAP 2: SCHEMA FREEZE (No Changes Weeks 3-5)
================================================================================

□ Documented frozen tool schemas in:
  □ _PHASE1_TOOL_DEFINITIONS.py (locked versions)
  □ PHASE1_FROZEN_SCHEMAS dict with version + freeze dates
  □ Change control process for critical fixes

□ Check at boot time:
  □ Schema validation code in place
  □ Raises exception if schema changed
  □ Prevents accidental modifications

□ Team communication:
  □ Development team notified: no schema changes Weeks 3-5
  □ Change control process documented
  □ Exception process (critical bugs) defined

□ Week 3-5 log:
  □ No schema changes made (or all approved + re-tested)
  □ Document any exceptions with sign-off
  □ Re-run divergence detector after any change

Verification:
  Check code: schema_validation_at_boot_time
  Expected: Raises exception if schema differs

================================================================================
GAP 3: GOLDEN DATASET (20-50 Scenarios)
================================================================================

□ Created _PHASE1_GOLDEN_DATASET.json with:
  □ run_burp_scan: 5+ representative scenarios
    □ basic_quick: www.example.com, quick scan
    □ typical_standard: app.example.com, standard scan
    □ complex_thorough: complex target, thorough scan
    □ edge_case: unusual chars in target
    □ timeout: slow target scenario
  □ list_targets: 5+ scenarios
    □ all: no filter
    □ filtered: tag filter applied
    □ paginated: limit=1 offset=0
    □ large_offset: pagination edge case
    □ empty: no results
  □ get_report: 5+ scenarios
    □ exists: report found
    □ not_found: invalid ID
    □ in_progress: report not ready
    □ many_findings: large result
    □ error: report generation failed

□ Dataset structure:
  □ {command}:{scenario_name}
  □ params: input parameters
  □ result: expected output
  □ captured_at: timestamp

□ Stored and versioned:
  □ _PHASE1_GOLDEN_DATASET.json (in git)
  □ _PHASE1_GOLDEN_DATASET_WEEK5_FINAL.json (archived after migration)

□ Used for regression testing:
  □ check_regression_vs_golden() in Week 3
  □ Catches any unexpected output changes
  □ Faster debugging than log archaeology

Verification:
  Check: _PHASE1_GOLDEN_DATASET.json exists
  Expected: ≥15 scenarios total (5 per command)

================================================================================
GAP 4: POLICY IMPACT TRACKING (Separate Logging)
================================================================================

□ Created _phase1_policy_impact_tracker.py with:
  □ PolicyDenial: Quota exceeded, role unauthorized, concurrency exceeded
  □ RateLimit: Concurrency limit, quota limit, per-second limit
  □ LatencyOverhead: Validation ms + policy check ms

□ Integration with shadow runner:
  □ Track: would_have_been_denied_by_policy
  □ Track: would_have_been_rate_limited
  □ Track: latency overhead from policy checks
  □ NOT counted as divergence (expected behavior change)

□ Metrics export:
  □ phase1_policy_denials_total
  □ phase1_rate_limits_total
  □ phase1_latency_overhead_mean_ms
  □ phase1_policy_denial_{reason} (quota_exceeded, role_unauthorized, ...)
  □ phase1_rate_limit_{type} (concurrency_limit, quota_limit, ...)

□ Reporting:
  □ generate_policy_impact_report() creates JSON report
  □ Included in Week 3 readiness report
  □ Assessment: "no impact", "low impact", "moderate impact", or "ALERT"

□ Monitoring:
  □ Dashboard shows policy impact trends
  □ Alert if: denials > 100 OR failed_rate_limits > 50
  □ Weekly review: are thresholds too strict?

Verification:
  python -c "from _phase1_policy_impact_tracker import PolicyImpactTracker; t=PolicyImpactTracker(); t.log_policy_denial('test', 'user1', 'user', 'quota_exceeded'); print(f'✅ Policy impact tracked: {t.get_policy_report()}')"
  Expected: Policy impact tracked with deny count > 0

================================================================================
SIGN-OFF AUTHORIZATION
================================================================================

Approved by (signatures):

Development Lead: __________________ Date: __________
  Confirms: All 5 rules implemented, all 4 gaps closed

QA Lead: __________________________ Date: __________
  Confirms: All tests passing, readiness audit 100% pass

Release Manager: __________________ Date: __________
  Confirms: Enforcement procedures in place, gates locked

Ops Lead: ________________________ Date: __________
  Confirms: Monitoring, alerting, rollback procedures ready

Exec Sponsor: _____________________ Date: __________
  Confirms: Ready to proceed with Week 3 staging

================================================================================
FINAL CHECKLIST
================================================================================

Before Week 3 Staging Begins:

□ All 5 rules locked in place
□ All 4 gaps closed with implementations
□ MCP server production-ready
□ All 9 Phase 1 files created and tested
□ All emergency procedures tested
□ Monitoring dashboards configured
□ On-call runbook prepared
□ Readiness audit exits with code 0
□ Load test shows safe concurrency ceiling
□ Golden dataset captured (20+ scenarios)
□ Schema frozen for Weeks 3-5
□ Semantic match spec signed off

Gate: If any checkbox unchecked → DO NOT PROCEED

Next Action: Run _PHASE1_READINESS_AUDIT.py
Expected: Exit code 0, all 15 checks PASS
If fails: Fix and re-run

================================================================================
EMERGENCY CONTACTS
================================================================================

On-Call Team: [contact info]
  Response time: < 15 minutes
  Escalation: [manager contact]

Security Team: [contact info]
  For: Regression alerts, bypass attempts

Release Manager: [contact info]
  For: Canary approval, rollback decisions

Tech Lead: [contact info]
  For: Architecture questions, design decisions

================================================================================
DOCUMENTATION REFERENCES
================================================================================

Read before approval:
  1. _PHASE1_HARDENED_ENFORCEMENT_RULES.md (this file)
  2. _PHASE1_SEMANTIC_MATCH_SPEC.md (GAP 1)
  3. _PHASE1_COMPLETE_DELIVERY_PACKAGE.md (overview)
  4. _PHASE1_INTEGRATION_COMPLETE.md (implementation)
  5. _PHASE1_READINESS_AUDIT.py (verification gate)

Technical References:
  - _phase1_tool_definitions.py (tool schemas + validation)
  - _phase1_shadow_runner.py (A/B comparison)
  - _phase1_divergence_detection.py (mismatch detection)
  - _phase1_load_test.py (performance validation)
  - _phase1_safety_upgrades.py (fail-safe + metrics)
  - _phase1_policy_impact_tracker.py (policy tracking)

Operational:
  - Emergency procedures in _phase1_safety_upgrades.py
  - Monitoring dashboard configuration [URL]
  - On-call runbook [URL]
  - Incident response procedures [URL]
"""

print(__doc__)

if __name__ == "__main__":
    print("\n" + "="*80)
    print("PHASE 1 ENFORCEMENT VERIFICATION CHECKLIST")
    print("="*80)
    print("\nPrint this document and attach to your PR/ticket")
    print("All checkboxes must pass—no exceptions")
    print("\nNext step: Run _PHASE1_READINESS_AUDIT.py")
