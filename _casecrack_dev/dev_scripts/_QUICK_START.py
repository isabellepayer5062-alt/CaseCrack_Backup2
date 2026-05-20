#!/usr/bin/env python3
"""
QUICK START: Passthrough Command Analysis

This file shows you exactly how to get started in 5 minutes.
"""

# =============================================================================
# 5-MINUTE QUICK START
# =============================================================================

# STEP 1: Run the analyzer (demo mode - no production data needed yet)
# ───────────────────────────────────────────────────────────────────
print("""
STEP 1: RUN THE ANALYZER (Demo)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$ cd "c:\\Users\\ya754\\CaseCrack v1.0"
$ python _analyze_passthrough_metrics.py

Expected Output:
  ✓ 8 commands analyzed
  ✓ 2,537 total calls
  ✓ 3 categories (core, edge, dead)
  ✓ JSON report saved


STEP 2: READ THE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━

$ cat _PASSTHROUGH_COMMANDS_SUMMARY.txt

Expected Output:
  ✓ 🟢 CORE WORKFLOWS (Phase 1)
  ✓ 🟡 EDGE/DEBUG (Phase 2)
  ✓ 🔴 DEAD/RARE (Phase 3)
  ✓ Roadmap with effort/risk estimates


STEP 3: INTEGRATE WITH REAL METRICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# When you have a running MCP server:
from mcp_server import mcp_server
from _analyze_passthrough_metrics import PassthroughAnalyzer

analyzer = PassthroughAnalyzer(mcp_server.metrics)
report = analyzer.generate_report()

# Get Phase 1 commands to harden
phase1 = report['categories']['core_workflows']['commands']
print(f"Harden these first: {phase1}")


STEP 4: SET UP WEEKLY REPORTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Add this to your MCP server initialization:
from apscheduler.schedulers.background import BackgroundScheduler
from _analyze_passthrough_metrics import PassthroughAnalyzer

def weekly_analysis():
    analyzer = PassthroughAnalyzer(mcp_server.metrics)
    report = analyzer.generate_report()
    
    # Save report
    import json
    from datetime import datetime
    filename = f"reports/analysis_{datetime.now():%Y-%m-%d}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"✓ Weekly analysis saved to {filename}")

scheduler = BackgroundScheduler()
scheduler.add_job(weekly_analysis, 'cron', day_of_week='mon', hour=9)
scheduler.start()


STEP 5: START PHASE 1 HARDENING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Identified Phase 1 commands:
phase1_commands = report['categories']['core_workflows']['commands']

# These 3–5 commands account for ~76% of your traffic
# Priority actions:
#
#  1. Add MCP tool definitions for each command
#  2. Implement arg validation in MCP handlers
#  3. Add error handling + retry logic
#  4. Test in staging environment
#  5. Measure error rate improvement
#  6. Deploy to production
#
# Expected timeline: 4–6 weeks for Phase 1


STEP 6: TRACK PROGRESS
━━━━━━━━━━━━━━━━━━━━━

# After Phase 1 is live, track:
#
#  1. Error rate for Phase 1 commands (target: < 1%)
#  2. Percentage of Phase 1 hardened (target: 100%)
#  3. Tenant adoption of MCP vs CLI (target: 80%+ on MCP)
#  4. Support ticket volume (target: trending down)
#
# Rerun analyzer weekly to monitor improvements
""".strip())


# =============================================================================
# WHAT YOU HAVE NOW
# =============================================================================

print("""

WHAT YOU HAVE NOW
═════════════════════════════════════════════════════════════════════════════

📊 ANALYSIS TOOL
  _analyze_passthrough_metrics.py (480 LOC)
    • Extracts stats from MCPMetrics
    • Ranks by volume, tenant count, error rate
    • Auto-categorizes into 3 tiers
    • Outputs console + JSON

📖 DOCUMENTATION
  _PASSTHROUGH_ANALYSIS_GUIDE.md (10 KB)
    • Full integration patterns
    • Production deployment checklist
    • FAQ & troubleshooting
    • Expected outcomes & timeline

📋 QUICK REFERENCE
  _PASSTHROUGH_QUICK_REFERENCE.py (350 LOC)
    • 7 usage patterns
    • Copy-paste integration code
    • Common patterns explained
    • Example function signatures

📈 EXECUTIVE SUMMARY
  _PASSTHROUGH_COMMANDS_SUMMARY.txt (this file)
    • High-level overview
    • Results from demo data
    • Success criteria
    • Implementation checklist

📊 JSON REPORT
  _passthrough_analysis_report.json (auto-generated)
    • Machine-readable output
    • Historical tracking ready
    • Dashboard-friendly format
    • All metrics included


KEY FILES IN MCP SERVER
───────────────────────
  mcp_server.py
    • Already calling record_passthrough_call() ✓
    • Metrics collection active ✓
    • Ready for analysis ✓

  mcp_metrics.py
    • Stores (tenant_id, command) → count
    • Stores (tenant_id, request_id, outcome) → count
    • Thread-safe aggregation ✓

  mcp_config.py
    • Optional: add analysis scheduling config


INTEGRATION POINTS (Pick One)
─────────────────────────────

  [OPTION A] Standalone Demo (Today)
    $ python _analyze_passthrough_metrics.py
    → Outputs summary + JSON
    → No production data needed

  [OPTION B] Direct Import (Production)
    from _analyze_passthrough_metrics import PassthroughAnalyzer
    analyzer = PassthroughAnalyzer(mcp_server.metrics)
    report = analyzer.generate_report()

  [OPTION C] HTTP Endpoint (Dashboard)
    GET /mcp/metrics/passthrough-analysis
    → Returns JSON
    → Integrate with Grafana/DataDog

  [OPTION D] Scheduled Reports (Weekly)
    APScheduler job → generates reports
    → Tracks trends over time
    → Alerts on spikes


EXPECTED OUTCOMES
─────────────────

After running analysis, you'll have:

  ✓ Clear ranking of top 5–10 commands by volume
  ✓ Error rates per command (stability signal)
  ✓ Tenant adoption breadth per command
  ✓ 3-tier roadmap (Phase 1/2/3)
  ✓ Effort & risk estimates for each phase
  ✓ Prioritization for hardening/migration work


TYPICAL FINDINGS (Your Data May Vary)
─────────────────────────────────────

From demo data of 2,537 calls:

  Phase 1 (76% of traffic):
    • 3 commands: run_burp_scan, list_targets, get_report
    • Error rate: 0.2–0.5% (stable, safe to harden)
    • Tenants: All 3 use these (high impact)
    • Action: Complete MCP hardening first

  Phase 2 (19% of traffic):
    • 2 commands: export_findings, check_status
    • Error rate: 0.7–1.1% (acceptable but audit first)
    • Tenants: Some use these
    • Action: Review for error causes before hardening

  Phase 3 (<5% of traffic):
    • 3 commands: admin_config, debug_verbose, experimental_ml
    • Error rate: 2.3–12.5% (high - likely fragile)
    • Tenants: Rare usage
    • Action: Defer or deprecate


YOUR ROADMAP (Typical 8–12 Weeks)
──────────────────────────────────

Week 1–2:
  □ Extract production metrics
  □ Run analyzer on real data
  □ Validate categorization

Week 3–4:
  □ Implement MCP for Phase 1 commands (top 3)
  □ Add arg validation
  □ Error handling + retry logic

Week 5–6:
  □ Test Phase 1 in staging
  □ Measure error rate improvement
  □ Prepare rollout plan

Week 7–8:
  □ Deploy Phase 1 to production
  □ Monitor error rates
  □ Track Venator adoption

Week 9–10:
  □ Audit Phase 2 commands
  □ Investigate high-error commands
  □ Plan Phase 2 implementation

Week 11–12:
  □ Phase 2 hardening & rollout
  □ Phase 3 cleanup (if time permits)


SUCCESS CRITERIA
────────────────

You'll know this is working when:

  ✓ Phase 1 error rate < 1% after hardening
  ✓ 80% of traffic on MCP vs CLI within 4 weeks
  ✓ Support ticket volume decreases for Phase 1 commands
  ✓ Analysis runs weekly; trends are visible
  ✓ Phase 2 risks are identified before hardening


QUESTIONS?
──────────

1. What if my error rates are different?
   → Adjust thresholds in categorize_commands()
   → Re-run analyzer; output adjusts automatically

2. What if Phase 1 has 10 commands instead of 3?
   → Still better to concentrate effort
   → May split into Phase 1a (top 3) and Phase 1b (next 7)

3. How do I know if metric collection is working?
   → Check: does analyzer find any commands?
   → If 0 commands: verify record_passthrough_call() is being called

4. What about latency analysis?
   → Current version tracks error rates
   → Can extend to track latency (P50/P99) if needed

5. Should I wait for perfect data before starting?
   → No! Start with whatever data you have
   → Refine as you collect more metrics


NEXT STEP
─────────

Run this to see demo analysis output:

$ cd "c:\\Users\\ya754\\CaseCrack v1.0"
$ python _analyze_passthrough_metrics.py

Then read the output summary to understand what it means.

""".strip())


# =============================================================================
# ONE-LINER QUICK IMPORTS
# =============================================================================

"""
COPY-PASTE THESE INTO YOUR CODE
════════════════════════════════

# Get analysis report
from _analyze_passthrough_metrics import PassthroughAnalyzer
analyzer = PassthroughAnalyzer(metrics)
report = analyzer.generate_report()

# Get Phase 1 commands
phase1 = report['categories']['core_workflows']['commands']

# Get top 5 commands by volume
top5 = report['rankings']['by_volume'][:5]

# Get Phase 1 stats
phase1_stats = report['categories']['core_workflows']['stats']

# Get error rates
error_rates = [(item['command'], item['error_rate']) 
               for item in report['rankings']['by_error_rate']]

# Get roadmap
roadmap = report['roadmap']
print(f"Phase 1 (HIGH priority): {roadmap['phase_1_high_priority']['action']}")
print(f"Phase 2 (MEDIUM priority): {roadmap['phase_2_medium_priority']['action']}")
print(f"Phase 3 (DEFERRED): {roadmap['phase_3_deferred']['action']}")
"""

# =============================================================================

if __name__ == "__main__":
    import sys
    print("\n" + "="*79)
    print("PASSTHROUGH COMMAND ANALYSIS - QUICK START")
    print("="*79 + "\n")
    
    print("See the script contents for detailed 6-step integration guide.")
    print("Run: python _analyze_passthrough_metrics.py for demo.")
