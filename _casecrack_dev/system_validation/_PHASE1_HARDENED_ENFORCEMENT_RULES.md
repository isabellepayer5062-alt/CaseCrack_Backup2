#!/usr/bin/env python3
"""
PHASE 1 HARDENED ENFORCEMENT RULES
===================================

🔒 5 NON-NEGOTIABLE RULES (Hard Gates, Not Advisory)
🔹 4 CRITICAL GAPS CLOSED (Explicit Definitions)

This document locks in production-grade enforcement for Phase 1 migration.

RULE VIOLATIONS = STOP DEPLOYMENT (zero overrides)

================================================================================
🔒 RULE 1: NO CANARY WITHOUT READINESS AUDIT PASSING 100%
================================================================================

DEFINITION:
-----------
_PHASE1_READINESS_AUDIT.py is not advisory—it is a hard gate.

REQUIREMENT:
  All 15 checks MUST pass:
  ✓ Files exist
  ✓ Imports working
  ✓ Tool definitions complete
  ✓ Parameter validators (edge cases)
  ✓ Policy enforcer (role/quota/concurrency)
  ✓ Shadow runner operational
  ✓ Divergence detection working
  ✓ Fail-safe mode operational
  ✓ Load test results acceptable
  ✓ Latency overhead <20%
  ✓ mcp_server integration wired
  ✓ Metrics collection working
  ✓ Regression detection ready
  ✓ Phase 1 dependencies traced
  ✓ Deployment configuration ready

ENFORCEMENT:
  1. Run at end of Week 3: python _PHASE1_READINESS_AUDIT.py
  2. Record output to _phase1_readiness_audit_report.json
  3. Check exit code: 0 = proceed, 1 = STOP
  4. If FAIL:
     - Do not deploy
     - Do not "test anyway"
     - Do not override or skip
     - Fix failed checks and re-run
  5. If PASS:
     - Proceed to Week 4 canary
     - Attach audit report to PR/ticket

CODE ENFORCEMENT:
  ```python
  import subprocess
  import sys
  
  # Week 3 sign-off gate
  result = subprocess.run(
      ["python", "_PHASE1_READINESS_AUDIT.py"],
      capture_output=True
  )
  
  if result.returncode != 0:
      sys.exit("❌ READINESS AUDIT FAILED - DO NOT PROCEED")
  
  print("✅ READINESS AUDIT PASSED - SAFE TO PROCEED")
  ```

ESCALATION:
  If ANY check fails:
  → Escalate to tech lead
  → File blocking issue
  → Must fix before retry

================================================================================
🔒 RULE 2: NO PROGRESSION IF DIVERGENCE ≠ 0
================================================================================

DEFINITION:
-----------
Your migration plan says "≥99% match" but we're pushing harder for Phase 1:

👉 TREAT ANY UNEXPLAINED DIVERGENCE AS A BLOCKER

RATIONALE:
  - Phase 1 commands are highest volume (76% of traffic)
  - These are foundational behavior that downstream systems depend on
  - Unlike Phase 2/3, divergence here breaks contracts for many callers

ENFORCEMENT:

  Week 2 (Testing):
  ─────────────────
  Run: python _phase1_divergence_detection.py
  Expected: 0 divergences (or all classified as "EXACT_MATCH")
  
  If divergences found:
  → Investigate root cause
  → Either fix typed implementation OR accept and document
  → MUST be resolved before Week 3 staging

  Week 3 (Staging - Critical Path):
  ──────────────────────────────────
  Run shadow test for 7 days at 100% concurrency
  
  Requirement: ZERO unexplained divergences
  
  Allowed divergences (documented):
  ✓ EXACT_MATCH: Identical normalized output
  ✓ SEMANTIC_MATCH: Logically equivalent, different structure (only if approved)
  
  NOT allowed:
  ✗ DIVERGENCE: Output mismatch (investigate why)
  ✗ FATAL_DIVERGENCE: One succeeded, one failed (STOP immediately)
  ✗ SOFT_DIVERGENCE: Policy side-effect (document but don't ignore)
  
  Blocking criteria:
  - > 0.1% divergence rate → STOP
  - Any FATAL_DIVERGENCE → STOP immediately
  - Unresolved SOFT_DIVERGENCE → STOP
  
  Code gate:
  ```python
  def check_divergence_blocking(report):
      divergence_rate = report['divergence_count'] / report['total_requests']
      fatal_count = report['fatal_divergence_count']
      
      if divergence_rate > 0.001:  # >0.1% is failure
          raise Exception(f"DIVERGENCE BLOCKER: {divergence_rate*100:.2f}%")
      
      if fatal_count > 0:
          raise Exception(f"FATAL DIVERGENCE BLOCKER: {fatal_count} failures")
  
  check_divergence_blocking(phase1.shadow_runner.get_readiness_report())
  ```

WEEK 4 IMPLICATIONS:
  If any divergence remains:
  - 10% canary → abort, scale back to staging
  - 50% canary → abort, scale back to 10% or disable
  - 100% canary → rollback immediately

================================================================================
🔒 RULE 3: FAIL-SAFE MODE MUST BE ON AT 10% CANARY
================================================================================

DEFINITION:
-----------
You built fail-safe mode—use it.

At early rollout (Week 4 10% stage):
  - typed fails → fallback to passthrough
  - log as CRITICAL divergence
  - return passthrough result to user (no visible breakage)

REQUIREMENT:

  Week 4, Days 1-3 (10% Canary):
  ── Environment ──
  MCP_PHASE1_SHADOW_LEVEL=soft
  MCP_PHASE1_FAILSAFE_ENABLED=true
  
  ── Initialization ──
  phase1.failsafe.enabled = True
  phase1.shadow_runner.mode = "soft"  # passthrough wins
  
  ── Behavior ──
  For each Phase 1 request:
  1. Execute typed implementation
  2. If typed succeeds → use typed result (shadow passive mode)
  3. If typed fails AND passthrough succeeds:
     → Return passthrough result
     → Log CRITICAL divergence
     → Record metric: failsafe_triggered += 1
  4. If both fail → return error to user
  
  Week 4, Days 4-6 (50% Canary):
  ── Precondition ──
  Must have zero failsafe triggers at 10%
  
  If failsafe_triggered > 0:
  → Keep at 10%
  → Investigate typed failures
  → Fix bugs or disable typed
  → Do not progress to 50%
  
  ── When Can Turn Off ──
  - Stable at 50%+ for 3 days
  - Zero typed failures
  - Zero failsafe triggers in past 24h
  
  ── Turn Off Process ──
  MCP_PHASE1_FAILSAFE_ENABLED=false
  MCP_PHASE1_SHADOW_LEVEL=full  # typed wins
  
  Week 4, Day 7+ (100% Canary):
  ── Requirement ──
  Fail-safe remains OFF
  Shadow mode = "full" or "strict"
  Only production strength at this point

CODE ENFORCEMENT:
  ```python
  # Week 4 canary startup
  if deployment_stage == "canary_10":
      phase1.failsafe.enabled = True
      phase1.shadow_runner.mode = "soft"
      logger.info("✅ Fail-safe mode ENABLED for 10% canary")
  elif deployment_stage == "canary_50":
      # Check precondition
      if phase1.failsafe.get_critical_divergences():
          raise Exception("Cannot progress: failsafe triggered at 10%")
      phase1.failsafe.enabled = False
      phase1.shadow_runner.mode = "full"
      logger.info("✅ Fail-safe mode DISABLED after 10% clear")
  elif deployment_stage == "canary_100":
      assert phase1.failsafe.enabled == False, "Failsafe should be off at 100%"
  ```

MONITORING:
  Track in metrics dashboard:
  - failsafe_triggers_per_minute
  - failsafe_total_count
  - failsafe_last_triggered_timestamp
  
  Alert if:
  - failsafe_triggers > 0 in 24h at 50%+
  - failsafe_triggers > 5 in any 1h period

================================================================================
🔒 RULE 4: LOAD TEST MUST REFLECT REAL PEAK (NOT AVERAGE)
================================================================================

DEFINITION:
-----------
Your _phase1_load_test.py is powerful—but only if used correctly.

❌ DO NOT test average concurrency
✅ DO test worst-case burst scenarios

REQUIREMENT:

  Step 1: Measure Your Real Peak
  ──────────────────────────────
  Before Week 3, collect:
  - Daily max concurrent Phase 1 requests
  - P95 / P99 concurrency spikes
  - Sustained peak duration (minutes/hours?)
  
  Example data:
  ```
  Current production:
    - Average: 5 concurrent
    - P95: 15 concurrent
    - P99: 28 concurrent
    - Peak spike: 80 concurrent (lasted 3 minutes, once per week)
  ```

  Step 2: Test at Peak + Buffer
  ──────────────────────────────
  If your P99 is 28: test 30+
  If your peak spike is 80: test 100+
  
  Run:
  ```python
  harness = LoadTestHarness(mcp_server)
  report = await harness.run_load_test(
      "run_burp_scan",
      concurrency_levels=[10, 30, 50, 80, 100],  # Peak + buffer
      requests_per_level=200,  # More samples = better confidence
      test_timeout_seconds=600  # 10 minutes per level
  )
  ```

  Step 3: Validate Against Requirements
  ──────────────────────────────────────
  PASS criteria:
  - All levels: latency_p99 < 2000ms (2 seconds acceptable)
  - All levels: overhead < 20%
  - No queue buildup pattern (p99 doesn't spike >50% from p50)
  - safe_concurrency_ceiling >= your_peak_spike
  
  FAIL criteria:
  - Any level: latency_p99 > 2000ms
  - Any level: overhead >= 20%
  - Queue buildup detected
  - safe_concurrency_ceiling < your_peak_spike
  
  Example:
  ```python
  max_p99 = max(level.typed_latency.p99_ms for level in report.concurrency_levels)
  if max_p99 > 2000:
      raise Exception(f"FAIL: p99 latency {max_p99}ms exceeds 2000ms")
  
  if report.safe_concurrency_ceiling < your_peak_spike:
      raise Exception(f"FAIL: Ceiling {report.safe_concurrency_ceiling} < peak {your_peak_spike}")
  ```

  Step 4: Document Findings
  ──────────────────────────
  Create _phase1_load_test_report_week3.json:
  ```json
  {
    "real_peak_concurrency": 80,
    "test_concurrency_levels": [10, 30, 50, 80, 100],
    "max_p99_latency_ms": 1450,
    "safe_ceiling": 100,
    "verdict": "PASS - Ready for 100+ concurrent in production"
  }
  ```

ENFORCEMENT:
  ```python
  def validate_load_test(report, real_peak):
      max_p99 = max(level.typed_latency.p99_ms for level in report.concurrency_levels)
      
      # Blocker 1: Latency SLA
      if max_p99 > 2000:
          raise Exception(f"❌ BLOCKER: p99 latency {max_p99}ms exceeds SLA")
      
      # Blocker 2: Ceiling safety margin
      required_ceiling = real_peak * 1.25  # 25% buffer
      if report.safe_concurrency_ceiling < required_ceiling:
          raise Exception(f"❌ BLOCKER: Ceiling {report.safe_concurrency_ceiling} < required {required_ceiling}")
      
      # Blocker 3: Overhead
      avg_overhead = mean(level.overhead_pct for level in report.concurrency_levels)
      if avg_overhead >= 20:
          raise Exception(f"❌ BLOCKER: Avg overhead {avg_overhead}% >= 20%")
      
      return True
  
  validate_load_test(report, real_peak_concurrency=80)
  ```

================================================================================
🔒 RULE 5: PASSTHROUGH REMOVAL MUST BE ENFORCED, NOT ASSUMED
================================================================================

DEFINITION:
-----------
After Week 5, you should have zero tolerance for passthrough calls.

Week 5 Decommissioning:
  1. Disable passthrough implementations for Phase 1 commands
  2. Activate regression detector: mark_migration_complete()
  3. Set alert threshold: passthrough_calls = 0 tolerance
  4. Archive shadow logs

Week 5+:
  ANY Phase 1 passthrough call = regression alert
  One call = alert (not "sum up and report daily")

REQUIREMENT:

  Code:
  ─────
  ```python
  # Week 5 finalization
  phase1.regression_detector.mark_migration_complete()
  phase1.shadow_runner.enabled = False
  
  # In request dispatch:
  if command in phase1_commands:
      if passthrough_path_taken:
          # This should never happen after Week 5
          phase1.regression_detector.check_regression(command, request)
          # Logs CRITICAL alert immediately
  ```

  Metrics Dashboard:
  ──────────────────
  Chart: "Phase 1 Passthrough Calls After Week 5"
  Target: Zero
  Alert: If > 0 in any 1-hour window
  
  Second metric: "Regression Detector Triggered"
  Alert if triggered = immediate paging

  Monitoring:
  ────────────
  Check every 6 hours:
  - Sum of Phase 1 passthrough calls (must be 0)
  - Number of regression alerts (must be 0)
  - If either > 0: page on-call engineer
  
  Weekly review:
  - Phase 1 typed_percentage (must be 99.9%+)
  - Passthrough calls (must be 0)
  - Divergence count (must be 0)

INCIDENT RESPONSE:
  If passthrough call detected after Week 5:
  
  1. Immediate actions:
     - Page on-call team
     - Investigate request logs (who? when? why?)
     - Check for configuration drift
     - Check for code bypass attempts
  
  2. Diagnosis questions:
     - Is the passthrough path still enabled? (it shouldn't be)
     - Is there a fallback somewhere? (find and disable)
     - Is Phase 2/3 calling Phase 1 internally? (dependency leak)
     - Is this a feature bypass attempt? (security issue)
  
  3. Resolution:
     - If code bug: fix and deploy hotfix
     - If config drift: correct configuration
     - If dependency leak: wire Phase 2/3 through typed path
     - If security breach: escalate to security team

================================================================================
🔹 GAP 1: DEFINE "SEMANTIC MATCH" EXPLICITLY
================================================================================

PROBLEM:
--------
"It looks fine" decisions kill migrations.
Ambiguity about what counts as "match" breaks shadow testing.

SOLUTION: Explicit Definitions
─────────────────────────────────

What IS Semantic Match (ALLOWED):
──────────────────────────────────

1. ORDERING DIFFERENCES
   Allowed if:
   - Arrays with same items (different order)
   - Example: [1,2,3] vs [3,1,2]
   - Why: Order doesn't matter for set-like results
   
   NOT allowed if:
   - Order matters (e.g., sorted scan results by severity)
   - Documentation says "results ordered by X"

2. TIMESTAMP VARIANCE
   Allowed if:
   - Timestamps within ±5 seconds of each other
   - Why: Network latency + clock skew
   - Applied to: created_at, modified_at, started_at fields
   
   NOT allowed if:
   - Timestamp differs by >5 seconds
   - ISO format differs (8601 vs epoch vs custom)

3. OPTIONAL FIELDS
   Allowed if:
   - Typed returns extra fields (superset)
   - Example: {id, name} vs {id, name, metadata}
   - Why: Forward compatibility
   
   NOT allowed if:
   - Typed omits fields (subset)
   - Example: {id} vs {id, name}
   - Why: Callers may depend on fields

4. NUMERIC TYPE COERCION
   Allowed if:
   - 100 (int) vs "100" (string) in JSON
   - Why: JSON type differences
   
   NOT allowed if:
   - 100 vs 101 (different values)
   - 100 vs 100.0 when decimals matter

5. NULL VS EMPTY
   Allowed if:
   - null vs missing field (same semantic)
   - Example: {count: null} vs {} (no count field)
   - Why: JSON representation difference
   
   NOT allowed if:
   - null vs empty list/object when they differ semantically

What IS NOT Semantic Match (BLOCKER):
──────────────────────────────────────

1. MISSING FIELDS
   Example: Passthrough returns {id, name, status}
            Typed returns {id, name}
   Status: 🛑 DIVERGENCE (must investigate)
   Why: Caller may depend on status field

2. CHANGED VALUES
   Example: Passthrough returns {count: 42}
            Typed returns {count: 41}
   Status: 🛑 DIVERGENCE (different behavior)
   Why: Calling code breaks if values differ

3. DIFFERENT RESULT COUNTS
   Example: Passthrough returns 100 items
            Typed returns 95 items
   Status: 🛑 DIVERGENCE (filtering difference)
   Why: Caller loops over results, count mismatch breaks logic

4. SUCCESS/FAILURE MISMATCH
   Example: Passthrough succeeds {status: "ok"}
            Typed fails {error: "timeout"}
   Status: 🛑 FATAL_DIVERGENCE (immediate rollback)
   Why: Error handling completely different

5. STRUCTURE CHANGES
   Example: Passthrough returns [{item}]
            Typed returns {items: [{item}]}
   Status: 🛑 DIVERGENCE (unless explicitly wrapped)
   Why: Calling code iteration breaks

IMPLEMENTATION:
───────────────
```python
class DivergenceDetector:
    ALLOWED_SEMANTIC_DIFFERENCES = {
        'ordering': True,
        'timestamp_variance_seconds': 5,
        'optional_extra_fields': True,
        'numeric_type_coercion': True,
        'null_vs_missing_field': True,
    }
    
    def is_semantic_match(self, pt_result, typed_result):
        """Check if results are semantically equivalent"""
        
        # Check for blockers first
        if self._is_missing_fields(pt_result, typed_result):
            return False, "MISSING_FIELDS"
        
        if self._changed_values(pt_result, typed_result):
            return False, "CHANGED_VALUES"
        
        if self._different_count(pt_result, typed_result):
            return False, "DIFFERENT_COUNT"
        
        if self._success_failure_mismatch(pt_result, typed_result):
            return False, "FATAL_DIVERGENCE"
        
        # Check for allowed differences
        if self._ordering_difference(pt_result, typed_result):
            return True, "ORDERING_DIFFERENCE_OK"
        
        if self._timestamp_variance(pt_result, typed_result, variance_sec=5):
            return True, "TIMESTAMP_VARIANCE_OK"
        
        # If no differences found at all
        return True, "EXACT_MATCH"
```

DOCUMENTATION:
───────────────
Store in _PHASE1_SEMANTIC_MATCH_SPEC.md:
- Matrix of allowed vs blocked differences
- Examples for each command (run_burp_scan, list_targets, get_report)
- Reference for code review of divergence classification

================================================================================
🔹 GAP 2: FREEZE TOOL SCHEMAS DURING MIGRATION
================================================================================

PROBLEM:
--------
If you change tool definitions during migration (Weeks 3-5):
- Your shadow comparisons become invalid
- Old vs new have different parameters
- Divergence detector can't compare apples to apples

SOLUTION: Schema Freeze
────────────────────────

Phase 1 Tool Definitions are LOCKED for Weeks 3-5:
  ✅ Parameters (target, scan_profile, timeout_seconds)
  ✅ Validation rules (min/max, enum values, format checks)
  ✅ Output format (response structure, field names)
  ✅ Policy rules (role access, quota limits, concurrency)

ENFORCEMENT:

  Week 1-2: Changes allowed
  ────────
  Can modify:
  - Tool schemas
  - Validation logic
  - Output format
  
  Must do:
  - Test all changes thoroughly
  - Document all changes
  - Update divergence detector if needed
  
  Week 3: FREEZE (Staging Test)
  ──────
  No changes allowed
  
  If bugs found:
  - Fix in separate issue (post-migration)
  - Document known issue
  - Do not change schema
  
  Week 4: FREEZE (Canary)
  ──────
  No changes allowed
  
  Exception process:
  - Critical prod bug only (page on-call)
  - Require tech lead sign-off
  - Re-run divergence detector after change
  - Re-run load test if parameters changed
  
  Week 5: FREEZE (Stabilization)
  ───────
  No changes allowed
  
  After Week 5 (Phase 2): Changes allowed again

CODE ENFORCEMENT:
─────────────────
```python
# Define frozen schemas
PHASE1_FROZEN_SCHEMAS = {
    "run_burp_scan": {
        "version": "v1",
        "frozen_at": "2024-04-15T00:00:00Z",
        "frozen_until": "2024-04-28T00:00:00Z",
        "parameters": ["target", "scan_profile", "timeout_seconds", "output_format"],
    },
    # ... other commands
}

def check_schema_changes():
    """Verify schemas haven't changed"""
    current_schema = ToolDefinitions().get_run_burp_scan()
    frozen_schema = PHASE1_FROZEN_SCHEMAS["run_burp_scan"]
    
    # Check parameters match
    current_params = set(current_schema["parameters"].keys())
    frozen_params = set(frozen_schema["parameters"])
    
    if current_params != frozen_params:
        raise Exception(f"❌ Schema change detected: {current_params} != {frozen_params}")
    
    return True

# At boot time during Weeks 3-5:
if in_migration_weeks_3_5():
    check_schema_changes()
    logger.info("✅ Schema freeze verified")
```

CHANGE CONTROL:
────────────────
If critical fix needed during freeze:
1. File issue with title: "SCHEMA CHANGE REQUEST: [reason]"
2. Get approval from: tech lead + release manager
3. Document in: PHASE1_SCHEMA_CHANGES_LOG.md
4. Include: "Re-validation: divergence detector, load test"
5. Estimated time: 2-4 hours (includes testing)

================================================================================
🔹 GAP 3: CAPTURE GOLDEN DATASET BEFORE STAGING
================================================================================

PROBLEM:
--------
If you only compare against current results:
- Can't detect regressions across versions
- Debugging issues takes much longer
- "Did this work before?" requires log archaeology

SOLUTION: Golden Dataset
────────────────────────

Before Week 3 Staging Test:
  Capture 20-50 representative requests per command
  Store expected outputs in _PHASE1_GOLDEN_DATASET.json

This gives you:
  ✓ Deterministic regression testing
  ✓ Faster debugging (expected vs actual)
  ✓ Evidence trail for validation

COLLECTION PROCESS:

Step 1: Select Representative Scenarios
─────────────────────────────────────────
For run_burp_scan:
  ✓ Quick scan on www.example.com (basic)
  ✓ Standard scan on complex app (typical)
  ✓ Thorough scan on slow target (slow)
  ✓ Scan with unusual characters in target (edge)
  ✓ Timeout scenario (failure case)

For list_targets:
  ✓ List all (no filter)
  ✓ List with tag filter (filter)
  ✓ List with limit=1 (pagination)
  ✓ List with large offset (edge)
  ✓ Empty result set (no targets)

For get_report:
  ✓ Report exists (normal)
  ✓ Report in progress (not ready)
  ✓ Report not found (invalid ID)
  ✓ Report with many findings (large result)

Step 2: Run Against Current (Week 3 Start)
────────────────────────────────────────────
```python
from _phase1_divergence_detection import DivergenceDetector

detector = DivergenceDetector()

scenarios = [
    # run_burp_scan scenarios
    {"command": "run_burp_scan", "params": {"target": "www.example.com", "scan_profile": "quick"}, "name": "basic_quick"},
    {"command": "run_burp_scan", "params": {"target": "app.example.com", "scan_profile": "standard"}, "name": "typical_standard"},
    # ... more scenarios
]

golden_dataset = {}
for scenario in scenarios:
    result = execute_typed(scenario["command"], scenario["params"])
    detector.snapshot_baseline_output(
        scenario["command"],
        scenario["name"],
        result
    )
    golden_dataset[f"{scenario['command']}:{scenario['name']}"] = {
        "params": scenario["params"],
        "result": result,
        "captured_at": datetime.now().isoformat(),
    }

# Save golden dataset
with open("_PHASE1_GOLDEN_DATASET.json", "w") as f:
    json.dump(golden_dataset, f, indent=2)
```

Step 3: Store in Repository
─────────────────────────────
```
_PHASE1_GOLDEN_DATASET.json
├─ run_burp_scan:basic_quick
│  ├─ params: {target, scan_profile}
│  ├─ result: {scan_id, status, ...}
│  └─ captured_at: 2024-04-15T10:30:00Z
├─ run_burp_scan:typical_standard
│  ├─ params: {...}
│  └─ result: {...}
├─ list_targets:all
├─ list_targets:filtered
├─ get_report:exists
└─ ...
```

Step 4: Use for Regression Testing
────────────────────────────────────
During Week 3-5:
```python
def check_regression_vs_golden():
    with open("_PHASE1_GOLDEN_DATASET.json") as f:
        golden = json.load(f)
    
    regressions = []
    for scenario_name, golden_data in golden.items():
        command, _ = scenario_name.split(":")
        current_result = execute_typed(command, golden_data["params"])
        
        regression = detector.check_regression(command, current_result)
        if regression['is_regression']:
            regressions.append({
                "scenario": scenario_name,
                "expected": golden_data["result"],
                "actual": current_result,
                "difference": regression['difference'],
            })
    
    if regressions:
        raise Exception(f"❌ {len(regressions)} regressions detected")
    
    return True

check_regression_vs_golden()
```

Step 5: Archive After Migration
──────────────────────────────────
After Week 5:
  cp _PHASE1_GOLDEN_DATASET.json _PHASE1_GOLDEN_DATASET_WEEK5_FINAL.json
  
Use for future:
  - Baseline for Phase 2 migration (shows what Phase 1 looks like)
  - Regression detection in production
  - Debugging when things go wrong

================================================================================
🔹 GAP 4: LOG POLICY IMPACT SEPARATELY
================================================================================

PROBLEM:
--------
Policy side-effects (quota denials, rate limits) are not output divergence.
But they ARE behavior changes that affect users.

If typed enforces quotas and passthrough didn't:
- Same input, different behavior
- Not a divergence in shadow runner sense
- But definitely a change users will notice

SOLUTION: Separate Policy Impact Logging
──────────────────────────────────────────

Track three categories:

1. WOULD_HAVE_BEEN_DENIED_BY_POLICY
   ────────────────────────────────────
   Definition:
     Request succeeds in passthrough
     Request would be denied by policy in typed
   
   Example:
     - User has free plan, daily quota = 10
     - User already made 10 calls today
     - Passthrough: allows 11th call (no enforcement)
     - Typed: denies 11th call with "quota exceeded"
   
   Action:
     - Log as SOFT_DIVERGENCE
     - Don't block shadow runner (expected behavior)
     - But track separately:
   
   Metric:
     phase1_policy_denied_count (track by policy type)
     - quota_exceeded
     - role_unauthorized
     - concurrency_exceeded

2. WOULD_HAVE_BEEN_RATE_LIMITED
   ────────────────────────────────
   Definition:
     Request succeeds in passthrough
     Request would be rate-limited by policy in typed
   
   Example:
     - 100 concurrent list_targets calls
     - Passthrough: allows all
     - Typed: throttles after 10 concurrent
   
   Action:
     - Log as SOFT_DIVERGENCE with classification "RATE_LIMIT"
     - Track response time impact:
   
   Metric:
     phase1_rate_limited_count (track by limit type)
     - concurrency_limit_exceeded
     - quota_limit_exceeded

3. WOULD_HAVE_BEEN_THROTTLED
   ─────────────────────────────
   Definition:
     Request takes longer in typed due to policy
   
   Example:
     - Passthrough: 50ms response time (no validation)
     - Typed: 120ms response time (validation + policy check)
   
   Action:
     - Not a divergence (same result)
     - But track separately:
   
   Metric:
     phase1_policy_latency_overhead_ms
     - validation_overhead_ms
     - policy_check_overhead_ms
     - total_overhead_ms

CODE IMPLEMENTATION:
────────────────────
```python
class PolicyImpactTracker:
    def __init__(self):
        self.policy_denials = defaultdict(int)
        self.rate_limits = defaultdict(int)
        self.latency_overhead = []
    
    def log_would_have_been_denied(self, command, principal, reason):
        """Log policy denial that would have happened"""
        self.policy_denials[reason] += 1
        logger.warning(
            f"Policy denial (simulation): {command} from {principal.user} "
            f"- reason: {reason}"
        )
    
    def log_would_have_been_rate_limited(self, command, limit_type):
        """Log rate limiting that would have happened"""
        self.rate_limits[limit_type] += 1
        logger.warning(
            f"Rate limit (simulation): {command} - type: {limit_type}"
        )
    
    def log_latency_overhead(self, command, overhead_ms):
        """Log latency impact from policy checks"""
        self.latency_overhead.append({
            "command": command,
            "overhead_ms": overhead_ms,
            "timestamp": datetime.now().isoformat(),
        })
    
    def get_policy_report(self):
        """Generate policy impact report"""
        return {
            "policy_denials": dict(self.policy_denials),
            "rate_limits": dict(self.rate_limits),
            "latency_overhead": {
                "samples": len(self.latency_overhead),
                "mean_ms": mean([x["overhead_ms"] for x in self.latency_overhead]),
                "max_ms": max([x["overhead_ms"] for x in self.latency_overhead]),
            }
        }

# In shadow runner / typed path:
policy_tracker = PolicyImpactTracker()

# When policy would deny:
if policy_result['would_deny']:
    policy_tracker.log_would_have_been_denied(
        command, principal, policy_result['reason']
    )

# Track in metrics:
metrics.record_policy_impact(policy_tracker.get_policy_report())
```

REPORTING:
───────────
In Week 3 readiness report, include policy impact section:

```json
{
  "policy_impact": {
    "potential_denials": {
      "quota_exceeded": 47,
      "role_unauthorized": 0,
      "concurrency_exceeded": 5
    },
    "potential_rate_limits": {
      "concurrency_limit": 12,
      "quota_limit": 3
    },
    "latency_overhead": {
      "mean_ms": 8.5,
      "max_ms": 23,
      "p95_ms": 15
    },
    "assessment": "Policy impact acceptable - only edge cases affected"
  }
}
```

WEEK 4 MONITORING:
───────────────────
Track during canary:
- Are denials happening at expected rate?
- Are users accepting new policy constraints?
- Do we need to adjust thresholds?

If policy too strict:
- Increase quota limits
- Increase concurrency limits
- But don't remove enforcement (contract violation)

If policy too lenient:
- Good, less user friction
- But monitor for abuse

================================================================================
IMPLEMENTATION CHECKLIST
================================================================================

Week 1 (Development):
  □ Implement 5 core modules (tool defs, validators, policy, shadow, divergence)
  □ Implement load test harness
  □ Implement safety upgrades (fail-safe, metrics, regression detection)
  □ Document semantic match spec
  □ Run Python syntax check on all files
  □ Run import tests

Week 2 (Testing):
  □ Test all validators with edge cases
  □ Test policy enforcer (role/quota/concurrency)
  □ Test shadow runner in isolation
  □ Test divergence detector (exact, semantic, fatal)
  □ Document schema for freeze
  □ Test all emergency procedures

Week 3 (Staging):
  □ Freeze tool schemas
  □ Capture golden dataset (20-50 scenarios per command)
  □ Run shadow test for 7 days at 100% concurrency
  □ Run load test (peak + buffer)
  □ Verify zero unexplained divergences
  □ Run _PHASE1_READINESS_AUDIT.py (all 15 checks pass)
  □ Document any expected policy impacts
  □ Sign off: ready for canary

Week 4 (Canary):
  □ Enable fail-safe mode at 10% (MCP_PHASE1_FAILSAFE_ENABLED=true)
  □ Monitor for 3 days (expect zero failsafe triggers)
  □ If zero triggers: progress to 50%
  □ Disable fail-safe at 50%
  □ Monitor for 3 days
  □ If stable: progress to 100%
  □ Monitor for 7 days at 100%

Week 5 (Finalization):
  □ Mark regression detector active
  □ Disable shadow runner
  □ Disable passthrough for Phase 1 commands
  □ Archive shadow logs
  □ Set up regression alert: passthrough_calls = 0 tolerance
  □ Generate final completion report

Week 6+ (Operations):
  □ Monitor regression detector (should be silent)
  □ Monitor metrics (typed_percentage = 99.9%+)
  □ Monthly review: are we ready for Phase 2?

================================================================================
SIGN-OFF
================================================================================

Once all 5 rules and 4 gaps are locked in:
  □ Tech lead signs this document
  □ Release manager confirms enforcement
  □ QA lead confirms test procedures
  □ Ops lead confirms monitoring/alerting

Expected outcome:
  ✅ Phase 1 migration is production-grade
  ✅ Safety mechanisms are non-negotiable
  ✅ Divergence is investigated, not ignored
  ✅ Load testing reflects real world
  ✅ No surprises during canary or production

Questions? See:
  _PHASE1_COMPLETE_DELIVERY_PACKAGE.md
  _PHASE1_INTEGRATION_COMPLETE.md
  _PHASE1_READINESS_AUDIT.py
"""

print(__doc__)
