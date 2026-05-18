#!/usr/bin/env python3
"""
PHASE 1 SEMANTIC MATCH SPECIFICATION
=====================================

Explicit definitions of what counts as "semantic match" vs "divergence"
for Phase 1 shadow testing.

This is the definitive reference for classifying divergences during
Week 3 staging and Week 4 canary.

GOLDEN RULES:
  1. Ambiguity = blocker
  2. Document all allowed differences
  3. When in doubt, treat as divergence and investigate
  4. Updates to this spec require tech lead approval

================================================================================
RUN_BURP_SCAN SPECIFICATION
================================================================================

Command: run_burp_scan
Purpose: Start a Burp Enterprise scan on a target
Input: {target, scan_profile, timeout_seconds, output_format}
Expected Output: {scan_id, target, profile, status, estimated_time_seconds}

ALLOWED DIFFERENCES:
──────────────────

1. Scan ID Format
   Allowed: UUID vs integer vs alphanumeric string
   Example: 
     Passthrough: {scan_id: "550e8400-e29b"}
     Typed: {scan_id: 12345}
   Why: Internal format doesn't matter
   Verify: IDs are unique and consistent

2. Status Enum Values (case-insensitive)
   Allowed: "queued" vs "Queued" vs "QUEUED"
   Example:
     Passthrough: {status: "queued"}
     Typed: {status: "QUEUED"}
   Why: JSON convention difference
   Verify: Normalize to lowercase before compare

3. Timestamp Variance (±5 seconds)
   Allowed: Clock skew between services
   Example:
     Passthrough: {started_at: "2024-04-15T10:30:00Z"}
     Typed: {started_at: "2024-04-15T10:30:03Z"}
   Why: Network latency, system clock differences
   Verify: timestamp_diff <= 5 seconds

4. Numeric Precision
   Allowed: 180 vs 180.0 for timeout_seconds
   Example:
     Passthrough: {timeout_seconds: 300}
     Typed: {timeout_seconds: 300.0}
   Why: Int vs float JSON representation
   Verify: Values equal when coerced to same type

5. Optional Extra Fields (Typed Superset)
   Allowed: Typed adds new fields not in passthrough
   Example:
     Passthrough: {scan_id, target, status}
     Typed: {scan_id, target, status, correlation_id, version}
   Why: Forward compatibility, newer system has more info
   Verify: All passthrough fields present in typed result

NOT ALLOWED DIFFERENCES:
───────────────────────

1. Missing Fields (Typed is Subset)
   ❌ Passthrough: {scan_id, target, status}
      Typed: {scan_id, target}
   Why: Missing "status" breaks callers checking scan state
   Action: BLOCKER - investigate why field missing

2. Changed Values
   ❌ Passthrough: {target: "example.com"}
      Typed: {target: "example.org"}
   Why: Different target means different behavior
   Action: BLOCKER - check parameter handling

3. Different Statuses
   ❌ Passthrough: {status: "queued"}
      Typed: {status: "failed"}
   Why: Calling code branches on status
   Action: BLOCKER - immediate investigation

4. Structure Change (Wrapper Difference)
   ❌ Passthrough: {scan_id, ...}
      Typed: {scan: {scan_id, ...}}
   Why: Client iteration/field access breaks
   Action: BLOCKER - unless explicitly versioned

5. Success vs Failure
   ❌ Passthrough: {status: "ok"}
      Typed: {error: "timeout"}
   Why: Error handling completely different
   Action: FATAL_DIVERGENCE - rollback

================================================================================
LIST_TARGETS SPECIFICATION
================================================================================

Command: list_targets
Purpose: List targets with optional filtering and pagination
Input: {filter_tag, limit, offset}
Expected Output: {targets: [{id, name, tags}], count, total, limit, offset}

ALLOWED DIFFERENCES:
──────────────────

1. Target Array Ordering
   Allowed: Different order of items in array
   Example:
     Passthrough: [{id: 1, name: "a"}, {id: 2, name: "b"}]
     Typed: [{id: 2, name: "b"}, {id: 1, name: "a"}]
   Why: Order not guaranteed in spec
   Verify: Set comparison (same items, different order)
   ⚠️ Only if docs don't specify "sorted by X"

2. Tags Ordering Within Item
   Allowed: [{tags: ["x", "y"]} vs {tags: ["y", "x"]}]
   Why: Tag order is unordered list
   Verify: Sort tags before compare

3. Count vs Returned Items
   Allowed: count: 25, returned: 25 (always match)
   ✓ Allowed: count field indicates query results
   ✓ Allowed: returned items = count

4. Total Metadata Differences
   Allowed: total: 500 vs total: null
   Example:
     Passthrough: {total: 500}  (exact count)
     Typed: {total: null}       (too expensive to compute)
   Why: Implementation detail
   Verify: Document which is correct behavior

NOT ALLOWED DIFFERENCES:
───────────────────────

1. Different Result Count
   ❌ Passthrough: {count: 25, items: [25 items]}
      Typed: {count: 20, items: [20 items]}
   Why: Caller loops over count, gets mismatched items
   Action: BLOCKER - filter logic differs

2. Missing Items
   ❌ Passthrough: [{id: 1}, {id: 2}, {id: 3}]
      Typed: [{id: 1}, {id: 2}]
   Why: Items dropped unexpectedly
   Action: BLOCKER - filtering/pagination bug

3. Changed Item Structure
   ❌ Passthrough: [{id, name, tags}]
      Typed: [{id, name}]  (missing tags)
   Why: Caller may depend on tags
   Action: BLOCKER - investigate

4. Filter Not Applied
   ❌ Request: filter_tag="prod"
      Passthrough: [{tags: ["prod"]}, {tags: ["dev"]}]  (filtered)
      Typed: [{tags: ["prod"]}, {tags: ["dev"]}]  (all returned)
   Why: Filter parameter ignored
   Action: BLOCKER - parameter handling bug

================================================================================
GET_REPORT SPECIFICATION
================================================================================

Command: get_report
Purpose: Retrieve a previously generated scan report
Input: {report_id, format}
Expected Output: {report_id, created_at, findings_count, severity_distribution}

ALLOWED DIFFERENCES:
──────────────────

1. Report ID Format
   Allowed: UUID vs alphanumeric vs other identifier format
   Example:
     Passthrough: {report_id: "550e8400-e29b"}
     Typed: {report_id: "rpt_12345"}
   Why: Internal representation
   Verify: IDs are consistent and valid

2. Timestamp Format (with ±5 second variance)
   Allowed: "2024-04-15T10:30:00Z" vs 1713181800
   Example:
     Passthrough: {created_at: "2024-04-15T10:30:00Z"}
     Typed: {created_at: 1713181800}
   Why: ISO 8601 vs epoch representation
   Verify: Timestamps convert to within 5 seconds

3. Severity Distribution (as dict vs nested)
   Allowed: Different representation of counts
   Example:
     Passthrough: {severity_distribution: {critical: 1, high: 3}}
     Typed: {findings: [{severity: "critical"}, ...]}
   Why: Different aggregation levels
   ⚠️ Only if semantically equivalent (same totals per severity)

4. Optional Report Metadata
   Allowed: Typed includes extra fields
   Example:
     Passthrough: {report_id, findings_count, severity_distribution}
     Typed: {report_id, findings_count, severity_distribution, scan_duration_sec, engine_version}
   Why: Forward compatibility

NOT ALLOWED DIFFERENCES:
───────────────────────

1. Report Not Found
   ❌ Passthrough: {report_id, findings_count: 5}
      Typed: {error: "not found"}
   Why: Calling code expects report data
   Action: BLOCKER - storage/retrieval difference

2. Wrong Report ID
   ❌ Request: report_id: "550e8400"
      Passthrough: {report_id: "550e8400"}
      Typed: {report_id: "incorrect-id"}
   Why: Wrong report returned
   Action: BLOCKER - critical bug

3. Different Finding Counts
   ❌ Passthrough: {findings_count: 42}
      Typed: {findings_count: 38}
   Why: Results differ
   Action: BLOCKER - parsing/filtering bug

4. Status/Availability Mismatch
   ❌ Passthrough: {status: "ready"}
      Typed: {status: "processing"}
   Why: Report availability different
   Action: BLOCKER - state inconsistency

================================================================================
POLICY SIDE-EFFECT CLASSIFICATION
================================================================================

These are NOT output divergences but BEHAVIOR changes:

SOFT_DIVERGENCE: Quota Exceeded
────────────────────────────────
Request succeeds in passthrough (no quota)
Request fails in typed (quota enforced)

Classification: SOFT_DIVERGENCE (not DIVERGENCE)
Blocking: No (allowed during canary with tracking)
Action: Log separately in policy_impact tracker

Example:
  Passthrough: {status: "ok", result: {...}}
  Typed: {error: "quota_exceeded"}

SOFT_DIVERGENCE: Rate Limited
──────────────────────────────
Request completes in passthrough (no rate limiting)
Request throttled in typed (concurrency limit enforced)

Classification: SOFT_DIVERGENCE
Blocking: No (allowed with tracking)
Action: Log as rate_limit in policy_impact tracker

Example:
  Passthrough: {latency_ms: 50, result: {...}}
  Typed: {latency_ms: 200, result: {...}}  (queued)

SOFT_DIVERGENCE: Authorization Denied
────────────────────────────────────────
Request succeeds in passthrough (no auth check)
Request fails in typed (role-based access enforced)

Classification: SOFT_DIVERGENCE
Blocking: No (expected behavior change)
Action: Log in policy_impact tracker, monitor per-role

Example:
  Passthrough: {status: "ok"}
  Typed: {error: "unauthorized"}

================================================================================
DIVERGENCE CLASSIFICATION MATRIX
================================================================================

                    Same Output    Different Output    Success→Fail
                    ─────────────  ──────────────────  ────────────
Allowed semantics   EXACT_MATCH    SEMANTIC_MATCH      N/A
                    (100% match)   (ordering, fmt)

Policy side-effects N/A            SOFT_DIVERGENCE     SOFT_DIVERGENCE
                    (quota/auth)   (expected)          (quota/auth)

Output mismatch     N/A            DIVERGENCE          FATAL_DIVERGENCE
                    (investigate)  (BLOCKER)           (STOP immediately)

================================================================================
IMPLEMENTATION REFERENCE
================================================================================

Use in DivergenceDetector:

```python
def analyze_divergence(self, pt_result, typed_result, command):
    \"\"\"Classify divergence type\"\"\"
    
    # Check for fatal divergence first
    if self._success_vs_failure_mismatch(pt_result, typed_result):
        return DivergenceAnalysis(
            matches=False,
            classification="FATAL_DIVERGENCE",
            severity=10
        )
    
    # Check for soft divergence (policy side-effect)
    if self._is_policy_side_effect(pt_result, typed_result):
        return DivergenceAnalysis(
            matches=True,  # Not a blocker
            classification="SOFT_DIVERGENCE",
            severity=2  # Low severity, expected
        )
    
    # Check for semantic match (allowed differences)
    if self._is_semantic_match(pt_result, typed_result, command):
        return DivergenceAnalysis(
            matches=True,
            classification="SEMANTIC_MATCH",
            severity=0,
            reason=self._semantic_match_reason
        )
    
    # Check for exact match
    if self._exact_match(pt_result, typed_result):
        return DivergenceAnalysis(
            matches=True,
            classification="EXACT_MATCH",
            severity=0
        )
    
    # Everything else is a blocker divergence
    return DivergenceAnalysis(
        matches=False,
        classification="DIVERGENCE",
        severity=8
    )
```
"""

print(__doc__)
