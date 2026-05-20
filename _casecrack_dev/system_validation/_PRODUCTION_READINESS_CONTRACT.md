# Production Readiness Contract

Date: 2026-04-25
Scope: MCP backend, transport, adapter, intelligence and explanation layers, dashboard fidelity
Decision model: Binary. If any blocking item is unproven, status is NOT READY.

## Release Rule

Production Ready means all 5 layers are proven with objective evidence:

1. Backend correctness (tools and policy outcomes)
2. Transport integrity (SSE and snapshot reconciliation)
3. Adapter invariants (identity, immutability, dedupe, bounded growth, convergence)
4. Intelligence and explanation correctness (deterministic, evidence-backed, consistent)
5. UI fidelity (render-only, no logic drift)

A single failed or unproven blocking criterion in any layer fails release.

## Evidence Model

Each criterion must have:

- Test ID
- Input scenario
- Expected output
- Observed output
- Verdict (PASS or FAIL)
- Artifact path (report, log, screenshot, JSON)

Required release artifacts:

- Frontend integration gate report JSON
- Tri-state validator report JSON
- Adapter invariant stress report JSON
- Transport chaos test report JSON
- Intelligence and explanation determinism report JSON
- UI leakage audit report
- Concurrency/load benchmark report

## Layer 1: Backend Correctness (Blocking)

### Must prove

- Every exposed tool returns request_id on accepted execution paths.
- Every failure returns structured outcome: ok, error, code.
- Policy enforcement is correct for ALLOWLIST_DENY, LICENSE_REQUIRED, RATE_LIMITED.
- No silent success and no silent failure.

### Required tests

- CP-001 Valid execution returns success envelope.
- CP-002 Invalid tool returns ALLOWLIST_DENY.
- CP-003 No license returns LICENSE_REQUIRED.
- CP-004 Burst traffic triggers RATE_LIMITED.
- CP-005 Malformed input returns HTTP 400 with structured error.
- CP-006 Per-tool coverage matrix is 100 percent for policy and envelope assertions.

### Pass condition

- 100 percent passing on CP-001..CP-006.
- 100 percent per-tool policy/envelope coverage.

## Layer 2: Transport Integrity (Blocking)

### Must prove

- Normal request, SSE result, and snapshot converge to same terminal truth.
- Missing terminal event recovers from snapshot without data loss.
- SSE disconnect during in-flight operations reconciles all actions after reconnect.
- Out-of-order events do not corrupt final state.
- Duplicate events do not create duplicate records.

### Required tests

- TX-001 Normal flow convergence.
- TX-002 Missing terminal event recovery.
- TX-003 Disconnect mid-flight with 3+ concurrent actions.
- TX-004 Out-of-order event delivery (result before pending).
- TX-005 Duplicate event replay for same request_id.

### Pass condition

- 100 percent passing on TX-001..TX-005.
- No pending leftovers after reconciliation windows close.

## Layer 3: Adapter Invariants (Blocking)

### Required invariants

- INV-001 request_id uniqueness under replay and burst.
- INV-002 final-state immutability (success/error never regresses, final never returns to pending).
- INV-003 missing terminal recovery remains correct.
- INV-004 bounded history under burst 250+ with pending retention (cap 200).
- INV-005 snapshot and SSE convergence after arbitrary event sequences.

### Stress profile

- Burst tests: 250, 500, and 1000 action synthetic streams.
- Replay tests: duplicate and out-of-order injections.
- Reconciliation tests: repeated disconnect/reconnect cycles.

### Pass condition

- 100 percent passing on INV-001..INV-005.
- No duplicate request_id and no state regression in any stress run.

## Layer 4: Concurrency and Load (Blocking)

### Must prove

- Concurrency ramps 1, 5, 10, 25, 50 are stable.
- Backpressure behaves predictably under sustained load.
- Mixed outcomes (success, error, rate-limit) are represented correctly without hangs.

### Required tests

- LD-001 Concurrency ramp with latency and error histograms.
- LD-002 Sustained load backpressure and queue depth tracking.
- LD-003 Mixed-outcome correctness at high concurrency.

### Pass condition

- No deadlocks, no hangs, no silent drops.
- Rate limiting appears when expected and is reflected correctly in adapter state.
- Latency and failure rates remain within declared SLOs.

## Layer 5: Intelligence Correctness (Blocking)

### Must prove

- No false positives below configured thresholds.
- No missed anomalies for defined detectable patterns.
- Deterministic outputs for identical history windows.
- Every recommendation maps to evidence and includes reason.

### Required tests

- IN-001 Threshold sanity (single error does not trigger anomaly).
- IN-002 Repeated error cluster always detected when threshold met.
- IN-003 Determinism check with fixed replay fixture.
- IN-004 Recommendation evidence binding validation.

### Pass condition

- 100 percent passing on IN-001..IN-004.
- No recommendation emitted without supporting evidence object.

## Layer 6: Explainability Correctness (Blocking)

### Must prove

- No hallucination: each explanation field maps to deterministic source.
- Internal consistency: no contradictory statements in same output.
- Confidence behavior: increases with corroboration, decreases with conflict.

### Source mapping contract

- summary: dominant severity and anomaly frequency
- situation: warnings and anomalies aggregation
- causes: deterministic signal-to-cause rules
- projectedOutcome: deterministic forward rules
- recommendedActions: passthrough from recommendation engine

### Required tests

- EX-001 Field provenance validation.
- EX-002 Contradiction detector on explanation object.
- EX-003 Confidence monotonicity and conflict penalty checks.

### Pass condition

- 100 percent passing on EX-001..EX-003.
- No contradiction in any fixture set.

## Layer 7: UI Fidelity (Blocking)

### Must prove

- No logic leakage to UI: no direct MCP calls outside adapter and no dashboard-side anomaly heuristics.
- UI reflects adapter outputs only: getSystemState and getSystemExplanation.
- Rendering remains stable under rapid updates and 100+ action views.

### Required tests

- UI-001 Static leakage scan for disallowed patterns.
- UI-002 Render truth parity against adapter snapshots.
- UI-003 Stress rendering with rapid update cadence.

### Pass condition

- 0 leakage findings.
- 100 percent parity for sampled render snapshots.
- No duplicate or stale rows during stress.

## End-to-End Scenario Suite (Blocking)

- E2E-001 Offline to degraded to healthy progression.
- E2E-002 Burst with rate limiting and corrective recommendation.
- E2E-003 Transport failure with reconciliation and stability explanation.
- E2E-004 Persistent license failure with anomaly and correct recommendation.

Pass condition: all scenarios PASS with saved artifacts.

## Final Release Gate

Release is READY only when all are true:

- Integration gate verdict is GO.
- Tri-state validator verdict is GO.
- Adapter invariants PASS.
- Zero duplicate request_id.
- Zero state regression events.
- Zero UI logic leakage findings.
- Explanation consistency checks PASS.
- Concurrency and transport recovery proofs PASS.

If any single item is FAIL or UNPROVEN, release verdict is NOT READY.

## Decision Output Format

Use this exact release output:

- verdict: READY or NOT_READY
- failed_blockers: [list of failed or unproven blocking IDs]
- passed_blockers: [list of passed blocking IDs]
- evidence_index: [artifact paths]
- timestamp: ISO-8601
