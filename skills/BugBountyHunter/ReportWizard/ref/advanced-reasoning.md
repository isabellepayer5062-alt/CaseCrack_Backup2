## Advanced Reasoning Primitives

### Tree-of-Thought — Severity Calibration

```
THOUGHT TREE — Is this finding truly High or Medium?
Root: IDOR on /admin/users exposes foreign user emails
├─ Branch A: Critical (CVSS 9.0+)
│  ├─ Evidence: mass data exfiltration possible (confidence 0.30)
│  └─ Counter: only single-record access, no bulk endpoint (confidence 0.70)
├─ Branch B: High (CVSS 7.0–8.9)
│  ├─ Evidence: unauth access to PII, clear impact (confidence 0.85)
│  └─ Counter: no modification possible, limited blast radius (confidence 0.40)
└─ Branch C: Medium (CVSS 4.0–6.9)
   ├─ Evidence: auth required but insufficient (confidence 0.20)
   └─ Counter: no auth required at all (confidence 0.80)

SELECT: Branch B (CVSS 7.5, High — best evidence alignment)
```

### ReAct — Report Validation Loop

```
Observation: PoCForge produced 3-step PoC for IDOR
Thought: Need to verify report reproduces all 3 steps exactly.
Action: Cross-reference poc-steps.md with report.md "Steps to Reproduce"
Observation: Step 2 missing from report
Thought: Report is incomplete. Must add missing step.
Action: Insert Step 2 into report, re-validate completeness
Observation: All 3 steps now present
Thought: Report is complete. Proceed to schema validation.
Action: execute_tool("json_schema_validator", ["--file", "report.json"])
Observation: Schema validation passed
Conclusion: Report is ready for submission
```

### Reflection — Impact Claim Review

```
Claim: "An attacker can access all user data"
Evidence: ["IDOR on /admin/users?id=9999"]
Reflection:
  - Counter-evidence: ["only single-record access confirmed, no bulk endpoint"]
  - Revised claim: "An attacker can access arbitrary individual user records by ID"
  - Revised impact: "Limited to single-record enumeration, not mass exfiltration"
  - Confidence: 0.82 (downgraded from 0.95)
  - Action: Downgrade severity rationale and add enumeration limitation note
```

### Hypothesis Tracking with Confidence Scoring

```python
# Prior: base rate of triager acceptance for this program
confidence_prior = kg_query("acceptance_rate", program="hackerone", severity="High")  # e.g., 0.60

# Evidence: complete PoC + source correlation + CVSS alignment
likelihood_accepted = 0.90
likelihood_rejected = 0.20

confidence_posterior = (
    confidence_prior * likelihood_accepted
) / (
    confidence_prior * likelihood_accepted
    + (1 - confidence_prior) * likelihood_rejected
)
# Result: 0.87 → high confidence, ready for submission
```

---

