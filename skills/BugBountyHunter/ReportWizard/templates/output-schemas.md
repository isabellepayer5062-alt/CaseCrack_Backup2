## [TRG-a1b2c3d4] — Broken Access Control on api.example.com

**Severity:** High (CVSS 3.1: 8.1 | CVSS 4.0: 8.3)
**CVSS 3.1 Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
**CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N  _(include when platform supports 4.0)_
**CWE:** CWE-284 — Improper Access Control
**OWASP:** A01:2021 — Broken Access Control
**Asset:** https://api.example.com/admin/users
**Bounty Program:** <program name>
**Researcher:** {{manifest.researcher_handle | env.BB_RESEARCHER_HANDLE | 'anonymous'}}
**Report Date:** <ISO8601>

### Summary
One paragraph. What is the vulnerability, what is the direct impact,
and what attacker capability does it grant?

### Business Impact
What can an unauthenticated or low-privileged attacker do?
What data or accounts are at risk? What is the blast radius?

### Steps to Reproduce
Copy the numbered step sequence from PoCForge exactly.
Include all HTTP requests verbatim.

### Expected vs Observed Behaviour
**Expected:** <what the application should do>
**Observed:** <what actually happens>

### Evidence
- [ ] Screenshot or response body capture: `evidence/<filename>`
- [ ] Raw HTTP request: see `repro-requests.http#step-N`
- [ ] Triage source: `triage-ranked.json#TRG-a1b2c3d4`
- [ ] Source correlation (if available): `source-correlations.json`

### Root Cause (if source available)
File: `app/controllers/admin_controller.py:152`
Guard status: None
Taint path: route → service → DB query without ownership check.

### Remediation
Specific, actionable guidance:
1. <Primary fix>
2. <Defence-in-depth measure>
3. <Test case to verify fix>

### References
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- OWASP A01: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CVSS 3.1 Calculator: https://www.first.org/cvss/calculator/3.1
- CVSS 4.0 Calculator: https://www.first.org/cvss/calculator/4.0
```

### Attack Chain Findings

When a finding originated from a ChainHunter chain, replace the standard
`## [TRG-id]` section with this extended template:

```markdown
## [CHAIN-id] — <chain_class>: <chain_title>

**Type:** Attack Chain ({{chain_class}})
**Compound CVSS:** <compound_cvss_score>
**Steps:** <N>-step chain
**Bounty Program:** <program name>
**Report Date:** <ISO8601>

### Chain Summary
<chain_narrative from chains-discovered.json>

One paragraph explaining: why each step is necessary, what the cumulative
impact is, and why this chain is more severe than any individual finding.

### Chain Steps

#### Step 1 — <step_title>
**Asset:** <step.asset>
**Technique:** <step.technique>
**Precondition:** <step.precondition>

<HTTP request verbatim>

**Observed:** <step.expected_outcome>

#### Step 2 — <step_title>
...

### Business Impact
What is the combined impact? What can an attacker achieve by completing
all steps? Reference the individual CVSS scores and explain the escalation.

### Evidence
- [ ] Step-by-step execution log: `evidence/chain_exec_CHAIN-id.log`
- [ ] All step requests: `repro-requests.http#CHAIN-id`
- [ ] Chain source: `chains-discovered.json#CHAIN-id`

### Remediation
Address the chain break points in priority order:
1. Break Step 1 (highest leverage): <fix>
2. Break Step 2 (defence in depth): <fix>

### Rollback Notes
<rollback_plan.note from chains-discovered.json>
```

## `report.json` Schema

Emit one JSON object per finding conforming to:

```jsonc
{
  "$schema": "file://schemas/bb-report.2026-05.schema.json",
  "report_version": "2026.05",
  "run_id": "<run_id>",
  "researcher_handle": "{{manifest.researcher_handle | env.BB_RESEARCHER_HANDLE | 'anonymous'}}",
  "generated_at": "<ISO8601>",
  "findings": [
    {
      "id": "TRG-a1b2c3d4",
      "chain_id": null,              // "CHAIN-xxx" when finding originates from ChainHunter
      "title": "Broken Access Control on api.example.com/admin/users",
      "severity": "High",
      "cvss_score": 8.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
      "cvss_vector_40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",  // null when platform doesn't support CVSS 4.0
      "cvss_temporal_score": null,           // populated when oracle_score ≥ gate_threshold
      "cvss_temporal_vector": null,          // CVSS 3.1 temporal vector; null if no confirmed PoC
      "cwe_id": "CWE-284",
      "owasp_category": "A01:2021",
      "asset": "https://api.example.com/admin/users",
      "vuln_class": "Broken Access Control",
      "confidence": 0.82,
      "oracle_score": 90,
      "validation_outcome": "success",
      "waf_bypass_found": false,
      "waf_bypass_exhausted": false,
      "poc_complexity": "trivial",
      "estimated_bounty_usd_range": [500, 2000],
      "has_source_correlation": true,
      "guard_status": "none",
      "evidence_files": [
        "evidence/recon-normalized.jsonl",
        "evidence/triage-ranked.json",
        "evidence/repro-requests.http"
      ],
      "remediation_summary": "Enforce ownership check before returning user records.",
      "status": "ready_for_submission"
    }
  ],
  "summary": {
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "informational": 0,
    "total_estimated_bounty_usd_min": 0,
    "total_estimated_bounty_usd_max": 0,
    "oracle_confirmed": 0,
    "waf_bypasses_found": 0
  }
}
```

## `triager-checklist.md`

One H2 section per finding with a checklist the triager can tick off:

```markdown
## [TRG-id] — <title>

### Researcher Verification (pre-submission)
- [ ] Severity matches CVSS base score calculation
- [ ] CVSS temporal score includes E:P (PoC exists) if PoC is complete
- [ ] Reproduction steps are complete and self-contained
- [ ] Evidence files are referenced and accessible
- [ ] No real user data was accessed or included in the report
- [ ] Impact claim is supported by a PoC step or oracle confirmation
- [ ] Remediation guidance is specific and actionable
- [ ] CWE and OWASP references are correct
- [ ] Report is free of speculative claims
- [ ] Oracle score: {{oracle_score}} / gate threshold: {{gate_threshold_for_vuln_class}}
      // Thresholds: Race Condition=70, Blind SSRF=75, Stored XSS=80, Default=85
- [ ] Intra-run dedup: no duplicate `(fqdn, vuln_class, endpoint)` tuple merged in this report
- [ ] Cross-platform dedup: \[PENDING — Platform Submission module will query platform API for prior submissions\]
- [ ] Rate-limit compliance: all requests within 2/s per host

### For Chain Findings (if applicable)
- [ ] Compound CVSS re-computed at each escalation step
- [ ] Each chain step individually verifiable
- [ ] Impact delta ≥ 1.5 over highest individual finding
```

## CVSS Temporal Score

When a complete PoC exists (oracle_score ≥ gate_threshold), include
the CVSS 3.1 Temporal score in addition to the Base score:

| Temporal Metric | Value | Condition |
|----------------|-------|-----------|
| Exploit Code Maturity (E) | `P` (Proof-of-Concept) | PoC exists and validated |
| Exploit Code Maturity (E) | `U` (Unproven) | candidate status only |
| Remediation Level (RL) | `U` (Unavailable) | Default for new findings |
| Report Confidence (RC) | `C` (Confirmed) | oracle_score ≥ gate_threshold |
| Report Confidence (RC) | `R` (Reasonable) | partial_fail outcome |

Emit the temporal fields in `report.json` alongside the canonical base fields:
```jsonc
{
  "cvss_score": 8.1,                    // canonical base score — always present
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  // canonical base vector
  "cvss_vector_40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",  // optional; include when platform supports CVSS 4.0
  "cvss_temporal_score": 7.5,           // additive; null if no confirmed PoC
  "cvss_temporal_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N/E:P/RL:U/RC:C"  // additive
}
```

> **Field naming contract:** Use `cvss_score` / `cvss_vector` (not `cvss_base_score` /
> `cvss_base_vector`) as the canonical root fields throughout `report.json`.
> Temporal and CVSS 4.0 values are *additive* — they extend but never replace the
> primary `cvss_score` and `cvss_vector` fields that the Platform Submission module reads.

