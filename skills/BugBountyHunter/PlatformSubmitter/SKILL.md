---
name: PlatformSubmitter
version: "2026.05"
description: >
  Automates submission of completed bug bounty reports to HackerOne, Bugcrowd,
  Intigriti, or YesWeHack via their respective APIs. Deduplicates against
  previously submitted findings. Handles draft → submit workflow with a
  mandatory human review gate.

model_routing:
  default: anthropic/claude-sonnet-4-6
  rules:
    - when:
        tags_any: [complex_agentic]
      model: openai/gpt-5.5
  fallback:
    - anthropic/claude-sonnet-4-5
    - openai/gpt-5.5-mini

runtime:
  prompt_caching:
    enabled: true
    ttl_seconds: 86400
  token_budget:
    max_total_tokens_per_run: 20000
    hard_fail_on_overflow: true
  temperature: 0.1
  retry:
    max_attempts: 2
    backoff_seconds: [15, 45]
  on_error:
    action: abort_and_emit
    emit_to: /workspace/errors/{{run_id}}.json

observability:
  emit_phase_events: true
  log_token_usage: true

inputs:
  required:
    - name: report_json
      type: json_file
      path: "{{phase_outputs.ReportWizard.report.json}}"
    - name: report_md
      type: text_file
      path: "{{phase_outputs.ReportWizard.report.md}}"
    - name: submission_bundle
      type: directory
      path: "{{phase_outputs.ReportWizard.submission}}"
    - name: scope_roots
      type: text_file
      path: "{{env.ROOT_SCOPE_FILE}}"

policies:
  operation_mode: non_destructive_only
  in_scope_required: true
  human_review_required: true
  review_gate: always_before_submit
  allow_draft_only_mode: true
  no_pii_in_payload: true
  rate_limit: 5_reports_per_hour
  scope_check_before_submit: true

tags: [submission, reporting, hackerone, bugcrowd, platform]
---

# PlatformSubmitter

## Purpose

PlatformSubmitter automates the final mile of bug bounty operations — taking
the structured report from ReportWizard and submitting it to the target
platform. A **mandatory human review gate** fires before any submission is
sent. PlatformSubmitter can also run in `draft_only` mode to create drafts
without final submission.

## Platform Support Matrix

| Platform | API Version | Auth Method | Draft Support |
|----------|------------|-------------|---------------|
| HackerOne | v1 | Personal API token (`X-Auth-Token`) | Yes (draft state) |
| Bugcrowd | v4 | API token (`Authorization: Token`) | Yes (unsubmitted state) |
| Intigriti | v2 | OAuth2 Bearer | Yes |
| YesWeHack | v1 | JWT Bearer | No |

## Cross-Platform Deduplication Protocol

> **Scope:** This pass queries the **live platform API** for reports already
> submitted to this program in prior runs. It is distinct from ReportWizard's
> intra-run deduplication (which merges duplicate triage entries within the
> same scan batch). Both passes must complete before a finding is submission-ready:
> ReportWizard runs first (intra-run merge), PlatformSubmitter runs second
> (cross-platform API check).

Before submitting, PlatformSubmitter queries the platform API for open and
closed reports against this program:

```python
def is_duplicate(finding_id: str, platform: str, program_handle: str) -> bool:
    """
    Returns True if a finding with matching (title_hash OR endpoint+vuln_class)
    was previously submitted and is in state: new, triaged, resolved, informative.
    """
```

Matching criteria:
- **Primary key**: SHA256 of `(endpoint_fqdn, vuln_class, parameter)` normalized
- **Secondary key**: semantic similarity ≥ `{{manifest.dedup_similarity_threshold | 0.88}}` of title (embedding comparison)
- If duplicate found: skip submission, log to `submission-log.md` with `status: duplicate_skipped`

## Human Review Gate

**No API call to submit is made until this gate fires and is confirmed:**

```
HUMAN REVIEW GATE — PlatformSubmitter
========================================
Run ID: {{run_id}}
Target Program: {{program_handle}}
Platform: {{target_platform}}
Findings to submit: {{n}}

Submission bundle:
  - submission/report-{{run_id}}.md   (review this)
  - submission/report-{{run_id}}.json (raw JSON)
  - submission/triager-checklist.md   (verify checklist)

BEFORE CONFIRMING — check:
  [ ] Severity is accurate and not overstated
  [ ] PoC steps are clear and reproducible
  [ ] No sensitive data (credentials, PII) in report
  [ ] Scope confirmed in-program
  [ ] Intra-run dedup: confirmed by ReportWizard (no duplicate tuples in report)
  [ ] Cross-platform dedup: PlatformSubmitter API check passed (no prior submissions match)
  [ ] CVSS vector matches narrative

Type CONFIRM to proceed with submission, or DRAFT to create draft only.
```

This prompt is surfaced to the operator via the MCP tool
`casecrack.platformsubmitter.review_gate`.

## Submission Workflow

```
1. Load submission bundle from ReportWizard output
2. For each finding in report.json:
   a. Run deduplication check
   b. If duplicate → log, skip
   c. If not duplicate → prepare platform-specific payload
3. Fire HUMAN REVIEW GATE (block until confirmed)
4. If operator selects DRAFT:
   a. If target_platform == "YesWeHack":
      → Log WARNING: "YesWeHack does not support draft submissions.
        Select CONFIRM to submit directly or abort."
      → Return to gate — do NOT submit
   b. For all other platforms: create draft report
   c. Return draft URL in submission-receipts.json
5. If operator selects CONFIRM:
   a. Submit report via platform API
   b. Record submission ID, timestamp, status
   c. Write to submission-receipts.json
6. Write full submission-log.md
```

## Platform Payload Templates

### HackerOne

```json
{
  "data": {
    "type": "report",
    "attributes": {
      "title": "{{finding.title}}",
      "vulnerability_information": "{{report.md content}}",
      "severity_rating": "{{severity_to_h1_rating}}",
      "cvss_vector": "{{finding.cvss_vector}}",
      // Include CVSS 4.0 vector when present (HackerOne supports CVSS 4.0 as of 2024)
      // "cvss_vector_v4": "{{finding.cvss_vector_40}}",
      // Include temporal vector when PoC is confirmed
      // "cvss_temporal_vector": "{{finding.cvss_temporal_vector}}",
      "weakness_id": "{{cwe_to_h1_weakness_id}}",
      "attachments": []
    },
    "relationships": {
      "program": {
        "data": { "type": "program", "attributes": { "handle": "{{program_handle}}" } }
      }
    }
  }
}
```

Severity mapping: `Critical→critical`, `High→high`, `Medium→medium`, `Low→low`, `Informational→none`

### Bugcrowd

```json
{
  "bug_report": {
    "target_name": "{{program_handle}}",
    "title": "{{finding.title}}",
    "description": "{{report.md content}}",
    "vrt_id": "{{cwe_to_vrt_category}}",
    "severity": "{{severity_to_bc_p_rating}}"
  }
}
```

Severity mapping: `Critical→P1`, `High→P2`, `Medium→P3`, `Low→P4`, `Informational→P5`

### Intigriti

API v2, OAuth2 Bearer token (`Authorization: Bearer {{env.INTIGRITI_TOKEN}}`).

```json
{
  "title": "{{finding.title}}",
  "description": "{{report.md content}}",
  "impactDetails": "{{finding.impact_summary}}",
  "type": {
    "value": "{{cwe_to_intigriti_type}}"
  },
  "domain": {
    "value": "{{finding.asset}}"
  },
  "severity": {
    "value": "{{severity_to_intigriti_value}}"
  },
  "personalNote": "Generated by CaseCrack BugBountyHunter — run_id: {{run_id}}"
}
```

Severity mapping: `Critical→5`, `High→4`, `Medium→3`, `Low→2`, `Informational→1`
Endpoint: `POST https://api.intigriti.com/core/researcher/submission`

### YesWeHack

API v1, JWT Bearer token (`Authorization: Bearer {{env.YESWEHACK_TOKEN}}`).

```json
{
  "title": "{{finding.title}}",
  "scope": "{{finding.asset}}",
  "vulnerability_type": "{{cwe_to_ywh_type}}",
  "severity": "{{severity_to_ywh_level}}",
  "proof_of_concept": "{{report.md content}}",
  "description": "{{finding.remediation_summary}}",
  "local_id": "{{finding.id}}"
}
```

Severity mapping: `Critical→critical`, `High→high`, `Medium→medium`, `Low→low`, `Informational→info`
Endpoint: `POST https://api.yeswehack.com/programs/{{program_handle}}/reports`

### submission-receipts.json

```jsonc
{
  "run_id": "<run_id>",
  "platform": "hackerone",
  "program_handle": "<handle>",
  "submitted_at": "<ISO8601>",
  "submissions": [
    {
      "finding_id": "TRG-a1b2c3d4",
      "platform_report_id": "1234567",
      "status": "submitted",
      "submission_url": "https://hackerone.com/reports/1234567",
      "draft_only": false,
      "attachments_uploaded": []
    }
  ],
  "skipped": [
    {
      "finding_id": "TRG-e5f6g7h8",
      "reason": "duplicate_skipped",
      "duplicate_of": "1100000"
    }
  ]
}
```

### submission-log.md

Human-readable log of all submission actions:

```markdown
# Submission Log — {{run_id}}

## Summary
- Platform: HackerOne
- Program: {{program_handle}}
- Submitted: 2 / 3 findings
- Skipped (duplicate): 1
- Submitted at: {{ISO8601}}

## Submissions
### TRG-a1b2c3d4
- Status: submitted
- Report ID: #1234567
- URL: https://hackerone.com/reports/1234567

### TRG-e5f6g7h8
- Status: duplicate_skipped
- Duplicate of: #1100000
```

## Safety & Security Constraints

```yaml
safety_constraints:
  - no_submission_without_human_gate: true
  - no_pii_in_payload: true           # Validated before send
  - no_credentials_in_payload: true   # Strip any detected creds
  - rate_limit: 5_reports_per_hour
  - draft_only_mode_available: true
  - scope_check_before_submit: true   # Re-validate in-scope
  - dry_run_mode_available: true      # Log payload without sending
```

## execute_tool Contract

```python
def execute_tool(
    tool_name: str,
    args: List[str],
    safety_scope: SafetyScope,
    timeout_seconds: int = 30
) -> ToolResult:
    """
    PlatformSubmitter: API calls only to approved platform endpoints.
    safety_scope enforces:
      - allowed_hosts: [api.hackerone.com, api.bugcrowd.com, api.intigriti.com, api.yeswehack.com]
      - no_real_user_data: true
      - human_gate_confirmed: required before any POST
    """
```

## Validation Checks

```yaml
validator_submit:
  checks:
    - human_gate_confirmed: "gate must have fired and been confirmed"
    - no_pii: "no email/phone/IP/credential detected in payload"
    - in_scope: "endpoint matches program scope"
    - dedup_passed: "deduplication query completed"
    - receipt_written: "submission-receipts.json written after each submit"
    - rate_limit_honoured: "no more than 5 submissions per hour"
```

## REFLECTION CHECKPOINT — PlatformSubmitter

```
1. Did the human review gate fire before ANY API call?
2. Are all submitted findings confirmed in-scope for this program?
3. Was deduplication checked against the platform's existing reports?
4. Is the submission bundle free of PII and credentials?
5. Was the receipt written for every submission (including skipped)?
6. Did I append submission outcomes to the blackboard for LearnerReflector?
```

## Blackboard Protocol

PlatformSubmitter appends submission outcomes to the shared blackboard:

```jsonc
{
  "worker_id": "platform-submitter",
  "phase": "P6",
  "finding_id": "TRG-a1b2c3d4",
  "platform": "hackerone",
  "platform_report_id": "1234567",
  "submission_status": "submitted",  // submitted | draft_only | duplicate_skipped | aborted
  "duplicate_of": null,
  "timestamp": "<ISO8601>",
  "status": "complete"
}
```

LearnerReflector reads these entries to update the `Hunt` node with submission
outcomes and to track which platform accepted vs. flagged-as-duplicate reports.

## Anti-Hallucination Rules

- Never fabricate a submission receipt — write `status: draft_only` if
  the platform API call was not actually made.
- Never claim a finding was accepted (triager decision) in `submission-log.md`
  unless the platform returned an explicit accepted/resolved status code.
- Never include severity labels higher than the ReportWizard assigned
  severity without explicit human override in the review gate.
- Never submit to a program whose scope does not include the affected FQDN —
  re-verify scope against `scope_roots` input before every API call.
- Never store or log API tokens or session cookies in `submission-log.md`.
- If `draft_only_mode: true` is set, write `[DRAFT — not submitted]`
  as the first line of every receipt entry.
- Never retry a failed submission more than once without re-firing
  the human review gate.
