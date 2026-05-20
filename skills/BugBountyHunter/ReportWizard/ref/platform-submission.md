## Platform Submission

> **Activation condition**: runs only when `target_platform` is set in the run manifest
> AND `auto_submit != false`. When inactive, the submission bundle in `submission/`
> is still produced — operators can submit manually. The Report Generation phases
> above run unconditionally.

This section is the direct continuation of the report pipeline. After all reports are
finalized and the submission bundle is written, ReportWizard proceeds to platform
submission. A **mandatory human review gate** fires before any API call.

### Platform Support Matrix

| Platform | API Version | Auth Method | Draft Support |
|----------|------------|-------------|---------------|
| HackerOne | v1 | Personal API token (`X-Auth-Token`) | Yes (draft state) |
| Bugcrowd | v4 | API token (`Authorization: Token`) | Yes (unsubmitted state) |
| Intigriti | v2 | OAuth2 Bearer | Yes |
| YesWeHack | v1 | JWT Bearer | No |

### Cross-Platform Deduplication

> **Scope:** This pass queries the **live platform API** for reports already
> submitted to this program in prior runs. It is distinct from the intra-run
> deduplication above (which merges duplicate triage entries within the current
> scan batch). Both passes must complete before a finding is submission-ready:
> intra-run dedup runs first during report generation; platform API dedup runs
> second here, immediately before the human review gate.

Before submitting, query the platform API for open and closed reports against this program:

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

### Human Review Gate

**No API call to submit is made until this gate fires and is confirmed:**

```
HUMAN REVIEW GATE — ReportWizard Submission
=============================================
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
  [ ] Intra-run dedup: confirmed by report generation phase (no duplicate tuples)
  [ ] Cross-platform dedup: platform API check passed (no prior submissions match)
  [ ] CVSS vector matches narrative

Type CONFIRM to proceed with submission, or DRAFT to create draft only.
```

This prompt is surfaced to the operator via the MCP tool
`casecrack.reportwizard.review_gate`.

### Submission Workflow

```
1. Load submission bundle from submission/ directory
2. For each finding in report.json:
   a. Run cross-platform deduplication check
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

### Platform Payload Templates

#### HackerOne

Auth: `X-Auth-Token: {{env.HACKERONE_TOKEN}}`

```json
{
  "data": {
    "type": "report",
    "attributes": {
      "title": "{{finding.title}}",
      "vulnerability_information": "{{report.md content}}",
      "severity_rating": "{{severity_to_h1_rating}}",
      "cvss_vector": "{{finding.cvss_vector}}",
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

> HackerOne supports CVSS 4.0 as of 2024. When `finding.cvss_vector_40` is present,
> include `"cvss_vector_v4": "{{finding.cvss_vector_40}}"` alongside the 3.1 vector.
> When `finding.cvss_temporal_vector` is present (PoC confirmed), include
> `"cvss_temporal_vector": "{{finding.cvss_temporal_vector}}"`.

#### Bugcrowd

Auth: `Authorization: Token {{env.BUGCROWD_TOKEN}}`

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

#### Intigriti

Auth: `Authorization: Bearer {{env.INTIGRITI_TOKEN}}`
Endpoint: `POST https://api.intigriti.com/core/researcher/submission`

```json
{
  "title": "{{finding.title}}",
  "description": "{{report.md content}}",
  "impactDetails": "{{finding.impact_summary}}",
  "type": { "value": "{{cwe_to_intigriti_type}}" },
  "domain": { "value": "{{finding.asset}}" },
  "severity": { "value": "{{severity_to_intigriti_value}}" },
  "personalNote": "Generated by CaseCrack BugBountyHunter — run_id: {{run_id}}"
}
```

Severity mapping: `Critical→5`, `High→4`, `Medium→3`, `Low→2`, `Informational→1`

#### YesWeHack

Auth: `Authorization: Bearer {{env.YESWEHACK_TOKEN}}`
Endpoint: `POST https://api.yeswehack.com/programs/{{program_handle}}/reports`

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

### Submission Output Schemas

#### `submission-receipts.json`

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

#### `submission-log.md`

```markdown
# Submission Log — {{run_id}}

