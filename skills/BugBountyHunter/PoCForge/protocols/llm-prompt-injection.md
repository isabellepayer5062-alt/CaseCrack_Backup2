    safety_scope enforces:
      - in_scope_hosts only
      - non_destructive_only (no state-changing requests)
      - require_test_account: true
      - max_request_rate_per_host: 2
    """
```

## Dynamic Dependency & Swarm Graph

PoCForge can spawn parallel PoC workers for different complexity levels:

```yaml
swarm_workers:
  - worker_id: poc-trivial
    condition: "finding.poc_complexity == trivial"
    max_steps: 2
    model: anthropic/claude-sonnet-4-6
    priority: 1
    note: "2 steps needed for credentialed CORS (origin check + credentialed response check)"
  - worker_id: poc-moderate
    condition: "finding.poc_complexity == moderate"
    max_steps: 5
    model: anthropic/claude-sonnet-4-6
    priority: 2
  - worker_id: poc-complex
    condition: "finding.poc_complexity == complex"
    max_steps: 10
    model: openai/gpt-5.5
    escalate_tags: [complex_agentic, exploit_poc, race_condition]
    priority: 3
```

### Blackboard Protocol

Each worker writes PoC hypotheses:

```jsonc
{
  "worker_id": "poc-moderate",
  "phase": "P4",
  "hypothesis": "IDOR on /admin/users?id=9999 via sequential ID enumeration",
  "confidence": 0.85,
  "evidence": ["http_200_with_foreign_user_data", "no_auth_header_required"],
  "poc_steps": 3,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "timestamp": "<ISO8601>",
  "status": "confirmed"
}
```

## Validation & Reflection Loop

Validator checks for PoCForge:

```yaml
validator_poc:
  checks:
    - cvss_completeness: "all_8_base_metrics_present"
    - step_completeness: "every_step_has_precondition_request_expected_rollback"
    - safety_compliance: "no_destructive_requests"
    - test_account_usage: "auth_header_uses_test_token_placeholder"
