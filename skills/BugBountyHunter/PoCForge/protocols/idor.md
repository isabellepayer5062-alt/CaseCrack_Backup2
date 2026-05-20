    - reproducibility: "http_file_is_valid_rfc9110"
    - race_safety: "race_conditions_described_not_executed"
    - deterministic_headers: "X-Bug-Bounty-Researcher and X-Request-ID on every request"
    - evidence_bundle_present: "evidence/{poc_id}/ has step requests and responses"
    - chain_impact_validated: "chain PoCs confirm cumulative impact or set chain_impact_partially_demonstrated"
    - waf_auto_probe_logged: "WAF bypass starts with 4-probe auto-probe before full matrix"
    - metrics_emitted: "poc-metrics.json present with correct top-level fields"
```

### Self-Reflection Prompt

```
REFLECTION CHECKPOINT â€” PoCForge:
1. Did I compute CVSS from all 8 base metrics, not guess?
2. Is every PoC step safe (read-only or described-only for races)?
3. Do all auth headers use <attacker_test_token> placeholder?
4. Is the HTTP file valid RFC 9110 syntax?
5. For race conditions: did I describe the window without executing it, and include the single-threaded timing probe steps?
6. Did I emit the evidence bundle (evidence/{poc_id}/) with all required artifact files?
7. Is X-Bug-Bounty-Researcher and X-Request-ID present on every request?
8. For chain PoCs: did I verify cumulative impact or mark chain_impact_partially_demonstrated?
9. For WAF blocks: did I attempt the 4 auto-probes before the full bypass matrix?
10. Did I emit poc-metrics.json at run end?
```

## Persistent Memory & Learner

Pre-hunt retrieval:

```python
# Query for historically effective PoC patterns (Neo4j Cypher â€” not SPARQL)
effective_pocs = execute_tool("update_kg", [
    "--cypher",
    "MATCH (f:Finding)-[:exploited_via]->(t:Technique) "
    "WHERE f.triager_accepted_rate IS NOT NULL "
    "RETURN t.name AS pattern, avg(f.cvss_score) AS avg_cvss, "
    "avg(f.triager_accepted_rate) AS success_rate "
    "ORDER BY success_rate DESC LIMIT 10"
])
# Use top patterns as PoC templates
```

Post-hunt update:

```python
update_knowledge_graph(
    outcome_type="successful_poc" if triager_accepted else "false_positive",
    target_fqdn=finding.fqdn,
    vuln_class=finding.vuln_class,
    cwe_id=finding.cwe_id,
    attack_pattern=f"poc:{finding.poc_complexity}:{finding.cvss_vector}",
    protocol_used=finding.active_protocol,        # e.g., "SSRF Redirect Loop Oracle"
    waf_bypass_strategy=finding.waf_bypass_strategy,
    evidence_quality_score=finding.evidence_quality_score,
    time_to_triage_hours=finding.triage_response_time_hours,
    tool_efficacy={"http_replay": 0.95, "playwright_replay": 0.7},
    reporter_confidence=finding.confidence,
    triager_accepted=triager_accepted,
    triager_rejection_reason=finding.rejection_reason,
    bounty_payout_usd=bounty_payout,
    notes=f"PoC complexity: {finding.poc_complexity}, CVSS: {finding.cvss_score}"
)
# Per-protocol acceptance tracking for learning loop
update_knowledge_graph(
    entity_type="Protocol",
    name=finding.active_protocol,
    vuln_class=finding.vuln_class,
    accepted=triager_accepted,
    bounty_payout_usd=bounty_payout
)
```

## Exploit Chaining Protocol

PoCForge consumes ChainHunter output for complex findings:

```yaml
chain_hunter_consumption:
  input: "{{phase_outputs.ChainHunter.chains-discovered.json}}"
  poc_input: "{{phase_outputs.ChainHunter.chain-poc-requests.md}}"
  mapping:
    - chain_state: entry
      poc_step: "Step 1: Access entry endpoint"
    - chain_state: authentication
      poc_step: "Step 2: Bypass auth (if bypassable)"
    - chain_state: authorization
      poc_step: "Step 3: Escalate privileges (if bypassable)"
    - chain_state: middleware
      poc_step: "Step 4: Bypass input validation"
    - chain_state: sink
      poc_step: "Step 5: Reach vulnerable sink"
    - chain_state: impact
      poc_step: "Step 6: Confirm impact"
```

For each `chain_finding` in `chains-discovered.json`:
1. Map each chain step to a PoCForge step using the chain's `steps[].endpoint` and `attacker_capability_gained`.
2. Inherit the `chain-poc-requests.md` step sequences verbatim as starting points.
3. Add `rollback` fields from the chain's `rollback_plan` to each step.
4. Compute a fresh CVSS from the compound attacker position.
5. Validate that the PoC steps collectively demonstrate the cumulative impact
   stated in the chain's `chain_impact_summary`:
   - Each step's `attacker_capability_gained` must be observable in the step response.
   - The final step must confirm the worst-case impact (e.g., admin access, data exfil).
   - If full chain cannot be safely demonstrated in replay: mark
     `chain_impact_partially_demonstrated: true` and document what manual confirmation
     would require.

## Advanced Reasoning Primitives

### Tree-of-Thought â€” PoC Strategy Selection

```
THOUGHT TREE â€” What is the minimum effective PoC for this IDOR?
Root: /admin/users?id=9999 returns foreign user data without auth
â”œâ”€ Branch A: Single GET request with attacker session
â”‚  â”œâ”€ Evidence: 200 OK with victim data (confidence 0.95)
â”‚  â””â”€ PoC: 1 step, trivial complexity
