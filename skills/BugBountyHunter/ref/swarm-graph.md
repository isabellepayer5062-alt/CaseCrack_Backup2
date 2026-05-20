## Dynamic Dependency & Swarm Graph

The orchestrator maintains a live dependency DAG and can spawn parallel
micro-agents (swarm workers) per phase.

```yaml
swarm:
  enabled: true
  max_workers_per_phase: 10
  blackboard:
    path: /workspace/blackboard/{{run_id}}.jsonl
    format: jsonl
    ttl_hours: 48
  worker_spawn_rules:
    ReconAnalyzer:
      - variant: default
        seed: null
      - variant: deep_dns
        seed: dns_brute_force
        tool: subfinder -all -recursive
      - variant: permutations
        seed: alt_dns_permutations
        tool: dnsgen + massdns
    TrafficTriage:
      - variant: default
      - variant: auth_surface_focus
        filter: "endpoint matches /(login|oauth|reset|session|auth)/i"
      - variant: api_surface_focus
        filter: "content_type matches /json|graphql/i"
```

### Blackboard Protocol

Each worker writes hypotheses to the blackboard:

```jsonc
{
  "worker_id": "ReconAnalyzer-deep_dns-3",
  "phase": "P1",
  "hypothesis": "api-v2.example.com is an undocumented staging endpoint",
  "confidence": 0.71,
  "evidence": ["dns_brute_force_hit", "httpx_200_no_redirect"],
  "timestamp": "<ISO8601>",
  "status": "proposed | confirmed | rejected"
}
```

The orchestrator reads the blackboard after each phase, merges confirmed
hypotheses into the canonical phase output, and rejects outliers via
inter-quartile confidence filtering.

