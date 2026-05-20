## Persistent Memory & Learner

Cross-run intelligence is stored in a local RAG + knowledge graph that
compounds with every hunt.

```yaml
memory:
  rag_store:
    path: /bb/memory/rag/
    embedding_model: openai/text-embedding-3-large
    chunk_size: 512
    overlap: 64
  knowledge_graph:
    path: /bb/memory/kg/
    schema: openclaw/kg/bb-kg-schema-2026-05.ttl
    update_on: [confirmed_finding, rejected_hypothesis, successful_poc]
```

### update_knowledge_graph Contract

```python
def update_knowledge_graph(
    outcome_type: Literal["confirmed_finding", "rejected_hypothesis", "successful_poc", "false_positive"],
    target_fqdn: str,
    vuln_class: str,
    cwe_id: str,
    attack_pattern: str,
    guard_bypass_method: Optional[str],
    tool_efficacy: Dict[str, float],  # tool -> signal_strength
    reporter_confidence: float,
    triager_accepted: Optional[bool],
    bounty_payout_usd: Optional[float],
    notes: str
) -> None:
    """
    Writes a structured node into the knowledge graph.
    Nodes are queryable by (target_fqdn, vuln_class, attack_pattern)
    for future hunts against similar stacks.
    """
```

### Pre-Hunt Retrieval

Before each run, the orchestrator queries the knowledge graph:
- `similar_targets(stack_fingerprint)` → past findings on same tech stack
- `effective_tools(vuln_class)` → tools that historically produced strong signals
- `guard_bypass_patterns(cwe_id)` → known bypasses for this weakness class
- `false_positive_signals(pattern)` → patterns that previously led to FPs

Retrieved context is injected into the system prompt of each subskill
(up to 4000 tokens, ranked by recency and bounty payout).

