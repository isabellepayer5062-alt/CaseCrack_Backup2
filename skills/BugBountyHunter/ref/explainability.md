## Explainability & Finding Rationale

Every finding promoted to `status: finding` must include a machine-readable
reasoning trace enabling triagers to understand prioritization logic without
re-reading raw evidence artifacts.

### `finding_rationale` Schema

Each finding in `triage-ranked.json` carries a `finding_rationale` object:

```jsonc
{
  "finding_rationale": {
    "top_signals": [
      {
        "signal": "admin_route_exposed",
        "contribution": 3.5,
        "tier": "B",
        "why": "Route returns 200 OK without auth redirect — no session cookie required"
      },
      {
        "signal": "no_auth_redirect",
        "contribution": 2.1,
        "tier": "B",
        "why": "All tested clients receive data payload, not 401/403 or login redirect"
      }
    ],
    "independence_adjustment": "auth_surface group: 2nd signal ×0.6",
    "kg_adjustment": "+0.12 (auth_bypass historical payout rate for scope)",
    "confidence_basis": "2× Tier-B signals → 0.78 baseline; corroboration +0.05; final: 0.82",
    "competing_hypotheses": [
      {
        "hypothesis": "False positive — rate-limited admin route with deferred 401",
        "likelihood": 0.12,
        "refuted_by": "Verified 5 consecutive requests all returned 200 with user data"
      }
    ],
    "prioritization_summary": "High-value admin endpoint with no observable auth enforcement. Two independent Tier-B signals with KG-boosted weight and historical payout correlation make this the top-ranked finding for this host."
  }
}
```

### Narrative Quality Requirements

The `prioritization_summary` field and every `next-steps.md` entry must satisfy:

- **Self-contained**: a triager reading only the summary must understand the full
  reasoning without consulting raw evidence files.
- **Falsifiable**: state at least one observation that would refute the claim.
- **Calibrated**: every confidence value must be traceable to the signal tier table
  and independence rules — no opaque or estimated scores.
- **Chain-aware**: if `chain_relevance: true`, describe what the chain enables and
  what the critical intermediate step is.
