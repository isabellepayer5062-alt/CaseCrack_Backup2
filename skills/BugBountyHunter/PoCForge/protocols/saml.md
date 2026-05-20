  "total_pocs_built": 0,
  "complexity_breakdown": { "trivial": 0, "moderate": 0, "complex": 0 },
  "waf_blocks_encountered": 0,
  "waf_auto_bypass_successes": 0,
  "waf_full_matrix_required": 0,
  "chain_pocs_built": 0,
  "evidence_quality_avg": 0.0,
  "validator_pass_rate": 0.0,
  "avg_cvss_score": 0.0,
  "protocols_used": []
}
```

## Reproducibility & Determinism

Every PoC must be independently reproducible by a triager without prior context.

### Mandatory Headers for All PoC Requests

Every request in `repro-requests.http` must include:

```http
X-Bug-Bounty-Researcher: true
X-Request-ID: {{poc_id}}-step{{N}}
```

- `X-Bug-Bounty-Researcher: true` marks the request as researcher traffic in server logs.
- `X-Request-ID` provides a stable replay token enabling log correlation by the triager.
- **Never use live timestamps**: frozen placeholder only â€” `X-Timestamp: {{ISO8601_frozen}}`
  set at PoC creation time, not at replay time.

### Timing Variance Notes

- Annotate timing-sensitive steps with `timing_sensitive: true`.
- Race condition `race_window_evidence` must provide a `[min_delta_ms, max_delta_ms]` range,
  not a single point value.
- All `timing_delta_confirmed_ms` values must be anchored to a single-threaded baseline
  probe (Race Condition Protocol step 6) before the concurrent storm description.

### `.http` File Validation Checklist

Before emitting `repro-requests.http`:
- [ ] Every block starts with `### Step N â€“ <verb>: <description>`
- [ ] All auth headers use `<attacker_test_token>` â€” no real tokens
- [ ] All URLs are absolute (`https://...`), never relative paths
- [ ] `Content-Type` present on all POST/PUT/PATCH/DELETE requests
- [ ] `X-Bug-Bounty-Researcher: true` on every request
- [ ] `X-Request-ID: {{poc_id}}-step{{N}}` on every request
