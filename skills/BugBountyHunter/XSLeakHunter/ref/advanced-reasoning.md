## Advanced Reasoning Primitives

### Oracle Selection Heuristic

```
Given endpoint characteristics:
  IF response_size_varies_per_user AND hex ETag present AND resource cacheable:
    → Oracle 2 (ETag + 431 + History delta) — MOST PRECISE for content-size leaks
       → verify 431 threshold first; calibrate baselineHeaderBytes per target
  IF endpoint_redirects_to_auth AND destination is from a known finite set:
    → Oracle 1 (connection pool saturation)
       → prefer Firefox; Chrome 123+ requires per-session pool-size calibration
  IF endpoint_redirects_to_auth AND destination is unknown:
    → Oracle 1v (lex-order binary search) — extract hostname character-by-character
  IF search_parameter_present AND auth_required:
    → Oracle 4 (XS-search timing) — HIGHEST PRIORITY; highest bounty yield
       → if timing differential < 50ms, switch to Oracle 8 (SAB clock) for precision
  IF response_includes_conditional_iframes:
    → Oracle 5 (frame counting) — most cross-browser portable
  IF user_controlled_css_present:
    → Oracle 6 (CSS injection side-channel)
  IF URL pattern is predictable AND returns JS resource conditionally on auth+existence:
    → Oracle 9 (script load/error event) — fast enumeration
       → CVE-2025-5266 timing variant: Chrome 120–123 only (patched Chrome 124+)
  IF timing signal present BUT performance.now() resolution insufficient:
    → Oracle 8 (SharedArrayBuffer clock) — requires COOP+COEP on attacker PoC page
  IF none_of_above:
    → Oracle 7 (fetch keepalive timing) — most reliable cross-browser fallback

  BROWSER SELECTION GUIDANCE:
    Oracles 1, 1v: use Firefox — Chrome 123+ pool randomization degrades signal ~25–40%
    Oracles 2, 5, 7: portable across Chrome/Firefox/Safari/Edge; prioritize for diverse targets
    Oracle 8 (SAB clock): Chrome/Firefox with COOP+COEP; Safari SharedArrayBuffer restricted
    Oracle 9 (CVE-2025-5266 timing): Chrome 120–123 only; verify target user browser distribution
    Safari timing floor (~1ms): prevents fine-grained discrimination for Oracles 4 and 8
```

### Statistical Validation Protocol

```python
from scipy.stats import mannwhitneyu

def validate_oracle(timing_set_A, timing_set_B, alpha=0.05):
    """
    timing_set_A: timings when oracle condition is TRUE  (e.g., user HAS matching data)
    timing_set_B: timings when oracle condition is FALSE (e.g., user has NO matching data)
    Returns: confirmed=bool, p_value, median_diff_ms, effect_size_r, report_as

    Example — CONFIRMED oracle (XS-search on /api/messages?q=, 30 samples each):
      timing_set_A (query matches):    [112, 118, 115, 121, 109, 116, ...]  mean=115ms
      timing_set_B (query no match):   [ 42,  38,  41,  39,  44,  40, ...]  mean= 41ms
      → result:
           confirmed:      True
           p_value:        0.000012   # far below 0.05; strong statistical signal
           median_diff_ms: 73.0       # 115 - 42 = 73ms differential
           effect_size_r:  0.91       # r > 0.5 = large practical effect
           confidence:     "high"
           report_as:      "confirmed_oracle"

    Counter-example — NEGATIVE result (keepalive timing on /api/profile, 30 samples each):
      timing_set_A (user_id=1001):  [98, 145, 87, 201, 73, ...]  stddev=43ms
      timing_set_B (user_id=9999):  [103, 89, 167, 94, 121, ...] stddev=36ms
      → result:
           confirmed:      False
           p_value:        0.62        # high variance masks any real signal
           median_diff_ms: 6.0         # below 50ms minimum threshold
           effect_size_r:  0.08        # negligible
           confidence:     "low"
           report_as:      "oracle_tested_negative"  # MUST be reported, not omitted
    """
    statistic, p_value = mannwhitneyu(timing_set_A, timing_set_B, alternative='two-sided')
    # Rank-biserial correlation r: r > 0.5 = large effect; r ≈ 0 = no discriminating power
    effect_size_r = statistic / (len(timing_set_A) * len(timing_set_B))
    median_diff   = abs(median(timing_set_A) - median(timing_set_B))
    confirmed     = p_value < alpha and median_diff > 50  # at least 50ms distinguishable
    return {
        "confirmed":        confirmed,
        "p_value":          round(p_value, 6),
        "median_diff_ms":   round(median_diff, 1),
        "effect_size_r":    round(effect_size_r, 3),
        "sample_sizes":     (len(timing_set_A), len(timing_set_B)),
        "confidence":       "high" if p_value < 0.01 else "medium" if p_value < 0.05 else "low",
        "report_as":        "confirmed_oracle" if confirmed else "oracle_tested_negative",
    }
```

Require `confirmed: true` before emitting any timing oracle as a finding.
