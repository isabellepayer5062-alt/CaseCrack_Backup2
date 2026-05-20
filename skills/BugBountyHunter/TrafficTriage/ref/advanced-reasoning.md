## Advanced Reasoning Primitives

### Tree-of-Thought — Signal Scoring

```
THOUGHT TREE — What is the true exploitability of api.example.com/admin?
Root: Host has admin route + no auth redirect + direct origin
├─ Branch A: IDOR via predictable IDs
│  ├─ Evidence: no authz check in source (confidence 0.82)
│  └─ Counter: IDs are UUID v4 (confidence 0.35)
├─ Branch B: Privilege escalation via role bypass
│  ├─ Evidence: no role middleware on route (confidence 0.78)
│  └─ Counter: JWT contains role claim (confidence 0.55)
└─ Branch C: Information disclosure via verbose errors
   ├─ Evidence: 500 response leaks stack trace (confidence 0.91)
   └─ Counter: error handler strips internals in prod (confidence 0.40)

SELECT: Branch C (highest confidence, strongest evidence)
→ exploit_score: 6.5, confidence: 0.91, vuln_class: Information Disclosure
```

### ReAct — Signal Confirmation Loop

```
Observation: target-graph shows /admin/users with 200 OK, no redirect
Thought: This suggests missing authz. Need to confirm with probe.
Action: execute_tool("curl_probe", ["-sS", "https://api.example.com/admin/users", "-H", "X-Bug-Bounty-Researcher: true"])
Observation: HTTP 200 with JSON array of user objects
Thought: Confirmed: no authentication required for admin endpoint.
Action: Score as Broken Access Control, exploit_score += 3.5
```

### Reflection — Score Calibration

```
Claim: "This finding deserves exploit_score 9.0"
Evidence: ["admin_route", "no_auth", "direct_origin", "nuclei_high"]
Reflection:
  - Counter-evidence: ["nuclei_high is for outdated nginx, not this route"]
  - Revised: remove nuclei_high signal
  - Revised exploit_score: 7.5 (still High, but not Critical)
  - Confidence: 0.82 (downgraded from 0.95)
  - Action: Emit as High, not Critical.
```

### Hypothesis Tracking with Confidence Scoring

```python
# Prior: base rate of auth bypass for exposed admin routes
confidence_prior = kg_query("auth_bypass_rate", route_type="admin")  # e.g., 0.25

# Evidence: HTTP 200 without auth header
likelihood_bypass = 0.85
likelihood_false_positive = 0.15

confidence_posterior = (
    confidence_prior * likelihood_bypass
) / (
    confidence_prior * likelihood_bypass
    + (1 - confidence_prior) * likelihood_false_positive
)
# Result: 0.65 → medium confidence, candidate status
```
