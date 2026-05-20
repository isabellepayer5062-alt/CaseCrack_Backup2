â”œâ”€ Branch B: Enumerate IDs 1-100 to find valid victims
â”‚  â”œâ”€ Evidence: sequential IDs confirmed (confidence 0.80)
â”‚  â””â”€ PoC: 2 steps, moderate complexity
â””â”€ Branch C: Chain with XSS to steal admin session first
   â”œâ”€ Evidence: no XSS vector found (confidence 0.20)
   â””â”€ PoC: rejected â€” unnecessary complexity

SELECT: Branch A (minimum effective, highest confidence)
```

### ReAct â€” PoC Validation Loop

```
Observation: Constructed GET /admin/users?id=9999 with test token
Thought: Need to confirm this returns data for user 9999, not current user.
Action: execute_tool("http_replay", ["--request", "step1.http", "--output", "response.json"])
Observation: Response contains {"id": 9999, "email": "victim@example.com"}
Thought: Confirmed IDOR. Current test user is attacker@example.com (id: 42).
Action: Mark PoC as confirmed, cvss_score = 7.5
```

### Reflection â€” CVSS Calibration

```
Claim: "This IDOR deserves CVSS 9.0 (Critical)"
Evidence: ["unauth_access", "full_user_data_exposure"]
Reflection:
  - Counter-evidence: ["only read access, no modification possible"]
  - Revised CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
  - Revised severity: High (not Critical)
  - Confidence: 0.88
  - Action: Downgrade from Critical to High
```

### Hypothesis Tracking with Confidence Scoring

```python
# Prior: base rate of successful IDOR PoCs for exposed admin routes
confidence_prior = kg_query("idor_success_rate", route_type="admin")  # e.g., 0.45

# Evidence: HTTP 200 with foreign user data
likelihood_success = 0.90
likelihood_false_positive = 0.10

confidence_posterior = (
    confidence_prior * likelihood_success
) / (
    confidence_prior * likelihood_success
    + (1 - confidence_prior) * likelihood_false_positive
)
# Result: 0.88 â†’ high confidence, proceed to ReportWizard
```
