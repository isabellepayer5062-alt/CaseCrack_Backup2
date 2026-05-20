## Advanced Reasoning Primitives

### Tree-of-Thought — Taint Path Exploration

```
THOUGHT TREE — Is user input reaching the deleteUser sink safely?
Root: DELETE /api/users/:id → userService.deleteUser(id)
├─ Branch A: ID is validated against current user's owned IDs
│  ├─ Evidence: auth middleware checks req.user.id == resource.owner (confidence 0.85)
│  └─ Conclusion: guard_status = effective
├─ Branch B: ID is validated but ownership check is bypassable
│  ├─ Evidence: ownership check uses == but IDs are strings vs ints (confidence 0.72)
│  └─ Conclusion: guard_status = bypassable
└─ Branch C: No validation at all
   ├─ Evidence: id parameter passed directly to DELETE query (confidence 0.91)
   └─ Conclusion: guard_status = none

SELECT: Branch C (strongest evidence, direct code observation)
```

### ReAct — Sink Discovery Loop

```
Observation: TrafficTriage flagged /api/webhook as SSRF-relevant
Thought: Need to find where webhook URL is used in source.
Action: execute_tool("grep_search", ["-r", "-n", "webhook", "--include=*.py", "src/"])
Observation: 12 matches in 4 files
Thought: Need to trace which matches accept user-controlled URLs.
Action: execute_tool("ast_parser", ["--find-sinks", "--pattern=requests.get", "src/services/webhook.py"])
Observation: Line 89: requests.get(user_input_url) with no allowlist
Thought: Confirmed SSRF sink. Need to check for guards.
Action: execute_tool("grep_search", ["-B5", "-A5", "requests.get", "src/services/webhook.py"])
Observation: No URL validation in surrounding 10 lines
Conclusion: guard_status = none, sink_label = ssrf_sink
```

### Reflection — Guard Assessment

```
Claim: "The auth check on this route is effective"
Evidence: ["@require_auth decorator present on route handler"]
Reflection:
  - Counter-evidence: ["decorator returns True for all users, not just admins"]
  - Revised claim: "Auth check verifies login but not role"
  - Revised guard_status: bypassable (authentication present, authorization absent)
  - Confidence: 0.78 (downgraded from 0.92)
  - Action: Emit correlation with guard_status = bypassable
```

### Hypothesis Tracking with Confidence Scoring

```python
# Prior: base rate of missing guards for this framework
confidence_prior = kg_query("missing_guard_rate", framework="django")  # e.g., 0.12

# Evidence: no auth decorator found in 5-line surrounding context
likelihood_missing = 0.80
likelihood_present = 0.20

confidence_posterior = (
    confidence_prior * likelihood_missing
) / (
    confidence_prior * likelihood_missing
    + (1 - confidence_prior) * likelihood_present
)
# Result: 0.35 → low confidence, search broader context before concluding
```
