## Advanced Reasoning Primitives

Every critical decision in the pipeline must use one of the following
reasoning frameworks, selected by the orchestrator based on task complexity:

### 1. Tree-of-Thought (ToT) — for branching exploration

Used in: ReconAnalyzer (variant selection), TrafficTriage (signal scoring),
ChainHunter (path exploration).

```
THOUGHT TREE — depth 3, branch factor 2
Root: Given signal X, what are the most likely vulnerability classes?
├─ Branch A: Broken Access Control
│  ├─ Leaf A1: IDOR via predictable UUID (confidence 0.78)
│  └─ Leaf A2: Missing authz on admin route (confidence 0.65)
└─ Branch B: Information Disclosure
   ├─ Leaf B1: Verbose error leaks stack trace (confidence 0.82)
   └─ Leaf B2: Debug endpoint exposes env vars (confidence 0.71)

SELECT: Branch B → Leaf B1 (highest confidence, strongest evidence)
```

### 2. ReAct (Reasoning + Acting) — for tool-driven loops

Used in: PoCForge (step construction), SourceHunter (taint tracing).

```
Observation: <what the tool returned>
Thought: <what this means for the hypothesis>
Action: <next tool call or analysis step>
→ Repeat until hypothesis is confirmed or falsified.
```

### 3. Reflection — for self-correction

Used in: Validator, ReportWizard (severity review), after every phase.

```
Claim: "This endpoint is vulnerable to SSRF"
Evidence: ["requests.get(user_input) at line 142", "no URL allowlist"]
Reflection:
  - Counter-evidence: ["Input is validated against regex ^https?://.*"]
  - Revised claim: "SSRF is possible but limited to http/https schemes"
  - Revised confidence: 0.55 (downgraded from 0.82)
  - Action: Emit as candidate, not finding.
```

### 4. Hypothesis Tracking with Confidence Scoring

Every hypothesis carries a living confidence score updated by Bayesian
inference as new evidence arrives:

```python
confidence_posterior = (
    confidence_prior * likelihood(evidence | hypothesis)
) / (
    confidence_prior * likelihood(evidence | hypothesis)
    + (1 - confidence_prior) * likelihood(evidence | not_hypothesis)
)
```

The orchestrator surfaces all hypotheses with `confidence_posterior >= 0.6`
to downstream phases. Hypotheses below 0.6 are archived in the blackboard
for future runs (stack fingerprint may change, making them relevant later).

