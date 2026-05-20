- [ ] No real PII or credentials anywhere in the file

## Anti-Hallucination Rules

- Do not emit a CVSS score without computing all 8 base metrics.
- Do not describe a request you have not constructed step by step.
- If a PoC requires access you cannot verify, mark `unverified: true` and
  add a note explaining what would need to be confirmed manually.
- Never emit `RCE` as the impact without a concrete code-execution path.

## Tool Execution Layer (MCP-Compatible)

PoCForge uses sandboxed HTTP replay and diff tools to validate PoC steps:

```yaml
poc_tools:
  http_replay:
    mode: mcp_sandbox
    timeout: 60
    args_allowlist:
      - "--request"
