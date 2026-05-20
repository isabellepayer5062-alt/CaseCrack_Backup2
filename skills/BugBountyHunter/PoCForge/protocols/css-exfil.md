      - "--compare"
      - "--output"
      - "--header"
      - "--data"
      - "--method"
      - "--body"
      - "--cookie"
    conditional_allow:
      - arg: "--follow-redirects"
        when: "vuln_class in ['Open Redirect', 'OAuth Abuse', 'CSRF', 'Auth Bypass via Redirect', 'Broken Authentication']"
        note: "Required for OAuth code-theft and redirect chain validation. Must still enforce in_scope_only for every redirect hop."
    deny:
      - "--cookie-jar"
    safety_scope:
      in_scope_only: true
      non_destructive_only: true
      max_request_rate_per_host: 2
      require_test_account: true
  response_diff:
    mode: mcp_sandbox
    timeout: 30
    args_allowlist:
      - "--baseline"
      - "--modified"
      - "--json"
    deny: []
  playwright_replay:
    mode: mcp_sandbox
