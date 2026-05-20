## Swarm Workers

ChainHunter spawns parallel chain-building workers by class:

```yaml
swarm_workers:
  - worker_id: chain-auth
    chain_classes: ["Auth → Escalation", "Open Redirect → OAuth", "IDP Injection → Federation"]
    entry_flags: [auth_bypass, idp_bypass]
    model: anthropic/claude-sonnet-4-6
    priority: 1
  - worker_id: chain-network
    chain_classes: ["SSRF → Internal", "Path Traversal → SSRF", "gRPC Unauth → Enum → Priv"]
    entry_flags: [ssrf_vector, path_traversal, grpc_unauth]
    model: openai/gpt-5.5
    priority: 2
  - worker_id: chain-financial
    chain_classes: ["Race → Financial"]
    entry_flags: [race_condition]
    model: openai/gpt-5.5
    escalate_tags: [race_condition, complex_agentic]
    priority: 3
  - worker_id: chain-subdomain
    chain_classes: ["Subdomain Takeover → Session"]
    entry_flags: [subdomain_takeover]
    model: anthropic/claude-sonnet-4-6
    priority: 4
  - worker_id: chain-rce
    chain_classes: ["Deserialization → RCE", "SSTI → RCE"]
    entry_flags: [deser_sink, ssti_sink]
    model: openai/gpt-5.5
    escalate_tags: [exploit_poc, complex_agentic]
    priority: 1
  - worker_id: chain-secrets
    chain_classes: ["Credential Leak → ATO"]
    entry_flags: [credential_leak]
    model: anthropic/claude-sonnet-4-6
    priority: 3
  - worker_id: chain-smuggling
    chain_classes: ["HTTP Smuggling → Cache Poison"]
    entry_flags: [http_smuggling]
    model: openai/gpt-5.5
    escalate_tags: [complex_agentic]
    priority: 2
  - worker_id: chain-cache
    chain_classes: ["Web Cache Deception → ATO", "Next.js Internal Cache Poison → XSS"]
    entry_flags: [cache_deception, nextjs_cache]
    model: anthropic/claude-sonnet-4-6
    priority: 2
  - worker_id: chain-sidechannel
    chain_classes: ["Cookie Tossing → OAuth Code Theft", "OAuth Non-Happy-Path → ATO", "Parser Differential → Auth Bypass"]
    entry_flags: [cookie_tossing, parser_differential, open_redirect]
    model: openai/gpt-5.5
    escalate_tags: [complex_agentic]
    priority: 3
  - worker_id: chain-h2-orm
    chain_classes: ["HTTP/2 CONNECT → Internal Port Scan", "ORM Filter → Data Exfiltration"]
    entry_flags: [h2_connect, orm_leak]
    model: anthropic/claude-sonnet-4-6
    priority: 3
  - worker_id: chain-oauth-full
    chain_classes: ["OAuth Implicit Flow → Token Theft", "OAuth PKCE Bypass → ATO", "OAuth Redirect URI Bypass → ATO", "Cross-Tenant OAuth Confusion → Privilege Escalation"]
    entry_flags: [oauth_token_theft, oauth_redirect_bypass, cross_tenant_oauth]
    model: openai/gpt-5.5
    escalate_tags: [complex_agentic]
    priority: 2
  - worker_id: chain-graphql
    chain_classes: ["GraphQL Introspection → IDOR Chain", "GraphQL Unauthenticated Mutation → Data Tampering"]
    entry_flags: [graphql_open]
    model: anthropic/claude-sonnet-4-6
    priority: 2
  - worker_id: chain-websocket
    chain_classes: ["CSWSH → Session Token Theft", "WebSocket Unauth → Real-Time Abuse"]
    entry_flags: [cswsh, websocket_unauth]
    model: openai/gpt-5.5
    escalate_tags: [complex_agentic]
    priority: 2
  - worker_id: chain-cloud
    chain_classes: ["Cloud Bucket Open → Data Exfil + Supply Chain", "Cloud IAM Escalation → Full Account Compromise"]
    entry_flags: [cloud_bucket_open, cloud_iam_escalation]
    model: openai/gpt-5.5
    escalate_tags: [complex_agentic]
    priority: 1
  - worker_id: chain-infra-bypass
    chain_classes: ["Direct Origin IP + WAF Bypass → Full Exploit", "Admin Panel Exposed → Default Credential → RCE", "Forbidden Bypass → Sensitive API Access"]
    entry_flags: [origin_exposed, admin_panel_exposed, forbidden_bypass]
    model: anthropic/claude-sonnet-4-6
    priority: 2
  - worker_id: chain-social-eng
    chain_classes: ["Email Spoofing → Phishing → ATO", "VCS Deep Secret → Infrastructure Access"]
    entry_flags: [email_spoof, third_party_credential]
    model: anthropic/claude-sonnet-4-6
    priority: 3
  - worker_id: chain-client-side
    chain_classes: ["DOM XSS → Session Token Theft", "TLS Downgrade → Credential Interception", "Source Map Recovery → Hidden Endpoint Discovery"]
    entry_flags: [dom_xss, tls_weakness, info_disclosure]
    model: anthropic/claude-sonnet-4-6
    priority: 3
  - worker_id: chain-saml
    chain_classes: ["SAML XSW → Authentication Bypass", "SAML Assertion Replay → ATO", "SAML Comment Injection → Account Takeover"]
    entry_flags: [saml_xsw, saml_replay, idp_bypass]
    model: openai/gpt-5.5
    priority: 1
  - worker_id: chain-postmessage
    chain_classes: ["postMessage Wildcard → Cross-Origin Data Theft", "postMessage No-Origin → DOM XSS + Token Theft", "Cross-Window Chain via window.opener"]
    entry_flags: [postmessage_unvalidated]
    model: anthropic/claude-sonnet-4-6
    priority: 2
  - worker_id: chain-ipv6
    chain_classes: ["IPv6 ACL Bypass → Firewall Rule Evasion", "IPv6 Port Exposure → Hidden Service Access"]
    entry_flags: [ipv6_acl_bypass]
    model: anthropic/claude-sonnet-4-6
    priority: 2
  - worker_id: chain-supply-chain
    chain_classes: ["Dep Confusion → Build Pipeline RCE", "Vulnerable Dependency → Known CVE Exploitation", "CDN No-SRI → Supply Chain XSS", "GH Actions Secrets → CI/CD Compromise"]
    entry_flags: [dep_confusion, cdn_no_sri, cicd_secret_leak, critical_cve_dep]
    model: anthropic/claude-sonnet-4-6
    priority: 2
  - worker_id: chain-takeover
    chain_classes: ["Subdomain Takeover → Session Hijacking", "Subdomain Takeover → OAuth Code Theft", "Subdomain Takeover → Cookie Tossing"]
    entry_flags: [subdomain_takeover_verified, subdomain_takeover, cookie_tossing]
    model: openai/gpt-5.5
    priority: 1
  - worker_id: chain-second-order
    chain_classes: ["Second-Order Stored XSS → Admin Session Theft", "Second-Order SQLi → Data Exfiltration", "Second-Order SSTI → Delayed RCE"]
    entry_flags: [second_order]
    model: openai/gpt-5.5
    priority: 1
  - worker_id: chain-sse-csp
    chain_classes: ["SSE CORS Open → Cross-Origin Event Stream Exfiltration", "CSP Bypass via JSONP → XSS Escalation", "CSP Bypass via Script Gadget → XSS on Protected Page", "Error Page Version Leak → Targeted CVE Exploitation"]
    entry_flags: [sse_cors_open, csp_bypass, error_page_version_leak, favicon_known_cve]
    model: anthropic/claude-sonnet-4-6
    priority: 2
  - worker_id: chain-mobile-log
    chain_classes: ["Mobile Deep Link Hijacking → OAuth Token Theft", "Log Endpoint Exposed → Credential Harvest + ATO", "Hidden Parameter → Undocumented Admin Function Access"]
    entry_flags: [mobile_deeplink_hijack, log_endpoint_open, hidden_param, spa_route_bypass]
    model: anthropic/claude-sonnet-4-6
    priority: 3
  # ── Infrastructure workers for the neuro-symbolic pipeline ──
  - worker_id: graph-builder
    role: infrastructure
    description: >
      Loads all capability-enriched findings, constructs the directed attack graph
      (nodes = findings, edges = capability transitions), prunes low-confidence edges,
      and indexes nodes by impact_tags for efficient worker queries. Runs once before
      all chain-class workers. Emits graph_stats to the blackboard.
    model: anthropic/claude-sonnet-4-6
    priority: 0
    max_steps: 3
    runs_before: all_chain_workers
  - worker_id: path-enumerator
    role: infrastructure
    description: >
      Executes bounded DFS from the initial_state node across the attack graph built
      by graph-builder. Applies confidence pruning (product < 0.20 → abort), CVSS delta
      pruning (< 0.3 gain per step → deprioritize), and redundancy pruning. Emits the
      top_n_paths (default 20) retained paths to the blackboard for chain-class workers
      to score and narrate.
    model: openai/gpt-5.5
    escalate_tags: [complex_agentic]
    priority: 0
    max_steps: 5
    runs_after: graph-builder
    config:
      top_n_paths: 20
      min_chain_confidence: 0.45
      max_depth: 5
      max_nodes: 200
      max_edges_before_subsampling: 800
      goal_capabilities_override: null  # list of capability labels to restrict goal set
  - worker_id: novelty-scorer
    role: infrastructure
    description: >
      After chain-class workers produce scored chains, computes novelty_score for each
      via embedding cosine distance from prior KG chains. Chains with novelty_score > 0.70
      are flagged high_priority. Chains with novelty_score < 0.20 are flagged known_pattern.
      Generates the final ranked output list and writes to chains-discovered.json.
    model: anthropic/claude-sonnet-4-6
    priority: 0
    max_steps: 2
    runs_after: all_chain_workers
```

