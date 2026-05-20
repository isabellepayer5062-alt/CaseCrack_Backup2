## Tool Execution Layer (MCP-Compatible)

ReconAnalyzer delegates all external recon tool invocations through the
sandboxed MCP tool registry. Direct shell execution is prohibited.

```yaml
recon_tools:
  subfinder:
    mode: mcp_sandbox
    timeout: 300
    args_allowlist:
      - "-dL"
      - "-silent"
      - "-all"
      - "-o"
      - "-recursive"
      - "-t"
    deny:
      - "-v"
      - "-proxy"
  httpx:
    mode: mcp_sandbox
    timeout: 600
    args_allowlist:
      - "-l"
      - "-silent"
      - "-threads"
      - "-timeout"
      - "-retries"
      - "-title"
      - "-status-code"
      - "-tech-detect"
      - "-json"
      - "-o"
    deny:
      - "-x"
      - "-proxy"
      - "-unsafe"
  nuclei:
    mode: mcp_sandbox
    timeout: 1800
    args_allowlist:
      - "-l"
      - "-severity"
      - "-rate-limit"
      - "-bulk-size"
      - "-c"
      - "-jsonl"
      - "-o"
      - "-tags"
    deny:
      - "-interactsh-server"
      - "-it"
      - "-proxy"
      - "-headless"
  nuclei_oob:
    mode: mcp_sandbox
    timeout: 1800
    description: "Nuclei with interactsh for blind SSRF/XSS/SSTI detection"
    args_allowlist:
      - "-l"
      - "-severity"
      - "-rate-limit"
      - "-bulk-size"
      - "-c"
      - "-jsonl"
      - "-o"
      - "-tags"
      - "-interactsh-server"
    deny:
      - "-proxy"
      - "-headless"
    condition: "interactsh_server_configured == true"
  naabu:
    mode: mcp_sandbox
    timeout: 600
    description: "Port scanner for non-standard port discovery"
    args_allowlist:
      - "-l"
      - "-p"
      - "-top-ports"
      - "-silent"
      - "-json"
      - "-o"
      - "-rate"
    deny:
      - "-proxy"
      - "-nmap-cli"
  gau:
    mode: mcp_sandbox
    timeout: 300
    description: "Historical URL discovery via Wayback/CommonCrawl/AlienVault"
    args_allowlist:
      - "--threads"
      - "--timeout"
      - "--providers"
      - "--blacklist"
      - "--o"
    deny:
      - "--proxy"
  waybackurls:
    mode: mcp_sandbox
    timeout: 300
    description: "Wayback Machine historical URL extraction"
    args_allowlist:
      - "--no-subs"
      - "--get-versions"
    deny: []
  jsluice:
    mode: mcp_sandbox
    timeout: 120
    description: "Extract URLs, secrets, and endpoints from JavaScript bundles"
    args_allowlist:
      - "urls"
      - "secrets"
      - "-r"
      - "--input"
    deny:
      - "--write"
  linkfinder:
    mode: mcp_sandbox
    timeout: 60
    description: "JavaScript endpoint discovery via regex pattern matching"
    args_allowlist:
      - "-i"
      - "-o"
      - "-d"
    deny:
      - "--burp"
  oauth_recon:
    mode: mcp_sandbox
    timeout: 600
    description: "OAuth/OIDC deep recon — provider detection, client-ID extraction, PKCE probing, scope enum, well-known audit"
    args_allowlist:
      - "--target"
      - "--enumerate-scopes"
      - "--probe-pkce"
      - "--audit-well-known"
      - "--max-threads"
      - "--output"
    deny:
      - "--proxy"
      - "--exploit"
  graphql_recon:
    mode: mcp_sandbox
    timeout: 300
    description: "GraphQL recon — endpoint discovery, introspection bypass, schema extraction, IDE detection"
    args_allowlist:
      - "--target"
      - "--probe-introspection"
      - "--probe-ide"
      - "--extract-schema"
      - "--output"
    deny:
      - "--proxy"
      - "--mutate"
  websocket_recon:
    mode: mcp_sandbox
    timeout: 300
    description: "WebSocket recon — WS endpoint discovery, CSWSH testing, protocol fingerprinting"
    args_allowlist:
      - "--target"
      - "--probe-cswsh"
      - "--probe-auth"
      - "--output"
    deny:
      - "--proxy"
  github_deep_recon:
    mode: mcp_sandbox
    timeout: 900
    description: "GitHub/GitLab/Bitbucket/AzureDevOps deep recon — org members, commit history, GH Actions secrets, CFOR, gists"
    args_allowlist:
      - "--domain"
      - "--probe-org-members"
      - "--probe-actions"
      - "--probe-cfor"
      - "--output"
    deny:
      - "--proxy"
      - "--write"
    condition: "vcs_api_key_configured == true"
  nmap:
    mode: mcp_sandbox
    timeout: 900
    description: "Nmap deep service fingerprinting (runs inside Docker, non-destructive scan only)"
    args_allowlist:
      - "-sV"
      - "-sC"
      - "-O"
      - "--script=vuln,version"
      - "--top-ports"
      - "-oJ"
      - "-T4"
    deny:
      - "-sS"
      - "--script-args"
      - "--send-eth"
      - "-6"
    condition: "explicit_port_scan_authorized == true"
  screenshot:
    mode: mcp_sandbox
    timeout: 600
    description: "Headless Chromium screenshots — page categorization and perceptual hash clustering"
    args_allowlist:
      - "--targets"
      - "--headless"
      - "--categorize"
      - "--cluster"
      - "--output"
    deny:
      - "--proxy"
  tls_scanner:
    mode: mcp_sandbox
    timeout: 300
    description: "TLS cipher suite grading, certificate analysis, JA3/JA4 fingerprinting, weak protocol detection"
    args_allowlist:
      - "--targets"
      - "--cipher-grade"
      - "--ja3"
      - "--output"
    deny: []
  dns_security:
    mode: mcp_sandbox
    timeout: 300
    description: "DNS zone transfer, DNSSEC validation, DNS rebinding, NSEC zone walking"
    args_allowlist:
      - "--domain"
      - "--zone-transfer"
      - "--rebinding"
      - "--nsec-walk"
      - "--output"
    deny:
      - "--poison"
  cloud_asset_discovery:
    mode: mcp_sandbox
    timeout: 900
    description: "Multi-cloud asset discovery + bucket enumeration (AWS S3/Azure Blob/GCP)"
    args_allowlist:
      - "--domain"
      - "--cloud-enum"
      - "--bucket-scan"
      - "--output"
    deny:
      - "--write"
      - "--delete"
  wafw00f:
    mode: mcp_sandbox
    timeout: 300
    description: "WAF fingerprinting — 180+ vendor signatures"
    args_allowlist:
      - "-a"
      - "-o"
      - "--no-redirect"
    deny:
      - "--proxy"
  osint_recon:
    mode: mcp_sandbox
    timeout: 600
    description: "OSINT aggregation — crt.sh, email intel, breach data, RDAP/WHOIS, BGPView ASN, subdomain aggregator"
    args_allowlist:
      - "--domain"
      - "--all-providers"
      - "--include-bgpview"
      - "--include-breach"
      - "--output"
    deny: []
  saas_integration_recon:
    mode: mcp_sandbox
    timeout: 300
    description: "SaaS integration token discovery in frontend HTML/JS"
    args_allowlist:
      - "--domain"
      - "--output"
    deny: []
  email_security:
    mode: mcp_sandbox
    timeout: 120
    description: "SPF/DMARC/DKIM analysis and spoofing risk scoring"
    args_allowlist:
      - "--domain"
      - "--spf"
      - "--dmarc"
      - "--dkim"
      - "--output"
    deny: []
  vhostfinder:
    mode: mcp_sandbox
    timeout: 600
    description: "Virtual host enumeration on discovered IPs"
    args_allowlist:
      - "--ips"
      - "--wordlist"
      - "--output"
    deny:
      - "--proxy"
    condition: "explicit_vhost_scan_authorized == true"
  origin_ip_hunter:
    mode: mcp_sandbox
    timeout: 300
    description: "Real origin IP discovery behind CDN/WAF via historical DNS, subdomains, CT, Shodan"
    args_allowlist:
      - "--domain"
      - "--methods"
      - "--output"
    deny: []
  nomore403:
    mode: mcp_sandbox
    timeout: 300
    description: "403 bypass tester — path variations, header injection, URL encoding"
    args_allowlist:
      - "--urls"
      - "--output"
      - "--techniques"
    deny:
      - "--proxy"
  sourcemapper:
    mode: mcp_sandbox
    timeout: 300
    description: "JavaScript source map recovery from .map files"
    args_allowlist:
      - "--input"
      - "--output"
    deny: []
  dom_xss_analyzer:
    mode: mcp_sandbox
    timeout: 300
    description: "DOM XSS static analysis via JavaScript AST — finds dangerous sinks"
    args_allowlist:
      - "--input"
      - "--output"
    deny: []
  browser_extension_recon:
    mode: mcp_sandbox
    timeout: 300
    description: "Browser extension recon — manifest analysis, hardcoded API keys/endpoints"
    args_allowlist:
      - "--domain"
      - "--output"
    deny: []
  sse_security:
    mode: mcp_sandbox
    timeout: 300
    description: "SSE endpoint discovery + CORS misconfiguration + auth bypass on event streams"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  saml_security:
    mode: mcp_sandbox
    timeout: 600
    description: "SAML SP/IdP recon + XML Signature Wrapping susceptibility analysis"
    args_allowlist:
      - "--target"
      - "--output"
      - "--metadata-url"
    deny: []
  favicon_correlation:
    mode: mcp_sandbox
    timeout: 300
    description: "Favicon hash correlation against 600+ product fingerprints"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  csp_analyzer:
    mode: mcp_sandbox
    timeout: 300
    description: "CSP directive parsing + bypass vector detection"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  error_page_analyzer:
    mode: mcp_sandbox
    timeout: 300
    description: "Error page info extraction: server versions, paths, IPs, stack traces"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  mobile_api:
    mode: mcp_sandbox
    timeout: 600
    description: "Mobile API endpoint discovery + cert pinning bypass + deep link hijacking"
    args_allowlist:
      - "--target"
      - "--output"
      - "--apk"
      - "--ipa"
    deny: []
  second_order_detector:
    mode: mcp_sandbox
    timeout: 900
    description: "Second-order injection storage point enumeration with canary payloads"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  postmessage_analyzer:
    mode: mcp_sandbox
    timeout: 300
    description: "postMessage origin analysis in JS bundles — wildcard targetOrigin, weak validation"
    args_allowlist:
      - "--input"
      - "--output"
    deny: []
  ipv6_scanner:
    mode: mcp_sandbox
    timeout: 600
    description: "IPv6 dual-stack discovery + ACL bypass + SLAAC prediction + NDP enumeration"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  supply_chain_intel:
    mode: mcp_sandbox
    timeout: 600
    description: "Supply chain: dep confusion, typosquatting, OSV CVEs, CDN SRI, GH Actions"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  juicy_files:
    mode: mcp_sandbox
    timeout: 600
    description: "Juicy file hunter — 150+ extensions, backup variants, IDE artifacts"
    args_allowlist:
      - "--target"
      - "--output"
      - "--min-level"
    deny: []
  google_dorking:
    mode: mcp_sandbox
    timeout: 600
    description: "Google/Bing/DuckDuckGo dorking — 100+ templates, 12 categories"
    args_allowlist:
      - "--domain"
      - "--engines"
      - "--categories"
      - "--output"
    deny: []
  http2_security:
    mode: mcp_sandbox
    timeout: 300
    description: "HTTP/2 security: smuggling, HPACK injection, RST flood, h2c upgrade"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  http3_scanner:
    mode: mcp_sandbox
    timeout: 300
    description: "HTTP/3/QUIC service discovery + security differential analysis"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  wappalyzer_engine:
    mode: mcp_sandbox
    timeout: 300
    description: "Wappalyzer full tech detection — 1200+ technology fingerprints"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  subdomain_takeover:
    mode: mcp_sandbox
    timeout: 600
    description: "Subdomain takeover verification — CNAME to decommissioned services"
    args_allowlist:
      - "--target"
      - "--subdomains"
      - "--output"
    deny: []
  sbom_generator:
    mode: mcp_sandbox
    timeout: 600
    description: "SBOM generation + OSV CVE correlation + EOL package detection"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  spa_security:
    mode: mcp_sandbox
    timeout: 600
    description: "SPA security analysis — React/Angular/Vue specific sinks, routing bypass"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  wasm_analysis:
    mode: mcp_sandbox
    timeout: 600
    description: "WebAssembly analysis — exported functions, crypto, memory access patterns"
    args_allowlist:
      - "--target"
      - "--output"
    deny: []
  param_discovery:
    mode: mcp_sandbox
    timeout: 900
    description: "Parameter discovery with AI-generated wordlists + Arjun-style enumeration"
    args_allowlist:
      - "--target"
      - "--output"
      - "--wordlist"
    deny: []

### execute_tool Contract

```python
def execute_tool(
    tool_name: str,
    args: List[str],
    safety_scope: SafetyScope,
    timeout_seconds: int = 300,
    token_quota: int = 2000,
    capture_stdout: bool = True,
    capture_stderr: bool = True
) -> ToolResult:
    """
    safety_scope enforces:
      - in_scope_hosts only (from ROOT_SCOPE_FILE)
      - non_destructive_only
      - max_hosts_per_run: 10000
    """
```

