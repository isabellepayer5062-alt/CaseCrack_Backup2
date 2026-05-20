## Dynamic Dependency & Swarm Graph

ReconAnalyzer can spawn parallel recon workers with different strategies:

```yaml
swarm_workers:
  - worker_id: recon-default
    tool: subfinder -dL scope.txt -silent -all
    priority: 1
  - worker_id: recon-deep-dns
    tool: subfinder -dL scope.txt -silent -all -recursive -t 50
    priority: 2
    condition: "default_worker.hosts_found < 100"
  - worker_id: recon-permutations
    tool: dnsgen scope.txt | massdns -r resolvers.txt -o J
    priority: 3
    condition: "deep_dns_worker.hosts_found < 50"
  - worker_id: recon-historical
    tools: [gau, waybackurls]
    description: "Historical URL discovery from Wayback/CommonCrawl"
    priority: 2
    parallel: true
  - worker_id: recon-ports
    tool: naabu -l scope.txt -top-ports 1000 -silent -json
    priority: 3
    condition: "explicit_port_scan_authorized == true"
  - worker_id: recon-js-endpoints
    tool: jsluice urls -r js_bundles/
    priority: 4
    condition: "js_bundles_downloaded == true"
  - worker_id: recon-oauth
    tool: oauth_recon --target {{scope_root}} --enumerate-scopes --probe-pkce --audit-well-known
    priority: 3
    description: "Full OAuth/OIDC deep recon — provider detection, client-ID extraction, redirect-URI policy, PKCE status, scope enumeration, token format analysis, well-known config audit, cross-tenant trust mapping"
    condition: "oauth_endpoints_detected == true OR login_page_found == true"
    outputs: [oauth_recon_output]
  - worker_id: recon-graphql
    tool: graphql_recon --target {{scope_root}} --probe-introspection --probe-ide --extract-schema
    priority: 3
    description: "GraphQL endpoint discovery, introspection bypass probes, schema extraction, mutation pattern analysis, IDE (GraphiQL/Playground/Altair) detection"
    condition: "graphql_endpoint_hint == true"
    outputs: [graphql_recon_output]
  - worker_id: recon-websocket
    tool: websocket_recon --target {{scope_root}} --probe-cswsh --probe-auth
    priority: 3
    description: "WebSocket endpoint discovery, protocol fingerprinting (Socket.IO/SignalR/STOMP/MQTT/GraphQL-WS), CSWSH testing, auth token replay, schema inference"
    condition: "websocket_upgrade_detected == true"
    outputs: [websocket_recon_output]
  - worker_id: recon-vcs-deep
    tool: github_deep_recon --domain {{scope_root}} --probe-org-members --probe-actions --probe-cfor
    priority: 4
    description: "GitHub/GitLab/Bitbucket/AzureDevOps deep recon — org member enum, commit history mining (deleted secrets), GH Actions secrets, cross-fork object references, gist/wiki, .env files"
    condition: "github_org_identified == true OR vcs_links_found == true"
    outputs: [github_deep_output]
  - worker_id: recon-nmap-service
    tool: nmap -sV -sC -O --script=vuln,version --top-ports 1000 -oJ nmap_output.json
    priority: 3
    description: "Deep service fingerprinting with OS detection, service version, and NSE script results (via Docker sandbox)"
    condition: "naabu_open_ports_found == true AND explicit_port_scan_authorized == true"
    outputs: [nmap_output]
  - worker_id: recon-screenshot
    tool: screenshot --targets {{priority_hosts}} --headless --categorize --cluster
    priority: 2
    description: "Visual recon — headless Chromium screenshots, page categorization (login/admin/default-install/error/API), perceptual hash clustering"
    condition: "httpx_hosts_found == true"
    outputs: [screenshot_output]
  - worker_id: recon-tls
    tool: tls_scanner --targets {{priority_hosts}} --cipher-grade --ja3
    priority: 3
    description: "TLS cipher suite grading, certificate validity, JA3/JA4 fingerprinting, weak protocol (SSLv3/TLSv1.0) detection"
    outputs: [tls_scan_output]
  - worker_id: recon-dns-security
    tool: dns_security --domain {{scope_root}} --zone-transfer --rebinding --nsec-walk
    priority: 3
    description: "DNS security — zone transfer testing, DNSSEC validation, DNS rebinding, NSEC zone walking for hidden subdomains"
    outputs: [dns_security_output]
  - worker_id: recon-cloud-assets
    tool: cloud_asset_discovery --domain {{scope_root}} --cloud-enum --bucket-scan
    priority: 3
    description: "Multi-cloud asset discovery + bucket enumeration (AWS S3/Azure Blob/GCP) — public bucket listing, IAM misconfiguration"
    outputs: [cloud_assets_output]
  - worker_id: recon-waf
    tool: wafw00f {{priority_hosts}} -o wafw00f_output.json
    priority: 2
    description: "WAF vendor fingerprinting (180+ signatures) — affects downstream exploit scoring and triggers WAF bypass protocol in PoCForge"
    outputs: [wafw00f_output]
  - worker_id: recon-osint
    tool: osint_recon --domain {{scope_root}} --all-providers --include-bgpview --include-breach
    priority: 2
    description: "OSINT aggregation — crt.sh CT search, email intel, breach data (XposedOrNot), RDAP/WHOIS, BGPView ASN/IP ranges, Anubis+Wayback passive subdomain aggregator"
    outputs: [osint_output]
  - worker_id: recon-saas-intel
    tool: saas_integration_recon --domain {{scope_root}}
    priority: 3
    description: "SaaS integration discovery — find API tokens/webhooks for Slack, Jira, Confluence, Salesforce, GitHub, Trello visible in frontend HTML/JS sources"
    outputs: [saas_intel_output]
  - worker_id: recon-email-security
    tool: email_security --domain {{scope_root}} --spf --dmarc --dkim
    priority: 2
    description: "Email security scan — SPF/DMARC/DKIM analysis, spoofing risk scoring, SMTP relay testing"
    outputs: [email_security_output]
  - worker_id: recon-vhosts
    tool: vhostfinder --ips {{discovered_ips}} --wordlist vhost_wordlist.txt
    priority: 3
    description: "Virtual host enumeration — discover additional attack surfaces on shared IPs not present in DNS"
    condition: "explicit_vhost_scan_authorized == true"
    outputs: [vhostfinder_output]
  - worker_id: recon-api-spec
    tool: api_discovery --target {{priority_hosts}} --postman --openapi
    priority: 3
    description: "API spec discovery — exposed Postman collections, OpenAPI/Swagger JSON, WSDL files; feeds TrafficTriage with documented endpoint inventory"
    outputs: [api_spec_output]
  - worker_id: recon-browser-ext
    tool: browser_extension_recon --domain {{scope_root}}
    priority: 4
    description: "Browser extension recon — manifest analysis, content scripts, hardcoded API keys/endpoints"
    condition: "browser_extension_hint_found == true"
    outputs: [browser_ext_output]
  - worker_id: recon-sourcemap
    tool: sourcemapper --targets {{js_bundle_urls}} --output sourcemap_output.jsonl
    priority: 4
    description: "Source map recovery — extract original unminified JavaScript source from .map files; feeds SourceHunter for deeper sink analysis beyond jsluice"
    condition: "js_bundles_downloaded == true"
    outputs: [sourcemap_output]
  - worker_id: recon-dom-xss
    tool: dom_xss_analyzer --input js_bundles/ --output dom_xss_output.jsonl
    priority: 4
    description: "DOM XSS static analysis via JavaScript AST — dangerous sinks (innerHTML, document.write, eval, location.href with attacker-controlled data)"
    condition: "js_bundles_downloaded == true"
    outputs: [dom_xss_output]
  - worker_id: recon-origin-ip
    tool: origin_ip_hunter --domain {{scope_root}} --methods historical,subdomains,shodan,ct
    priority: 3
    description: "Real origin IP discovery behind CDN/WAF — enables direct exploitation bypassing WAF protections"
    condition: "behind_cdn == true"
    outputs: [origin_ip_output]
  - worker_id: recon-403-bypass
    tool: nomore403 --urls {{forbidden_urls}} --output nomore403_output.jsonl
    priority: 3
    description: "403 bypass tester — path variations, X-Original-URL/X-Rewrite-URL headers, trailing slash, URL encoding bypass techniques"
    condition: "forbidden_responses_found == true"
    outputs: [nomore403_output]
  - worker_id: recon-sse
    tool: casecrack sse-scan --target {{target}} --output sse_recon_output.jsonl
    priority: 3
    description: "SSE endpoint discovery + CORS misconfiguration analysis + auth bypass testing on event streams + session hijacking via SSE"
    condition: "always"
    outputs: [sse_recon_output]
  - worker_id: recon-saml
    tool: casecrack saml-recon --target {{target}} --output saml_recon_output.jsonl
    priority: 2
    description: "SAML SP/IdP metadata discovery + ACS endpoint enumeration + XML Signature Wrapping susceptibility analysis + relay state testing"
    condition: "saml_login_detected == true OR sso_endpoint_found == true"
    outputs: [saml_recon_output]
  - worker_id: recon-favicon
    tool: casecrack favicon-correlate --target {{target}} --output favicon_recon_output.jsonl
    priority: 3
    description: "Favicon MMH3/MD5 hash computation + correlation against 600+ product fingerprints via Shodan/FOFA/Censys InternetDB + related infra discovery"
    condition: "always"
    outputs: [favicon_recon_output]
  - worker_id: recon-csp
    tool: casecrack csp-analyze --target {{target}} --output csp_analysis_output.jsonl
    priority: 3
    description: "CSP directive-level parsing + bypass vector detection: unsafe-inline, JSONP callbacks, script gadgets, nonce reuse, base-uri hijack, wildcard sources"
    condition: "always"
    outputs: [csp_analysis_output]
  - worker_id: recon-error-pages
    tool: casecrack error-analyze --target {{target}} --output error_page_output.jsonl
    priority: 3
    description: "Error page info extraction: server/framework/DB versions, file paths, internal IPs, connection strings, stack trace paths from 4xx/5xx responses"
    condition: "always"
    outputs: [error_page_output]
  - worker_id: recon-mobile-api
    tool: casecrack mobile-api-recon --target {{target}} --output mobile_api_output.jsonl
    priority: 3
    description: "Mobile API endpoint discovery + cert pinning bypass detection + deep link/URL scheme hijacking + JWT refresh abuse + device fingerprint bypass"
    condition: "mobile_app_detected == true OR android_app_link_found == true OR ios_universal_link_found == true"
    outputs: [mobile_api_output]
  - worker_id: recon-second-order
    tool: casecrack second-order-scan --target {{target}} --output second_order_output.jsonl
    priority: 2
    description: "Second-order injection storage point enumeration: forms, API endpoints, profile fields, comment boxes where user input is stored and later rendered"
    condition: "storage_endpoints_found == true OR user_profile_found == true"
    outputs: [second_order_output]
  - worker_id: recon-postmessage
    tool: casecrack postmessage-analyze --target {{target}} --output postmessage_output.jsonl
    priority: 3
    description: "postMessage origin analysis in JS bundles: wildcard targetOrigin, weak origin validation, message dispatch routing without auth, cross-window/opener chains"
    condition: "js_bundles_found == true"
    outputs: [postmessage_output]
  - worker_id: recon-ipv6
    tool: casecrack ipv6-scan --target {{target}} --output ipv6_scan_output.jsonl
    priority: 3
    description: "IPv6 dual-stack discovery: port exposure, SLAAC address prediction, dual-stack ACL bypass (IPv4 blocked but IPv6 accessible), NDP enumeration, extension header abuse"
    condition: "always"
    outputs: [ipv6_scan_output]
  - worker_id: recon-supply-chain
    tool: casecrack supply-chain-intel --target {{target}} --output supply_chain_output.jsonl
    priority: 2
    description: "Supply chain analysis: npm/PyPI dep confusion, typosquatting detection, OSV CVEs for discovered versions, CDN SRI missing/weak, GH Actions workflow secrets exposure"
    condition: "package_json_found == true OR requirements_txt_found == true OR github_repo_found == true"
    outputs: [supply_chain_output]
  - worker_id: recon-juicy-files
    tool: casecrack juicy-files --target {{target}} --output juicy_files_output.jsonl
    priority: 2
    description: "Juicy file hunting: 150+ extensions, 7-level severity scale, backup variants (.bak/.old/.swp), IDE artifacts (.idea/.vscode), source maps, directory-based probing"
    condition: "always"
    outputs: [juicy_files_output]
  - worker_id: recon-dork
    tool: casecrack google-dork --target {{target}} --output google_dork_output.jsonl
    priority: 3
    description: "Google/Bing/DuckDuckGo/Yahoo dorking: 100+ templates, 12 categories covering admin panels, credentials, exposed docs, file listings, error pages, shadow IT"
    condition: "always"
    outputs: [google_dork_output]
  - worker_id: recon-http2
    tool: casecrack http2-security --target {{target}} --output http2_security_output.jsonl
    priority: 3
    description: "HTTP/2 security testing: request smuggling, HPACK header injection, RST flood, h2c cleartext upgrade, HTTP/2-specific security vulnerabilities"
    condition: "http2_supported == true"
    outputs: [http2_security_output]
  - worker_id: recon-http3
    tool: casecrack http3-scan --target {{target}} --output http3_scan_output.jsonl
    priority: 3
    description: "HTTP/3/QUIC service discovery + endpoint enumeration + HTTP/2 vs HTTP/3 differential security analysis"
    condition: "quic_service_detected == true OR port_443_udp_open == true"
    outputs: [http3_scan_output]
  - worker_id: recon-wappalyzer
    tool: casecrack wappalyzer-scan --target {{target}} --output wappalyzer_output.jsonl
    priority: 3
    description: "Wappalyzer full tech detection: 1200+ technology fingerprints, CMS/framework/plugin versions broader and more accurate than httpx tech-detect"
    condition: "always"
    outputs: [wappalyzer_output]
  - worker_id: recon-takeover-verify
    tool: casecrack takeover-verify --target {{target}} --output subdomain_takeover_output.jsonl
    priority: 1
    description: "Subdomain takeover verification: CNAME pointing to decommissioned cloud services (GitHub Pages, Heroku, Fastly, Azure, S3), NS delegation takeover candidates"
    condition: "subdomains_found == true"
    outputs: [subdomain_takeover_output]
  - worker_id: recon-sbom
    tool: casecrack sbom-generate --target {{target}} --output sbom_output.jsonl
    priority: 3
    description: "SBOM generation + dependency analysis: extract package.json/requirements.txt/yarn.lock, OSV CVE correlation, vulnerable version detection, EOL package flagging"
    condition: "dependency_files_found == true OR js_bundles_found == true"
    outputs: [sbom_output]
  - worker_id: recon-spa
    tool: casecrack spa-security --target {{target}} --output spa_security_output.jsonl
    priority: 3
    description: "SPA security analysis: client-side routing bypass, React/Angular/Vue specific sink patterns, hydration desync, shadow DOM injection, framework-specific XSS"
    condition: "spa_framework_detected == true (React OR Angular OR Vue OR Svelte)"
    outputs: [spa_security_output]
  - worker_id: recon-wasm
    tool: casecrack wasm-analyze --target {{target}} --output wasm_analysis_output.jsonl
    priority: 3
    description: "WebAssembly binary analysis: exported function discovery, memory access patterns, crypto implementation review, dangerous imports (eval-like), WASM hardening gaps"
    condition: "wasm_files_found == true"
    outputs: [wasm_analysis_output]
  - worker_id: recon-archive-sourcemap
    tool: casecrack archive-sourcemap --target {{target}} --output archive_sourcemap_output.jsonl
    priority: 3
    description: "Wayback Machine .js.map/.css.map scanning: probes archived versions for source maps historically exposed, recovers original unminified source from cache"
    condition: "always"
    outputs: [archive_sourcemap_output]
  - worker_id: recon-headers
    tool: casecrack headers-analyze --target {{target}} --output headers_analysis_output.jsonl
    priority: 3
    description: "HTTP security header completeness: HSTS absent/short max-age, X-Frame-Options, missing CSP/CORP/COEP/COOP, CORS wildcard, cookie Secure/HttpOnly/SameSite"
    condition: "always"
    outputs: [headers_analysis_output]
  - worker_id: recon-log-endpoints
    tool: casecrack log-endpoint-scan --target {{target}} --output log_endpoint_output.jsonl
    priority: 3
    description: "Exposed log/debug endpoint detection: /logs, /_logs, /debug/logs, /admin/logs, actuator/logfile, laravel log, django debug toolbar without auth"
    condition: "always"
    outputs: [log_endpoint_output]
  - worker_id: recon-params
    tool: casecrack param-discover --target {{target}} --output param_discovery_output.jsonl
    priority: 3
    description: "Parameter discovery: AI-generated target-specific wordlists (smart_wordlists.py), hidden param enumeration (Arjun-style), parameter mining from JS/docs/responses"
    condition: "endpoints_found == true"
    outputs: [param_discovery_output]
```

### Blackboard Protocol

Each worker writes to the shared blackboard:

```jsonc
{
  "worker_id": "recon-deep-dns",
  "phase": "P1",
  "hypothesis": "staging-api.example.com is an undocumented subdomain",
  "confidence": 0.65,
  "evidence": ["dns_brute_force_hit", "nxdomain_fallback"],
  "timestamp": "<ISO8601>",
  "status": "proposed"
}
```

The orchestrator merges all worker outputs, deduplicates by `(fqdn, port)`,
and selects the highest `anomaly_score` per host.

