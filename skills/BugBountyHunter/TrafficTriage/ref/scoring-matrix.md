## Scoring Matrix

| Signal | Exploit Score Contribution |
|--------|----------------------------|
| Auth endpoint (login/oauth/reset/session) exposed | +2.5 |
| JWT accepted without signature verification signal | +3.0 |
| Admin/internal route reachable without auth signal | +3.5 |
| Verbose error / stack trace in response body | +2.0 |
| Directory listing enabled | +1.5 |
| Debug header present (`X-Debug`, `X-Powered-By` w/ version) | +1.0 |
| Swagger/OpenAPI/GraphQL introspection publicly accessible | +2.0 |
| Non-standard high port with 200 OK | +1.5 |
| Nuclei hit severity=critical | +4.0 |
| Nuclei hit severity=high | +2.5 |
| Nuclei hit severity=medium | +1.5 |
| Direct origin IP (no CDN) | +0.5 |
| CORS misconfiguration signal | +2.0 |
| Open redirect signal | +1.0 |
| SSRF sink reachable | +3.0 |
| Race-window potential (payment/coupon/transfer) | +3.5 |
| `.git/HEAD` or `.env` publicly accessible | +4.0 |
| S3/GCS/Azure blob bucket endpoint detected | +2.5 |
| IDP/SAML/OIDC endpoint exposed (IdP, ACS, relay) | +3.0 |
| GraphQL introspection with deep nested type access | +2.5 |
| `Authorization: Bearer` accepted on unauthenticated path | +3.5 |
| Sensitive `cache-control` header absent on auth endpoint | +1.5 |
| Path traversal sequence (`../`, `%2e%2e`) in URL param | +2.0 |
| Mass assignment endpoint (PUT/PATCH with broad body) | +2.5 |
| Prototype pollution sink in JavaScript bundle | +2.5 |
| Subdomain with dangling CNAME (takeover candidate) | +3.5 |
| gRPC/protobuf endpoint accessible without auth | +3.0 |
| Supply chain: known-CVE package version in X-Powered-By | +2.0 |
| gitleaks/trufflehog secret detected on this host's assets | +4.5 |
| Exposed `.git/config` or commit history (not just `.git/HEAD`) | +3.5 |
| Host header injection reflected in Location/redirect | +2.5 |
| HTTP Request Smuggling indicator (ambiguous CL+TE headers) | +3.5 |
| TE.0 smuggling indicator (OPTIONS/CONNECT with TE:chunked but no Content-Length) | +3.0 |
| SSTI payload pattern in URL/body response (`{{7*7}}`→49) | +4.0 |
| SSTI error-based indicator (framework exception from malformed template expr) | +3.5 |
| Insecure deserialization header/param (`_method`, `X-Java-Serialized-Object`) | +3.5 |
| Account enumeration via timing differential (auth endpoint) | +2.0 |
| Web cache deception potential (path extension suffix on auth endpoint, e.g. `/account/x.css`) | +2.5 |
| ORM filter/search param leaking (JSON `$eq/$in/$regex` style, ORM field traversal) | +2.5 |
| HTTP/2 CONNECT proxy accessible (h2c cleartext or CONNECT method not blocked) | +2.5 |
| XS-Leak surface (ETag discloses payload length, cross-origin timing oracle detectable) | +2.0 |
| Parser differential indicator (front-end route accepted, back-end interprets differently) | +3.0 |
| Cookie tossing surface (subdomain can set cookies for parent domain, OAuth flow present) | +2.5 |
| OAuth Referer-based redirect accepted during auth flow (Referer honored as redirect_uri) | +3.0 |
| Deprecated/old API version accessible alongside current (/v1 + /v3 both live) | +2.0 |
| DoubleClickjacking surface (iframe embeddable, sensitive action on double-click/drag) | +1.5 |
| gRPC server reflection enabled (all service methods queryable without auth) | +2.5 |
| GraphQL batch queries enabled (array of operations in single POST body) | +2.0 |
| Unicode normalization attack surface (charset conversion endpoint, user-controlled charset) | +2.0 |
| Next.js internal fetch cache (RSC endpoint, stale data from internal route handler) | +2.5 |
| Cookie prefix bypass surface (`__Host-`/`__Secure-` cookie processed by Django/ASP.NET/Tomcat/Jetty ≥ path with subdomain XSS) | +2.5 |
| WebSocket Socket.IO server-side prototype pollution (`EIO=4` endpoint + `{"__proto__":…}` in message body) | +3.0 |
| CSS injection via inline style attribute (user-controlled value reflected inside `style="…"` without sanitization) | +2.5 |
| LLM-integrated feature endpoint (app calls LLM API with user-controlled prompt; function-calling tools present) | +3.5 |
| CL.0 desync indicator (server pauses on request body for unknown method/path, no TE/CL required for response desync) | +3.0 |
| DOM clobbering candidate (id-based DOM element shares name with global variable referenced in script) | +2.5 |
| SAML Void Canonicalization exposure (ruby-saml < 1.18.0, php-saml, xmlseclibs < 3.1.4 fingerprinted on target SP) | +4.0 |
| **[OAuth/OIDC Recon Signals — from oauth_recon_output]** | |
| OAuth implicit flow enabled (token returned in URL fragment via response_type=token) | +3.0 |
| OAuth PKCE downgrade possible (code_challenge_method=plain accepted, or PKCE not required) | +3.5 |
| OAuth dangerous scope available (admin, write:*, openid+email simultaneously) | +2.5 |
| OAuth redirect_uri validation weak (subdomain wildcard, prefix match, or no validation) | +3.0 |
| OAuth cross-tenant token acceptance (token minted for provider A accepted by provider B) | +4.0 |
| OAuth implicit grant + CORS wildcard on token endpoint | +4.0 |
| Well-known config misconfiguration (none alg, implicit flow, missing PKCE, insecure grant types) | +2.5 |
| **[GraphQL Recon Signals — from graphql_recon_output]** | |
| GraphQL introspection enabled (full schema returned without authentication) | +2.5 |
| GraphQL introspection bypass succeeded (batched/alternative endpoint bypasses disabled introspection) | +3.5 |
| GraphQL IDE exposed without auth (GraphiQL, Playground, Altair accessible at known paths) | +3.0 |
| GraphQL mutation available without authentication | +4.0 |
| GraphQL sensitive field names in schema (password, ssn, token, secret, key) | +3.0 |
| **[WebSocket Recon Signals — from websocket_recon_output]** | |
| WebSocket endpoint using ws:// (unencrypted) | +2.5 |
| WebSocket CSWSH vulnerable (cross-origin WS connection accepted without origin validation) | +4.0 |
| WebSocket CSWSH partial (origin validated on some endpoints but not all) | +2.5 |
| WebSocket auth bypass (connection accepted without auth token or cookie) | +3.5 |
| WebSocket injection possible (structured message with user-controlled field, no sanitization) | +3.0 |
| **[TLS/Certificate Signals — from tls_scan_output]** | |
| TLS weak cipher suite accepted (RC4, NULL, EXPORT, 3DES) | +2.5 |
| TLS deprecated protocol accepted (SSLv3, TLSv1.0, TLSv1.1) | +2.5 |
| TLS certificate expired or self-signed in production | +2.0 |
| TLS certificate hostname mismatch (cert issued for different domain) | +2.0 |
| **[Cloud Asset Signals — from cloud_assets_output]** | |
| Cloud storage bucket publicly listable (AWS S3, Azure Blob, GCP Storage) | +4.0 |
| Cloud storage bucket public write enabled | +5.0 |
| Cloud IAM misconfiguration (over-permissive role, public Lambda, unauthenticated API GW) | +3.5 |
| **[DNS Security Signals — from dns_security_output]** | |
| DNS zone transfer allowed (AXFR reveals all internal hostnames) | +3.5 |
| DNS rebinding potential (short TTL + predictable IP range, internal service accessible) | +2.5 |
| NSEC zone walking possible (DNSSEC NSEC records enumerate all zone names) | +2.0 |
| **[Email Security Signals — from email_security_output]** | |
| Email spoofing risk HIGH (SPF absent/+all AND DMARC absent/p=none) | +2.5 |
| DMARC absent for main domain | +1.5 |
| SPF includes wildcard/permissive rule (+all or ?all) | +1.5 |
| **[WAF/Access Control Signals — from wafw00f_output + nomore403_output]** | |
| 403 bypass confirmed (path accessible after bypass technique) | +3.0 |
| WAF vendor identified (affects downstream exploit difficulty, note bypass hints) | +0.5 |
| **[Visual Recon Signals — from screenshot_output]** | |
| Admin panel found (page_category: admin, default_install, or setup) | +2.5 |
| Login panel found on non-standard port (page_category: login, port not 443) | +2.0 |
| Default installation page (Tomcat manager, phpMyAdmin, Kibana, Grafana default) | +3.0 |
| **[SaaS / Integration Signals — from saas_intel_output]** | |
| SaaS API token/webhook secret visible in frontend HTML or JS | +3.5 |
| Third-party OAuth token (Slack, Jira, GitHub) visible in page source | +3.5 |
| **[VCS Deep Recon Signals — from github_deep_output]** | |
| Secret found via GitHub org member recon (member repo, personal fork) | +3.5 |
| Secret found via GitHub Actions workflow file (CI/CD env var leak) | +4.0 |
| Secret found via cross-fork object reference (CFOR, deleted commit still accessible) | +4.0 |
| **[Origin IP / Infrastructure Signals — from origin_ip_output]** | |
| Direct origin IP accessible behind CDN (Cloudflare/Akamai/Fastly bypass) | +2.5 |
| **[Browser Extension Signals — from browser_ext_output]** | |
| Hardcoded API key or endpoint in browser extension source | +3.0 |
| Browser extension has overly broad content script permissions | +1.5 |
| **[DOM/Source Signals — from dom_xss_output + sourcemap_output]** | |
| DOM XSS dangerous sink found in JS bundle (innerHTML, document.write, eval with user input) | +3.0 |
| Original source recovered from source map (exposes business logic, hidden endpoints) | +2.0 |
| **[SSE Signals — from sse_recon_output]** | |
| SSE endpoint accessible with CORS wildcard (cross-origin event stream reading possible) | +3.0 |
| SSE endpoint accessible without authentication (no auth required on event stream) | +3.0 |
| SSE endpoint with credential exposure in event data | +3.5 |
| SSE event injection candidate found (attacker-controlled event data) | +2.5 |
| **[SAML Signals — from saml_recon_output]** | |
| SAML endpoint susceptible to XML Signature Wrapping (assertion forgery possible) | +4.5 |
| SAML signature algorithm is weak or exclusion bypass possible | +3.5 |
| SAML assertion replay possible (no replay cache, no timestamp validation) | +3.5 |
| SAML comment injection indicator found | +3.0 |
| SAML IdP confusion / SP metadata manipulation possible | +3.0 |
| **[Favicon Correlation Signals — from favicon_recon_output]** | |
| Favicon hash matched CVE-affected product (600+ product database) | +2.5 |
| Favicon hash revealed related infrastructure (same product on other IPs/ports) | +2.0 |
| **[CSP Analysis Signals — from csp_analysis_output]** | |
| CSP bypass vector found: JSONP callback endpoint in allowed sources | +3.0 |
| CSP bypass vector found: script gadget in allowed origin (angular.min.js, etc.) | +3.0 |
| CSP bypass vector found: unsafe-inline present on authenticated page | +2.5 |
| CSP bypass vector found: base-uri hijack possible (no base-uri or 'none') | +2.5 |
| CSP bypass vector found: wildcard source in script-src | +2.0 |
| CSP bypass via nonce reuse or static nonce detected | +3.0 |
| CSP completely absent on page with sensitive data / auth form | +2.5 |
| **[Error Page Signals — from error_page_output]** | |
| Server/framework version disclosed in error response (direct CVE fingerprinting) | +2.0 |
| Internal IP address disclosed in error response | +2.5 |
| Absolute file path disclosed in error response | +2.0 |
| Database connection string disclosed in error response | +3.5 |
| Environment variable values disclosed in error response | +3.0 |
| Stack trace with framework internals disclosed | +2.5 |
| **[Mobile API Signals — from mobile_api_output]** | |
| Certificate pinning bypassable (mobile API accessible without pinned cert) | +2.5 |
| Deep link / URL scheme hijacking possible (OAuth token theft via app intent) | +3.0 |
| Mobile API key exposed in binary or configuration | +3.0 |
| JWT refresh token abuse pattern detected in mobile API | +3.0 |
| **[Second-Order Injection Signals — from second_order_output]** | |
| Second-order injection storage point found (stored XSS/SQLi/SSTI/CMDi candidate) | +3.5 |
| OOB callback triggered from stored payload (blind second-order injection confirmed) | +4.5 |
| **[postMessage Signals — from postmessage_output]** | |
| postMessage wildcard targetOrigin found (postMessage(data, '*') in production) | +3.0 |
| postMessage handler without origin validation (any sender can trigger handler) | +3.5 |
| Weak origin validation bypassable (indexOf/endsWith/match with permissive regex) | +3.0 |
| postMessage structured dispatch routing without auth (internal command API exposed) | +3.0 |
| Cross-window chain via window.opener or window.parent with postMessage | +2.5 |
| **[IPv6 Signals — from ipv6_scan_output]** | |
| IPv6 dual-stack ACL bypass: IPv4 is blocked but IPv6 endpoint is accessible | +3.5 |
| IPv6 port exposure: service accessible only on IPv6 (not audited by IPv4 tools) | +2.5 |
| SLAAC address predictable (EUI-64 based, allows targeted scanning) | +2.0 |
| IPv6 extension header abuse possible (evasion of security appliances) | +2.5 |
| **[Supply Chain Signals — from supply_chain_output]** | |
| Dependency confusion vector: internal package name on public npm/PyPI registry | +4.0 |
| Typosquatted package detected in dependency tree | +3.5 |
| Known CVE in production dependency (from OSV.dev correlation) | +3.0 |
| CDN script without SRI integrity attribute (supply chain XSS possible) | +2.0 |
| Abandoned/deprecated package in use (no security patches) | +2.0 |
| GitHub Actions workflow exposes secrets in run block (CI/CD compromise) | +4.0 |
| **[Juicy File Signals — from juicy_files_output]** | |
| Critical juicy file accessible (level 1: .sql, .key, .env, private key, .pem) | +4.5 |
| High juicy file accessible (level 2: config file with credentials, backup.tar.gz) | +3.5 |
| Significant juicy file accessible (level 3: .js source, .php source code) | +2.5 |
| Backup variant accessible for known file (.bak, .old, .orig, .swp, ~) | +3.0 |
| IDE artifacts accessible (.idea/, .vscode/, .DS_Store, Thumbs.db) | +1.5 |
| **[Google Dork Signals — from google_dork_output]** | |
| Google/Bing/DuckDuckGo dork hit: sensitive resource indexed (admin/credentials/source) | +3.0 |
| Dork revealed exposed file listing (directory listing indexed by search engine) | +2.5 |
| Dork revealed cached version of internal/sensitive page | +2.5 |
| **[HTTP/2 Security Signals — from http2_security_output]** | |
| HTTP/2 HPACK header injection possible | +2.5 |
| HTTP/2 request smuggling vector found | +4.0 |
| h2c cleartext upgrade accepted (HTTP/2 over cleartext without TLS) | +2.0 |
| **[Subdomain Takeover Signals — from subdomain_takeover_output]** | |
| Subdomain takeover verified: CNAME confirmed pointing to unclaimed cloud service | +4.5 |
| Subdomain takeover candidate: CNAME chain to decommissioned service (unverified) | +3.0 |
| **[SBOM/Dependency Signals — from sbom_output]** | |
| Critical CVE (CVSS >= 9.0) in production dependency from SBOM analysis | +3.5 |
| High CVE (CVSS >= 7.0) in production dependency | +2.5 |
| End-of-life package in production with known unpatched vulnerabilities | +2.0 |
| **[SPA Security Signals — from spa_security_output]** | |
| SPA client-side routing bypass: authenticated route accessible without auth | +3.0 |
| React/Angular/Vue framework-specific XSS sink detected | +2.5 |
| Hydration desync between server and client rendering | +2.0 |
| **[WASM Security Signals — from wasm_analysis_output]** | |
| WASM binary uses weak cryptographic implementation | +2.5 |
| WASM binary has unsafe memory access patterns | +3.0 |
| WASM exported function with unsanitized external input | +2.5 |
| **[Headers/Missing Security Headers — from headers_analysis_output]** | |
| HSTS absent on HTTPS endpoint (SSL stripping possible on future visits) | +1.5 |
| X-Frame-Options absent (Clickjacking / DoubleClickjacking possible) | +1.0 |
| CORS: Access-Control-Allow-Origin wildcard with credentials | +3.0 |
| Cookie missing Secure, HttpOnly, or SameSite attributes on auth cookie | +2.0 |
| **[Log Endpoint Signals — from log_endpoint_output]** | |
| Debug/log endpoint accessible without authentication (/logs, /debug/logs, actuator/logfile) | +3.5 |
| Log endpoint exposes PII (email, usernames, session tokens visible in logs) | +4.0 |
| **[Parameter Discovery Signals — from param_discovery_output]** | |
| Hidden parameter found beyond crawl/docs (Arjun-style discovery) | +2.0 |
| Novel parameter bypasses access control or validation when added | +3.0 |

### Score Computation Rules

**Base formula**: `exploit_score = min(Σ(adjusted_weight × independence_factor), 10.0)`

**Signal Independence Groups** — correlated signals from the same root cause apply
at diminishing returns. Within each group, rank signals descending by weight;
the highest-weight signal counts at 100%, each subsequent same-group signal counts
at 60%:

| Group ID | Member Signals |
|----------|---------------|
| `auth_surface` | auth_endpoint, jwt_weak, admin_route, bearer_on_unauth_path, saml_endpoint_exposed |
| `injection_rce` | ssti_indicator, deserialization_param, ssrf_sink, path_traversal, xxe_indicator |
| `info_disclosure` | verbose_error, debug_header, error_page_version, error_page_stack_trace, error_page_internal_ip |
| `oauth_signals` | oauth_implicit_flow, oauth_pkce_downgrade, oauth_redirect_weak, oauth_cross_tenant, oauth_dangerous_scope |
| `graphql_signals` | graphql_introspection, graphql_ide_exposed, graphql_mutation_unauth, graphql_batching |
| `secret_exposure` | secrets_detected, gitleaks_hit, trufflehog_hit, github_actions_secret, juicy_file_critical |
| `request_smuggling` | cl_te_smuggling, te0_desync, cl0_desync, http2_smuggling |
| `cloud_storage` | cloud_bucket_listable, cloud_bucket_writable, cloud_iam_misconfigured |

**KG-dynamic weight adjustment** — before summing, adjust each signal's weight
using historical payout data from the knowledge graph:

```python
for signal in matched_signals:
    kg_factor = kg_query(
        "signal_payout_rate",
        signal=signal.name,
        tech_stack=host.tech_stack,
        target_scope=manifest.target_domain
    )  # returns 1.0 when no KG data; > 1.0 for historically high-value signal
    adjusted_weight = signal.base_weight * clamp(kg_factor, min=0.5, max=1.5)
```

Apply `independence_factor` (1.0 for first in group, 0.6 for each subsequent)
AFTER KG weight adjustment. Record per-signal breakdown in `score_justification`.

**Program-priority multiplier** — if `attack_surface_priorities` input is present:
After KG adjustment and independence factoring, apply a final ×1.3 multiplier to
the `exploit_score` of any signal whose `vuln_class` matches a CRITICAL or HIGH
priority class listed in `attack_surface_priorities`. Record this multiplier in
`score_justification` as `program_priority_bonus: ×1.3`. Cap final score at 10.0.

Cap final score at 10.0.

