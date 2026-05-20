  5. If no protocol matches: apply Step Template only; set poc_complexity: trivial.
  6. If WAF detected (wafw00f signal present): also load protocols/waf-bypass.md.
```

| `vuln_class` / trigger signal | Protocol subfile | Notes |
|-------------------------------|-----------------|-------|
| `race_condition`, `toctou`, `time_of_check_time_of_use` | `race-condition.md` | |
| `request_smuggling`, `http_desync`, `cl_te_smuggling`, `cl0_desync`, `te0_desync` | `http-smuggling.md` | |
| `ssti`, `template_injection`, `ssti_sink` | `ssti.md` | |
| `saml`, `golden_saml`, `saml_wrapping`, `saml_xsw` | `saml.md` | |
| `cookie_bypass`, `cookie_prefix`, `cookie_chaos` | `cookie-bypass.md` | |
| `css_injection`, `css_exfil` | `css-exfil.md` | |
| `prototype_pollution` AND `websocket` in chain_flags | `websocket-proto-pollution.md` | WebSocket-specific; see also generic below |
| `llm_injection`, `prompt_injection`, `indirect_prompt_injection` | `llm-prompt-injection.md` | |
| `idor`, `bola`, `broken_object_level_auth` | `idor.md` | |
| `auth_bypass`, `broken_auth`, `jwt_weak`, `jwt_none_alg`, `jwt_alg_confusion` | `auth-bypass.md` | |
| `ssrf`, `blind_ssrf`, `ssrf_sink`, `server_side_request_forgery` | `ssrf.md` | Includes OOB-free fallback |
| `xxe`, `xml_injection`, `xxe_indicator` | `xxe.md` | |
| `business_logic`, `price_manipulation`, `workflow_bypass`, `negative_quantity` | `business-logic.md` | |
| `web_cache`, `cache_poisoning`, `cache_deception`, `unkeyed_header` | `web-cache.md` | |
| `subdomain_takeover`, `dangling_cname`, `ns_delegation_takeover` | `subdomain-takeover.md` | |
| `prototype_pollution` (generic, no WebSocket flag) | `prototype-pollution.md` | |
| `cors_misconfiguration`, `cors_sink` | `cors.md` | |
| `path_traversal`, `lfi`, `directory_traversal`, `path_traversal_sink` | `path-traversal.md` | |
| `open_redirect`, `open_redirect_sink` | `open-redirect.md` | |
| `graphql_introspection`, `graphql_ide_exposed`, `graphql_mutation_unauth`, `graphql_batching` | `graphql.md` | |
| `insecure_deserialization`, `deser_sink` | `insecure-deserialization.md` | |
| `orm_injection`, `sqli`, `sqli_sink`, `mass_assignment_sink` | `orm-injection.md` | |
| WAF detected (any `wafw00f_signal` present) | `waf-bypass.md` | Load alongside primary protocol |

## Output Format


### `poc-steps.md`

Markdown with one H2 section per finding:
- Header: `## [TRG-id] vuln_class on fqdn` 
- CVSS vector and score
- poc_complexity and model used
- Full step sequence using the step template above

### `repro-requests.http`
