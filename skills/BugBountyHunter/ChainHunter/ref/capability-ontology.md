## Capability Ontology

Every finding is mapped to a `requires` set (what attacker state is needed before this step
is exploitable) and a `grants` set (what new attacker capabilities the step confers upon
successful exploitation). Chains are valid when the grants of step N satisfy the requires of
step N+1. This replaces ad-hoc pairwise reasoning with auditable graph edges.

### Capability Hierarchy

```yaml
capability_ontology:
  ontology_version: "2026.05-cap1"

  # Reachability
  reachability:
    - external_network_access       # attacker can send HTTP requests to target
    - internal_network_access       # attacker can reach 10.x/172.x/169.254.x networks
    - subdomain_control             # attacker controls a subdomain of the target domain
    - origin_ip_direct_access       # attacker can reach origin IP bypassing CDN/WAF

  # Authentication & Authorization
  authn_authz:
    - unauthenticated               # default initial attacker state
    - authenticated_as_user         # valid low-privilege session
    - authenticated_as_admin        # valid admin/superuser session
    - auth_bypass_achieved          # authentication skipped or forged
    - session_token_stolen          # valid victim session credential obtained
    - oauth_authorization_code      # OAuth authorization code in attacker possession
    - oauth_access_token            # OAuth access token in attacker possession
    - saml_assertion_forged         # SAML assertion created without valid IdP sig
    - credential_harvested          # plaintext username/password obtained
    - idor_access                   # can access any object via ID manipulation
    - horizontal_priv_esc           # peer account access (different user, same role)
    - vertical_priv_esc             # elevated role (user → admin, tenant → super)

  # Execution & Control
  execution:
    - arbitrary_code_execution      # RCE on the server
    - template_injection_rce        # SSTI → RCE path
    - prototype_pollution_server    # Node.js global prototype corrupted
    - business_logic_abuse          # races, duplicate transactions, workflow bypass
    - cache_poisoned                # CDN/in-memory cache contains attacker payload
    - request_smuggled              # HTTP desync achieved — back-end sees poisoned prefix

  # Data & Secrets
  data_secrets:
    - sensitive_data_read           # user PII, financial data, health records
    - internal_secret_leak          # API key, private key, DB credential
    - cloud_iam_creds_extracted     # AWS/GCP/Azure IAM credential from IMDS or vault
    - source_code_recovered         # app source or route map obtained from source maps
    - dom_attribute_exfiltrated     # user DOM attribute value leaked via CSS/timing

  # Client-Side & Supply Chain
  client_supply:
    - xss_executed                  # JavaScript runs in victim browser context
    - postmessage_abused            # cross-origin message handler exploited
    - csp_bypassed                  # Content Security Policy circumvented
    - supply_chain_injected         # malicious code in shared CDN/package

  # Cloud & Federation
  cloud_federation:
    - cross_tenant_access           # data/actions in another tenant achieved
    - idp_federation_abused         # cross-IdP identity assertion accepted
    - cloud_account_compromised     # cloud root/admin credentials extracted

  # Enablers (not goals, but transition catalysts)
  enablers:
    - info_disclosure_enabling      # version, path, internal IP disclosed
    - parser_differential_abused    # front-end / back-end parse request differently
    - dns_zone_enumerated           # full internal hostname map obtained
```

### Capability Extraction Protocol

For each `chain_relevance`-annotated finding, extract a structured capability record:

```jsonc
{
  "triage_id": "TRG-a1b2c3d4",
  "vuln_class": "Server-Side Request Forgery",
  "requires": ["external_network_access"],
  "grants": ["internal_network_access", "cloud_iam_creds_extracted"],
  "impact_tags": ["lateral_movement", "credential_theft"],
  "confidence": 0.90
}
```

**Transition matching rule**: B can follow A when:
- `grants_A ∩ requires_B ≠ ∅` (hard match), OR
- `embedding_cosine(grants_A_vector, requires_B_vector) > 0.72` (soft semantic match)
- AND tech-stack plausibility from `source_correlations` is not contradicted.

### Canonical Capability Maps (by Chain Class)

| Chain Class | requires | grants |
|-------------|----------|--------|
| SSRF → Internal | `external_network_access` | `internal_network_access` |
| IMDS → IAM Credential | `internal_network_access` | `cloud_iam_creds_extracted` |
| Open Redirect → OAuth | `external_network_access` | `oauth_authorization_code` |
| Subdomain Takeover → Cookie | `subdomain_control` | `session_token_stolen` |
| XSS → Session Theft | `xss_executed` | `session_token_stolen` |
| SAML Void Canon → Forgery | `external_network_access` | `saml_assertion_forged`, `auth_bypass_achieved` |
| Prototype Pollution | `external_network_access` | `prototype_pollution_server` |
| LLM Indirect Injection | `external_network_access` | `sensitive_data_read`, `business_logic_abuse` |
| Cookie Prefix Bypass + XSS | `xss_executed`, `subdomain_control` | `session_token_stolen`, `auth_bypass_achieved` |
| CL.0 Desync | `external_network_access` | `request_smuggled`, `cache_poisoned` |
| Supply Chain Injection | `external_network_access` | `supply_chain_injected`, `xss_executed` |
| Cloud IAM Escalation | `cloud_iam_creds_extracted` | `cloud_account_compromised`, `vertical_priv_esc` |
| SSRF Redirect Loop | `ssrf_vector` | `blind_ssrf_amplified`, `internal_network_access` |
| LLM Fetch → SSRF | `llm_fetch_capability` | `internal_network_access`, `blind_ssrf_amplified` |

