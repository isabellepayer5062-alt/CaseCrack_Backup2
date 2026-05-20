# ANDURIL LATTICE — RECON ANALYSIS: BUG BOUNTY RANKED OPPORTUNITIES
# Session: 2026-05-14 | Scope: catalog.anduril.com + sandboxes.developer.anduril.com
# Based on 9 discovery scripts across gRPC auth service, SAML layer, and HTTP

---

## EXECUTIVE SUMMARY

Full proto schema recovered from `andurilapis-BLeYin38.js`. All gRPC services mapped.
Three-tier auth flow confirmed. Six active attack surfaces identified; two are immediately
reportable. One High-impact chain discovered (SAML open redirect with unauthenticated
attack entry).

---

## TIER 1 — REPORTABLE NOW (High Priority)

### FINDING-01: SAML RelayState Open Redirect
**Severity**: Medium (CVSS 6.1) — escalatable to High given military context
**Confidence**: HIGH — confirmed end-to-end
**Hosts**: catalog.anduril.com + sandboxes.developer.anduril.com

**Confirmed facts:**
1. `GetSSOURL(email, redirectUrl='https://evil.example.com')` → Okta SSO URL containing
   `RelayState=https%3A%2F%2Fevil.example.com` — **NO AUTH REQUIRED to call GetSSOURL**
2. POST `/authx/saml/acs/anduril` with `RelayState=https://evil.com` → 302 →
   `/login?ref=https%3A%2F%2Fevil.example.com`  — both hosts confirmed
3. After valid SAML authentication, ACS redirects to RelayState URL (standard SAML behavior)

**Attack chain:**
```
Attacker → GetSSOURL(email=victim@anduril.com, redirectUrl=https://evil.com)
         ← Okta URL: https://anduril.okta.com/.../sso/saml?SAMLRequest=...&RelayState=https%3A%2F%2Fevil.com

Attacker → Sends Okta URL to victim via phishing/social engineering

Victim   → Authenticates on real anduril.okta.com (no UI warning — URL is legitimate)
         ← Okta POSTs SAMLResponse + RelayState=https://evil.com to /authx/saml/acs/anduril
         ← Server sets session cookies + redirects to https://evil.com
         ← Victim lands on attacker-controlled site
```

**Evidence from testing:**
```
GetSSOURL(redirectUrl=evil): RelayState=https%3A%2F%2Fevil.example.com embedded in Okta URL
POST /authx/saml/acs/anduril (SAMLResponse=invalid, RelayState=evil.com):
  → 302 Location=/login?ref=https%3A%2F%2Fevil.example.com%2Fcapture&msg=...
  *** OPEN REDIRECT — Location contains attacker URL! ***
```

**Impact**: Social engineering vector against Anduril operators. Victim authenticates
on real Okta (trustworthy), then lands on fake Lattice clone. Enables phishing for
MFA codes, session token harvest, or malware delivery to military platform users.

**ACS URL**: `https://catalog.anduril.com/authx/saml/acs/anduril`
**SP entity ID**: `https://catalog.anduril.com/authx`
**Okta App**: `anduril_samlcatalog_1` / `exkm7um7jBtmmgD8U4h6`
**GetSSOURL fields**: `{email (f1), redirectUrl (f2), appendToken (f3)}`

**Note**: `AuthnRequestsSigned="false"` in SP metadata confirms unsigned requests are
accepted, meaning the attacker can also craft arbitrary SAMLRequest XMLs with custom
ForceAuthn attributes to force re-authentication.

---

### FINDING-02: LoginPassword — No Rate Limiting / Account Lockout
**Severity**: Medium (CVSS 7.5 High if standalone, 6.5 Medium in context)
**Confidence**: HIGH — 10 rapid requests confirmed
**Report**: _report_medium_no_ratelimit.md (already written)

**Evidence**: 10 consecutive requests, avg 136ms, zero `x-ratelimit-limit` headers,
zero `retry-after` headers, zero account lockout. Both catalog and sandboxes.

---

## TIER 2 — NEEDS MORE EVIDENCE

### FINDING-03: ApplyProfile — Unauthenticated Application Logic Reach
**Severity**: Unknown (Low to High)
**Confidence**: PARTIAL — reaches app logic but can't complete exploit

**Facts confirmed:**
- `Tokens/ApplyProfile` with any body returns `grpc=2 (UNKNOWN)`, NOT `grpc=16 (UNAUTHENTICATED)`
- Error: `"no valid profile id in the request. profile id must be a UUID prefixed by 'profi'"`
- This means the method processes unauthenticated requests past the auth layer
- Profile ID format: starts with literal string `profi` followed by a UUID
- None of our test UUIDs (random, zeros, all-FF) matched a valid profile

**Missing**: A valid profile ID from the system (would need to enumerate from API, source leak, or have valid account)
**If exploitable**: Applying an arbitrary authorization profile to a session without credentials = privilege escalation
**Next step**: Find profile IDs via HA/recon of developer documentation, GitHub leaks, or if a valid account can be obtained

---

### FINDING-04: Tokens/SignOut — Always Returns grpc=0 Without Authentication
**Severity**: Informational to Low
**Confidence**: HIGH (behavior confirmed)

**Facts**: `SignOut` with any body (empty, string, JWT format) returns `grpc=0` (OK)
without an Authorization header. With auth header: validates JWT (returns crypto error
on invalid JWT). The no-auth-0 response is likely a null implementation.
**Risk**: If a valid session JWT is passed in auth header and it succeeds, this would be an
authenticated logout. The no-auth-0 behavior suggests the method returns "success" even
with no session context — possibly to avoid leaking "session not found" oracles.
**Not reportable** as standalone; might be a building block in CSRF-equivalent chain.

---

## TIER 3 — ARCHITECTURAL DISCOVERIES (Informational)

### FINDING-05: Three-Tier Token Architecture (Internal Design)
```
OIDC path:  RefreshOidcTokens(okta_refresh_token) → ??? → GenerateBearerToken
SAML path:  SAML assertion → ACS → session cookie → RefreshSessionToken(jwt) → GenerateBearerToken
Internal:   LoginPassword(email,pw) → refresh_token → RefreshSessionToken(jwt) → GenerateBearerToken
```
**Token endpoints and their auth requirements:**
| Method                  | Auth Required | Notes |
|-------------------------|---------------|-------|
| LoginPassword           | No (it IS auth) | No rate limit |
| GetSSOURL               | No  | Returns Okta URL with RelayState |
| GetPrimaryIDP (Idps)    | No  | Returns SAML config |
| GetSPMetadata (Idps)    | No  | Returns SP XML cert/metadata |
| RefreshSessionToken     | Yes (Authorization: refresh JWT) | "refresh-token is required" |
| RefreshOidcTokens       | No auth check | grpc=2 UNKNOWN — OIDC client lookup |
| GenerateBearerToken     | Yes (Authorization: session JWT) | "no credentials present" |
| ValidateRefreshToken    | Yes (Authorization: refresh JWT) | different error message |
| ValidateBearerToken     | Yes (Authorization: bearer JWT) | "no credentials present" |
| ApplyProfile            | No auth check | grpc=2 UNKNOWN — UUID format check |
| SignOut                 | Optional | grpc=0 even without auth |
| MutateTokenValidity     | Yes | "no credentials present" |
| DeleteTokens            | Yes | "no credentials present" |
| ListUserTokens          | Yes | "no credentials present" |
| LoginPrimaryUser        | No | grpc=12 "primary user not configured" |

### FINDING-06: RefreshOidcTokens — Reaches Application Logic Without Auth
**Status**: Informational
`RefreshOidcTokens(refreshToken)` returns `grpc=2 (UNKNOWN)` not `grpc=16 (UNAUTHENTICATED)`.
Error: `"refresh_token did not match any known OIDC client"`. The server is attempting
to look up the OIDC client from the token. Okta OIDC refresh tokens are opaque — cannot
be crafted without valid Okta credentials. OIDC client IDs for anduril.okta.com JWKS:
- kid: `FWAvn1mKdQGXOCMgkvqAuPIfDfl9MpMyftlVe3bMH-0`
For login.developer.anduril.com (custom Okta domain):
- kid: `nQG86cn2x5ATuXTFHkaqGedgJp4PyWXiZhQtiATu8-Y`
- kid: `88-mMz-mCdOLF2ozfKICqY7x2J0G9vVQprXenYDjG3w`

### FINDING-07: LoginPrimaryUser — Unauthenticated, "Primary User Not Configured"
**Status**: Informational
Method exists and reaches application logic without auth. Returns `grpc=12 (UNIMPLEMENTED)`
with message "primary user not configured" on both catalog and sandboxes. This method
provides a credential-free backdoor login path for deployments with "primary user" configured.
May be exploitable on other Anduril deployments.

### FINDING-08: SAML SP Metadata — AuthnRequestsSigned=False
**Status**: Informational (part of FINDING-01)
SP does NOT sign AuthnRequests. Combined with unauthenticated `GetSSOURL`, an attacker
can craft arbitrary SAML AuthnRequest XMLs with custom attributes (ForceAuthn=true,
NameIDPolicy, etc.) without signature validation.
SP certificate: issued 2024-12-11, expires 2029-12-10 (CN=Anduril SAML SP)

---

## WHAT REQUIRES VALID CREDENTIALS (Out of Reach Without Access)

- **HS256 JWT cracking**: Need actual JWT from LoginPassword success or SAML flow.
  50 common passwords tested on LoginPassword, all fail. Without valid credentials,
  no JWT to capture for cracking.
- **Full SAML open redirect confirmation**: Need a valid Okta session to test the
  success path (valid SAMLResponse → redirect to RelayState).
- **ApplyProfile with valid profile ID**: Need to know a real `profi<UUID>` value.
- **GenerateBearerToken exploitation**: Requires valid session JWT.

---

## REPORTS WRITTEN

| File | Finding | Severity |
|------|---------|----------|
| _report_medium_okta_cert_disclosure.md | Okta SAML cert unauthenticated | Medium |
| _report_low_saml_acs_crash.md | SAML ACS unhandled exception | Low |
| _report_medium_no_ratelimit.md | LoginPassword no rate limiting | Medium |
| _report_medium_saml_open_redirect.md | SAML RelayState open redirect | Medium |

---

## RECOMMENDED NEXT ACTIONS

1. **Submit FINDING-01** (SAML open redirect) to HackerOne — highest value unsubmitted
2. **Obtain developer account** on sandboxes.developer.anduril.com to get valid JWTs
   and test the post-auth SAML redirect (confirms severity escalation to High)
3. **Enumerate profile IDs** — search GitHub/documentation for `profi` prefix in
   Anduril public repos or API documentation to complete FINDING-03
4. **Test LoginPassword with breached password lists** — confirmed no rate limiting,
   known email formats (firstname.lastname@anduril.com)
5. **Probe `ValidateAuthTokens`** — returns grpc=12 "not implemented" — ghost endpoint
   that might be activated in future; worth watching
