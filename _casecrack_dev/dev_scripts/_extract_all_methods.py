#!/usr/bin/env python3
"""
1. Extract ALL methods from 6.8MB catalog bundle (all 64 services)
2. Probe InsecureAuthAdmin + InsecureAccessManagerAPI on catalog/sandbox
3. Check buf.build for Anduril public proto schema
4. Get OAuth2 client credentials endpoint
"""
import requests, re, json, struct
requests.packages.urllib3.disable_warnings()

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# ---- Proto helpers ----
def _vi(v):
    r = b""
    while True:
        b = v & 0x7F; v >>= 7
        r += bytes([b|0x80]) if v else bytes([b])
        if not v: break
    return r
def ps(fn, s): v=s.encode(); return _vi((fn<<3)|2)+_vi(len(v))+v
def gf(b): return b"\x00" + struct.pack(">I", len(b)) + b

GRPC_HEADERS = {
    "content-type": "application/grpc-web+proto",
    "x-grpc-web": "1",
    "accept": "application/grpc-web+proto",
    "User-Agent": BROWSER_UA,
}

def decode_grpc_web(body_bytes):
    offset = 0
    parts = []
    while offset < len(body_bytes):
        if offset + 5 > len(body_bytes): break
        flag = body_bytes[offset]
        length = struct.unpack(">I", body_bytes[offset+1:offset+5])[0]
        frame_body = body_bytes[offset+5:offset+5+length]
        parts.append(("TRAILER" if flag & 0x80 else "DATA", frame_body))
        offset += 5 + length
    return parts

def probe(host, pkg_svc, method, body=b"", timeout=12):
    url = f"{host}/{pkg_svc}/{method}"
    frame = gf(body)
    try:
        r = requests.post(url, headers=GRPC_HEADERS, data=frame, verify=False, timeout=timeout)
        frames = decode_grpc_web(r.content)
        trailer_txt = ""
        data_hex = ""
        for ftype, fbody in frames:
            if ftype == "TRAILER":
                try: trailer_txt = fbody.decode('utf-8', errors='replace')
                except: trailer_txt = fbody.hex()
            else:
                data_hex = fbody.hex()[:80]
        status = r.headers.get("grpc-status", "?")
        host_s = host.split("://")[1].split(".anduril")[0]
        
        # Flag interesting responses
        flag = ""
        if r.status_code == 200 and "unknown service" not in trailer_txt and "grpc-status:12" not in trailer_txt:
            if "grpc-status:0" in trailer_txt or data_hex:
                flag = " *** DATA RESPONSE ***"
            elif "grpc-status:16" not in trailer_txt and "grpc-status:7" not in trailer_txt:
                flag = " <-- INTERESTING"
        
        print(f"  [{host_s}] {pkg_svc.split('.')[-1]}/{method}: HTTP {r.status_code} | {trailer_txt[:100]}{flag}")
        return r, data_hex, trailer_txt
    except Exception as e:
        host_s = host.split("://")[1].split(".anduril")[0]
        print(f"  [{host_s}] {pkg_svc.split('.')[-1]}/{method}: ERROR {e}")
        return None, "", ""

CATALOG = "https://catalog.anduril.com"
SANDBOX = "https://sandboxes.developer.anduril.com"
PG = "https://proving-ground.anduril.com"

# ---- Step 1: Extract ALL methods from catalog bundle ----
print("=== Extracting all methods from catalog bundle ===\n")
with open("_catalog_bundle_D1Me60L7.js", "r", encoding="utf-8", errors="replace") as f:
    bundle = f.read()

# Extract service+method pairs
service_method_pairs = re.findall(
    r'serviceName\s*:\s*"([^"]+)"[^}]*?methodName\s*:\s*"([^"]+)"',
    bundle, re.DOTALL
)
alt_pairs = re.findall(
    r'methodName\s*:\s*"([^"]+)"[^}]*?serviceName\s*:\s*"([^"]+)"',
    bundle, re.DOTALL
)

# Build service->methods map
from collections import defaultdict
svc_methods = defaultdict(set)
for svc, meth in service_method_pairs:
    svc_methods[svc].add(meth)
for meth, svc in alt_pairs:
    svc_methods[svc].add(meth)

print(f"Total service-method pairs: {sum(len(v) for v in svc_methods.values())}")
for svc in sorted(svc_methods.keys()):
    meths = sorted(svc_methods[svc])
    print(f"\n  {svc} ({len(meths)} methods):")
    for m in meths:
        print(f"    {m}")

# Also check for "insecure" references
insecure_refs = re.findall(r'[Ii]nsecure[^"]{0,100}', bundle)
print(f"\n\nInsecure references in bundle: {len(insecure_refs)}")
for ref in sorted(set(insecure_refs))[:20]:
    print(f"  {ref[:100]}")
