"""Comprehensive gap analysis of sugarrushed.ca findings."""
import json
from collections import defaultdict

f = json.load(open('CaseCrack/reports/recon-all-findings.json', encoding='utf-8'))
total = len(f)
print(f"Total findings: {total}")
print()

# Key attack vectors for Shopify
print("=== GraphQL findings ===")
gql = [x for x in f if 'graphql' in x.get('title','').lower()]
for x in gql:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== Race Condition findings ===")
race = [x for x in f if 'race' in x.get('title','').lower()]
for x in race:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== Business Logic / Cart / Price / Discount findings ===")
bizlogic = [x for x in f if any(k in x.get('title','').lower() for k in ['bizlogic','business logic','price','discount','cart','coupon','checkout','payment'])]
for x in bizlogic:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== IDOR findings ===")
idor = [x for x in f if any(k in x.get('title','').lower() for k in ['idor','insecure direct','object reference'])]
for x in idor:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== SSRF findings ===")
ssrf = [x for x in f if 'ssrf' in x.get('title','').lower() or 'server-side request' in x.get('title','').lower()]
for x in ssrf:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== OAuth / SAML / JWT findings ===")
auth = [x for x in f if any(k in x.get('title','').lower() for k in ['oauth','saml','jwt','oidc'])]
for x in auth:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== CORS findings ===")
cors = [x for x in f if 'cors' in x.get('title','').lower()]
for x in cors:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== File Upload findings ===")
upload = [x for x in f if 'upload' in x.get('title','').lower() or 'file inclusion' in x.get('title','').lower()]
for x in upload:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== HTTP Smuggling findings ===")
smug = [x for x in f if 'smuggl' in x.get('title','').lower()]
for x in smug:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== Shopify-specific signals ===")
shop = [x for x in f if 'shopify' in x.get('title','').lower() or 'shopify' in x.get('evidence','').lower() or 'shopify' in str(x.get('url','')).lower()]
for x in shop:
    print(f"  [{x.get('severity')}] {x.get('title','')[:80]}")

print(f"\n=== Phases with ZERO findings ===")
phase_counts = defaultdict(int)
for x in f:
    phase_counts[x.get('phase','')] += 1
ALL_PHASES = [
    "Fingerprinting & Technology",
    "Endpoint & Asset Discovery",
    "JS Analysis & Source Maps",
    "URL Aggregation & Dorking",
    "Parameter Discovery",
    "Visual Recon & Screenshots",
    "Subdomain Discovery",
    "DNS Resolution & Brute-force",
    "Virtual Host Discovery",
    "Network & Port Scanning",
    "TLS & Certificate Analysis",
    "DNS Security Testing",
    "Cloud Storage Enumeration",
    "WAF Detection & Fingerprinting",
    "Secrets Scanning",
    "CVE Correlation",
    "Active Vulnerability Testing",
    "OSINT Intelligence",
    "Passive Internet Search",
    "Source Code & Reverse Analytics",
    "Unified Crawl + Secrets Pipeline",
    "Attack Surface & Analysis",
    "Access Control & Privilege Testing",
    "Injection & Deserialization Testing",
    "Advanced Exploitation Testing",
    "Cloud & Container Security",
    "Supply Chain Security",
    "Defensive Posture Assessment",
    "Network Topology Mapping",
    "Correlation & Compliance",
    "Exploitation Verification & Risk Assessment",
]
for p in ALL_PHASES:
    cnt = phase_counts.get(p, 0)
    if cnt == 0:
        print(f"  ZERO: {p}")
    elif cnt < 5:
        print(f"  LOW({cnt}): {p}")

print(f"\n=== EO-Terminated tool status (check raw files) ===")
import os, glob
eo_killed = []
for fn in glob.glob('CaseCrack/reports/recon-*.json'):
    try:
        raw = json.load(open(fn))
        if raw.get('_eo_terminated') or raw.get('skipped'):
            eo_killed.append(os.path.basename(fn))
    except Exception:
        pass
for fn in sorted(eo_killed):
    print(f"  EO_TERMINATED: {fn}")

print(f"\n=== Tools that ran but found ZERO findings ===")
zero_findings = []
for fn in glob.glob('CaseCrack/reports/recon-*.json'):
    try:
        raw = json.load(open(fn))
        findings = raw.get('findings', [])
        tool = raw.get('tool', '')
        if not raw.get('_eo_terminated') and not raw.get('skipped') and tool and isinstance(findings, list) and len(findings) == 0:
            duration = raw.get('duration_seconds', 0)
            zero_findings.append((tool, os.path.basename(fn), duration))
    except Exception:
        pass
for tool, fn, dur in sorted(zero_findings, key=lambda x: x[2], reverse=True)[:25]:
    print(f"  {tool:20s} | {dur:6.1f}s | {fn}")
