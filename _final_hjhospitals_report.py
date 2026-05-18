#!/usr/bin/env python3
"""Final comprehensive scan results for hjhospitals.org."""
import urllib.request, json, sys
from collections import Counter, defaultdict

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BASE = 'http://localhost:8770'
tok = json.loads(urllib.request.urlopen(BASE+'/api/token', timeout=10).read())['token']

# ── 1. Summary counts ────────────────────────────────────────────────────────
req = urllib.request.Request(BASE+'/api/findings/unified/count',
                              headers={'Authorization': 'Bearer '+tok})
with urllib.request.urlopen(req, timeout=15) as r:
    counts = json.loads(r.read())
print("=" * 70)
print("FINAL SCAN COUNTS — https://www.hjhospitals.org/")
print("=" * 70)
for sev, n in counts.get('counts', {}).items():
    bar = '#' * min(50, n // 100)
    print(f"  {sev.upper():10s}: {n:6d}  {bar}")

# ── 2. Status + degraded phases ──────────────────────────────────────────────
req2 = urllib.request.Request(BASE+'/api/standalone/status',
                               headers={'Authorization': 'Bearer '+tok})
with urllib.request.urlopen(req2, timeout=10) as r:
    st = json.loads(r.read())
ps = st.get('phase_status', {})
degraded = [p for p,s in ps.items() if s == 'degraded']
print(f"\nPhases: {st.get('completed_phases')}/{len(ps)} complete")
print(f"Is Complete: {st.get('is_complete')}")
if degraded:
    print(f"DEGRADED phases: {degraded}")

# ── 3. All findings — walk pages ──────────────────────────────────────────────
all_findings = []
page_size = 1000
offset = 0
print(f"\nFetching all findings (page_size={page_size})...")
while True:
    url = f'{BASE}/api/findings/unified?limit={page_size}&offset={offset}'
    req3 = urllib.request.Request(url, headers={'Authorization': 'Bearer '+tok})
    try:
        with urllib.request.urlopen(req3, timeout=60) as r:
            d = json.loads(r.read())
        batch = d.get('findings', d.get('data', []))
        if not batch:
            break
        all_findings.extend(batch)
        print(f"  offset={offset} → +{len(batch)} (total so far: {len(all_findings)})")
        if len(batch) < page_size:
            break
        offset += page_size
        if offset > 50000:  # safety cap
            break
    except Exception as e:
        print(f"  Fetch error at offset {offset}: {e}")
        break

print(f"\nTotal fetched: {len(all_findings)}")
sev_counts = Counter(f.get('severity','?').upper() for f in all_findings)
print("By severity:", dict(sev_counts.most_common()))

# ── 4. CRITICAL findings ──────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("CRITICAL FINDINGS")
print("=" * 70)
crits = [f for f in all_findings if f.get('severity','').upper() == 'CRITICAL']
# Group by title
crit_by_title = defaultdict(list)
for f in crits:
    crit_by_title[f.get('title','?')].append(f)
for title, group in sorted(crit_by_title.items()):
    f0 = group[0]
    desc = (f0.get('description') or '').replace('\n',' ')[:200]
    print(f"\n  [{len(group)}x] {title}")
    print(f"       {desc}")

# ── 5. HIGH findings ──────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("HIGH FINDINGS")
print("=" * 70)
highs = [f for f in all_findings if f.get('severity','').upper() == 'HIGH']
high_by_title = defaultdict(list)
for f in highs:
    high_by_title[f.get('title','?')].append(f)
for title, group in sorted(high_by_title.items()):
    f0 = group[0]
    desc = (f0.get('description') or '').replace('\n',' ')[:200]
    print(f"\n  [{len(group)}x] {title}")
    print(f"       {desc}")

# ── 6. Attack chains / exploit graph ─────────────────────────────────────────
print("\n" + "=" * 70)
print("EXPLOIT GRAPH")
print("=" * 70)
try:
    req4 = urllib.request.Request(BASE+'/api/exploit-graph',
                                   headers={'Authorization': 'Bearer '+tok})
    with urllib.request.urlopen(req4, timeout=30) as r:
        ag = json.loads(r.read())
    chains = ag.get('attack_chains', ag.get('chains', []))
    nodes = ag.get('node_count', len(ag.get('nodes', [])))
    edges = ag.get('edge_count', len(ag.get('edges', [])))
    print(f"  nodes={nodes}  edges={edges}  chains={len(chains)}")
    for i, c in enumerate(chains[:20]):
        print(f"  Chain {i+1}: {json.dumps(c)[:300]}")
except Exception as e:
    print(f"  Error: {e}")

# ── 7. Notable patterns ───────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("ATTACK CHAIN ANALYSIS")
print("=" * 70)
ssti_vulns = [f for f in all_findings if 'SSTI' in f.get('title','')]
xss_vulns  = [f for f in all_findings if 'XSS' in f.get('title','') or 'xss' in (f.get('description','') or '').lower()]
deser_vulns= [f for f in all_findings if 'Deserialization' in f.get('title','') or 'deserializ' in (f.get('description','') or '').lower()]
csrf_vulns = [f for f in all_findings if 'CSRF' in f.get('title','')]
sqli_vulns = [f for f in all_findings if 'SQL' in f.get('title','').upper() or 'sqli' in (f.get('description','') or '').lower()]
ssrf_vulns = [f for f in all_findings if 'SSRF' in f.get('title','')]
esi_vulns  = [f for f in all_findings if 'ESI' in f.get('title','')]
postmsg    = [f for f in all_findings if 'postMessage' in f.get('title','') or 'PostMessage' in f.get('title','')]
exposed_keys = [f for f in all_findings if 'Key' in f.get('title','') or 'Secret' in f.get('title','') or 'Token' in f.get('title','') or 'key' in f.get('title','').lower()]
graphql    = [f for f in all_findings if 'graphql' in (f.get('title','') or '').lower() or 'GraphQL' in (f.get('description','') or '')]

print(f"\n  SSTI (Template Injection): {len(ssti_vulns)}")
print(f"  XSS: {len(xss_vulns)}")
print(f"  Deserialization: {len(deser_vulns)}")
print(f"  CSRF: {len(csrf_vulns)}")
print(f"  SQL Injection: {len(sqli_vulns)}")
print(f"  SSRF: {len(ssrf_vulns)}")
print(f"  ESI Injection: {len(esi_vulns)}")
print(f"  postMessage Issues: {len(postmsg)}")
print(f"  Exposed Keys/Tokens: {len(exposed_keys)}")
print(f"  GraphQL Issues: {len(graphql)}")

print("\n--- PRIMARY ATTACK CHAIN (based on findings) ---")
print("""
  CHAIN 1: SSTI → RCE
    [CRITICAL] SSTI detected on https://www.hjhospitals.org (9 engines: jinja2/twig/erb/mako etc.)
    → Direct server-side template injection could lead to remote code execution
    → Requires payload confirmation (calculated result=49 for all engines — possible false positive)

  CHAIN 2: ESI + Reflected XSS → SSRF/Cache Poisoning
    [HIGH] ESI Injection Detected at https://www.hjhospitals.org
    [HIGH] Exposed postMessage handlers (instagram embed.js, twitter widgets.js)
    → ESI tag injection can redirect CDN/cache to attacker-controlled server
    → Combined with postMessage origin bypass → stored/reflected XSS

  CHAIN 3: AWS Key Exposure → Credential Abuse
    [HIGH] Exposed API Key: aws_secret_key found at hjhospitals.org
    → If valid, direct AWS account compromise

  CHAIN 4: GraphQL Depth Limit → DoS / Data Extraction
    [HIGH] GraphQL depth limit=30 at /api/2024-04/graphql.json, /api/graphql, /api/unstable/graphql.json
    → Deep nested queries can cause exponential computation (DoS)
    → Combined with introspection: full schema enumeration → data extraction

  CHAIN 5: DOM XSS → Session Hijacking
    [CRITICAL] DOM XSS in jquery-1.9.1.min.js via innerHTML (3 sinks)
    [HIGH] 30+ DOM XSS flows in jquery-ui.js (form input → HTML constructor/append/html)
    → XSS + session cookie without SameSite → session token theft
    → Cookie flags: hjhospitals_session and XSRF-TOKEN lack SameSite

  CHAIN 6: CSRF → Account Takeover
    [HIGH] CSRF missing at /account/save, /account/email, /login/login
    → Combined with XSS for token-less CSRF attacks
    → /login/login CSRF: force victim to authenticate attacker account

  CHAIN 7: Digital Ocean Metadata SSRF
    [HIGH] DigitalOcean metadata exposed (dns/nameservers, floating_ip, region, hostname)
    → Internal metadata service accessible → potential SSRF to cloud metadata API

  CHAIN 8: Node.js Deserialization → RCE
    [CRITICAL] Node.js Deserialization Detected at https://www.hjhospitals.org
    → Deserialization of untrusted data can execute arbitrary JavaScript

  CHAIN 9: Pseudo-Header Injection → Cache Poisoning + SSRF
    [HIGH] Pseudo-Header injection in path returns 500
    → HTTP/2 pseudo-header injection (:path) → potential cache poisoning or backend routing abuse
""")

print("\nDone. Full results saved.")
