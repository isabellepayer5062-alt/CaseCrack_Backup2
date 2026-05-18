import json
from collections import Counter

with open('reports/recon-all-findings.json') as f:
    findings = json.load(f)

print("=== ACTIVE VULN TESTING ===")
avt = [x for x in findings if x.get('phase') == 'Active Vulnerability Testing']
titles = Counter(x.get('title') for x in avt)
for t,c in titles.most_common(30):
    print(f'  {c:3d}  {t}')

print("\n=== OSINT INTELLIGENCE ===")
osint = [x for x in findings if x.get('phase') == 'OSINT Intelligence']
print(f'Total OSINT: {len(osint)}')
otypes = Counter(x.get('title') for x in osint)
for t,c in otypes.most_common(10):
    print(f'  {c:3d}  {t}')

print("\n=== SOURCE CODE & REVERSE ANALYTICS ===")
src = [x for x in findings if x.get('phase') == 'Source Code & Reverse Analytics']
print(f'Total: {len(src)}')
for s in src[:5]:
    print(f"  {s.get('severity')} | {s.get('title','')[:70]}")

print("\n=== ADVANCED EXPLOITATION ===")
ae = [x for x in findings if x.get('phase') == 'Advanced Exploitation Testing']
aetitles = Counter(x.get('title') for x in ae)
for t,c in aetitles.most_common(20):
    print(f'  {c:3d}  {t}')

print("\n=== ZERO-FINDING PHASES (not in data) ===")
all_phases = set(x.get('phase','?') for x in findings)
expected_phases = [
    'Race Condition & Business Logic Testing',
    'Business Logic Testing',
    'GraphQL Security Testing',
    'OAuth/Authentication Testing',
    'JWT Testing',
    'CORS Testing',
    'Cache Poisoning Testing',
    'HTTP Request Smuggling',
    'API Security Testing',
    'SSRF Testing',
    'LDAP Injection Testing',
    'Mobile API Testing',
    'Command Injection Testing',
]
for p in expected_phases:
    if p not in all_phases:
        print(f'  ZERO: {p}')

print("\n=== SECRETS: ROOT URL vs JS FILES ===")
secs = [x for x in findings if x.get('scan_type') == 'secret' or x.get('category') in ('secrets','secret_in_code')]
root_secs = [x for x in secs if x.get('secret_url','').rstrip('/') == 'https://sugarrushed.ca']
js_secs = [x for x in secs if x.get('secret_url','').rstrip('/') != 'https://sugarrushed.ca']
print(f'From root URL (likely FP): {len(root_secs)}')
print(f'From actual JS files (worth keeping): {len(js_secs)}')
print('JS file secrets:')
for s in js_secs:
    print(f"  {s.get('secret_type',s.get('title',''))} | {s.get('secret_url',s.get('url',''))[:80]}")

print("\n=== DISCOVERED PARAMETERIZED ENDPOINTS (injection opportunities) ===")
params = [x for x in findings if x.get('phase') == 'Parameter Discovery']
inj_urls = set()
for p in params:
    u = p.get('url','')
    if 'FUZZ' in u and ('return_to' in u or 'redirect' in u or 'callback' in u or 'url' in u or 'q=' in u or 'search' in u):
        inj_urls.add(u)
print(f'Injection-interesting parameterized URLs: {len(inj_urls)}')
for u in sorted(inj_urls)[:20]:
    print(f'  {u[:110]}')

print("\n=== CONFIDENCE DISTRIBUTION OF HIGH/CRITICAL ===")
hc = [x for x in findings if x.get('severity') in ('critical','high')]
conf_dist = Counter()
for x in hc:
    c = x.get('confidence')
    if isinstance(c, dict):
        score = c.get('score', 0)
    elif isinstance(c, (int,float)):
        score = c
    else:
        score = -1
    bucket = f'{(score//10)*10}-{(score//10)*10+9}' if score >= 0 else 'no-conf'
    conf_dist[bucket] += 1
print('High/Critical confidence distribution:')
for k in sorted(conf_dist.keys()):
    print(f'  {k}: {conf_dist[k]}')
