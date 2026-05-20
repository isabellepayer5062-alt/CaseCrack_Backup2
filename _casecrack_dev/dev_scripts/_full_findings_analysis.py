import json, collections

data = json.load(open(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack\reports\recon-all-findings.json', encoding='utf-8'))
print(f'Total findings: {len(data)}')

sev = collections.Counter(f.get('severity','?') for f in data)
print('Severity breakdown:', dict(sev))

cats = collections.Counter(f.get('category','?') for f in data)
print('\nTop categories:')
for c, n in cats.most_common(25):
    print(f'  {n:3d}x  {c}')

phases = collections.Counter(f.get('phase','?') for f in data)
print('\nTop phases:')
for p, n in phases.most_common(20):
    print(f'  {n:3d}x  {p}')

print('\n=== Non-INFO findings ===')
ninfo = [f for f in data if f.get('severity','') not in ('info','informational','',None)]
print(f'Count: {len(ninfo)}')
for f in ninfo:
    sev_val = f.get('severity','').upper()
    title = f.get('title','')[:90]
    url = f.get('url','')[:80]
    cat = f.get('category','')
    phase = f.get('phase','')
    evidence = str(f.get('evidence','') or f.get('detail',''))[:100]
    print(f'\n  [{sev_val}] {title}')
    print(f'    URL: {url}')
    print(f'    Cat={cat} | Phase={phase}')
    print(f'    Evidence: {evidence}')

print('\n=== SSTI signals ===')
ssti = [f for f in data if 'ssti' in f.get('title','').lower() or 'template error' in f.get('title','').lower() or 'SSTI' in f.get('title','')]
for f in ssti:
    print(f'  [{f.get("severity","").upper()}] {f.get("title","")[:100]}')
    print(f'  URL: {f.get("url","")[:80]}')
    print(f'  Detail: {str(f.get("detail",""))[:150]}')
    print(f'  Evidence: {str(f.get("evidence",""))[:150]}')

print('\n=== Redis findings ===')
redis_f = [f for f in data if 'redis' in f.get('title','').lower()]
print(f'Count: {len(redis_f)}')
for f in redis_f[:5]:
    print(f'  [{f.get("severity","").upper()}] {f.get("title","")[:80]}')
    print(f'  URL: {f.get("url","")[:80]}')
    print(f'  Evidence: {str(f.get("evidence",""))[:120]}')

print('\n=== PHP warning findings ===')
php_f = [f for f in data if 'php' in f.get('title','').lower() and 'warning' in f.get('title','').lower()]
print(f'Count: {len(php_f)}')
for f in php_f:
    print(f'  [{f.get("severity","").upper()}] {f.get("title","")[:100]}')
    print(f'  URL: {f.get("url","")[:80]}')

print('\n=== XSS findings ===')
xss_f = [f for f in data if any(k in f.get('title','').lower() for k in ['xss', 'cross-site scripting'])]
print(f'Count: {len(xss_f)}')
for f in xss_f[:10]:
    print(f'  [{f.get("severity","").upper()}] {f.get("title","")[:100]}')
    print(f'  URL: {f.get("url","")[:80]}')

print('\n=== Prototype Pollution findings ===')
pp_f = [f for f in data if 'prototype' in f.get('title','').lower()]
print(f'Count: {len(pp_f)}')

print('\n=== LDAP findings ===')
ldap_f = [f for f in data if 'ldap' in f.get('title','').lower()]
print(f'Count: {len(ldap_f)}')

print('\n=== Supply chain findings ===')
sc_f = [f for f in data if any(k in f.get('title','').lower() for k in ['supply chain', 'cookie', 'exfil', 'sri missing'])]
print(f'Count: {len(sc_f)}')
for f in sc_f[:5]:
    print(f'  [{f.get("severity","").upper()}] {f.get("title","")[:100]}')

print('\n=== Injection findings ===')
inj_f = [f for f in data if any(k in f.get('title','').lower() for k in ['injection', 'sqli', 'rce', 'command inject', 'deseria'])]
print(f'Count: {len(inj_f)}')
for f in inj_f[:10]:
    print(f'  [{f.get("severity","").upper()}] {f.get("title","")[:100]}')

print('\n=== Top 40 finding titles ===')
titles = collections.Counter(f.get('title','')[:80] for f in data)
for t, c in titles.most_common(40):
    print(f'  {c:3d}x  {t}')
