import json, collections, os, sys

os.chdir(r'c:\Users\ya754\CaseCrack v1.0')

NEEDLE = '"type":"finding"'

with open('_scan_monitor_20260505_run3.log', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

print(f'Total lines: {len(lines)}')

findings = []
for line in lines:
    line = line.strip()
    try:
        obj = json.loads(line)
        text = obj.get('text', '')
        if NEEDLE in text:
            try:
                inner = json.loads(text)
                if isinstance(inner, dict) and inner.get('type') == 'finding':
                    findings.append(inner)
            except:
                pass
    except:
        pass

print(f'Total parsed findings: {len(findings)}')
sev_counter = collections.Counter(f.get('severity','?') for f in findings)
print('Severity breakdown:', dict(sev_counter))

cats = collections.Counter(f.get('category','?') for f in findings)
print('\nCategory breakdown:')
for cat, cnt in cats.most_common(25):
    print(f'  {cnt:3d}x  {cat}')

print('\n=== Non-INFO findings ===')
ninfo = [f for f in findings if f.get('severity','') not in ('info', 'informational', '', None)]
if not ninfo:
    print('  (none - all findings are INFO level)')
for f in ninfo:
    sev = f.get('severity','')
    print(f'  [{sev.upper()}] {f.get("title","")[:100]}')
    print(f'    URL: {f.get("url","")[:80]}')
    ev = f.get('evidence','') or f.get('detail','')
    print(f'    Evidence: {str(ev)[:100]}')

print('\n=== Redis findings ===')
redis_f = [f for f in findings if 'redis' in f.get('title','').lower()]
print(f'Count: {len(redis_f)}')
for f in redis_f[:5]:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:80]}')
    ev = f.get('evidence','') or f.get('detail','')
    print(f'    Evidence: {str(ev)[:120]}')
    print(f'    URL: {f.get("url","")[:80]}')

print('\n=== SSTI findings ===')
ssti_f = [f for f in findings if 'ssti' in f.get('title','').lower()]
print(f'Count: {len(ssti_f)}')
for f in ssti_f:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:100]}')
    print(f'  URL: {f.get("url","")[:80]}')
    ev = f.get('evidence','') or f.get('detail','')
    print(f'  Evidence: {str(ev)[:150]}')

print('\n=== PHP warning findings ===')
php_f = [f for f in findings if 'php' in f.get('title','').lower()]
print(f'Count: {len(php_f)}')
for f in php_f:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:100]}')
    print(f'  URL: {f.get("url","")[:80]}')

print('\n=== XSS findings ===')
xss_f = [f for f in findings if any(k in f.get('title','').lower() for k in ['xss', 'cross-site scripting', 'script inject'])]
print(f'Count: {len(xss_f)}')
for f in xss_f:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:100]}')
    print(f'  URL: {f.get("url","")[:80]}')

print('\n=== Prototype Pollution findings ===')
pp_f = [f for f in findings if 'prototype' in f.get('title','').lower() or 'pollution' in f.get('title','').lower()]
print(f'Count: {len(pp_f)}')

print('\n=== LDAP findings ===')
ldap_f = [f for f in findings if 'ldap' in f.get('title','').lower()]
print(f'Count: {len(ldap_f)}')

print('\n=== Injection/RCE findings ===')
inj_f = [f for f in findings if any(k in f.get('title','').lower() for k in ['injection', 'sqli', 'command inject', 'rce', 'deseria'])]
print(f'Count: {len(inj_f)}')
for f in inj_f[:5]:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:100]}')

print('\n=== Top 35 finding titles ===')
titles = collections.Counter(f.get('title','')[:80] for f in findings)
for t, c in titles.most_common(35):
    print(f'  {c:3d}x  {t}')

print('\n=== Phase breakdown of findings ===')
phase_counts = collections.Counter(f.get('phase','?') for f in findings)
for p, c in phase_counts.most_common(20):
    print(f'  {c:3d}x  {p}')
