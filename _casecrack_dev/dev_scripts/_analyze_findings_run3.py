import json, collections

NEEDLE = '"type":"finding"'
NEEDLE2 = '"type": "finding"'

with open('_scan_monitor_20260505_run3.log', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

findings = []
for line in lines:
    line = line.strip()
    try:
        obj = json.loads(line)
        text = obj.get('text', '')
        if NEEDLE in text or NEEDLE2 in text:
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
print('Category breakdown:')
for cat, cnt in cats.most_common(20):
    print(f'  {cnt:3d}x  {cat}')

print()
print('=== Non-INFO findings ===')
ninfo = [f for f in findings if f.get('severity','') not in ('info', 'informational', '')]
if not ninfo:
    print('  (none found - all findings are INFO level)')
for f in ninfo:
    sev = f.get('severity','')
    print(f'  [{sev.upper()}] {f.get("title","")[:100]}')
    print(f'    URL: {f.get("url","")[:80]}')
    print(f'    Cat: {f.get("category","")} | Phase: {f.get("phase","")}')
    print(f'    Evidence: {str(f.get("evidence",""))[:80]}')

print()
print('=== Redis Error Disclosure findings ===')
redis_f = [f for f in findings if 'redis' in f.get('title','').lower() or 'Redis' in f.get('title','')]
print(f'  Count: {len(redis_f)}')
for f in redis_f[:5]:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:80]}')
    print(f'    Evidence: {str(f.get("evidence",""))[:120]}')

print()
print('=== SSTI findings ===')
ssti_f = [f for f in findings if 'ssti' in f.get('title','').lower() or 'SSTI' in f.get('title','')]
for f in ssti_f:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:100]}')
    print(f'    URL: {f.get("url","")[:80]}')
    print(f'    Evidence: {str(f.get("evidence",""))[:120]}')

print()
print('=== PHP warning findings ===')
php_f = [f for f in findings if 'php' in f.get('title','').lower() or 'PHP' in f.get('title','')]
for f in php_f:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:100]}')
    print(f'    URL: {f.get("url","")[:80]}')

print()
print('=== Supply chain / cookie findings ===')
sc_f = [f for f in findings if 'cookie' in f.get('title','').lower() or 'supply chain' in f.get('title','').lower() or 'exfil' in f.get('title','').lower()]
for f in sc_f:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:100]}')

print()
print('=== XSS findings ===')
xss_f = [f for f in findings if 'xss' in f.get('title','').lower() or 'XSS' in f.get('title','') or 'cross-site' in f.get('title','').lower()]
print(f'  Count: {len(xss_f)}')
for f in xss_f[:5]:
    print(f'  Sev={f.get("severity","")} | {f.get("title","")[:100]}')

print()
print('=== Prototype pollution findings ===')
pp_f = [f for f in findings if 'prototype' in f.get('title','').lower() or 'pollution' in f.get('title','').lower()]
print(f'  Count: {len(pp_f)}')

print()
print('=== Top 30 finding titles ===')
titles = collections.Counter(f.get('title','')[:80] for f in findings)
for t, c in titles.most_common(30):
    print(f'  {c:3d}x  {t}')
