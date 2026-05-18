import json, collections

data = json.load(open(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack\reports\recon-all-findings.json'))

sev = collections.Counter(f.get('severity','?') for f in data)
print('SEVERITY BREAKDOWN:')
for s, n in sorted(sev.items(), key=lambda x: ['critical','high','medium','low','info','?'].index(x[0]) if x[0] in ['critical','high','medium','low','info'] else 99):
    print(f'  {s.upper()}: {n}')

empty = [f for f in data if not f.get('title','').strip() and not f.get('url','').strip()]
print(f'\nEmpty ghost findings (no title/url): {len(empty)}')

secrets_f = [f for f in data if 'secret' in f.get('category','').lower() or ('secret' in f.get('title','').lower() and 'detected' in f.get('title','').lower())]
print(f'\nSecrets findings: {len(secrets_f)}')
for f in secrets_f:
    sev_v = f.get('severity','').upper()
    title = f.get('title','')[:80]
    ev = str(f.get('evidence','') or f.get('detail',''))[:150]
    print(f'  [{sev_v}] {title}')
    print(f'    Evidence: {ev}')

bypass_f = [f for f in data if 'bypass' in f.get('title','').lower() or ('403' in f.get('title','') and 'bypass' in f.get('title','').lower())]
print(f'\n403 Bypass findings: {len(bypass_f)}')
for f in bypass_f:
    sev_v = f.get('severity','').upper()
    title = f.get('title','')[:100]
    url = f.get('url','')[:80]
    ev = str(f.get('evidence',''))[:150]
    print(f'  [{sev_v}] {title}')
    print(f'    URL: {url}')
    print(f'    Evidence: {ev}')

sqli_f = [f for f in data if 'sql' in f.get('title','').lower() or 'sqli' in f.get('category','').lower()]
print(f'\nSQL Injection findings: {len(sqli_f)}')
for f in sqli_f:
    sev_v = f.get('severity','').upper()
    title = f.get('title','')[:100]
    url = f.get('url','')[:80]
    ev = str(f.get('evidence',''))[:120]
    print(f'  [{sev_v}] {title}')
    print(f'    URL: {url}')
    print(f'    Ev: {ev}')

# AI/ML FPs
aiml_f = [f for f in data if f.get('phase','') == 'AI-Enhanced Testing' or 'aiml' in f.get('category','').lower()]
print(f'\nAI/ML phase findings: {len(aiml_f)}')
for f in aiml_f:
    sev_v = f.get('severity','').upper()
    title = f.get('title','')[:100]
    url = f.get('url','')[:80]
    print(f'  [{sev_v}] {title} | {url}')

# Unique phases with finding counts (non-info)
print('\nPhase breakdown (non-info findings):')
phase_ninfo = collections.Counter()
for f in data:
    if f.get('severity','') not in ('info','informational','',None):
        phase_ninfo[f.get('phase','?')] += 1
for p, n in phase_ninfo.most_common(20):
    print(f'  {n:3d}x  {p}')
