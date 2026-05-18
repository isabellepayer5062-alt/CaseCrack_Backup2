#!/usr/bin/env python3
"""Query HIGH/CRITICAL findings with severity filter."""
import urllib.request, json, sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BASE = 'http://localhost:8770'
tok = json.loads(urllib.request.urlopen(BASE+'/api/token', timeout=8).read())['token']

# Count endpoint
try:
    req = urllib.request.Request(BASE+'/api/findings/unified/count',
                                  headers={'Authorization': 'Bearer '+tok})
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.loads(r.read())
    print('Count endpoint:', d)
except Exception as e:
    print('Count error:', e)

# Try ALL findings with large limit to get severity breakdown
try:
    req = urllib.request.Request(BASE+'/api/findings/unified?limit=5000',
                                  headers={'Authorization': 'Bearer '+tok})
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.loads(r.read())
    findings = d.get('findings', d.get('data', []))
    print(f'\nTotal returned: {len(findings)}')
    from collections import Counter
    sev = Counter(f.get('severity','?').upper() for f in findings)
    print('By severity:', dict(sev.most_common()))

    print('\n=== CRITICAL ===')
    for f in findings:
        if f.get('severity','').upper() == 'CRITICAL':
            url = f.get('url') or f.get('target') or ''
            desc = f.get('description', '')[:120]
            print(f"  [CRIT] {f.get('title','?')}")
            print(f"         URL: {url[:100]}")
            if desc:
                print(f"         DESC: {desc}")
            print()

    print('\n=== HIGH ===')
    for f in findings:
        if f.get('severity','').upper() == 'HIGH':
            url = f.get('url') or f.get('target') or ''
            desc = f.get('description', '')[:120]
            print(f"  [HIGH] {f.get('title','?')}")
            print(f"         URL: {url[:100]}")
            if desc:
                print(f"         DESC: {desc}")
            print()
except Exception as e:
    print('Findings error:', e)
