import re
with open('CaseCrack/tools/burp_enterprise/recon_dashboard/runner.py','r',encoding='utf-8',errors='replace') as f:
    lines = f.readlines()
print(f'Total lines: {len(lines)}')
print('=== Phase/section markers ===')
for i, l in enumerate(lines, 1):
    s = l.strip()
    if 'phase' in s.lower() and ('19' in s or '20' in s or '21' in s or '22' in s or '23' in s or '24' in s or '45' in s or 'threat' in s.lower() or 'osint' in s.lower()):
        print(f'{i}: {l.rstrip()[:120]}')
