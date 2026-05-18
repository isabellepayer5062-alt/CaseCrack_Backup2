import json, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

with open('CaseCrack/reports/recon-all-findings.json', encoding='utf-8', errors='replace') as f:
    data = json.load(f)

highs = [f for f in data if (f.get('severity') or '').lower() == 'high']

# Deep dump findings 1-27 (atomic findings, not correlation chains)
for i in range(27):
    f = highs[i]
    title = f.get('title') or f.get('name') or f.get('finding_type') or '?'
    print(f'=== [{i+1:02d}] {title} ===')
    for k, v in f.items():
        if k == 'evidence' and isinstance(v, dict):
            for ek, ev in v.items():
                val_str = repr(ev)[:500]
                print(f'  evidence.{ek}: {val_str}')
        elif k == 'evidence' and isinstance(v, str):
            print(f'  evidence: {repr(v)[:500]}')
        elif k not in ('raw',):
            print(f'  {k}: {repr(v)[:300]}')
    print()
