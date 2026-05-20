import json, re
from pathlib import Path

data = json.loads(Path('_recovery_classification.json').read_text(encoding='utf-8'))
WS = Path(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')

# Pick a few representative bucket-A modules and show their caller context
samples = ['tools.burp_enterprise.loop.loop_config',
           'tools.burp_enterprise.loop.world_state',
           'tools.burp_enterprise.exploit_chains.system_audit_harness',
           'tools.burp_enterprise.loop.ai_directed_executor']

items_by_mod = {t['module']: t for t in data['A_safe_restore']}

for mod in samples:
    if mod not in items_by_mod: continue
    t = items_by_mod[mod]
    print(f'\n### {mod} (hard callers: {t["hard_callers"]})')
    for caller_path in t['hard_sample']:
        p = Path(caller_path)
        try:
            lines = p.read_text(encoding='utf-8', errors='ignore').splitlines()
        except Exception:
            continue
        rel = str(p).replace(str(WS) + '\\', '')
        # find the import line
        for i, L in enumerate(lines):
            if mod in L and ('import' in L or 'from' in L):
                start = max(0, i-3); end = min(len(lines), i+3)
                print(f'  {rel}:')
                for j in range(start, end):
                    prefix = '>>>' if j == i else '   '
                    print(f'    {prefix} {j+1}: {lines[j][:120]}')
                break