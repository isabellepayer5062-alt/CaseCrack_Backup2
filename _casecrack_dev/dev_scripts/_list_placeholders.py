import json, os
from pathlib import Path

reports = Path('CaseCrack/reports')
placeholders = []
for f in sorted(reports.glob('*.json')):
    try:
        data = json.loads(f.read_text(encoding='utf-8', errors='replace'))
        if isinstance(data, dict) and data.get('_placeholder'):
            placeholders.append({
                'file': f.name,
                'tool': data.get('tool', ''),
                'phase': data.get('_phase', ''),
                'reason': data.get('_reason', ''),
                'cmd': data.get('_cmd', []),
                'size': f.stat().st_size,
            })
    except Exception:
        pass

print(f'Total placeholders: {len(placeholders)}')
print()
for p in placeholders:
    cmd_str = ' '.join(p['cmd']) if p['cmd'] else ''
    print(f"FILE={p['file']} TOOL={p['tool']} PHASE={p['phase']} REASON={p['reason']} CMD={cmd_str}")
