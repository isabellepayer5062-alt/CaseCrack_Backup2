import json, os
from pathlib import Path
from urllib.parse import unquote
HIST = Path(os.environ['APPDATA']) / 'Code' / 'User' / 'History'
found = None
for entries_json in HIST.rglob('entries.json'):
    try:
        j = json.loads(entries_json.read_text(encoding='utf-8'))
    except Exception:
        continue
    res = j.get('resource', '')
    if 'unified_arbitration.py' in res and 'casecrack' in res.lower():
        bn = Path(unquote(res)).name
        if bn == 'unified_arbitration.py':
            latest = max(j['entries'], key=lambda e: e.get('timestamp', 0))
            snap = entries_json.parent / latest['id']
            if snap.exists():
                if found is None or found[0] < latest['timestamp']:
                    found = (latest['timestamp'], str(snap), snap.stat().st_size, unquote(res))
if found:
    print(f'Found: {found[2]}B  ts={found[0]}  {found[1]}')
    print(f'  resource: {found[3]}')
else:
    print('NOT FOUND in history')