import json, os, sys
from pathlib import Path
from urllib.parse import unquote

HIST = Path(os.environ['APPDATA']) / 'Code' / 'User' / 'History'
WS = Path(r'c:\Users\ya754\CaseCrack v1.0')

by_resource = {}
count = 0
for entries_json in HIST.rglob('entries.json'):
    try:
        j = json.loads(entries_json.read_text(encoding='utf-8'))
    except Exception:
        continue
    res = j.get('resource', '')
    if not res.startswith('file:///'):
        continue
    p = unquote(res[len('file:///'):]).replace('/', '\\')
    if not p.lower().endswith('.py'):
        continue
    if 'casecrack' not in p.lower():
        continue
    entries = j.get('entries', [])
    if not entries:
        continue
    latest = max(entries, key=lambda e: e.get('timestamp', 0))
    snap = entries_json.parent / latest['id']
    if not snap.exists():
        continue
    sz = snap.stat().st_size
    ts = latest.get('timestamp', 0)
    cur = by_resource.get(p)
    if cur is None or cur['ts'] < ts:
        by_resource[p] = {'ts': ts, 'snap': str(snap), 'size': sz}
    count += 1

print('scanned', count, 'entries;', len(by_resource), 'unique', file=sys.stderr)

missing = []
size_diff = []
ok = 0
for p, info in by_resource.items():
    cp = Path(p)
    if not cp.exists():
        missing.append((p, info))
    else:
        cur_sz = cp.stat().st_size
        if info['size'] > cur_sz * 1.5 and (info['size'] - cur_sz) > 2048:
            size_diff.append((p, info, cur_sz))
        else:
            ok += 1

lines = []
lines.append('MISSING_COUNT=' + str(len(missing)))
for p, info in sorted(missing, key=lambda x: -x[1]['size']):
    rel = p.replace(str(WS) + '\\', '')
    lines.append('M ' + str(info['size']).rjust(7) + ' ' + rel + ' :: ' + info['snap'])
lines.append('')
lines.append('STUBS_COUNT=' + str(len(size_diff)))
for p, info, cur in sorted(size_diff, key=lambda x: -(x[1]['size'] - x[2])):
    rel = p.replace(str(WS) + '\\', '')
    lines.append('S snap=' + str(info['size']).rjust(7) + ' cur=' + str(cur).rjust(7) + ' ' + rel + ' :: ' + info['snap'])
lines.append('')
lines.append('OK_COUNT=' + str(ok))

Path('_recovery_scan_report.txt').write_text('\n'.join(lines), encoding='utf-8')
print('missing=', len(missing), 'stubs=', len(size_diff), 'ok=', ok)