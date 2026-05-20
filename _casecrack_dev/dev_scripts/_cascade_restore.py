"""Iteratively restore missing modules from VS Code history.
Each round: run target test, detect ModuleNotFoundError, look up snapshot,
restore; repeat until no more progress."""
import json, os, re, shutil, subprocess, sys
from pathlib import Path
from urllib.parse import unquote

HIST = Path(os.environ['APPDATA']) / 'Code' / 'User' / 'History'
WS = Path(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')

# Build snapshot index: module dotted path -> (snap path, size)
print('Indexing history...', file=sys.stderr)
snap_index = {}
for entries_json in HIST.rglob('entries.json'):
    try:
        j = json.loads(entries_json.read_text(encoding='utf-8'))
    except Exception:
        continue
    res = j.get('resource', '')
    if not res.startswith('file:///'): continue
    p_str = unquote(res[len('file:///'):]).replace('/', '\\')
    pl = p_str.lower()
    if 'casecrack' not in pl: continue
    if not pl.endswith('.py'): continue
    # derive dotted module path relative to CaseCrack/
    try:
        i = pl.index('casecrack\\')
    except ValueError:
        continue
    rel = p_str[i+len('casecrack\\'):]
    mod = rel.replace('\\', '.').replace('.py', '')
    if mod.endswith('.__init__'):
        mod = mod[:-len('.__init__')]
    entries = j.get('entries', [])
    if not entries: continue
    latest = max(entries, key=lambda e: e.get('timestamp', 0))
    snap = entries_json.parent / latest['id']
    if not snap.exists(): continue
    ts = latest.get('timestamp', 0)
    cur = snap_index.get(mod)
    if cur is None or cur['ts'] < ts:
        snap_index[mod] = {'ts': ts, 'snap': str(snap), 'size': snap.stat().st_size, 'rel': rel}

print(f'Index: {len(snap_index)} modules', file=sys.stderr)

def restore(mod):
    info = snap_index.get(mod)
    if info is None: return None
    dest = WS / info['rel']
    dest.parent.mkdir(parents=True, exist_ok=True)
    # ensure parent __init__.py chain
    parent = dest.parent
    while parent != WS and parent.exists():
        init = parent / '__init__.py'
        if not init.exists():
            init.write_text('', encoding='utf-8')
        parent = parent.parent
    shutil.copy2(info['snap'], dest)
    return (str(dest), info['size'])

PY = r'c:\Users\ya754\CaseCrack v1.0\.venv\Scripts\python.exe'
def try_import(mod):
    r = subprocess.run(
        [PY, '-c', f'import {mod}'],
        capture_output=True, text=True, cwd=str(WS), timeout=30
    )
    if r.returncode == 0:
        return None
    # parse ModuleNotFoundError
    err = r.stderr
    m = re.search(r"No module named '([\w\.]+)'", err)
    if m: return ('ModuleNotFoundError', m.group(1))
    m = re.search(r"cannot import name '([\w_]+)' from '([\w\.]+)'", err)
    if m: return ('ImportError', m.group(2), m.group(1))
    return ('OtherError', err.splitlines()[-1][:200] if err else '(empty)')

TARGET = sys.argv[1] if len(sys.argv) > 1 else 'tools.burp_enterprise.loop.autonomous_loop'

restored_list = []
seen = set()
for round_ in range(30):
    err = try_import(TARGET)
    if err is None:
        print(f'\n=== SUCCESS in {round_} rounds ===')
        break
    print(f'\nRound {round_}: {err}')
    if err[0] == 'ModuleNotFoundError':
        missing = err[1]
        if missing in seen:
            print(f'  SEEN: {missing} already attempted — giving up')
            break
        seen.add(missing)
        info = restore(missing)
        if info:
            restored_list.append((missing, info[1]))
            print(f'  restored {info[1]}B {missing}')
        else:
            print(f'  NO SNAPSHOT for {missing} — giving up')
            break
    else:
        print(f'  Not a ModuleNotFoundError — stopping')
        break

print(f'\nTotal restored this run: {len(restored_list)}')
for m, sz in restored_list:
    print(f'  {sz:>7}B  {m}')