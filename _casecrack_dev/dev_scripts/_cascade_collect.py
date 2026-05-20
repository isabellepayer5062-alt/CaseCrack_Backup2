import json, os, re, shutil, subprocess, sys
from pathlib import Path
from urllib.parse import unquote

HIST = Path(os.environ['APPDATA']) / 'Code' / 'User' / 'History'
WS = Path(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')
PY = r'c:\Users\ya754\CaseCrack v1.0\.venv\Scripts\python.exe'

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
    try: i = pl.index('casecrack\\')
    except ValueError: continue
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
print(f'Index: {len(snap_index)}', file=sys.stderr)

def restore(mod):
    info = snap_index.get(mod)
    if info is None: return None
    dest = WS / info['rel']
    dest.parent.mkdir(parents=True, exist_ok=True)
    parent = dest.parent
    while parent != WS and parent.exists():
        init = parent / '__init__.py'
        if not init.exists():
            init.write_text('', encoding='utf-8')
        parent = parent.parent
    shutil.copy2(info['snap'], dest)
    return info['size']

def run_collect(tests):
    r = subprocess.run(
        [PY, '-m', 'pytest'] + tests + ['--collect-only', '--override-ini=addopts=', '-q'],
        capture_output=True, text=True, cwd=str(WS), timeout=60
    )
    out = r.stdout + '\n' + r.stderr
    return r.returncode, out

def run_tests(tests):
    r = subprocess.run(
        [PY, '-m', 'pytest'] + tests + ['--override-ini=addopts=', '-p', 'no:randomly', '--timeout=60', '-q'],
        capture_output=True, text=True, cwd=str(WS), timeout=300
    )
    out = r.stdout + '\n' + r.stderr
    return r.returncode, out

TESTS = sys.argv[1:] or ['tests/test_autonomous_loop.py', 'tests/test_adversarial_upgrades.py']

restored_all = []
seen = set()
for round_ in range(50):
    rc, out = run_tests(TESTS)
    if rc == 0:
        print(f'\n=== ALL TESTS PASS after {round_} restore rounds ===')
        break
    missing = set(re.findall(r"No module named '([\w\.]+)'", out))
    cannot_import = re.findall(r"cannot import name '([\w_]+)' from '([\w\.]+)'", out)
    if not missing and not cannot_import:
        print(f'\nRound {round_}: no recognizable import errors')
        # dump last 30 lines
        for l in out.splitlines()[-30:]:
            print(' |', l)
        break
    progress = False
    for m in sorted(missing):
        if m in seen: continue
        seen.add(m)
        sz = restore(m)
        if sz:
            restored_all.append((m, sz))
            print(f'  R{round_}: restored {sz:>7}B {m}')
            progress = True
        else:
            print(f'  R{round_}: NO SNAPSHOT for {m}')
    # Handle cannot_import as restore-target module with latest snapshot
    for name, src in cannot_import:
        if src in seen: continue
        # don't re-restore an existing module (likely we already did)
    if not progress:
        print(f'\nNo progress — stopping')
        # show tail for diagnosis
        for l in out.splitlines()[-30:]:
            print(' |', l)
        break

print(f'\nTotal restored: {len(restored_all)}')
sys.exit(rc)