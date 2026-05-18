"""Restore modules rewriting old-style CaseCrack.tools.* imports to tools.*"""
import json, os, re, shutil, sys
from pathlib import Path
from urllib.parse import unquote

HIST = Path(os.environ['APPDATA']) / 'Code' / 'User' / 'History'
WS = Path(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')

snap_index = {}
for entries_json in HIST.rglob('entries.json'):
    try: j = json.loads(entries_json.read_text(encoding='utf-8'))
    except Exception: continue
    res = j.get('resource', '')
    if not res.startswith('file:///'): continue
    p_str = unquote(res[len('file:///'):]).replace('/', '\\')
    pl = p_str.lower()
    if 'casecrack' not in pl or not pl.endswith('.py'): continue
    try: i = pl.index('casecrack\\')
    except ValueError: continue
    rel = p_str[i+len('casecrack\\'):]
    mod = rel.replace('\\', '.').replace('.py', '')
    if mod.endswith('.__init__'): mod = mod[:-len('.__init__')]
    entries = j.get('entries', [])
    if not entries: continue
    latest = max(entries, key=lambda e: e.get('timestamp', 0))
    snap = entries_json.parent / latest['id']
    if not snap.exists(): continue
    ts = latest.get('timestamp', 0)
    cur = snap_index.get(mod)
    if cur is None or cur['ts'] < ts:
        snap_index[mod] = {'ts': ts, 'snap': str(snap), 'rel': rel}

def rewrite(content: str) -> str:
    # Rewrite 'CaseCrack.tools.' prefix to 'tools.'
    content = re.sub(r'\bCaseCrack\.tools\.', 'tools.', content)
    return content

for mod in sys.argv[1:]:
    info = snap_index.get(mod)
    if info is None:
        print(f'MISS  {mod}')
        continue
    src = Path(info['snap']).read_text(encoding='utf-8', errors='replace')
    rewritten = rewrite(src)
    n = src.count('CaseCrack.tools.')
    dest = WS / info['rel']
    dest.parent.mkdir(parents=True, exist_ok=True)
    parent = dest.parent
    while parent != WS and parent.exists():
        init = parent / '__init__.py'
        if not init.exists(): init.write_text('', encoding='utf-8')
        parent = parent.parent
    dest.write_text(rewritten, encoding='utf-8')
    print(f'OK   {len(rewritten):>7}B  rewrote={n}  {mod}')