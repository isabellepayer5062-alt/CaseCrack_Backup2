import pathlib, ast
ROOT = pathlib.Path('tools/burp_enterprise')
SKIP = {'__pycache__', '_archive', '_cold_storage'}
hits = []
for p in ROOT.rglob('*.py'):
    if any(s in p.parts for s in SKIP):
        continue
    try:
        src = p.read_text(encoding='utf-8')
    except Exception:
        continue
    if 'cli.dynamic_chain' not in src:
        continue
    for i, ln in enumerate(src.splitlines()):
        if 'cli.dynamic_chain' in ln and 'cli.commands.dynamic_chain' not in ln and 'cli._parsers.dynamic_chain' not in ln:
            rel = p.relative_to(ROOT).as_posix()
            hits.append(f'  {rel}:{i+1}: {ln.strip()[:140]}')

print(f'References to bare cli.dynamic_chain: {len(hits)}')
for h in hits[:25]:
    print(h)
