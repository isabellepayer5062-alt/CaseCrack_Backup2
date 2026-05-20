import json, shutil
from pathlib import Path

data = json.loads(Path('_recovery_classification.json').read_text(encoding='utf-8'))
WS = Path(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')

# Pilot cluster: loop/*
cluster = [t for t in data['A_safe_restore'] if '.loop.' in t['module']]
print(f'Loop cluster: {len(cluster)} files')

restored = []
for t in cluster:
    rel = t['rel']
    if rel.startswith('CaseCrack\\'):
        rel = rel[len('CaseCrack\\'):]
    dest = WS / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    # ensure __init__.py for package
    init = dest.parent / '__init__.py'
    if not init.exists():
        init.write_text('', encoding='utf-8')
    shutil.copy2(t['snap'], dest)
    restored.append((str(dest), dest.stat().st_size))
    print(f"  restored {dest.stat().st_size:>7}B  {rel}")

print(f'\nTotal restored: {len(restored)}')