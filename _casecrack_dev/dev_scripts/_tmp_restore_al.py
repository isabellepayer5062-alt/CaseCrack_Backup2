import json, shutil
from pathlib import Path
data = json.loads(Path('_recovery_classification.json').read_text(encoding='utf-8'))
WS = Path(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')
al = next(t for t in data['B_needs_merge'] if t['module'].endswith('autonomous_loop'))
rel = al['rel']
if rel.startswith('CaseCrack\\'):
    rel = rel[len('CaseCrack\\'):]
dest = WS / rel
shutil.copy2(al['snap'], dest)
print(f'restored {dest.stat().st_size}B -> {dest}')