import json, ast
from pathlib import Path
data = json.loads(Path('_recovery_classification.json').read_text(encoding='utf-8'))
# Find autonomous_loop snapshot
al = next(t for t in data['B_needs_merge'] if t['module'].endswith('autonomous_loop'))
src = Path(al['snap']).read_text(encoding='utf-8', errors='ignore')
tree = ast.parse(src)
print(f'LOC: {src.count(chr(10))+1}, size: {len(src)}B')
# List all imports
imports = set()
for n in ast.walk(tree):
    if isinstance(n, ast.ImportFrom) and n.module:
        imports.add(n.module)
    elif isinstance(n, ast.Import):
        for a in n.names:
            imports.add(a.name)
old = [m for m in imports if m.startswith('CaseCrack') or m.startswith('src.')]
print(f'Total imports: {len(imports)}, old-style: {len(old)}')
if old:
    print('Old imports:', old)
# Check if any imports reference still-missing modules
missing_mods = [t['module'] for t in data['A_safe_restore'] + data['B_needs_merge'] + data['C_defer']]
still_missing_from_autonomous = []
for imp in imports:
    if imp in missing_mods:
        still_missing_from_autonomous.append(imp)
print(f'\nIts imports still missing ({len(still_missing_from_autonomous)}):')
for m in sorted(still_missing_from_autonomous):
    print('  ', m)