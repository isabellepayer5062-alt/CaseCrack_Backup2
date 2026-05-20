"""Find the actual files that reference the top missing targets."""
import ast, pathlib
ROOT = pathlib.Path('tools/burp_enterprise')
SKIP = {'__pycache__', '_archive', '_cold_storage'}

# Build existing modules set
existing = set()
for p in ROOT.rglob('*.py'):
    if any(s in p.parts for s in SKIP):
        continue
    rel_parts = p.relative_to(ROOT.parent.parent).with_suffix('').parts
    existing.add('.'.join(rel_parts))
    if p.name == '__init__.py':
        existing.add('.'.join(rel_parts[:-1]))

targets_to_find = {
    'tools.burp_enterprise.cli.dynamic_chain',
    'tools.burp_enterprise.recon.tool_wrappers._registry',
    'tools.burp_enterprise.mcp.atlas.models',
    'tools.burp_enterprise.recon_dashboard.logging_config',
}

results = {t: [] for t in targets_to_find}

for p in ROOT.rglob('*.py'):
    if any(s in p.parts for s in SKIP):
        continue
    try:
        src = p.read_text(encoding='utf-8')
        tree = ast.parse(src)
    except Exception:
        continue
    rel_parts = p.relative_to(ROOT.parent.parent).with_suffix('').parts
    pkg = '.'.join(rel_parts[:-1])
    
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ImportFrom) and node.module):
            continue
        if node.level > 0:
            base = pkg.split('.')
            base = base[: len(base) - node.level + 1]
            target = '.'.join(base + node.module.split('.'))
        else:
            target = node.module
        if target in targets_to_find:
            rel = p.relative_to(ROOT).as_posix()
            results[target].append(f'{rel}:{node.lineno}')

for target, locs in results.items():
    print(f'{target}: {len(locs)} references')
    for loc in locs[:6]:
        print(f'  {loc}')
    print()
