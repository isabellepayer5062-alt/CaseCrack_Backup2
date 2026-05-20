import ast, pathlib, sys
sys.path.insert(0, '.')
src = pathlib.Path('tools/burp_enterprise/persistent_agent.py').read_text('utf-8', errors='replace')
tree = ast.parse(src)
for node in ast.walk(tree):
    if not isinstance(node, ast.ImportFrom): continue
    m = node.module or ''
    if 'burp_enterprise' not in m: continue
    disk = pathlib.Path(m.replace('.', '/') + '.py')
    pkg  = pathlib.Path(m.replace('.', '/') + '/__init__.py')
    ok = disk.exists() or pkg.exists()
    status = 'OK  ' if ok else 'MISS'
    names = [a.name for a in node.names]
    print(status, m, '->', str(names[:5]))
