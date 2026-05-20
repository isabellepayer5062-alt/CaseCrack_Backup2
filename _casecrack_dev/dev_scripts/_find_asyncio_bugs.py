import ast, pathlib

def find_asyncio_scoping_bugs(src_path):
    issues = []
    for py_file in pathlib.Path(src_path).rglob('*.py'):
        try:
            tree = ast.parse(py_file.read_text(encoding='utf-8', errors='replace'))
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Collect local 'import asyncio' statements (no alias) in direct body
            local_import_lines = []
            for stmt in ast.walk(node):
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt is not node:
                    continue
                if isinstance(stmt, ast.Import):
                    for alias in stmt.names:
                        if alias.name == 'asyncio' and alias.asname is None:
                            local_import_lines.append(stmt.lineno)
            if not local_import_lines:
                continue
            min_import_line = min(local_import_lines)
            # Check if asyncio is used BEFORE the first local import
            for stmt in ast.walk(node):
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt is not node:
                    continue
                if isinstance(stmt, ast.Attribute):
                    if isinstance(stmt.value, ast.Name) and stmt.value.id == 'asyncio':
                        use_line = getattr(stmt, 'lineno', 0)
                        if use_line < min_import_line:
                            issues.append(
                                f'{py_file}:{node.lineno} {node.name}() - '
                                f'asyncio used at line {use_line} before import at {min_import_line}'
                            )
    return issues

issues = find_asyncio_scoping_bugs(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack\tools\burp_enterprise')
for i in issues:
    print(i)
if not issues:
    print('No asyncio scoping bugs found')
