"""
Find functions that have BOTH a local 'import asyncio' AND 'asyncio.xxx' usage
anywhere in them. These are candidates for UnboundLocalError because Python
marks 'asyncio' as local throughout the entire function scope.
"""
import ast, pathlib

def find_asyncio_scoping_candidates(src_path):
    issues = []
    for py_file in pathlib.Path(src_path).rglob('*.py'):
        if '.bak' in str(py_file) or '.pregap' in str(py_file):
            continue
        try:
            source = py_file.read_text(encoding='utf-8', errors='replace')
            tree = ast.parse(source)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Find local 'import asyncio' IN THE DIRECT BODY (not nested funcs)
            local_import_lines = []
            asyncio_uses = []
            # Walk the function body, but don't recurse into nested functions
            def walk_direct(n, results_import, results_use, depth=0):
                if depth > 0 and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return  # Stop at nested function boundaries
                if isinstance(n, ast.Import):
                    for alias in n.names:
                        if alias.name == 'asyncio' and alias.asname is None:
                            results_import.append(n.lineno)
                if isinstance(n, ast.Attribute):
                    if isinstance(n.value, ast.Name) and n.value.id == 'asyncio':
                        results_use.append(n.lineno)
                for child in ast.iter_child_nodes(n):
                    walk_direct(child, results_import, results_use, depth + 1)
            
            walk_direct(node, local_import_lines, asyncio_uses, depth=0)
            
            if local_import_lines and asyncio_uses:
                min_import = min(local_import_lines)
                # Check if any use is BEFORE the first import OR potentially
                # unreachable (import is conditional)
                uses_before_import = [l for l in asyncio_uses if l < min_import]
                uses_after_import = [l for l in asyncio_uses if l >= min_import]
                
                # Get parent class context
                parent_class = None
                for n in ast.walk(tree):
                    if isinstance(n, ast.ClassDef):
                        for item in ast.walk(n):
                            if item is node:
                                parent_class = n.name
                                break
                
                func_name = (f"{parent_class}.{node.name}" if parent_class 
                             else node.name)
                
                if uses_before_import:
                    issues.append({
                        'file': str(py_file.relative_to(src_path)),
                        'func': func_name,
                        'line': node.lineno,
                        'severity': 'HIGH - asyncio used BEFORE local import',
                        'import_lines': local_import_lines,
                        'use_lines': asyncio_uses,
                    })
                else:
                    # Even if uses are after import, if import is CONDITIONAL
                    # (inside if/try), asyncio could be unbound in other branches
                    issues.append({
                        'file': str(py_file.relative_to(src_path)),
                        'func': func_name,
                        'line': node.lineno,
                        'severity': 'WARN - local import asyncio (check if conditional)',
                        'import_lines': local_import_lines,
                        'use_lines': asyncio_uses,
                    })
    return issues

BASE = r'c:\Users\ya754\CaseCrack v1.0\CaseCrack\tools\burp_enterprise'
issues = find_asyncio_scoping_candidates(BASE)
print(f"Found {len(issues)} candidates:\n")
for i in issues:
    print(f"[{i['severity']}]")
    print(f"  {i['file']}:{i['line']} {i['func']}()")
    print(f"  local import at lines: {i['import_lines']}")
    print(f"  asyncio uses at lines: {i['use_lines']}")
    print()
