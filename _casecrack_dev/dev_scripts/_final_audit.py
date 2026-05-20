import pathlib, ast, py_compile, sys
sys.path.insert(0, '.')
root = pathlib.Path('tools/burp_enterprise')

total_ok = 0
total_missing = []
total_syntax_fail = []

for subdir in ['output', 'scanners', 'testing_tools']:
    subdir_path = root / subdir
    for p in sorted(subdir_path.glob('*.py')):
        if p.name.startswith('_'):
            continue
        try:
            py_compile.compile(str(p), doraise=True)
        except py_compile.PyCompileError as e:
            total_syntax_fail.append(f'{subdir}/{p.name}')
            continue
        src = p.read_text(encoding='utf-8')
        tree = ast.parse(src)
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef) or cls.name.startswith('_'):
                continue
            is_dc = any(
                (isinstance(d, ast.Name) and d.id == 'dataclass') or
                (isinstance(d, ast.Attribute) and d.attr == 'dataclass')
                for d in cls.decorator_list
            )
            if not is_dc:
                continue
            has_to_dict = any(
                isinstance(n, ast.FunctionDef) and n.name == 'to_dict'
                for n in cls.body
            )
            if has_to_dict:
                total_ok += 1
            else:
                total_missing.append(f'{subdir}/{p.name}::{cls.name}')

print(f'Dataclasses WITH to_dict: {total_ok}')
print(f'Dataclasses MISSING to_dict: {len(total_missing)}')
print(f'Syntax failures: {len(total_syntax_fail)}')
for m in total_missing:
    print(f'  MISSING: {m}')
for s in total_syntax_fail:
    print(f'  SYNTAX: {s}')
