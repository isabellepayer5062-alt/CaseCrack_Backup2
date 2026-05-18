"""Patch: raise max_gists default to 50 and update report table."""
import ast

FILEPATH = 'CaseCrack/tools/burp_enterprise/intel/github_deep_recon.py'

with open(FILEPATH, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# 1. Update max_gists default
for i, line in enumerate(lines):
    if '    max_gists: int = 30' in line:
        lines[i] = '    max_gists: int = 50\n'
        print(f"Updated max_gists default at line {i+1}")
        break

# 2. Update the report table row (Gist Matches -> richer info)
for i, line in enumerate(lines):
    if 'Gist Matches' in line and "st.get('gist_matches'" in line:
        lines[i] = (
            '    lines.append(f"| Gist Matches | {st.get(\'gist_matches\', 0)} '
            '(secrets: {st.get(\'gist_with_secrets\', 0)}, '
            'history-only: {st.get(\'gist_with_deleted_secrets\', 0)}, '
            'high-conf: {st.get(\'gist_high_confidence\', 0)}) |")\n'
        )
        print(f"Updated report table row at line {i+1}")
        break

with open(FILEPATH, 'w', encoding='utf-8') as f:
    f.writelines(lines)

with open(FILEPATH, 'r', encoding='utf-8') as f:
    src = f.read()
try:
    ast.parse(src)
    print("Syntax OK")
except SyntaxError as e:
    print(f"SyntaxError: {e}")
