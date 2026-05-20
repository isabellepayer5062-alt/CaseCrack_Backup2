import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

for filepath in [
    'CaseCrack/tools/burp_enterprise/secrets/secrets_scanner.py',
    'CaseCrack/tools/burp_enterprise/secrets/secret_patterns.py',
]:
    with open(filepath, encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    for i, line in enumerate(lines, 1):
        if 'discord' in line.lower():
            print(f'{filepath} L{i}: {line.rstrip()[:200]}')

print()
# Also look for gitleaks or nuclei secret detector patterns
for filepath in ['CaseCrack/tools/burp_enterprise/secrets/secrets_scanner.py']:
    with open(filepath, encoding='utf-8', errors='replace') as f:
        content = f.read()
    import re
    for m in re.finditer(r'(?i)discord[^\n]{0,200}', content):
        print('MATCH:', m.group()[:200])
