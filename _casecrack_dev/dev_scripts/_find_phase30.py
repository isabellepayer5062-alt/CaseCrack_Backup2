with open('CaseCrack/tools/burp_enterprise/recon_dashboard/runner.py', encoding='utf-8') as f:
    lines = f.readlines()

# Find ALL phase name definitions (look for lines with 'name': 'Something...' in PHASE_COMMANDS)
for i, line in enumerate(lines[:3000]):
    if '"name"' in line and ('Compliance' in line or 'Correlation' in line):
        print(f'  L{i+1}: {line.rstrip()}')
    if 'Correlation' in line and 'Compliance' in line and i < 3000:
        print(f'  L{i+1}: {line.rstrip()}')
