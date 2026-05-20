import re

with open('CaseCrack/tools/burp_enterprise/recon_dashboard/runner.py', encoding='utf-8') as f:
    lines = f.readlines()

# Find where phase names are defined in PHASE_COMMANDS 
print("=== Phase name definitions ===")
for i, line in enumerate(lines[:2700]):
    if re.search(r'"name"\s*:', line) or re.search(r"'name'\s*:", line):
        print(f'  L{i+1}: {line.rstrip()[:100]}')
