"""Find all lines with broken string literals in agent_roles.py."""
import os

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    dq = line.count('"') - line.count('\\"')
    if dq % 2 != 0 and not line.strip().startswith('#'):
        print(f'{i+1}: {line.rstrip()[:120]}')
