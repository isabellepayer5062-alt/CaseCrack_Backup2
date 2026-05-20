"""Comprehensive repair of agent_roles.py - find and fix all corruption."""
import os
import re

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")

# 1. Find all method definitions to understand structure
for keyword in ['def ', 'class ']:
    indices = [(i+1, lines[i].strip()) for i, l in enumerate(lines) if l.strip().startswith(keyword)]
    for idx, content in indices:
        print(f"  {idx}: {content}")

print("\n--- Checking for corruption ---")
# 2. Find lines that seem to be mid-dictionary/mid-expression
for i, line in enumerate(lines):
    stripped = line.strip()
    # Detect lines that start with quotes that look like dict keys outside a dict literal
    if re.match(r'^"(state|color|name|phases|priority|produces|consumes|capabilities|stats)":', stripped):
        # Check if we're inside a dict literal by looking backwards for a '{'
        in_dict = False
        for j in range(i-1, max(i-20, 0), -1):
            if '{' in lines[j]:
                in_dict = True
                break
            if 'def ' in lines[j] or 'class ' in lines[j]:
                break
        if not in_dict:
            print(f"  SUSPECT dict key at line {i+1}: {stripped[:80]}")
    # Detect merged lines
    if 'scope' in line and 'color' in line and 'self.color' in line:
        print(f"  MERGED line at {i+1}: {stripped[:80]}")
