"""Fix orphaned quote characters left by Unicode cleanup.

The em-dash (U+2014) was stored as mojibake: a + euro + left-double-quote.
When a and euro were stripped, the left-double-quote remained as a literal ",
breaking string literals and adding unwanted quotes to comments.

Strategy:
  - In comment lines: replace ` " ` with ` -- `
  - In string literal contexts: detect and fix broken quotes  
  - Special patterns: `0.0"1.0` -> `0.0-1.0`
"""
import os
import re

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

fixed_count = 0

def fix_comment_line(line: str) -> str:
    """Fix orphaned quotes in comment portions of lines."""
    global fixed_count
    # Find the comment portion
    hash_idx = -1
    in_string = False
    string_char = None
    for i, c in enumerate(line):
        if not in_string:
            if c in ('"', "'"):
                in_string = True
                string_char = c
            elif c == '#':
                hash_idx = i
                break
        else:
            if c == string_char and (i == 0 or line[i-1] != '\\'):
                in_string = False
    
    if hash_idx >= 0:
        before = line[:hash_idx]
        comment = line[hash_idx:]
        # Replace orphaned " in comments with --
        new_comment = comment.replace(' " ', ' -- ')
        if new_comment != comment:
            fixed_count += 1
        return before + new_comment
    return line


def fix_string_content(line: str) -> str:
    """Fix orphaned quotes that break string literals."""
    global fixed_count
    
    # Pattern: "text " text" -> "text -- text"
    # This happens when a " that was an em-dash sits inside a string
    # Detect: an odd number of " on the line (suggests a broken string)
    
    # Common patterns in this file:
    patterns = [
        # Description fields with broken em-dash
        (r'"([^"]*) " ([^"]*)"', r'"\1 -- \2"'),
        # Range patterns like 0.0"1.0
        (r'(\d+\.\d+)"(\d+\.\d+)', r'\1-\2'),
    ]
    
    for pattern, replacement in patterns:
        new_line = re.sub(pattern, replacement, line)
        if new_line != line:
            fixed_count += 1
            line = new_line
    
    return line


new_lines = []
in_docstring = False
docstring_char = None

for i, line in enumerate(lines):
    original = line
    stripped = line.strip()
    
    # Track docstring state (triple-quoted)
    triple_count = stripped.count('"""')
    if triple_count >= 1:
        if not in_docstring:
            in_docstring = True
            if triple_count >= 2:  # Opens and closes on same line
                in_docstring = False
        else:
            in_docstring = False
    
    if in_docstring:
        # In docstrings: replace orphaned " with --
        line = line.replace(' " ', ' -- ')
        line = re.sub(r'(\d+\.\d+)"(\d+\.\d+)', r'\1-\2', line)
        if line != original:
            fixed_count += 1
    else:
        # Fix comment portions
        line = fix_comment_line(line)
        # Fix string content  
        line = fix_string_content(line)
    
    new_lines.append(line)

with open(path, "w", encoding="utf-8") as f:
    f.writelines(new_lines)

print(f"Fixed {fixed_count} orphaned quote instances")
print("DONE")
