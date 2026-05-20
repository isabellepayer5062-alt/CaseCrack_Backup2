"""Rebuild indentation for agent_roles.py.

The file's indentation was collapsed to 1-space by a regex cleanup.
This script analyzes the code structure and restores 4-space indentation.

Rules:
  - Lines starting with 'class ' at col 0: 0 indent
  - Lines starting with 'def ' at 1-space indent: restore to 4-space (class method)
  - Lines starting with other code at 1-space: restore to 4-space (class body)
  - Lines at 2-space indent: restore to 8-space (nested in method)
  - Docstrings and their continuations follow the opener's indent
  - Decorators (@) follow the same rule as what they decorate
"""
import os
import re

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Build a proper indentation by tracking Python block structure
result = []
indent_stack = [0]  # Stack of indentation levels
in_docstring = False
docstring_indent = 0

# Phase 1: Determine the structure by analyzing keywords and colons
# Since all indentation was collapsed to 0/1/2 spaces, we need to
# reconstruct from context

# Strategy: Track nesting depth based on keywords
depth = 0
prev_was_block = False  # Was previous line a block opener (ends with :)?

for i, line in enumerate(lines):
    stripped = line.strip()
    
    if not stripped:
        # Blank line - preserve
        result.append('\n')
        continue
    
    original_indent = len(line) - len(line.lstrip())
    
    # Track docstrings
    triple_count = stripped.count('"""')
    if triple_count == 1:
        if not in_docstring:
            in_docstring = True
            docstring_indent = depth
        else:
            in_docstring = False
            # Docstring closer at docstring_indent
            result.append(' ' * (docstring_indent * 4) + stripped + '\n')
            continue
    elif triple_count >= 2:
        # Opens and closes on same line - one-liner docstring
        pass  # falls through to normal handling
    
    if in_docstring:
        # Docstring content at docstring_indent
        result.append(' ' * (docstring_indent * 4) + stripped + '\n')
        continue
    
    # Determine this line's depth
    if original_indent == 0:
        # Top-level: imports, constants, class declarations, decorators
        if stripped.startswith(('class ', 'def ', 'import ', 'from ', 
                                '@', 'logger', 'AGENT_ROLE_DEFINITIONS',
                                'TASK_PREFIX_MAP', 'AGENT_AUTO_TIMEOUT',
                                'DEFAULT_MAX_TURNS', 'AGENT_COLORS',
                                '_AgentAborted', '_AgentTimeout', '_MaxTurnsExceeded')):
            depth = 0
        elif stripped.startswith('#'):
            depth = 0  # Top-level comment
        else:
            # Could be continuation of a constant or dict
            pass
    elif original_indent == 1:
        # Was 4-space (class body) collapsed to 1
        if stripped.startswith(('def ', '@', 'class ')):
            depth = 1  # Method in a class
        elif stripped.startswith('#'):
            depth = 1  # Comment in class body
        else:
            depth = 1  # Other class body code
    elif original_indent == 2:
        # Was 8-space (method body) collapsed to 2
        depth = 2
    
    result.append(' ' * (depth * 4) + stripped + '\n')

# Write result
with open(path, "w", encoding="utf-8") as f:
    f.writelines(result)

# Verify indentation levels
from collections import Counter
indents = Counter()
for line in result:
    if line.strip():
        indent = len(line) - len(line.lstrip())
        indents[indent] += 1
for k in sorted(indents.keys()):
    print(f'  {k} spaces: {indents[k]} lines')

print("DONE")
