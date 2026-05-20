"""Sophisticated indentation rebuilder for agent_roles.py.

Tracks Python block structure to properly set indentation levels.
All indentation was collapsed to 0/1 spaces and needs reconstruction.
"""
import os
import re

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Block openers: keywords that start a new indented block
BLOCK_OPENERS = re.compile(
    r'^(class |def |if |elif |else:|for |while |try:|except |except:|finally:|with |async )'
)
BLOCK_CONTINUATIONS = re.compile(r'^(elif |else:|except |except:|finally:)')
DEDENT_STATEMENTS = re.compile(r'^(return |return$|pass$|break$|continue$|raise )')

def ends_with_colon(s: str) -> bool:
    """Check if a line (stripped) ends with : (block opener)."""
    s = s.rstrip()
    if s.endswith(':'):
        # Make sure it's not inside a string or dict literal
        # Simple heuristic: if the line starts with a known keyword, it's a block
        return bool(BLOCK_OPENERS.match(s))
    return False

def is_continuation(s: str) -> bool:
    """Check if line is a continuation of a multi-line expression."""
    # Lines that start with ), ], }, or common continuations
    return s.startswith((')', ']', '}', '",', "',", '],', '},', '),'))

def count_open_brackets(s: str) -> int:
    """Count net open brackets, ignoring those in strings."""
    opens = s.count('(') + s.count('[') + s.count('{')
    closes = s.count(')') + s.count(']') + s.count('}')
    return opens - closes

# Process file
result = []
depth = 0
in_docstring = False
bracket_depth = 0
indent_stack = [0]  # Stack of depths for each block level
expect_indent = False  # Next non-blank line should be indented
block_depths = []  # Stack tracking depth at each block open

for i, line in enumerate(lines):
    stripped = line.strip()
    
    if not stripped:
        result.append('\n')
        continue
    
    # Track docstrings
    triple_count = stripped.count('"""')
    if triple_count == 1:
        if not in_docstring:
            in_docstring = True
            result.append(' ' * (depth * 4) + stripped + '\n')
            continue
        else:
            in_docstring = False
            result.append(' ' * (depth * 4) + stripped + '\n')
            continue
    
    if in_docstring:
        result.append(' ' * (depth * 4) + stripped + '\n')
        continue
    
    # Track bracket depth for multi-line expressions
    orig_indent = len(line) - len(line.lstrip())
    
    # Determine depth for this line
    if orig_indent == 0:
        # File-level code
        depth = 0
        bracket_depth = 0
        block_depths = [0]
    elif expect_indent:
        depth = block_depths[-1] + 1
        block_depths.append(depth)
        expect_indent = False
    elif BLOCK_CONTINUATIONS.match(stripped):
        # elif/else/except/finally: same level as the if/try
        if block_depths:
            depth = block_depths[-1]
            # Pop the inner block, we're back at this level
            while len(block_depths) > 1 and block_depths[-1] > depth:
                block_depths.pop()
    
    # Handle bracket continuations
    if bracket_depth > 0:
        # We're inside a multi-line expression
        pass  # Keep current depth
    
    # Write the line
    result.append(' ' * (depth * 4) + stripped + '\n')
    
    # Update bracket tracking
    bracket_depth += count_open_brackets(stripped)
    if bracket_depth < 0:
        bracket_depth = 0
    
    # Check if this opens a new block
    if ends_with_colon(stripped) and bracket_depth == 0:
        expect_indent = True
    
    # Check if this is a return/pass/break that might end a block
    if DEDENT_STATEMENTS.match(stripped) and bracket_depth == 0:
        # After this line, depth should return to the opener's level
        if len(block_depths) > 1:
            pass  # Don't pop yet - the next non-blank line determines depth

# Write result
with open(path, "w", encoding="utf-8") as f:
    f.writelines(result)

# Verify
from collections import Counter
indents = Counter()
for line in result:
    if line.strip():
        indent = len(line) - len(line.lstrip())
        indents[indent] += 1
for k in sorted(indents.keys()):
    print(f'  {k} spaces: {indents[k]} lines')

print(f"\nTotal lines: {len(result)}")
print("DONE")
