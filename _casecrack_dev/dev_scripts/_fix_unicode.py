"""Fix all Unicode/encoding corruption in agent_roles.py."""
import os

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Map of corrupted sequences to their replacements
# These are UTF-8 bytes being interpreted as Latin-1 then re-encoded
replacements = {
    "\u00e2\u0080\u0094": " -- ",      # em-dash
    "\u00e2\u0080\u0093": " -- ",      # en-dash
    "\u00e2\u0086\u0092": " -> ",      # right arrow
    "\u00e2\u0086\u0090": " <- ",      # left arrow  
    "\u00e2\u0094\u0080": "-",         # box horizontal
    "\u00e2\u0094\u0082": "|",         # box vertical
    "\u00e2\u0094\u008c": "+",         # box top-left
    "\u00e2\u0094\u0090": "+",         # box top-right
    "\u00e2\u0094\u0094": "+",         # box bottom-left
    "\u00e2\u0094\u0098": "+",         # box bottom-right
    "\u00e2\u0094\u009c": "+",         # box left T
    "\u00e2\u0094\u00a4": "+",         # box right T
    "\u00e2\u0094\u00ac": "+",         # box top T
    "\u00e2\u0094\u00b4": "+",         # box bottom T
    "\u00e2\u0094\u00bc": "+",         # box cross
    "\u00e2\u0089\u0088": "~",         # approximately equal
    "\u00e2\u0089\u00a5": ">=",        # greater or equal
    "\u00e2\u0089\u00a4": "<=",        # less or equal
    "\u00c3\u0097": "x",              # multiplication sign
    "\u00e2\u0080\u0098": "'",         # left single quote
    "\u00e2\u0080\u0099": "'",         # right single quote
    "\u00e2\u0080\u009c": '"',         # left double quote
    "\u00e2\u0080\u009d": '"',         # right double quote
    "\u00e2\u0080\u00a6": "...",       # ellipsis
}

# Also handle the actual corrupted byte sequences
# The pattern is: UTF-8 multibyte chars got double-encoded
# \xe2\x80\x94 (em-dash) -> shows as Ã¢â\x80\x94 etc
byte_replacements = {
    b'\xc3\xa2\xc2\x80\xc2\x94': b' -- ',    # em-dash
    b'\xc3\xa2\xc2\x80\xc2\x93': b' -- ',    # en-dash  
    b'\xc3\xa2\xc2\x86\xc2\x92': b' -> ',    # right arrow
    b'\xc3\xa2\xc2\x80\xc2\x99': b"'",       # right single quote (Anthropic's)
    b'\xc3\xa2\xc2\x80\xc2\x9c': b'"',       # left double quote
    b'\xc3\xa2\xc2\x80\xc2\x9d': b'"',       # right double quote
}

# Try string-level replacements first
original = content
for old, new in replacements.items():
    content = content.replace(old, new)

# Now try byte-level for any remaining
content_bytes = content.encode('utf-8')
for old_bytes, new_bytes in byte_replacements.items():
    content_bytes = content_bytes.replace(old_bytes, new_bytes)
content = content_bytes.decode('utf-8')

# Also handle common mojibake patterns explicitly
mojibake_map = {
    'â€"': ' -- ',   # em-dash
    'â€"': ' -- ',   # en-dash
    'â†'': ' -> ',    # arrow
    'â€™': "'",       # right quote
    'â€˜': "'",       # left quote
    'â€œ': '"',       # left double
    'â€': '"',       # right double (partial)
    'â€¦': '...',     # ellipsis
    'â‰ˆ': '~',       # approx
    'â‰¥': '>=',      # gte
    'â‰¤': '<=',      # lte
    'Ã—': 'x',        # multiplication
    'â"€': '-',       # box horizontal
    'â"‚': '|',       # box vertical
    'â"Œ': '+',       # box corners
    'â"¬': '+',
    'â"˜': '+', 
    'â"¤': '+',
    'â"œ': '+',
    'â""': '+',
    'â"': '+',
    'â"¼': '+',
    'ÃŸ': 'ss',      # sharp s
    'Ã¶': 'o',       # o-umlaut
    'Ã¼': 'u',       # u-umlaut
    'Ã¤': 'a',       # a-umlaut
    '\u2500': '-',    # actual box horizontal  
    '\u2502': '|',    # actual box vertical
    '\u250c': '+',    # actual box corners
    '\u2510': '+',
    '\u2514': '+',
    '\u2518': '+',
    '\u2524': '+',
    '\u251c': '+',
    '\u252c': '+',
    '\u2534': '+',
    '\u253c': '+',
    '\u2550': '=',    # double horizontal
    '\u2551': '||',   # double vertical
    '\u2560': '+',
    '\u2563': '+',
    '\u2566': '+',
    '\u2569': '+',
    '\u256c': '+',
    '\u2554': '+',
    '\u2557': '+',
    '\u255a': '+',
    '\u255d': '+',
    '\u2191': '^',    # up arrow
    '\u2193': 'v',    # down arrow
    '\u2190': '<-',   # left arrow
    '\u2192': '->',   # right arrow
    '\u2248': '~',    # approx
    '\u2265': '>=',   # gte
    '\u2264': '<=',   # lte
    '\u2713': 'v',    # checkmark
    '\u2717': 'x',    # cross mark
    '\u2014': ' -- ', # em-dash
    '\u2013': ' -- ', # en-dash
    '\u2018': "'",    # quotes
    '\u2019': "'",
    '\u201c': '"',
    '\u201d': '"',
    '\u2026': '...',  # ellipsis
}

for old, new in mojibake_map.items():
    content = content.replace(old, new)

# Final cleanup: remove any remaining non-ASCII chars in comments/docstrings
# but preserve them in string literals
lines = content.split('\n')
cleaned_lines = []
for line in lines:
    # Only clean non-ASCII in comment/docstring lines
    stripped = line.lstrip()
    if stripped.startswith('#') or stripped.startswith('"""') or stripped.startswith("'''"):
        # Replace any remaining non-ASCII
        line = line.encode('ascii', 'replace').decode('ascii')
    elif not any(c in line for c in ['"', "'", 'f"', "f'"]):
        # Non-string, non-comment - safe to clean
        pass
    cleaned_lines.append(line)
content = '\n'.join(cleaned_lines)

if content != original:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("FIXED - Unicode corruption cleaned")
else:
    print("No changes needed")
