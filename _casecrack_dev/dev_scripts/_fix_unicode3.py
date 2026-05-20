"""Strip all non-ASCII from agent_roles.py - all non-ASCII is decorative."""
import os

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    text = f.read()

# Map known mojibake sequences (as they appear in cp1252-decoded text)
# These are the 2-3 char sequences that represent single original chars
text_replacements = [
    # Arrow patterns (â + † + ' = right arrow)
    ("\u00e2\u2020\u2019", " -> "),
    # Em-dash patterns 
    ("\u00e2\u20ac\u201c", " -- "),  # â€" em-dash variant 1
    ("\u00e2\u20ac\u201d", " -- "),  # â€" but with right quote
    ("\u00e2\u20ac\u201a", " -- "),  # en-dash variant
    # Single/double quotes
    ("\u00e2\u20ac\u2122", "'"),     # right single quote via mojibake
    ("\u00e2\u20ac\u0153", '"'),     # left double quote via mojibake
    # Box drawing (â + \x90-\xbc + \x80-\xbc area)
]

for old, new in text_replacements:
    count = text.count(old)
    if count > 0:
        text = text.replace(old, new)
        print(f"  Replaced {count} text sequences -> {repr(new)}")

# Now replace any remaining non-ASCII characters individually
char_map = {
    '\u00e2': '',       # stray 'â' from mojibake (first byte marker)
    '\u0090': '',       # C1 control char (stray mojibake byte)
    '\u20ac': '',       # Euro sign (stray mojibake byte for \x80)
    '\u2020': '',       # dagger (stray mojibake byte for \x86)
    '\u2019': "'",      # right single quote
    '\u2018': "'",      # left single quote
    '\u201c': '"',      # left double quote
    '\u201d': '"',      # right double quote
    '\u201a': ',',      # single low-9 quote (stray)
    '\u0153': '',       # oe ligature (stray)
    '\u0152': '',       # OE ligature (stray)
    '\u02dc': '~',      # small tilde
    '\u00c3': '',       # A-tilde (stray double-encoding marker)
    '\u2030': '',       # per mille (stray)
    '\u02c6': '^',      # circumflex
}

for old_char, new_char in char_map.items():
    count = text.count(old_char)
    if count > 0:
        text = text.replace(old_char, new_char)
        print(f"  Replaced {count} of U+{ord(old_char):04X} -> {repr(new_char)}")

# Verify no non-ASCII remains
remaining = sum(1 for c in text if ord(c) > 127)
print(f"\nRemaining non-ASCII: {remaining}")

# Clean up multiple spaces from removed chars
import re
text = re.sub(r'  +', ' ', text)
# But preserve indentation - only clean non-leading multiple spaces
lines = text.split('\n')
cleaned = []
for line in lines:
    # Preserve leading whitespace
    stripped = line.lstrip()
    indent = line[:len(line) - len(stripped)]
    # Clean multiple spaces in content
    stripped = re.sub(r'  +', ' ', stripped)
    cleaned.append(indent + stripped)
text = '\n'.join(cleaned)

with open(path, "w", encoding="utf-8") as f:
    f.write(text)

print("DONE")
