"""Fix all Unicode/encoding corruption in agent_roles.py using byte-level ops."""
import os
import re

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "rb") as f:
    data = f.read()

original_len = len(data)

# Strategy: find all non-ASCII bytes and replace common 
# mojibake patterns (double-encoded UTF-8)
# 
# Double-encoded UTF-8 em-dash: \xc3\xa2\xc2\x80\xc2\x94
# Double-encoded UTF-8 en-dash: \xc3\xa2\xc2\x80\xc2\x93
# Double-encoded UTF-8 arrow:   \xc3\xa2\xc2\x86\xc2\x92
# etc.
#
# Single UTF-8 em-dash: \xe2\x80\x94
# Single UTF-8 en-dash: \xe2\x80\x93
# etc.

byte_replacements = [
    # Double-encoded mojibake (6 bytes -> ASCII)
    (b'\xc3\xa2\xc2\x80\xc2\x94', b' -- '),     # em-dash
    (b'\xc3\xa2\xc2\x80\xc2\x93', b' -- '),     # en-dash
    (b'\xc3\xa2\xc2\x86\xc2\x92', b' -> '),     # right arrow
    (b'\xc3\xa2\xc2\x86\xc2\x90', b' <- '),     # left arrow
    (b'\xc3\xa2\xc2\x80\xc2\x99', b"'"),         # right single quote
    (b'\xc3\xa2\xc2\x80\xc2\x98', b"'"),         # left single quote
    (b'\xc3\xa2\xc2\x80\xc2\x9c', b'"'),         # left double quote
    (b'\xc3\xa2\xc2\x80\xc2\x9d', b'"'),         # right double quote
    (b'\xc3\xa2\xc2\x80\xc2\xa6', b'...'),       # ellipsis
    (b'\xc3\xa2\xc2\x89\xc2\x88', b'~'),         # approximately
    (b'\xc3\xa2\xc2\x89\xc2\xa5', b'>='),        # gte
    (b'\xc3\xa2\xc2\x89\xc2\xa4', b'<='),        # lte
    
    # Box drawing (double-encoded)
    (b'\xc3\xa2\xc2\x94\xc2\x80', b'-'),         # horizontal
    (b'\xc3\xa2\xc2\x94\xc2\x82', b'|'),         # vertical
    (b'\xc3\xa2\xc2\x94\xc2\x8c', b'+'),         # top-left
    (b'\xc3\xa2\xc2\x94\xc2\x90', b'+'),         # top-right
    (b'\xc3\xa2\xc2\x94\xc2\x94', b'+'),         # bottom-left
    (b'\xc3\xa2\xc2\x94\xc2\x98', b'+'),         # bottom-right
    (b'\xc3\xa2\xc2\x94\xc2\x9c', b'+'),         # left T
    (b'\xc3\xa2\xc2\x94\xc2\xa4', b'+'),         # right T
    (b'\xc3\xa2\xc2\x94\xc2\xac', b'+'),         # top T
    (b'\xc3\xa2\xc2\x94\xc2\xb4', b'+'),         # bottom T
    (b'\xc3\xa2\xc2\x94\xc2\xbc', b'+'),         # cross
    
    # Direct UTF-8 (3 bytes -> ASCII)
    (b'\xe2\x80\x94', b' -- '),     # em-dash
    (b'\xe2\x80\x93', b' -- '),     # en-dash
    (b'\xe2\x86\x92', b' -> '),     # right arrow
    (b'\xe2\x86\x90', b' <- '),     # left arrow
    (b'\xe2\x86\x91', b' ^ '),     # up arrow
    (b'\xe2\x86\x93', b' v '),     # down arrow
    (b'\xe2\x80\x99', b"'"),        # right single quote
    (b'\xe2\x80\x98', b"'"),        # left single quote
    (b'\xe2\x80\x9c', b'"'),        # left double quote
    (b'\xe2\x80\x9d', b'"'),        # right double quote
    (b'\xe2\x80\xa6', b'...'),      # ellipsis
    (b'\xe2\x89\x88', b'~'),        # approximately
    (b'\xe2\x89\xa5', b'>='),       # gte
    (b'\xe2\x89\xa4', b'<='),       # lte
    (b'\xe2\x9c\x93', b'[v]'),     # checkmark
    (b'\xe2\x9c\x97', b'[x]'),     # cross mark
    (b'\xe2\x80\xa2', b'*'),        # bullet
    
    # Box drawing direct
    (b'\xe2\x94\x80', b'-'),        # horizontal
    (b'\xe2\x94\x82', b'|'),        # vertical
    (b'\xe2\x94\x8c', b'+'),        
    (b'\xe2\x94\x90', b'+'),        
    (b'\xe2\x94\x94', b'+'),        
    (b'\xe2\x94\x98', b'+'),        
    (b'\xe2\x94\x9c', b'+'),        
    (b'\xe2\x94\xa4', b'+'),        
    (b'\xe2\x94\xac', b'+'),        
    (b'\xe2\x94\xb4', b'+'),        
    (b'\xe2\x94\xbc', b'+'),
    
    # Double box drawing
    (b'\xe2\x95\x90', b'='),
    (b'\xe2\x95\x91', b'||'),
    (b'\xe2\x95\x94', b'+'),
    (b'\xe2\x95\x97', b'+'),
    (b'\xe2\x95\x9a', b'+'),
    (b'\xe2\x95\x9d', b'+'),
    (b'\xe2\x95\xa0', b'+'),
    (b'\xe2\x95\xa3', b'+'),
    (b'\xe2\x95\xa6', b'+'),
    (b'\xe2\x95\xa9', b'+'),
    (b'\xe2\x95\xac', b'+'),
    
    # Special chars
    (b'\xc3\x97', b'x'),           # multiplication sign
]

count = 0
for old_bytes, new_bytes in byte_replacements:
    occurrences = data.count(old_bytes)
    if occurrences > 0:
        data = data.replace(old_bytes, new_bytes)
        count += occurrences
        print(f"  Replaced {occurrences} occurrences of {old_bytes[:6]}... -> {new_bytes}")

# Now handle any remaining non-ASCII bytes in comments/docstrings
# Decode to text for line-level processing
text = data.decode('utf-8', errors='replace')

# Replace the replacement character with ?
text = text.replace('\ufffd', '?')

# Final pass: ensure there are no remaining mojibake patterns
# Pattern: \xc3\xa[0-f] followed by \xc2\x[80-bf]
# These are double-encoded Latin-1 chars
remaining_non_ascii = sum(1 for c in text if ord(c) > 127)

with open(path, "w", encoding="utf-8") as f:
    f.write(text)

print(f"\nTotal replacements: {count}")
print(f"Remaining non-ASCII chars: {remaining_non_ascii}")
print(f"Size: {original_len} -> {len(text.encode('utf-8'))}")
print("DONE")
