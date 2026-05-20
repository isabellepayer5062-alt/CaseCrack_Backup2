#!/usr/bin/env python3
import requests, re

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"}

# Fetch the andurilapis bundle
r = requests.get("https://catalog.anduril.com/login/assets/andurilapis-D1Me60L7.js",
    headers=headers, timeout=30)
print("Status:", r.status_code, "Length:", len(r.text))
js = r.text

# Search for redirect logic
searches = [
    ("finalUrl",       "finalUrl"),
    ("ref param",      '"ref"'),
    ("RelayState",     "RelayState"),
    ("window.location","window.location"),
    ("searchParams",   "searchParams"),
    ("get-ref",        '.get("ref")'),
    ("get-relay",      '.get("RelayState")'),
    ("href assign",    ".href="),
    ("redirect func",  "redirect("),
    ("ref-assign",     "ref="),
]

for name, needle in searches:
    idxs = [m.start() for m in re.finditer(re.escape(needle), js)]
    if idxs:
        print(f"\n--- {name} ({len(idxs)} occurrences) ---")
        for idx in idxs[:4]:
            snippet = js[max(0, idx-80):idx+180]
            # Remove excessive whitespace
            snippet = re.sub(r"\s+", " ", snippet)
            print(f"  ...{snippet}...")
    else:
        print(f"[{name}] not found")

print()
# Also check for URL building with ref
pattern = r'(?:ref|relay|redirect|return|next)["\']?\s*[,:=]\s*.{0,120}'
matches = re.findall(pattern, js, re.I)
print(f"--- ref/relay/redirect assignments ({len(matches)} matches) ---")
for m in matches[:10]:
    clean = re.sub(r"\s+", " ", m)
    print(" ", clean[:150])
