import json
import re

# Check the unknown 32-char hex context in the bundle
import urllib.request

BUNDLE_URL = "https://www.anduril.com/assets/js/app.xx86qLsC2t.js"
req = urllib.request.Request(BUNDLE_URL, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, timeout=30) as resp:
    content = resp.read().decode('utf-8', errors='replace')

target = 'e6e4a06eaa23bf8d70162ed513d69033'
pos = content.find(target)
if pos != -1:
    ctx = content[max(0, pos-300):pos+300]
    print(f"=== Context around {target} ===")
    print(ctx)
else:
    print(f"{target} not found in bundle")

# Also check the crtsh subdomain data
print("\n\n=== CRTSH Subdomain Discovery ===")
with open('scan_data/reports/osint-crtsh.json', 'r') as f:
    crtsh = json.load(f)

print(f"Type: {type(crtsh)}")
if isinstance(crtsh, dict):
    print(f"Keys: {list(crtsh.keys())[:20]}")
    for k, v in crtsh.items():
        if isinstance(v, list):
            print(f"  {k}: {len(v)} items")
            if len(v) > 0 and len(v) <= 20:
                for item in v[:10]:
                    print(f"    {item}")
        elif isinstance(v, dict):
            print(f"  {k}: dict with {len(v)} keys")
        else:
            print(f"  {k}: {str(v)[:200]}")
elif isinstance(crtsh, list):
    print(f"List with {len(crtsh)} items")
    for item in crtsh[:20]:
        print(f"  {item}")
