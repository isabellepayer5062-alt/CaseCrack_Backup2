import json, sys

with open(r'C:\Users\ya754\CaseCrack v1.0\reports\recon-all-findings.json', encoding='utf-8') as f:
    data = json.load(f)

print(f"Total findings: {len(data)}")

# --- 1. Findings with no URL ---
no_url = [x for x in data if not str(x.get('url', '')).strip()]
print(f"\n=== NO-URL FINDINGS ({len(no_url)}) ===")
for x in no_url:
    print(f"  [{x.get('severity','?').upper()}] {x.get('title','?')}")

# --- 2. Findings with generic title ---
generic = [x for x in data if x.get('title','') in ('Finding', '', 'finding')]
print(f"\n=== GENERIC TITLE FINDINGS ({len(generic)}) ===")
for x in generic:
    print(f"  [{x.get('severity','?').upper()}] url={x.get('url','?')}")

# --- 3. Shopify CDN JS as source for high/critical ---
cdn_fp = [x for x in data if 'cdn.shopify' in str(x.get('url','')) and x.get('severity') in ('critical','high')]
print(f"\n=== SHOPIFY CDN HIGH/CRITICAL ({len(cdn_fp)}) ===")
for x in cdn_fp:
    print(f"  [{x.get('severity','?').upper()}] {x.get('title','?')} | {x.get('url','?')[:80]}")

# --- 4. Group all high findings by title ---
highs = {}
for x in data:
    if x.get('severity') in ('high','critical'):
        t = x.get('title','?')
        highs[t] = highs.get(t,0)+1
print(f"\n=== HIGH+CRITICAL BY TITLE ===")
for t,c in sorted(highs.items(), key=lambda kv: -kv[1]):
    print(f"  {c:3d}x  {t}")

# --- 5. Findings with PHP filter in URL (on a Shopify/Ruby site) ---
php_filter = [x for x in data if 'php%3A%2F%2Ffilter' in str(x.get('url','')) or 'php://filter' in str(x.get('url',''))]
print(f"\n=== PHP FILTER IN URL ({len(php_filter)}) ===")
for x in php_filter[:10]:
    print(f"  [{x.get('severity','?').upper()}] {x.get('title','?')} | {x.get('url','?')[:90]}")

# --- 6. Any 'Mock' findings ---
mock = [x for x in data if str(x.get('title','')).startswith('Mock ')]
print(f"\n=== MOCK FINDINGS ({len(mock)}) ===")
for x in mock:
    print(f"  [{x.get('severity','?').upper()}] {x.get('title','?')}")
