#!/usr/bin/env python3
"""Read the full LLM docs for authentication config - save to file"""
import requests, re, time
requests.packages.urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
S = requests.Session()
S.verify = False

print("=" * 70)
print("1. GET FULL llms-full.txt AND SEARCH FOR AUTH/JWT CONTENT")
print("=" * 70)

r = S.get("https://docs.anduril.com/llms-full.txt", 
          headers={"User-Agent": UA, "Accept": "text/plain"}, timeout=60, verify=False)
print(f"  Status: {r.status_code}, size: {len(r.content)}b")
full_text = r.text

# Save it
with open("_anduril_docs_full.txt", "w", encoding="utf-8") as f:
    f.write(full_text)
print("  Saved to _anduril_docs_full.txt")

# Search for auth-relevant content
terms = ['InsecureAuthAdmin', 'InsecureAccessManager', 'HS256', 'hmac', 'jwt secret', 
         'signing key', 'signing secret', 'HMAC', 'bearer token', 'sandbox token',
         'latticeAuth', 'sandbox_token', 'auth_token', 'client_id', 'client_secret']

for term in terms:
    idx = full_text.lower().find(term.lower())
    if idx != -1:
        print(f"\n  FOUND '{term}' at {idx}:")
        print(f"  {full_text[max(0,idx-100):idx+500]}")
    else:
        print(f"  NOT FOUND: '{term}'")

print("\n\n" + "=" * 70)
print("2. FIND AUTH SECTION IN DOCS")
print("=" * 70)

# Find the authenticate section
auth_idx = full_text.find('# Authenticate')
if auth_idx == -1:
    auth_idx = full_text.find('Authenticate')
if auth_idx != -1:
    print(f"  Auth section at {auth_idx}:")
    print(f"  {full_text[auth_idx:auth_idx+3000]}")

print("\n\n" + "=" * 70)
print("3. LOOK FOR OAUTH SECTION IN DOCS")
print("=" * 70)

oauth_idx = full_text.find('# OAuth')
if oauth_idx == -1:
    oauth_idx = full_text.find('OAuth')
if oauth_idx != -1:
    print(f"  OAuth section:")
    print(f"  {full_text[oauth_idx:oauth_idx+3000]}")

print("\n\n" + "=" * 70)
print("4. LOOK FOR SANDBOX SETUP INSTRUCTIONS")
print("=" * 70)

sandbox_idx = full_text.find('# Lattice Sandboxes')
if sandbox_idx == -1:
    sandbox_idx = full_text.find('Sandboxes')
if sandbox_idx != -1:
    print(f"  Sandbox section:")
    print(f"  {full_text[sandbox_idx:sandbox_idx+3000]}")

print("\n\n" + "=" * 70)
print("5. READ AUTHENTICATE PAGE DIRECTLY")
print("=" * 70)

# Try various URL formats
doc_urls = [
    "https://docs.anduril.com/guides/getting-started/authenticate",
    "https://docs.anduril.com/guides/getting-started/authenticate.md",
    "https://developer.anduril.com/guides/getting-started/authenticate.mdx",
    "https://docs.anduril.com/guides/getting-started/sandboxes",
    "https://docs.anduril.com/guides/getting-started/sandboxes.md",
]

for url in doc_urls:
    try:
        r = S.get(url, headers={"User-Agent": UA, "Accept": "text/html,text/plain"}, 
                  timeout=15, allow_redirects=True, verify=False)
        print(f"\n  {url}: HTTP {r.status_code} ({len(r.content)}b)")
        if r.status_code == 200:
            text = r.text
            # Extract visible text if HTML
            if '<html' in text[:200].lower() or '<!DOCTYPE' in text[:100]:
                clean = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
                clean = re.sub(r'<style[^>]*>.*?</style>', '', clean, flags=re.DOTALL)
                clean = re.sub(r'<[^>]+>', ' ', clean)
                clean = re.sub(r'\s+', ' ', clean).strip()
                print(f"  Visible: {clean[:3000]}")
            else:
                print(f"  Raw: {text[:3000]}")
    except Exception as e:
        print(f"  {url}: ERR {str(e)[:80]}")
    time.sleep(0.3)

print("\n[DONE]")
