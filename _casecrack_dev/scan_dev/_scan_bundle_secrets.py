import urllib.request
import re
import json

BUNDLE_URL = "https://www.anduril.com/assets/js/app.xx86qLsC2t.js"

print(f"Fetching {BUNDLE_URL}...")
req = urllib.request.Request(BUNDLE_URL, headers={
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})
with urllib.request.urlopen(req, timeout=30) as resp:
    content = resp.read().decode('utf-8', errors='replace')
print(f"Bundle size: {len(content)} bytes")

# AWS Access Key IDs: AKIA[A-Z0-9]{16}
aws_akid = re.findall(r'(?:AKIA|ASIA|ABIA|ACCA|AROA|AGPA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}', content)
print(f"\n=== AWS Access Key IDs (AKIA...) ===")
for k in set(aws_akid):
    # Skip obviously fake/test keys
    print(f"  {k}")

# AWS Secret Keys: pattern varies - 40 char base64-like after aws_secret|secret_key context
aws_secret_ctx = re.findall(r'(?:aws.{0,20}secret|secret.{0,20}key)[^"\']{0,30}["\']([A-Za-z0-9+/]{40})["\']', content, re.IGNORECASE)
print(f"\n=== AWS Secret Keys (context-matched) ===")
for k in set(aws_secret_ctx):
    print(f"  {k}")

# Firebase config: apiKey typically AIza...
firebase_keys = re.findall(r'AIza[A-Za-z0-9_\-]{35}', content)
print(f"\n=== Firebase API Keys (AIza...) ===")
for k in set(firebase_keys):
    print(f"  {k}")

# Firebase config block
fb_config = re.findall(r'(?:firebase|Firebase).{0,500}?apiKey["\s:]+["\']([^"\']{10,60})["\']', content, re.DOTALL)
print(f"\n=== Firebase config apiKey blocks ===")
for k in set(fb_config):
    print(f"  {k}")

# Facebook App ID / Secret patterns
fb_app = re.findall(r'(?:facebook|fb|meta).{0,50}(?:appId|app_id|client_id)[^"\']{0,10}["\'](\d{10,20})["\']', content, re.IGNORECASE)
print(f"\n=== Facebook App IDs ===")
for k in set(fb_app):
    print(f"  {k}")

fb_secret = re.findall(r'(?:facebook|fb|meta).{0,50}(?:secret|token)[^"\']{0,10}["\']([a-f0-9]{32})["\']', content, re.IGNORECASE)
print(f"\n=== Facebook Secrets (32-char hex) ===")
for k in set(fb_secret):
    print(f"  {k}")

# Generic 32-char hex that might be FB/other secrets
generic_32hex = re.findall(r'["\']([a-f0-9]{32})["\']', content)
print(f"\n=== Generic 32-char hex strings ===")
for k in set(generic_32hex):
    print(f"  {k}")

# Cloudinary
cloudinary = re.findall(r'cloudinary\.com/([a-z0-9\-_]{5,20})', content)
print(f"\n=== Cloudinary cloud names ===")
for k in set(cloudinary):
    print(f"  {k}")

# Cloudinary API key/secret (numeric API key)  
cloud_api_key = re.findall(r'cloudinary.{0,200}?(?:api_key|apiKey)["\s:]+["\']?(\d{10,15})', content, re.DOTALL)
print(f"\n=== Cloudinary API Keys ===")
for k in set(cloud_api_key):
    print(f"  {k}")

# Search around the Algolia init to see neighboring config
algolia_pos = content.find('EKYOZ1VARX')
if algolia_pos != -1:
    ctx = content[max(0, algolia_pos-500):algolia_pos+500]
    print(f"\n=== Context around Algolia key (±500 chars) ===")
    print(ctx)

# Generic high-entropy strings in common key assignment patterns
service_keys = re.findall(r'(?:apiKey|api_key|accessKey|access_key|clientSecret|client_secret|secretKey|secret_key)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,80})["\']', content)
print(f"\n=== Generic key assignments ===")
for k in set(service_keys):
    # Skip Algolia
    if 'cc7c97f46dd432f640dc8a1babb30233' not in k:
        print(f"  {k}")
