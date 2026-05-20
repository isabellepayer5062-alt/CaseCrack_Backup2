"""Test /login/session-refresh route"""
import requests
requests.packages.urllib3.disable_warnings()
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
for url in [
    'https://catalog.anduril.com/login/session-refresh',
    'https://catalog.anduril.com/login/session-refresh?ref=https://attacker.com',
    'https://proving-ground.anduril.com/login/session-refresh',
    'https://catalog.anduril.com/login/session-refresh?msg=test',
]:
    r = requests.get(url, headers={'User-Agent': UA}, allow_redirects=False, verify=False, timeout=10)
    loc = r.headers.get('location', '-')
    print(f'HTTP {r.status_code} | loc={loc[:80]} | {url}')
