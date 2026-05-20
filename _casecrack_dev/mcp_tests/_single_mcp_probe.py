import json
import time
import urllib.request
import urllib.error
import sys

sys.path.insert(0, 'CaseCrack')
from tools.burp_enterprise.recon_dashboard import ReconDashboard

base = 'http://127.0.0.1:8774'

d = ReconDashboard(target_url='', http_port=8774, ws_port=8775, auto_open=False)
d.start_background()
time.sleep(1.5)

tok = json.loads(urllib.request.urlopen(base + '/api/token').read().decode())['token']
print('TOKEN_LEN', len(tok))

headers = {'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json'}
body = json.dumps({'name':'get_tenant_control_status','arguments':{}}).encode()
req = urllib.request.Request(base + '/api/mcp/call', data=body, headers=headers, method='POST')
try:
    raw = urllib.request.urlopen(req).read().decode()
    print('HTTP_OK_RAW', raw)
except urllib.error.HTTPError as e:
    eraw = e.read().decode()
    print('HTTP_ERR_CODE', e.code)
    print('HTTP_ERR_RAW', eraw)

d.stop()
