import json, time, urllib.request, urllib.error, sys
sys.path.insert(0, 'CaseCrack')
from tools.burp_enterprise.recon_dashboard import ReconDashboard
base='http://127.0.0.1:8774'
d=ReconDashboard(target_url='', http_port=8774, ws_port=8775, auto_open=False)
d.start_background(); time.sleep(1.5)
tok=json.loads(urllib.request.urlopen(base+'/api/token').read().decode())['token']
headers={'Authorization':'Bearer '+tok,'Content-Type':'application/json'}
body=json.dumps({'name':'get_tenant_control_status','arguments':{}}).encode()
req=urllib.request.Request(base+'/api/mcp/call', data=body, headers=headers, method='POST')
try:
    urllib.request.urlopen(req)
except urllib.error.HTTPError as e:
    print('CALL', e.code, e.read().decode())
snap_req=urllib.request.Request(base+'/api/mcp/readonly/snapshot', headers=headers)
snap=json.loads(urllib.request.urlopen(snap_req).read().decode())
recent=snap.get('recent_actions') or []
print('SNAP_RECENT_LEN', len(recent))
if recent:
    print('SNAP_RECENT_FIRST', json.dumps(recent[0], sort_keys=True))
print('SNAP_STREAM_OK', (snap.get('stream') or {}).get('ok'))
d.stop(); time.sleep(0.2)
