import json
import time
import urllib.request
import urllib.error
import sys

sys.path.insert(0, 'CaseCrack')
from tools.burp_enterprise.recon_dashboard import ReconDashboard

base = 'http://127.0.0.1:8774'


def get_token():
    return json.loads(urllib.request.urlopen(base + '/api/token').read().decode())['token']


def req_headers(token):
    return {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
    }


def get_json(path, headers):
    req = urllib.request.Request(base + path, headers=headers)
    return json.loads(urllib.request.urlopen(req).read().decode())


def post_json(path, payload, headers):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=data, headers=headers, method='POST')
    try:
        return json.loads(urllib.request.urlopen(req).read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())


def main():
    d = ReconDashboard(target_url='', http_port=8774, ws_port=8775, auto_open=False)
    d.start_background()
    time.sleep(2.5)

    token = get_token()
    headers = req_headers(token)

    snap0 = get_json('/api/mcp/readonly/snapshot', headers)
    print('BASELINE status=%s stream_ok=%s recent=%s' % (
        snap0.get('status'),
        (snap0.get('stream') or {}).get('ok'),
        len(snap0.get('recent_actions') or []),
    ))

    tools = [
        ('get_tenant_control_status', {}),
        ('get_tenant_control_summary', {}),
        ('get_recent_tenant_control_events', {}),
        ('delete_everything', {}),
        ('run_burp_scan', {'target': 'https://example.com'}),
        ('get_tenant_control_status', {}),
        ('delete_everything', {}),
        ('get_tenant_control_summary', {}),
        ('get_recent_tenant_control_events', {}),
        ('get_tenant_control_status', {}),
    ]

    print('BURST_START')
    results = []
    for name, args in tools:
        r = post_json('/api/mcp/call', {'name': name, 'arguments': args}, headers)
        row = {
            'tool': name,
            'ok': r.get('ok'),
            'status': r.get('status'),
            'code': r.get('code'),
            'error': r.get('error'),
            'request_id': r.get('request_id'),
        }
        results.append(row)
        print('tool=%s ok=%s status=%s code=%s req=%s' % (
            row['tool'], row['ok'], row['status'], row['code'], row['request_id']
        ))

    snap1 = get_json('/api/mcp/readonly/snapshot', headers)
    recent = snap1.get('recent_actions') or []
    print('AFTER status=%s stream_ok=%s recent=%s' % (
        snap1.get('status'),
        (snap1.get('stream') or {}).get('ok'),
        len(recent),
    ))

    req_ids = [x.get('request_id') for x in recent if x.get('request_id')]
    dupes = len(req_ids) - len(set(req_ids))
    print('duplicate_request_ids_in_recent_actions=%s' % dupes)

    first_req = next((x.get('request_id') for x in results if x.get('request_id')), None)
    if first_req:
        match = next((x for x in recent if x.get('request_id') == first_req), None)
        print('request_id_trace_found=%s' % ('yes' if match else 'no'))
        if match:
            print('request_id_trace tool=%s status=%s code=%s' % (
                match.get('tool'), match.get('status'), match.get('code')
            ))
    else:
        print('request_id_trace_found=no_request_id_in_responses')

    denies = sum(1 for x in results if x.get('code') == 'ALLOWLIST_DENY')
    rates = sum(1 for x in results if x.get('code') == 'RATE_LIMITED')
    license_required = sum(1 for x in results if x.get('code') == 'LICENSE_REQUIRED')
    ok_calls = sum(1 for x in results if x.get('ok') is True)
    err_calls = len(results) - ok_calls

    print('policy_denials_detected=%s' % denies)
    print('rate_limited_detected=%s' % rates)
    print('license_required_detected=%s' % license_required)
    print('ok_calls=%s err_calls=%s' % (ok_calls, err_calls))

    d.stop()
    time.sleep(0.3)


if __name__ == '__main__':
    main()
