import urllib.request, json
from collections import Counter
BASE = 'http://localhost:8770'
with urllib.request.urlopen(BASE + '/api/token', timeout=5) as r:
    TOKEN = json.loads(r.read()).get('token','')
headers = {'Authorization': f'Bearer {TOKEN}'}
req = urllib.request.Request(BASE + '/api/standalone/status', headers=headers)
with urllib.request.urlopen(req, timeout=10) as r:
    status = json.loads(r.read())
counts = Counter(status.get('phase_status', {}).values())
completed = status['completed_phases']
total = len(status.get('phase_status', {}))
findings = status['findings_count']
is_complete = status['is_complete']
running = status['running_phases']
print(f'Progress: {completed}/{total} phases | findings={findings} | complete={is_complete}')
print(f'Running: {running}')
for st, n in sorted(counts.items()):
    print(f'  {st}: {n}')
