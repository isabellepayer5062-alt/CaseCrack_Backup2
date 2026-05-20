import urllib.request, json

r = urllib.request.urlopen('http://localhost:8770/api/standalone/console?limit=500', timeout=5)
console = json.loads(r.read().decode())
lines = console.get('lines', [])

interesting = ['Dashboard & Post-Scan Analysis', 'Passive Subdomain Aggregation',
               'OSINT Intelligence Gathering', 'Certificate Transparency (crt.sh)']
filtered = [l for l in lines if l.get('phase') in interesting]
print(f'Lines for interesting phases: {len(filtered)}')
for l in filtered[-60:]:
    lvl = l.get('level', '?')
    phase = l.get('phase', '?')
    text = l.get('text', '')[:120]
    print(f'[{lvl}][{phase}] {text}')

print()
print('=== LAST 20 LINES (any phase) ===')
for l in lines[-20:]:
    lvl = l.get('level', '?')
    phase = l.get('phase', '?')
    text = l.get('text', '')[:120]
    print(f'[{lvl}][{phase}] {text}')
