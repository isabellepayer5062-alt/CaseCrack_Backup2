import json, collections, sys

with open('_scan_monitor_20260505_run3.log', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

print(f'Total lines: {len(lines)}')

phases = collections.Counter()
errors = []
degraded = []
fails = []
findings_hcm = []
ssti_lines = []
redis_lines = []
timeout_lines = []
all_findings = []

for line in lines:
    line = line.strip()
    try:
        obj = json.loads(line)
    except:
        continue
    phase = obj.get('phase', 'unknown')
    text = obj.get('text', '')
    level = obj.get('level', '')
    stream = obj.get('stream', '')

    phases[phase] += 1

    if level == 'error':
        errors.append((phase, text[:120]))

    if 'DEGRADED' in text or 'FAILED' in text:
        degraded.append((phase, text[:130]))

    if 'FAIL]' in text or '[FAIL]' in text:
        fails.append((phase, text[:130]))

    if 'TIMEOUT' in text.upper() or 'timed out' in text.lower():
        timeout_lines.append((phase, text[:130]))

    if 'SSTI' in text or 'polyglot' in text.lower() or 'template error' in text.lower():
        ssti_lines.append((phase, text[:130]))

    if 'Redis' in text or 'redis' in text:
        redis_lines.append((phase, text[:130]))

    # Capture finding JSON embedded in text field
    if '"type":"finding"' in text or '"type": "finding"' in text:
        all_findings.append((phase, text[:300]))
        try:
            inner = json.loads(text)
            sev = inner.get('severity', '')
            title = inner.get('title', '')
            if sev in ('high', 'critical', 'medium'):
                findings_hcm.append((phase, sev, title[:120]))
        except:
            pass

print(f'Unique phases: {len(phases)}')
print(f'Error-level entries: {len(errors)}')
print(f'DEGRADED entries: {len(degraded)}')
print(f'FAIL entries: {len(fails)}')
print(f'TIMEOUT entries: {len(timeout_lines)}')
print(f'SSTI-related lines: {len(ssti_lines)}')
print(f'Redis-related lines: {len(redis_lines)}')
print(f'Total "finding" type lines: {len(all_findings)}')
print(f'High/Critical/Medium parsed findings: {len(findings_hcm)}')
print()

print('=== TOP PHASES BY ACTIVITY ===')
for p, c in phases.most_common(20):
    print(f'  {p}: {c}')

print()
print('=== DEGRADED EVENTS ===')
for p, t in degraded[:20]:
    print(f'  [{p}] {t}')

print()
print('=== FAIL EVENTS ===')
for p, t in fails[:15]:
    print(f'  [{p}] {t}')

print()
print('=== TIMEOUT EVENTS ===')
for p, t in timeout_lines[:15]:
    print(f'  [{p}] {t}')

print()
print('=== SSTI SIGNALS ===')
for p, t in ssti_lines[:10]:
    print(f'  [{p}] {t}')

print()
print('=== REDIS SIGNALS ===')
for p, t in redis_lines[:15]:
    print(f'  [{p}] {t}')

print()
print('=== HIGH/CRIT/MEDIUM FINDINGS ===')
for p, sev, title in findings_hcm[:30]:
    print(f'  [{sev.upper()}] [{p}] {title}')

print()
print('=== SAMPLE ALL FINDINGS ===')
for p, t in all_findings[:20]:
    print(f'  [{p}] {t[:200]}')
