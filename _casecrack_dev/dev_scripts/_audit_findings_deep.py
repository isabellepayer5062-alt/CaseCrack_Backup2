import sys, json, collections
sys.path.insert(0, 'CaseCrack')

# Analyze the empireminecraft log for finding-related patterns
finding_phases = collections.Counter()
finding_types = collections.Counter()
finding_sev = collections.Counter()
n_findings = 0
phase_findings = collections.defaultdict(int)
phases_with_zero = []
all_phases_seen = set()

# Also track: phases that ran but produced NO findings
phase_ran = set()

with open('_empireminecraft_log.jsonl', encoding='utf-8', errors='replace') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            rec = json.loads(line)
        except: continue
        t = rec.get('type','')
        phase = rec.get('phase','')
        if phase:
            all_phases_seen.add(phase)
        if t == 'finding':
            n_findings += 1
            sev = rec.get('severity','unknown')
            ftype = rec.get('finding_type') or rec.get('category','unknown')
            finding_phases[phase] += 1
            finding_types[ftype] += 1
            finding_sev[sev] += 1
            phase_findings[phase] += 1

phases_no_findings = sorted(all_phases_seen - set(finding_phases.keys()))

print(f'Total finding events in log: {n_findings}')
print(f'Unique phases seen: {len(all_phases_seen)}')
print(f'Phases producing findings: {len(finding_phases)}')
print()
print('=== FINDINGS BY SEVERITY ===')
for sev, cnt in sorted(finding_sev.items(), key=lambda x: -x[1]):
    print(f'  {sev:12s}: {cnt:5d}')
print()
print('=== PHASES PRODUCING ZERO FINDINGS ===')
for ph in phases_no_findings:
    print(f'  {ph}')
print()
print('=== FINDINGS BY PHASE ===')
for phase, cnt in sorted(finding_phases.items(), key=lambda x: -x[1]):
    print(f'  [{cnt:5d}] {phase}')
print()
print('=== FINDINGS BY TYPE (top 40) ===')
for ftype, cnt in sorted(finding_types.items(), key=lambda x: -x[1])[:40]:
    print(f'  [{cnt:5d}] {ftype!r}')
