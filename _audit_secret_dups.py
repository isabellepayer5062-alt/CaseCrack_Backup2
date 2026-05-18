import json, collections
with open('CaseCrack/reports/recon-all-findings.json', encoding='utf-8') as f:
    findings = json.load(f)

# What phase produces these duplicates?
fb = [f for f in findings if 'firebase_key' in f.get('title','') or 'aws_secret_key' in f.get('title','')]
phase_cnt = collections.Counter()
for f in fb:
    phase_cnt[f.get('phase','')] += 1

print('Phases producing secret duplicates:')
for p, c in sorted(phase_cnt.items(), key=lambda x: -x[1]):
    print(f'  [{c}] {p}')

# Check a few aws_secret_key entries
aws = [f for f in findings if 'aws_secret_key' in f.get('title','')]
print(f'\nAWS secret key: {len(aws)} total')
for f in aws[:3]:
    sec_url = f.get('url') or f.get('secret_url')
    masked = f.get('secret_masked_value')
    phase = f.get('phase')
    print(f'  url={sec_url!r}')
    print(f'  masked={masked!r}')
    print(f'  phase={phase!r}')
    print()

# Now check the adsbygoogle findings  
adsby = [f for f in findings if 'pagead2' in (f.get('url') or f.get('secret_url') or '')]
print(f'\nFindings from adsbygoogle.js: {len(adsby)}')
print('Types:')
type_cnt = collections.Counter(f.get('title','') for f in adsby)
for t, c in type_cnt.most_common(10):
    print(f'  [{c}] {t!r}')
