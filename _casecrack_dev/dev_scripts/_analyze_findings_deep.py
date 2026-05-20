#!/usr/bin/env python3
"""Deep dive analysis — false positives, CDN findings, dedup failures, secrets."""
import json
from collections import Counter, defaultdict

with open('_findings_export.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

findings = data.get('findings', [])

CDN_DOMAINS = [
    'shopify.com', 'shopifysvc.com', 'shopifycloud.com', 'shopifycdn.com',
    'cloudfront.net', 'fastly.net', 'myshopify.com', 'cdn.shopify',
]

def is_cdn_url(url):
    url = (url or '').lower()
    return any(d in url for d in CDN_DOMAINS) or '/cdn/' in url

# ==========================================================================
# SECTION 1: Exposed Secrets — are they really on sugarrushed.ca?
# ==========================================================================
print('='*70)
print('SECTION 1: EXPOSED SECRETS — CDN vs Own-Hosted')
print('='*70)
secret_findings = [f for f in findings if 'secret' in f.get('category','').lower()
                   or 'secret' in f.get('title','').lower()
                   or f.get('secret_type')]

cdn_secrets, own_secrets = [], []
for f in secret_findings:
    url = f.get('url','') or f.get('secret_url','') or ''
    if is_cdn_url(url):
        cdn_secrets.append(f)
    else:
        own_secrets.append(f)

print(f'Total secret findings: {len(secret_findings)}')
print(f'  CDN/Shopify-hosted: {len(cdn_secrets)}  — LIKELY FALSE POSITIVES (Shopify owns these files)')
print(f'  Own-hosted:         {len(own_secrets)}   — WORTH INVESTIGATING')
print()

print('[CDN-hosted secrets by title+host]')
cdn_by_key = defaultdict(list)
for f in cdn_secrets:
    url = f.get('url','')
    # Extract host path
    import re
    m = re.search(r'https?://[^/]+(.*?)(?:\?|$)', url)
    path = m.group(1)[:60] if m else url[:60]
    cdn_by_key[(f.get('title','?'), path)].append(f)
for (title, path), items in sorted(cdn_by_key.items(), key=lambda x: -len(x[1])):
    print(f'  {len(items):2d}x [{items[0].get("severity","?")}] {title} | {path}')

print()
print('[Own-hosted secrets]')
for f in own_secrets:
    print(f'  [{f.get("severity","?")}] {f.get("title","?")} | {f.get("url","?")}')
print()

# ==========================================================================
# SECTION 2: DOM XSS — CDN-hosted vs own JS files
# ==========================================================================
print('='*70)
print('SECTION 2: DOM XSS — CDN vs Own-Hosted JS')
print('='*70)
xss_findings = [f for f in findings if 'xss' in f.get('category','').lower()
                or 'xss' in f.get('title','').lower()]

cdn_xss, own_xss = [], []
for f in xss_findings:
    url = f.get('url','') or ''
    if is_cdn_url(url):
        cdn_xss.append(f)
    else:
        own_xss.append(f)

print(f'Total XSS findings: {len(xss_findings)}')
print(f'  CDN/Shopify-hosted: {len(cdn_xss)}  — FALSE POSITIVES (not target\'s code)')
print(f'  Own-hosted/root:    {len(own_xss)}  — REAL (target owns these)')
print()

print('[CDN-hosted XSS (false positives)]')
for f in sorted(cdn_xss, key=lambda x: x.get('severity',''))[:15]:
    url = f.get('url','')
    sev = f.get('severity','?')
    title = f.get('title','?')[:70]
    print(f'  [{sev}] {title}')
    print(f'    CDN: {url[:90]}')

print()
print('[Own-hosted XSS (real findings)]')
for f in sorted(own_xss, key=lambda x: x.get('severity','')):
    url = f.get('url','')
    sev = f.get('severity','?')
    title = f.get('title','?')
    conf = '[confirmed]' if f.get('confirmed') else ''
    print(f'  [{sev}] {conf} {title}')
    print(f'    URL: {url[:100]}')
print()

# ==========================================================================
# SECTION 3: DUPLICATE ANALYSIS — why are there 42 excess findings?
# ==========================================================================
print('='*70)
print('SECTION 3: DUPLICATE ANALYSIS')
print('='*70)
dup_key = defaultdict(list)
for i, f in enumerate(findings):
    key = (f.get('title','').strip(), (f.get('url','') or '').strip())
    dup_key[key].append(i)

dup_groups = {k: v for k, v in dup_key.items() if len(v) > 1}
total_excess = sum(len(v) - 1 for v in dup_groups.values())
print(f'Duplicate groups: {len(dup_groups)}')
print(f'Excess findings:  {total_excess}')
print()

print('[Duplicate details — checking why dedup missed them]')
for (title, url), indices in sorted(dup_groups.items(), key=lambda x: -len(x[1]))[:12]:
    items = [findings[i] for i in indices]
    phases = [f.get('phase','?') for f in items]
    sevs = [f.get('severity','?') for f in items]
    orig_idxs = [f.get('_origIdx', '?') for f in items]
    print(f'  {len(items)}x [{title[:55]}]')
    print(f'     url: {url[:70]}')
    print(f'     phases:   {phases}')
    print(f'     sevs:     {sevs}')
    print(f'     origIdx:  {orig_idxs}')
    # Check if any fields differ (explain why dedup missed)
    field_diffs = []
    ref = items[0]
    for other in items[1:]:
        for k in ['phase', 'category', 'scan_type', 'secret_type']:
            if ref.get(k) != other.get(k):
                field_diffs.append(f'{k}: {ref.get(k)!r} vs {other.get(k)!r}')
    if field_diffs:
        print(f'     diffs: {field_diffs[:3]}')
print()

# ==========================================================================
# SECTION 4: Missing category (16 findings) — what are they?
# ==========================================================================
print('='*70)
print('SECTION 4: MISSING CATEGORY FINDINGS')
print('='*70)
missing_cat = [f for f in findings if not f.get('category')]
print(f'Total: {len(missing_cat)}')
for f in missing_cat:
    print(f'  [{f.get("severity","?")}] {f.get("title","?")}')
    print(f'     phase={f.get("phase","?")} scan_type={f.get("scan_type","?")} url={str(f.get("url","?"))[:70]}')
print()

# ==========================================================================
# SECTION 5: Subdomain permutations — noise vs real?
# ==========================================================================
print('='*70)
print('SECTION 5: SUBDOMAIN PERMUTATIONS (84 findings)')
print('='*70)
subdomain_perms = [f for f in findings if f.get('category') == 'subdomain_permutation']
sev_counts = Counter(f.get('severity','?') for f in subdomain_perms)
print(f'Severity breakdown: {dict(sev_counts)}')
# How many have a real URL vs just a hostname guess?
has_url = sum(1 for f in subdomain_perms if f.get('url') and 'http' in f.get('url',''))
has_detail = sum(1 for f in subdomain_perms if f.get('detail'))
print(f'With resolvable URL: {has_url}')
print(f'With detail:         {has_detail}')
print()
print('[Sample subdomain permutation findings]')
for f in subdomain_perms[:10]:
    print(f'  [{f.get("severity","?")}] {f.get("title","?")} | {f.get("url","?")} | {str(f.get("detail",""))[:80]}')
print()

# ==========================================================================
# SECTION 6: Pipeline findings (category=pipeline) — internal noise?
# ==========================================================================
print('='*70)
print('SECTION 6: PIPELINE CATEGORY FINDINGS')
print('='*70)
pipeline_findings = [f for f in findings if f.get('category') == 'pipeline']
for f in pipeline_findings:
    print(f'  [{f.get("severity","?")}] {f.get("title","?")}')
    print(f'     detail: {str(f.get("detail",""))[:200]}')
    print(f'     phase: {f.get("phase","?")}')
print()

# ==========================================================================
# SECTION 7: Email domain findings — are they relevant?
# ==========================================================================
print('='*70)
print('SECTION 7: EMAIL DISCOVERY (22 findings)')
print('='*70)
email_findings = [f for f in findings if f.get('category') == 'email_discovery']
email_by_title = Counter(f.get('title','?') for f in email_findings)
for t, n in email_by_title.most_common():
    print(f'  {n:3d}  {t}')
print()
print('[Sample email findings]')
for f in email_findings[:5]:
    print(f'  {f.get("title","?")} | {str(f.get("detail",""))[:100]}')
print()

# ==========================================================================
# SECTION 8: Verification status gap
# ==========================================================================
print('='*70)
print('SECTION 8: VERIFICATION STATUS GAP')
print('='*70)
vs = Counter(repr(f.get('verification_status', 'MISSING')) for f in findings)
print('Verification status distribution:')
for s, n in vs.most_common():
    print(f'  {n:4d}  {s}')
print()
vs2 = Counter(repr(f.get('verification', 'MISSING')) for f in findings)
print('Verification field distribution (top 10):')
for s, n in vs2.most_common(10):
    print(f'  {n:4d}  {s}')
print()

# ==========================================================================
# SECTION 9: Scan_type completeness
# ==========================================================================
print('='*70)
print('SECTION 9: SCAN_TYPE FIELD COMPLETENESS')
print('='*70)
has_scan_type = sum(1 for f in findings if f.get('scan_type'))
missing_scan_type = len(findings) - has_scan_type
print(f'Has scan_type:     {has_scan_type}')
print(f'Missing scan_type: {missing_scan_type}  ({missing_scan_type/len(findings)*100:.1f}%)')
# Break down by phase
phase_scan_type = defaultdict(lambda: [0, 0])  # [has, missing]
for f in findings:
    ph = f.get('phase','?')
    if f.get('scan_type'):
        phase_scan_type[ph][0] += 1
    else:
        phase_scan_type[ph][1] += 1
print()
print('[scan_type coverage by phase]')
for ph, (has, miss) in sorted(phase_scan_type.items(), key=lambda x: -(x[1][0]+x[1][1])):
    total = has + miss
    pct = has/total*100 if total else 0
    print(f'  {pct:5.1f}% ({has:3d}/{total:3d})  {ph}')
print()

# ==========================================================================
# SECTION 10: Quick summary of real vs likely-FP breakdown
# ==========================================================================
print('='*70)
print('SECTION 10: REAL vs FALSE POSITIVE ESTIMATE')
print('='*70)

real_xss = len(own_xss)
fp_xss = len(cdn_xss)
real_secrets = len(own_secrets)
fp_secrets = len(cdn_secrets)
subdomain_perm_noise = len(subdomain_perms)  # mostly noise
email_noise = len(email_findings)  # depends
duplicate_excess = total_excess

print(f'Category                  Real   FP/Noise')
print(f'XSS findings:             {real_xss:4d}     {fp_xss:4d}  (CDN-hosted = Shopify code, not target)')
print(f'Exposed secrets:          {real_secrets:4d}     {fp_secrets:4d}  (CDN-hosted = Shopify infra secrets)')
print(f'Subdomain permutations:      -    {subdomain_perm_noise:4d}  (DNS brute-force, unverified)')
print(f'Email discovery:             -    {email_noise:4d}  (OSINT noise)')
print(f'Duplicate excess findings:   -    {duplicate_excess:4d}  (dedup pipeline failure)')
print()

# Real high/critical that need actual investigation
real_high_crit = [f for f in findings
                  if f.get('severity','').lower() in ('critical','high')
                  and not is_cdn_url(f.get('url',''))
                  and f.get('category') not in ('subdomain_permutation',)]
print(f'High/Critical on OWN domain: {len(real_high_crit)} (these need investigation)')
for f in real_high_crit[:20]:
    print(f'  [{f.get("severity","?")}] {f.get("title","?")}')
    print(f'     {f.get("url","?")}')
