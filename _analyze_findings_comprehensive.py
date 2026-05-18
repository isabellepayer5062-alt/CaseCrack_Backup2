#!/usr/bin/env python3
"""Comprehensive analysis of scan findings for false positives and issues."""
import json
from collections import Counter, defaultdict

with open('_findings_export.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

findings = data.get('findings', [])
print(f'=== COMPREHENSIVE FINDINGS ANALYSIS — sugarrushed.ca ===')
print(f'Total findings: {len(findings)}')
print()

# ---------------------------------------------------------------------------
# 1. Severity breakdown
# ---------------------------------------------------------------------------
sev_counts = Counter(f.get('severity', '?').lower() for f in findings)
print('--- SEVERITY BREAKDOWN ---')
for s in ['critical', 'high', 'medium', 'low', 'info', '?']:
    if s in sev_counts:
        print(f'  {s:10s}: {sev_counts[s]:4d}')
print()

# ---------------------------------------------------------------------------
# 2. Category breakdown
# ---------------------------------------------------------------------------
cat_counts = Counter(f.get('category', '?') for f in findings)
print('--- CATEGORY BREAKDOWN ---')
for cat, n in cat_counts.most_common():
    print(f'  {n:4d}  {cat}')
print()

# ---------------------------------------------------------------------------
# 3. Phase breakdown
# ---------------------------------------------------------------------------
phase_counts = Counter(f.get('phase', '?') for f in findings)
print('--- PHASE BREAKDOWN ---')
for ph, n in phase_counts.most_common():
    print(f'  {n:4d}  {ph}')
print()

# ---------------------------------------------------------------------------
# 4. False positive flags (built-in)
# ---------------------------------------------------------------------------
likely_fp = [f for f in findings if f.get('likely_false_positive')]
cdn_fp = [f for f in findings if f.get('cdn_false_positive')]
print('--- BUILT-IN FALSE POSITIVE FLAGS ---')
print(f'  likely_false_positive: {len(likely_fp)}')
print(f'  cdn_false_positive:    {len(cdn_fp)}')
print()

if likely_fp:
    print('  [likely_false_positive details]')
    for f in likely_fp[:20]:
        print(f'    [{f.get("severity","?")}] {f.get("title","?")} | reason: {f.get("fp_reason","?")} | phase: {f.get("phase","?")}')
    print()

if cdn_fp:
    print('  [cdn_false_positive details]')
    for f in cdn_fp[:20]:
        print(f'    [{f.get("severity","?")}] {f.get("title","?")} | phase: {f.get("phase","?")} | url: {f.get("url","?")}')
    print()

# ---------------------------------------------------------------------------
# 5. Secrets analysis — check for Shopify-hosted / CDN false positives
# ---------------------------------------------------------------------------
secrets = [f for f in findings if f.get('secret_type') or f.get('category', '').lower() in ('secret', 'secrets')]
print(f'--- SECRETS ({len(secrets)} total) ---')
secret_type_counts = Counter(f.get('secret_type', 'unknown') for f in secrets)
for st, n in secret_type_counts.most_common():
    print(f'  {n:4d}  {st}')
print()

# Flag secrets that are likely Shopify/CDN hosted (not the target's own)
cdn_domains = ['shopify.com', 'shopifysvc.com', 'shopifycdn.com', 'cloudfront.net',
               'akamai', 'fastly.net', 'cdn.shopify', 'myshopify.com']
print('  Secrets by host type:')
shopify_secrets, own_secrets = [], []
for f in secrets:
    url = f.get('secret_url') or f.get('url') or ''
    loc = f.get('secret_location', '')
    is_cdn = any(d in url.lower() or d in loc.lower() for d in cdn_domains)
    if is_cdn:
        shopify_secrets.append(f)
    else:
        own_secrets.append(f)
print(f'    Shopify/CDN-hosted: {len(shopify_secrets)}  (likely false positives)')
print(f'    Target-hosted:      {len(own_secrets)}  (worth investigating)')
print()

if own_secrets:
    print('  [Target-hosted secrets — HIGH priority review]')
    for f in own_secrets[:25]:
        url = f.get('secret_url') or f.get('url') or '?'
        print(f'    [{f.get("severity","?")}] {f.get("secret_type","?")} @ {url[:100]}')
        if f.get('secret_masked_value'):
            print(f'      masked: {f.get("secret_masked_value")}')
    print()

# ---------------------------------------------------------------------------
# 6. CVEs analysis — check for false positives (wrong product match)
# ---------------------------------------------------------------------------
cves = [f for f in findings if f.get('cve_id')]
print(f'--- CVEs ({len(cves)} total) ---')
for f in cves:
    cve = f.get('cve_id', '?')
    cvss = f.get('cvss_score', '?')
    prod = f.get('affected_product', '?')
    kev = '* KEV *' if f.get('in_kev') else ''
    exploit = '[has exploit]' if f.get('has_exploit') else ''
    combo = f.get('combo_technologies', [])
    sev = f.get('severity', '?')
    print(f'  [{sev}] {cve} CVSS={cvss} | {prod} {kev} {exploit}')
    if combo:
        print(f'    matched techs: {combo}')
print()

# ---------------------------------------------------------------------------
# 7. WAF bypass findings — common source of FPs
# ---------------------------------------------------------------------------
bypasses = [f for f in findings if f.get('bypass_technique') or f.get('category', '').lower() == 'waf bypass']
print(f'--- WAF BYPASS ({len(bypasses)} total) ---')
by_technique = Counter(f.get('bypass_technique', '?') for f in bypasses)
for tech, n in by_technique.most_common():
    print(f'  {n:4d}  {tech}')
print()

if bypasses:
    print('  [WAF Bypass samples]')
    for f in bypasses[:10]:
        print(f'    [{f.get("severity","?")}] {f.get("title","?")} | tech: {f.get("bypass_technique","?")} | url: {str(f.get("url","?"))[:80]}')
    print()

# ---------------------------------------------------------------------------
# 8. Verified vs unverified — key quality signal
# ---------------------------------------------------------------------------
vs = Counter(f.get('verification_status', 'unset') for f in findings)
print('--- VERIFICATION STATUS ---')
for status, n in vs.most_common():
    print(f'  {n:4d}  {status}')
print()

confirmed = [f for f in findings if f.get('confirmed')]
print(f'  Confirmed findings: {len(confirmed)}')
print()

# ---------------------------------------------------------------------------
# 9. Scan type (nuclei template) based analysis
# ---------------------------------------------------------------------------
scan_types = Counter(f.get('scan_type', '?') for f in findings)
print('--- SCAN TYPE BREAKDOWN ---')
for st, n in scan_types.most_common(20):
    print(f'  {n:4d}  {st}')
print()

# ---------------------------------------------------------------------------
# 10. Structural / pipeline issues — missing required fields
# ---------------------------------------------------------------------------
missing_title = [f for f in findings if not f.get('title')]
missing_sev = [f for f in findings if not f.get('severity')]
missing_phase = [f for f in findings if not f.get('phase')]
missing_cat = [f for f in findings if not f.get('category')]

print('--- PIPELINE QUALITY ISSUES ---')
print(f'  missing title:    {len(missing_title)}')
print(f'  missing severity: {len(missing_sev)}')
print(f'  missing phase:    {len(missing_phase)}')
print(f'  missing category: {len(missing_cat)}')

if missing_title:
    print('  [missing title samples]')
    for f in missing_title[:5]:
        print(f'    phase={f.get("phase","?")} sev={f.get("severity","?")} keys={list(f.keys())[:8]}')
print()

# ---------------------------------------------------------------------------
# 11. Duplicate analysis (same title+url appearing multiple times)
# ---------------------------------------------------------------------------
from collections import defaultdict
dup_key = defaultdict(list)
for i, f in enumerate(findings):
    key = (f.get('title', ''), f.get('url', ''))
    dup_key[key].append(i)

dups = {k: v for k, v in dup_key.items() if len(v) > 1}
print(f'--- DUPLICATE ANALYSIS ---')
print(f'  Duplicate title+url pairs: {len(dups)}')
total_dup_findings = sum(len(v) - 1 for v in dups.values())
print(f'  Excess (duplicate) findings: {total_dup_findings}')
if dups:
    print('  [Top duplicates]')
    for (title, url), indices in sorted(dups.items(), key=lambda x: -len(x[1]))[:10]:
        sevs = [findings[i].get('severity', '?') for i in indices]
        print(f'    {len(indices)}x [{"/".join(set(sevs))}] {title[:60]} @ {str(url)[:60]}')
print()

# ---------------------------------------------------------------------------
# 12. High/critical by title for quick triage
# ---------------------------------------------------------------------------
high_crit = [f for f in findings if f.get('severity', '').lower() in ('critical', 'high')]
print(f'--- HIGH/CRITICAL FINDINGS ({len(high_crit)}) ---')
# Group by title
by_title = defaultdict(list)
for f in high_crit:
    by_title[f.get('title', '?')].append(f)
for title, items in sorted(by_title.items(), key=lambda x: -len(x[1])):
    sev = items[0].get('severity', '?')
    urls = list(set(f.get('url', '') for f in items))
    fp_flags = sum(1 for f in items if f.get('likely_false_positive'))
    cdn_flags = sum(1 for f in items if f.get('cdn_false_positive'))
    fp_note = f' [FP={fp_flags}]' if fp_flags else ''
    cdn_note = f' [CDN-FP={cdn_flags}]' if cdn_flags else ''
    print(f'  [{sev}] {len(items)}x {title}{fp_note}{cdn_note}')
    for u in urls[:2]:
        if u:
            print(f'    -> {u[:100]}')
print()

# ---------------------------------------------------------------------------
# 13. Info-severity bulk check — common source of noise
# ---------------------------------------------------------------------------
info_findings = [f for f in findings if f.get('severity', '').lower() == 'info']
info_cats = Counter(f.get('category', '?') for f in info_findings)
print(f'--- INFO FINDINGS by category ({len(info_findings)} total) ---')
for cat, n in info_cats.most_common():
    print(f'  {n:4d}  {cat}')
print()

# ---------------------------------------------------------------------------
# 14. Save analysis summary
# ---------------------------------------------------------------------------
summary = {
    'total': len(findings),
    'severity': dict(sev_counts),
    'built_in_fp': {'likely_fp': len(likely_fp), 'cdn_fp': len(cdn_fp)},
    'secrets': {'total': len(secrets), 'cdn_hosted': len(shopify_secrets), 'target_hosted': len(own_secrets)},
    'cves': len(cves),
    'waf_bypass': len(bypasses),
    'duplicates': {'unique_dup_groups': len(dups), 'excess_findings': total_dup_findings},
    'pipeline_issues': {
        'missing_title': len(missing_title),
        'missing_severity': len(missing_sev),
        'missing_phase': len(missing_phase),
        'missing_category': len(missing_cat),
    },
    'high_critical': len(high_crit),
    'confirmed': len(confirmed),
}
with open('_findings_analysis_summary.json', 'w') as f:
    json.dump(summary, f, indent=2)
print('Summary saved to _findings_analysis_summary.json')
