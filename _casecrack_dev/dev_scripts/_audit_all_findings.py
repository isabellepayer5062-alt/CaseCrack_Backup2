"""
Deep findings audit against recon-all-findings.json
"""
import json, collections, sys

findings_path = r"c:\Users\ya754\CaseCrack v1.0\CaseCrack\reports\recon-all-findings.json"

with open(findings_path, encoding='utf-8', errors='replace') as f:
    try:
        data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}")
        sys.exit(1)

if isinstance(data, list):
    findings = data
elif isinstance(data, dict):
    findings = data.get('findings', data.get('results', [data]))
else:
    findings = []

print(f"Total findings: {len(findings)}")
print()

# Count by severity
sev_counter = collections.Counter()
phase_counter = collections.Counter()
type_counter = collections.Counter()
cat_counter = collections.Counter()
has_url = 0
has_payload = 0
has_cwe = 0
has_cvss = 0
has_confidence = 0
confidence_labels = collections.Counter()
missing_fields = collections.Counter()

# Track findings with issues
bad_schema = []
no_title = []
no_detail = []
no_phase = []
no_severity = []
duplicate_titles = collections.Counter()

REQUIRED_FIELDS = ['type', 'severity', 'title', 'detail', 'phase']

for i, f in enumerate(findings):
    if not isinstance(f, dict):
        continue
    
    sev = f.get('severity', 'MISSING')
    sev_counter[sev] += 1
    phase_counter[f.get('phase', 'MISSING')] += 1
    type_counter[f.get('type', 'MISSING')] += 1
    cat_counter[f.get('category', 'MISSING')] += 1
    
    if f.get('url'):
        has_url += 1
    if f.get('payload'):
        has_payload += 1
    if f.get('cwe'):
        has_cwe += 1
    if f.get('cvss_score'):
        has_cvss += 1
    
    conf = f.get('confidence')
    if conf:
        has_confidence += 1
        if isinstance(conf, dict):
            confidence_labels[conf.get('label', 'unknown')] += 1
    
    # Check for missing required fields
    for req in REQUIRED_FIELDS:
        if not f.get(req):
            missing_fields[req] += 1
    
    title = f.get('title', '')
    if not title:
        no_title.append(i)
    else:
        duplicate_titles[title] += 1

print("=== BY SEVERITY ===")
for sev, cnt in sorted(sev_counter.items(), key=lambda x: -x[1]):
    print(f"  {sev:12s}: {cnt:5d}")

print()
print("=== BY PHASE (top 30) ===")
for ph, cnt in sorted(phase_counter.items(), key=lambda x: -x[1])[:30]:
    print(f"  [{cnt:4d}] {ph}")

print()
print("=== BY CATEGORY (top 20) ===")
for cat, cnt in sorted(cat_counter.items(), key=lambda x: -x[1])[:20]:
    print(f"  [{cnt:4d}] {cat!r}")

print()
print("=== FINDING TYPE (top 20) ===")
for ft, cnt in sorted(type_counter.items(), key=lambda x: -x[1])[:20]:
    print(f"  [{cnt:4d}] {ft!r}")

print()
print("=== DATA QUALITY ===")
print(f"  Has URL:        {has_url}/{len(findings)} ({100*has_url//max(1,len(findings))}%)")
print(f"  Has payload:    {has_payload}/{len(findings)} ({100*has_payload//max(1,len(findings))}%)")
print(f"  Has CWE:        {has_cwe}/{len(findings)} ({100*has_cwe//max(1,len(findings))}%)")
print(f"  Has CVSS:       {has_cvss}/{len(findings)} ({100*has_cvss//max(1,len(findings))}%)")
print(f"  Has confidence: {has_confidence}/{len(findings)} ({100*has_confidence//max(1,len(findings))}%)")

print()
print("=== CONFIDENCE LABELS ===")
for lbl, cnt in sorted(confidence_labels.items(), key=lambda x: -x[1]):
    print(f"  {lbl:15s}: {cnt:4d}")

print()
print("=== MISSING REQUIRED FIELDS ===")
for field, cnt in sorted(missing_fields.items(), key=lambda x: -x[1]):
    print(f"  {field:15s}: {cnt:4d} missing")

print()
print("=== DUPLICATE TITLES (top 20) ===")
dups = [(t, c) for t, c in duplicate_titles.items() if c > 3]
for title, cnt in sorted(dups, key=lambda x: -x[1])[:20]:
    print(f"  [{cnt:4d}] {title[:80]!r}")

print()
print("=== FINDINGS WITHOUT TITLE ===", len(no_title), "findings")
