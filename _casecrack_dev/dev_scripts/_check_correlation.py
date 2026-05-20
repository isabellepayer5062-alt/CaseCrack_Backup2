import json, os

# Check recon-enriched.json structure
p = r"c:\Users\ya754\CaseCrack v1.0\CaseCrack\reports\recon-enriched.json"
with open(p, encoding='utf-8', errors='replace') as f:
    data = json.load(f)

if isinstance(data, dict):
    print("recon-enriched.json is a dict")
    for k, v in list(data.items())[:10]:
        vlen = len(v) if hasattr(v, '__len__') else 'N/A'
        print(f"  {k}: {type(v).__name__} len={vlen}")
elif isinstance(data, list):
    print(f"recon-enriched.json is a list of {len(data)} items")
    if data:
        print("First item keys:", list(data[0].keys())[:15])

# Check what the "enrich" command output looks like in finding_parsers
print()
import collections
# Simulate: count Correlation & Compliance phase findings
main_fp = r"c:\Users\ya754\CaseCrack v1.0\CaseCrack\reports\recon-all-findings.json"
with open(main_fp, encoding='utf-8') as f:
    findings = json.load(f)

corr_findings = [f for f in findings if f.get('phase') == 'Correlation & Compliance']
print(f"Correlation & Compliance findings: {len(corr_findings)}")
cats = collections.Counter(f.get('category','') for f in corr_findings)
for cat, cnt in cats.most_common(10):
    print(f"  [{cnt}] {cat!r}")
    
# Show sample secret_in_code from correlation phase
for f in corr_findings:
    if f.get('category') == 'secret_in_code':
        print("\nSample secret_in_code from Correlation:")
        for k, v in f.items():
            if v and k not in ('detail',):
                print(f"  {k}: {str(v)[:80]}")
        break
