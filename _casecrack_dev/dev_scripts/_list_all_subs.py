import json

with open('scan_data/reports/osint-passive-subs.json', 'r') as f:
    passive = json.load(f)

findings = passive.get('findings', [])
print(f"Total subdomain findings: {len(findings)}")

# Extract all subdomains from the 'extra' field
subs = []
for item in findings:
    if isinstance(item, dict):
        extra = item.get('extra', {})
        sub = extra.get('subdomain') or item.get('title', '').replace('Subdomain: ', '')
        if sub:
            subs.append(sub)

subs = sorted(set(subs))
print(f"Unique subdomains: {len(subs)}\n")

# Print all
for s in subs:
    print(s)
