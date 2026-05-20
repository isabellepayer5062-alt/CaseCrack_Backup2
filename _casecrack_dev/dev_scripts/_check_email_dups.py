import json
with open(r'C:\Users\ya754\CaseCrack v1.0\reports\recon-all-findings.json', encoding='utf-8') as f:
    data = json.load(f)
for x in data:
    t = x.get('title','')
    if any(kw in t for kw in ['SPF', 'DMARC', 'Email Spoofing', 'spf', 'dmarc', 'email spoofing']):
        print(f"[{x.get('severity','').upper()}] {repr(t)} | url={repr(x.get('url','(none)'))} | module={repr(x.get('module',''))} | source_tool={repr(x.get('source_tool',''))}")
