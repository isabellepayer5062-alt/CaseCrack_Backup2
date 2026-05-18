import json
with open('CaseCrack/reports/recon-all-findings.json', encoding='utf-8') as f:
    all_f = json.load(f)
# Find a secret_in_code finding
for f in all_f:
    if f.get('category') == 'secret_in_code':
        for k,v in f.items():
            if v is not None and v != '' and v != 0 and v is not False:
                print(f'  {k}: {str(v)[:80]!r}')
        break
print()
pos_keys = {'confirmed', 'verified', 'exploitable', 'response_body', 'response_diff', 
            'proof', 'matched_at', 'extracted_results', 'curl_command', 'matched_value', 
            'masked_value', 'masked_secret', 'status_code', 'response_size', 
            'cve_id', 'cwe_id', 'cvss_score', 'template_id', 'matcher_name'}
secs = [f for f in all_f if f.get('category') == 'secret_in_code']
print(f'Checking evidence keys for {len(secs)} secret_in_code findings:')
for f in secs[:5]:
    found = [k for k in pos_keys if f.get(k) not in (None,'',0,False)]
    conf_score = (f.get('confidence') or {}).get('score', '?')
    print(f'  evidence_keys={found} conf={conf_score}')
