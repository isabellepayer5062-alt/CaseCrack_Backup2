import pathlib
ROOT = pathlib.Path('CaseCrack/tools/burp_enterprise')

orch = ROOT / 'pipeline' / 'full_scan_orchestrator.py'
src = orch.read_text('utf-8', 'replace')

# _extract_findings full body
idx = src.find('def _extract_findings')
print('=== _extract_findings ===')
print(src[idx:idx+700])

# source setdefault context
search = 'finding_dict.setdefault("source"'
idx2 = src.find(search)
print()
print('=== source setdefault context ===')
print(src[max(0,idx2-200):idx2+500])
