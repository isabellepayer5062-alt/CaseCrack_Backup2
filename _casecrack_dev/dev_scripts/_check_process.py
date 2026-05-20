import pathlib
ROOT = pathlib.Path('CaseCrack/tools/burp_enterprise')
orch = ROOT / 'pipeline' / 'full_scan_orchestrator.py'
src = orch.read_text('utf-8', 'replace')

# Find the section that processes individual findings within _process_findings_through_pipeline
idx = src.find('def _process_findings_through_pipeline')
segment = src[idx:idx+2500]
print(segment)
