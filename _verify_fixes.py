import pathlib, re

root = pathlib.Path('CaseCrack/tools/burp_enterprise')
p = root / 'scanners' / 'scanner_hooks.py'
src = p.read_text('utf-8', 'replace')

# Count registry entries (4-tuples)
entries = re.findall(r'\(\s*"[^"]+",\s*"[^"]+",\s*"[^"]+",\s*"[^"]+"\s*\)', src)
print(f'Registry entries: {len(entries)}')

# Verify new entries exist
for expected in ['xss_tester', 'weak_hash_detector', 'defensive_monitoring']:
    found = any(expected in e for e in entries)
    print(f'  {expected}: {"OK" if found else "MISSING"}')

# Show the last 5 entries
print('\nLast 5 registry entries:')
for e in entries[-5:]:
    print('  ', e.strip())

# Also verify chain merge-back in orchestrator
p2 = root / 'pipeline' / 'full_scan_orchestrator.py'
src2 = p2.read_text('utf-8', 'replace')
has_chain_fix = 'GAP-FIX: merge attack chains' in src2
print(f'\nChain merge-back fix present: {"OK" if has_chain_fix else "MISSING"}')

# Count occurrences of module_results.append in correlation method
idx = src2.find('def _run_correlation_engine')
corr_section = src2[idx:idx+2000]
has_append = 'module_results.append' in corr_section
print(f'module_results.append in _run_correlation_engine: {"OK" if has_append else "MISSING"}')
