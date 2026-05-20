import ast, pathlib

root = pathlib.Path('CaseCrack/tools/burp_enterprise')

files = [
    root / 'scanners' / 'scanner_hooks.py',
    root / 'pipeline' / 'full_scan_orchestrator.py',
]

for p in files:
    try:
        ast.parse(p.read_text('utf-8', 'replace'))
        print(f'AST OK: {p.name}')
    except SyntaxError as e:
        print(f'SYNTAX ERROR in {p.name}: line {e.lineno}: {e.msg}')

print()

# Verify _SCANNER_REGISTRY new entries
p = root / 'scanners' / 'scanner_hooks.py'
src = p.read_text('utf-8', 'replace')
for scanner, module, cls in [
    ('xss_tester', 'xss', 'XSSScanner'),
    ('weak_hash_detector', 'weak_hash_detector', 'WeakHashDetector'),
    ('defensive_monitoring', 'defensive_monitoring_tester', 'DefensiveMonitoringTester'),
]:
    present = ('"' + module + '"') in src and ('"' + cls + '"') in src and ('"' + scanner + '"') in src
    print(f'Registry entry {scanner}: {"OK" if present else "MISSING"}')

print()

# Verify _run_correlation_engine chain merge
p2 = root / 'pipeline' / 'full_scan_orchestrator.py'
src2 = p2.read_text('utf-8', 'replace')
idx = src2.find('def _run_correlation_engine')
corr_full = src2[idx:idx+4000]
checks = [
    ('GAP-FIX comment', 'GAP-FIX: merge attack chains'),
    ('chain_findings list', 'chain_findings: list[dict]'),
    ('module_results.append', 'module_results.append(ModuleResult('),
    ('ScanPhase.POST', 'phase=ScanPhase.POST'),
]
for label, needle in checks:
    print(f'{label}: {"OK" if needle in corr_full else "MISSING"}')
