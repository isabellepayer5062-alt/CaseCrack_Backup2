"""Check dead phase-map entries for registerable classes."""
import pathlib, re

root = pathlib.Path('CaseCrack/tools/burp_enterprise')

checks = {
    'weak_hash_detector': ['weak_hash_detector.py'],
    'defensive_monitoring': ['defensive_monitoring_tester.py', 'defensive_monitoring.py'],
    'xss_tester': ['xss.py'],
    'sbom_generator': ['sbom_generator.py'],
    'siem_connector': ['siem_connector.py'],
    'threat_modeler': ['threat_modeler.py'],
}

for phase_name, filenames in checks.items():
    print(f'=== {phase_name} ===')
    found = False
    for fname in filenames:
        p = root / fname
        if p.exists():
            src = p.read_text('utf-8', 'replace')
            classes = re.findall(r'^class (\w+)', src, re.MULTILINE)
            print(f'  {fname}: {classes[:5]}')
            for cls in classes[:3]:
                pattern = r'class ' + re.escape(cls) + r'[^:]*:.*?(?=^class |\Z)'
                m = re.search(pattern, src, re.DOTALL | re.MULTILINE)
                if m:
                    meths = re.findall(r'^\s{4}def ([a-z]\w*)', m.group(0), re.MULTILINE)
                    print(f'    {cls}.methods: {meths[:8]}')
            found = True
    if not found:
        print('  No matching file found')

# Also check http2_fingerprint (missing from phase map, should be RECON)
print()
print('=== http2_fingerprint (in registry as RECON candidate) ===')
p = root / 'http2_fingerprint.py'
if p.exists():
    src = p.read_text('utf-8', 'replace')
    classes = re.findall(r'^class (\w+)', src, re.MULTILINE)
    print(f'  Classes: {classes}')
    for cls in classes[:2]:
        pattern = r'class ' + re.escape(cls) + r'[^:]*:.*?(?=^class |\Z)'
        m = re.search(pattern, src, re.DOTALL | re.MULTILINE)
        if m:
            meths = re.findall(r'^\s{4}def ([a-z]\w*)', m.group(0), re.MULTILINE)
            print(f'  {cls}.methods: {meths[:8]}')

# Check supply_chain_deep
print()
print('=== supply_chain_deep (missing from phase map) ===')
p = root / 'supply_chain_deep.py'
if p.exists():
    src = p.read_text('utf-8', 'replace')
    classes = re.findall(r'^class (\w+)', src, re.MULTILINE)
    print(f'  Classes: {classes[:5]}')
