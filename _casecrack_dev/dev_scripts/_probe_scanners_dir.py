"""Check scanners/ subdirectory for real class/method implementations."""
import pathlib, re

root = pathlib.Path('CaseCrack/tools/burp_enterprise')
scanners_dir = root / 'scanners'

checks = [
    ('scanners/weak_hash_detector.py', 'weak_hash_detector'),
    ('scanners/defensive_monitoring_tester.py', 'defensive_monitoring'),
    ('sbom_generator.py', 'sbom_generator'),
    ('siem_connector.py', 'siem_connector'),
    ('threat_modeler.py', 'threat_modeler'),
]

for rel_path, scanner_name in checks:
    p = root / rel_path
    if not p.exists():
        # try real scanners dir
        p = scanners_dir / rel_path.split('/')[-1]
    if p.exists():
        src = p.read_text('utf-8', 'replace')
        all_classes = re.findall(r'^class (\w+)', src, re.MULTILINE)
        print(f'=== {scanner_name}: {p.relative_to(root)} ===')
        print(f'  Classes: {all_classes[:8]}')
        for cls in all_classes:
            if any(k in cls for k in ('Scanner', 'Tester', 'Detector', 'Engine', 'Assessor', 'Generator', 'Connector', 'Modeler')):
                pattern = r'class ' + re.escape(cls) + r'[^:]*:.*?(?=^class |\Z)'
                m = re.search(pattern, src, re.DOTALL | re.MULTILINE)
                if m:
                    meths = re.findall(r'^\s{4}def ([a-z_]\w*)', m.group(0), re.MULTILINE)
                    public_meths = [mm for mm in meths if not mm.startswith('_')]
                    print(f'  {cls}: {public_meths[:8]}')
    else:
        print(f'=== {scanner_name}: NOT FOUND at {rel_path} ===')

# Also check http2_fingerprint
print()
p2 = root / 'http2_fingerprint.py'
if p2.exists():
    src2 = p2.read_text('utf-8', 'replace')
    print('http2_fingerprint.py first 300 chars:')
    print(src2[:300])
