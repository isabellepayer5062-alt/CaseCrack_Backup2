"""Find real module paths for shim scanners."""
import pathlib, re

root = pathlib.Path('CaseCrack/tools/burp_enterprise')

# Check shim targets
for name in ['sbom_generator', 'siem_connector', 'threat_modeler', 'http2_fingerprint']:
    p = root / (name + '.py')
    src = p.read_text('utf-8', 'replace')
    m = re.search(r'import_module\("([^"]+)"\)', src)
    if m:
        print(f'{name} -> {m.group(1)}')
    else:
        print(f'{name}: no import_module found')

# Check network/http2_fingerprint.py
np = root / 'network' / 'http2_fingerprint.py'
if np.exists():
    nsrc = np.read_text('utf-8', 'replace')
    classes = re.findall(r'^class (\w+)', nsrc, re.MULTILINE)
    print(f'\nnetwork/http2_fingerprint.py classes: {classes[:6]}')
    for cls in classes:
        if any(k in cls for k in ('Fingerprint', 'Scanner', 'Probe')):
            pattern = r'class ' + re.escape(cls) + r'[^:]*:.*?(?=^class |\Z)'
            m2 = re.search(pattern, nsrc, re.DOTALL | re.MULTILINE)
            if m2:
                meths = re.findall(r'^\s{4}def ([a-z_]\w*)', m2.group(0), re.MULTILINE)
                public = [x for x in meths if not x.startswith('_')]
                print(f'  {cls}: {public[:8]}')

# Check real sbom, siem, threat locations
for name in ['sbom_generator', 'siem_connector', 'threat_modeler']:
    p = root / (name + '.py')
    src = p.read_text('utf-8', 'replace')
    m = re.search(r'import_module\("([^"]+)"\)', src)
    if m:
        real_path = m.group(1).replace('tools.burp_enterprise.', '').replace('.', '/') + '.py'
        rp = root / real_path
        if rp.exists():
            rsrc = rp.read_text('utf-8', 'replace')
            rclasses = re.findall(r'^class (\w+)', rsrc, re.MULTILINE)
            print(f'\n{name} real ({real_path}): {rclasses[:5]}')
            for cls in rclasses:
                if any(k in cls for k in ('Generator', 'Connector', 'Modeler', 'Scanner', 'Engine')):
                    pattern = r'class ' + re.escape(cls) + r'[^:]*:.*?(?=^class |\Z)'
                    m2 = re.search(pattern, rsrc, re.DOTALL | re.MULTILINE)
                    if m2:
                        meths = re.findall(r'^\s{4}def ([a-z_]\w*)', m2.group(0), re.MULTILINE)
                        public = [x for x in meths if not x.startswith('_')]
                        print(f'  {cls}: {public[:6]}')
        else:
            print(f'\n{name}: real path {real_path} not found')
