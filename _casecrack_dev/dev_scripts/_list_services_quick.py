import re
content = open('_dev_andurilapis_bundle.js','r',errors='replace').read()
services = sorted(set(re.findall(r'anduril\.[a-z0-9_.]+\.[A-Z][A-Za-z]+[A-Z][A-Za-z]+', content)))
print('=== ALL UNIQUE GRPC SERVICES ===')
for s in services[:100]:
    print(' ', s)
print(f'\nTOTAL: {len(services)}')
