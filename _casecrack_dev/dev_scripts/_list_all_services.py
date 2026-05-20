import re
content = open('_dev_andurilapis_bundle.js','r',errors='replace').read()

# Extract all serviceName declarations
services = set(re.findall(r'serviceName:"([\w.]+)"', content))
for s in sorted(services):
    print(s)

print(f"\nTotal: {len(services)} services")

# Also get all methodName declarations with service context
print("\n--- All methods by service ---")
methods = re.findall(r'serviceName:"([\w.]+)"[^}]+methodName:"([\w.]+)"', content)
from collections import defaultdict
svc_map = defaultdict(list)
for svc, method in methods:
    svc_map[svc].append(method)
for svc in sorted(svc_map):
    print(f"\n[{svc}]")
    for m in sorted(set(svc_map[svc])):
        print(f"  {m}")
