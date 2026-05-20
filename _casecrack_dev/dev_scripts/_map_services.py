import re
from collections import defaultdict

for fname in ['andurilapis_bundle.js', '_dev_andurilapis_bundle.js']:
    try:
        content = open(fname, 'r', errors='replace').read()
        print(f"\n=== {fname} ({len(content):,} bytes) ===")
        services = set(re.findall(r'serviceName:"([\w.]+)"', content))
        print(f"Total services: {len(services)}")
        for s in sorted(services):
            print(f"  {s}")

        # methods per service
        methods = re.findall(r'serviceName:"([\w.]+)"[^}]{0,200}methodName:"([\w.]+)"', content)
        svc_map = defaultdict(set)
        for svc, method in methods:
            svc_map[svc].add(method)
        print("\n--- Methods ---")
        for svc in sorted(svc_map):
            print(f"\n  [{svc}]")
            for m in sorted(svc_map[svc]):
                print(f"    {m}")
    except Exception as e:
        print(f"Error: {e}")
