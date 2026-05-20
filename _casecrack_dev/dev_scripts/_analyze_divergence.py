"""Analyze divergence audit results."""
import json
from collections import Counter

with open("divergence_audit_results.json") as f:
    report = json.load(f)

# Count which fields diverge
field_counts = Counter()
scenario_counts = Counter()
for div in report["divergences"]:
    scenario_counts[div["scenario"]] += 1
    for d in div["differences"]:
        field_counts[d["field"]] += 1

print("Divergent fields:")
for field, count in field_counts.most_common():
    print(f"  {field}: {count}")

print(f"\nBy scenario:")
for sc, count in scenario_counts.most_common():
    print(f"  {sc}: {count}")

# Check one specific divergence to understand pattern
div0 = report["divergences"][0]
print(f"\nExample: {div0['scenario']} seed={div0['seed']} mode={div0['mode']}")
for d in div0["differences"]:
    field = d["field"]
    if field == "invariant_evidence":
        r1 = d["run1"]
        r2 = d["run2"]
        for i, (e1, e2) in enumerate(zip(r1, r2)):
            if e1 != e2:
                print(f"  INV-{i+1} evidence differs:")
                for k in set(list(e1.keys()) + list(e2.keys())):
                    v1 = e1.get(k)
                    v2 = e2.get(k)
                    if v1 != v2:
                        print(f"    {k}:")
                        print(f"      run1: {str(v1)[:100]}")
                        print(f"      run2: {str(v2)[:100]}")
    elif field == "metrics":
        r1 = d["run1"]
        r2 = d["run2"]
        for k in set(list(r1.keys()) + list(r2.keys())):
            v1 = r1.get(k)
            v2 = r2.get(k)
            if v1 != v2:
                print(f"  metric '{k}' differs:")
                print(f"    run1: {str(v1)[:100]}")
                print(f"    run2: {str(v2)[:100]}")
    else:
        print(f"  {field}: differs")
