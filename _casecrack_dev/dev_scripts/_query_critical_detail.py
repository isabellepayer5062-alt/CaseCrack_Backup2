import sqlite3
import json
import re
import urllib.request

print("=== Finding Race Condition endpoint context ===")
db = sqlite3.connect('scan_data/databases/intel.db')
db.row_factory = sqlite3.Row
cur = db.cursor()

# Check all critical findings full detail
cur.execute("""
    SELECT id, title, severity, description, detail_json, evidence_json, endpoint, category, phase, source_module
    FROM unified_findings
    WHERE severity = 'critical'
    ORDER BY id
""")
for r in cur.fetchall():
    print(f"\n[{r['id']}] {r['title']} | phase={r['phase']} | module={r['source_module']}")
    print(f"  endpoint: {r['endpoint']}")
    print(f"  desc: {r['description'][:300]}")
    if r['evidence_json']:
        print(f"  evidence: {str(r['evidence_json'])[:400]}")

print("\n\n=== Finding Mobile-API secrets details ===")
cur.execute("""
    SELECT id, title, severity, description, detail_json, evidence_json, endpoint, phase, source_module
    FROM unified_findings
    WHERE source_module = 'mobile-api'
    ORDER BY id
""")
for r in cur.fetchall():
    print(f"\n[{r['id']}] {r['title']} | module={r['source_module']}")
    print(f"  endpoint: {r['endpoint']}")
    print(f"  desc: {r['description'][:500]}")
    if r['evidence_json']:
        print(f"  evidence: {str(r['evidence_json'])[:800]}")
    if r['detail_json']:
        try:
            d = json.loads(r['detail_json'])
            print(f"  detail: {json.dumps(d, indent=2)[:800]}")
        except:
            print(f"  detail: {str(r['detail_json'])[:800]}")

db.close()
