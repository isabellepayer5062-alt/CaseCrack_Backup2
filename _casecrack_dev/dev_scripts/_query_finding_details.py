import sqlite3
import json

db = sqlite3.connect('scan_data/databases/intel.db')
db.row_factory = sqlite3.Row
cur = db.cursor()

print("=== DETAIL: Secret Findings in JS Bundle ===")
cur.execute("""
    SELECT id, title, severity, description, detail_json, evidence_json, endpoint
    FROM unified_findings
    WHERE id IN (38, 39, 40, 46)
    ORDER BY id
""")
for r in cur.fetchall():
    print(f"\n--- [{r['id']}] {r['title']} ---")
    print(f"endpoint: {r['endpoint']}")
    print(f"description: {r['description']}")
    if r['detail_json']:
        try:
            d = json.loads(r['detail_json'])
            print(f"detail: {json.dumps(d, indent=2)[:2000]}")
        except:
            print(f"detail_raw: {str(r['detail_json'])[:2000]}")
    if r['evidence_json']:
        try:
            e = json.loads(r['evidence_json'])
            print(f"evidence: {json.dumps(e, indent=2)[:2000]}")
        except:
            print(f"evidence_raw: {str(r['evidence_json'])[:2000]}")

print("\n\n=== DETAIL: GraphQL Findings ===")
cur.execute("""
    SELECT id, title, severity, description, detail_json, evidence_json, endpoint
    FROM unified_findings
    WHERE id IN (738, 739, 740, 741, 742)
    ORDER BY id
""")
for r in cur.fetchall():
    print(f"\n--- [{r['id']}] {r['title']} ---")
    print(f"endpoint: {r['endpoint']}")
    print(f"description: {r['description']}")
    if r['detail_json']:
        try:
            d = json.loads(r['detail_json'])
            print(f"detail: {json.dumps(d, indent=2)[:2000]}")
        except:
            print(f"detail_raw: {str(r['detail_json'])[:2000]}")
    if r['evidence_json']:
        try:
            e = json.loads(r['evidence_json'])
            print(f"evidence: {json.dumps(e, indent=2)[:2000]}")
        except:
            print(f"evidence_raw: {str(r['evidence_json'])[:2000]}")

print("\n\n=== DETAIL: Open Redirect + CSRF ===")
cur.execute("""
    SELECT id, title, severity, description, detail_json, evidence_json, endpoint
    FROM unified_findings
    WHERE id IN (445, 446, 447, 448)
    ORDER BY id
""")
for r in cur.fetchall():
    print(f"\n--- [{r['id']}] {r['title']} ---")
    print(f"endpoint: {r['endpoint']}")
    print(f"description: {r['description']}")
    if r['detail_json']:
        try:
            d = json.loads(r['detail_json'])
            print(f"detail: {json.dumps(d, indent=2)[:1500]}")
        except:
            print(f"detail_raw: {str(r['detail_json'])[:1500]}")

print("\n\n=== DETAIL: Critical Findings ===")
cur.execute("""
    SELECT id, title, severity, description, detail_json, evidence_json, endpoint, category
    FROM unified_findings
    WHERE id IN (35, 455, 458, 653, 661)
    ORDER BY id
""")
for r in cur.fetchall():
    print(f"\n--- [{r['id']}] {r['title']} (cat={r['category']}) ---")
    print(f"endpoint: {r['endpoint']}")
    print(f"description: {r['description']}")
    if r['detail_json']:
        try:
            d = json.loads(r['detail_json'])
            print(f"detail: {json.dumps(d, indent=2)[:2000]}")
        except:
            print(f"detail_raw: {str(r['detail_json'])[:2000]}")

db.close()
