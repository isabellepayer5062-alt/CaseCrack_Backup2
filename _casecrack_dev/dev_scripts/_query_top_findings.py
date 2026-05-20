import sqlite3
import json

db = sqlite3.connect('scan_data/databases/intel.db')
db.row_factory = sqlite3.Row
cur = db.cursor()

print("=== SEVERITY DISTRIBUTION ===")
cur.execute("""
    SELECT severity, COUNT(*) as cnt
    FROM unified_findings
    GROUP BY severity
    ORDER BY CASE severity
        WHEN 'critical' THEN 1 WHEN 'high' THEN 2
        WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
""")
for r in cur.fetchall():
    print(f"  {r['severity']}: {r['cnt']}")

print("\n=== CRITICAL FINDINGS ===")
cur.execute("""
    SELECT id, title, severity, cvss_score, confidence, endpoint, vuln_type, cwe_id, category, source_module
    FROM unified_findings
    WHERE severity = 'critical'
    ORDER BY cvss_score DESC, confidence DESC
""")
for r in cur.fetchall():
    print(f"[{r['id']}] {r['title']}")
    print(f"  CVSS={r['cvss_score']}  conf={r['confidence']}  type={r['vuln_type']}  cwe={r['cwe_id']}")
    print(f"  endpoint={r['endpoint']}")
    print(f"  module={r['source_module']}  cat={r['category']}")
    print()

print("\n=== HIGH FINDINGS (top 40 by CVSS+confidence) ===")
cur.execute("""
    SELECT id, title, severity, cvss_score, confidence, endpoint, vuln_type, cwe_id, category, source_module
    FROM unified_findings
    WHERE severity = 'high'
    ORDER BY cvss_score DESC, confidence DESC
    LIMIT 40
""")
for r in cur.fetchall():
    print(f"[{r['id']}] {r['title']}")
    print(f"  CVSS={r['cvss_score']}  conf={r['confidence']}  type={r['vuln_type']}  cwe={r['cwe_id']}")
    print(f"  endpoint={r['endpoint']}")
    print(f"  module={r['source_module']}  cat={r['category']}")
    print()

db.close()
