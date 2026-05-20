import sqlite3
import json

db = sqlite3.connect('scan_data/databases/intel.db')
db.row_factory = sqlite3.Row
cur = db.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [r['name'] for r in cur.fetchall()]
print('TABLES:', tables)

for tname in tables:
    cur.execute(f"SELECT COUNT(*) as cnt FROM [{tname}]")
    cnt = cur.fetchone()['cnt']
    print(f"  {tname}: {cnt} rows")
    if cnt > 0:
        cur.execute(f"PRAGMA table_info([{tname}])")
        cols = [r[1] for r in cur.fetchall()]
        print(f"    cols: {cols[:20]}")

db.close()
