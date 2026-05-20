import json, collections

warn_counts = collections.Counter()
err_counts = collections.Counter()
n = 0

with open('_empireminecraft_log.jsonl', 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        n += 1
        level = str(rec.get('level', '')).upper()
        msg = str(rec.get('msg') or rec.get('message') or rec.get('event') or rec.get('text') or '')
        if not msg:
            continue
        if level in ('WARNING', 'WARN'):
            warn_counts[msg[:100]] += 1
        elif level == 'ERROR':
            err_counts[msg[:100]] += 1

print(f'Scanned {n} records')
print(f'\n=== ALL WARNING MESSAGES ({sum(warn_counts.values())} total, {len(warn_counts)} distinct) ===')
for msg, cnt in sorted(warn_counts.items(), key=lambda x: -x[1]):
    print(f'  [{cnt:4d}x] {msg!r}')
print(f'\n=== ALL ERROR MESSAGES ({sum(err_counts.values())} total, {len(err_counts)} distinct) ===')
for msg, cnt in sorted(err_counts.items(), key=lambda x: -x[1]):
    print(f'  [{cnt:4d}x] {msg!r}')
