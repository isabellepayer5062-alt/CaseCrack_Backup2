with open('RECONNECTION_ROADMAP.md', 'r', encoding='utf-8') as f:
    content = f.read()

checks = [
    'Phase 1 Summary: 30',
    '13,787',
    'relay shims',
    'Substantive (>=100 LOC) | 105',
    'Sprint 1',
    '6.3 Recommended',
    'path_traversal_scanner',
    'llm_clients',
    'trufflehog_integration',
    'Updated 2026-04-18',
    '1.3 Current LOC Status',
    '3.3 Per-Module Recovery Audit',
    '6.1 What Still Needs LOC',
    '6.2 Relay Shim Canonical',
]
all_ok = True
for c in checks:
    # Use 'in' check
    found = c in content
    if not found:
        # Try without exact spacing
        found2 = c.replace(' | ', '|') in content or c.replace('>=', '≥') in content
        found = found2
    status = 'OK  ' if found else 'MISS'
    if not found:
        all_ok = False
    print(status + ': ' + c)

print()
print('Total lines:', len(content.splitlines()))
print('ALL OK' if all_ok else 'SOME MISSING')
