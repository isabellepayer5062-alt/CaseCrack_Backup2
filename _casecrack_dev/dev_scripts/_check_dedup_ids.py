import json

# Check if original Phase 1-29 findings have id fields
with open('CaseCrack/reports/recon-all-findings.json', encoding='utf-8') as f:
    all_f = json.load(f)

has_id = sum(1 for f in all_f if f.get('id'))
print(f'Findings with id: {has_id}/{len(all_f)}')
# Show samples
for f in all_f[:5]:
    fid = f.get('id')
    phase = f.get('phase')
    title = f.get('title','')[:40]
    print(f'  id={fid!r} phase={phase!r} title={title!r}')

# Check composite-rules findings  
with open('CaseCrack/reports/recon-composite-rules.json', encoding='utf-8') as f:
    comp = json.load(f)
comp_findings = comp.get('findings', [])
has_comp_id = sum(1 for f in comp_findings if f.get('id'))
print(f'Composite-rules findings with id: {has_comp_id}/{len(comp_findings)}')

# Compare: do comp-rule finding IDs match original finding IDs?
all_ids = set(f.get('id') for f in all_f if f.get('id'))
comp_ids = set(f.get('id') for f in comp_findings if f.get('id'))
overlap = all_ids & comp_ids
print(f'ID overlap between all-findings and composite-rules: {len(overlap)}/{len(comp_ids)}')
