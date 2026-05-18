import ast, re
from pathlib import Path
from collections import defaultdict

WS = Path(r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')

# Load referenced-missing manifest (70 files)
lines = Path('_recovery_referenced_missing.tsv').read_text(encoding='utf-8').splitlines()[1:]
targets = []
for ln in lines:
    parts = ln.split('\t')
    if len(parts) < 5: continue
    hits = int(parts[0]); sz = int(parts[1]); mod = parts[2]; rel = parts[3]; snap = parts[4]
    targets.append({'hits': hits, 'size': sz, 'module': mod, 'rel': rel, 'snap': snap})

# For each target: it is MISSING on disk. Classify whether callers:
#   (a) hard-fail on import (no guard) -> restoration is safer / needed
#   (b) guarded with try/except ImportError -> restoration optional
#   (c) references are inside docstrings/comments only -> dead reference
# Also snapshot properties: size, basic sanity (valid Python AST, has classes/functions)

# Pre-load all .py in CaseCrack
files = list(WS.glob('tools/**/*.py')) + list(WS.glob('tests/**/*.py'))
contents = {}
for p in files:
    try:
        contents[p] = p.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        pass

def classify_callers(mod):
    """Return (hard_imports, guarded_imports, comment_only) lists of caller paths."""
    hard = []; guarded = []; comment = []
    pat_from = re.compile(r'^(\s*)from\s+' + re.escape(mod) + r'\b', re.MULTILINE)
    pat_import = re.compile(r'^(\s*)import\s+' + re.escape(mod) + r'\b', re.MULTILINE)
    for p, txt in contents.items():
        found_hard = False; found_guard = False; found_comment = False
        for pat in (pat_from, pat_import):
            for m in pat.finditer(txt):
                # determine if inside a try block by scanning backwards for 'try:' before this line at same-or-outer indent
                idx = m.start()
                line_start = txt.rfind('\n', 0, idx) + 1
                # take up to 500 chars before, look for try: on a line
                back = txt[max(0, idx-600):idx]
                # simple heuristic: inside try block if the last non-blank statement-starting line at column 0 of the block is try:
                if re.search(r'\n\s*try\s*:\s*\n', back[-400:]) and 'except' not in back[back.rfind('try'):]:
                    found_guard = True
                else:
                    found_hard = True
        # references only in strings/comments?
        if not found_hard and not found_guard:
            # search for the name in a string/comment
            if mod in txt:
                found_comment = True
        if found_hard: hard.append(str(p))
        elif found_guard: guarded.append(str(p))
        elif found_comment: comment.append(str(p))
    return hard, guarded, comment

def snapshot_quality(snap_path):
    """Analyze the recovered snapshot: AST valid? LOC, classes, functions, imports."""
    try:
        src = Path(snap_path).read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        return {'ok': False, 'error': f'read: {e}'}
    loc = src.count('\n') + 1
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return {'ok': False, 'error': f'syntax: {e.msg} line {e.lineno}', 'loc': loc}
    classes = sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
    funcs = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    # old-style imports (CaseCrack.*) present?
    old_import = False
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module:
            if n.module.startswith('CaseCrack') or n.module.startswith('src.'):
                old_import = True
                break
    return {'ok': True, 'loc': loc, 'classes': classes, 'funcs': funcs, 'old_imports': old_import}

results = []
for t in targets:
    hard, guarded, comment = classify_callers(t['module'])
    qual = snapshot_quality(t['snap'])
    t['hard_callers'] = len(hard)
    t['guarded_callers'] = len(guarded)
    t['comment_refs'] = len(comment)
    t['hard_sample'] = hard[:2]
    t['snap_qual'] = qual
    results.append(t)

# Bucket into A/B/C
# A (SAFE restore): recovered snapshot is AST-valid + has hard callers (hard-fails currently) + no old imports OR few imports
# B (NEEDS MERGE): snapshot has old_imports or existing disk scaffolding or multiple guarded callers
# C (DEFER): no hard callers (references only in comments/guarded) OR very large (>60KB, wide blast radius)
# D (BROKEN snapshot): AST invalid — cannot restore safely

bucket = {'A': [], 'B': [], 'C': [], 'D': []}
for t in results:
    q = t['snap_qual']
    if not q.get('ok'):
        bucket['D'].append(t); continue
    if t['hard_callers'] == 0:
        bucket['C'].append(t); continue
    if q.get('old_imports') or t['size'] > 80000:
        bucket['B'].append(t); continue
    bucket['A'].append(t)

print(f'=== Classification of 70 referenced-missing modules ===')
for b in 'ABCD':
    items = bucket[b]
    print(f'\nBucket {b}: {len(items)} files')
    for t in sorted(items, key=lambda x: -x['hard_callers']):
        mod = t['module']
        if len(mod) > 65: mod = '...' + mod[-62:]
        q = t['snap_qual']
        if q.get('ok'):
            tag = f"loc={q['loc']:>4} cls={q['classes']:>2} fn={q['funcs']:>3}"
            if q.get('old_imports'): tag += ' OLD-IMPORTS'
        else:
            tag = f"BROKEN: {q.get('error','?')}"
        print(f"  hard={t['hard_callers']:>2} guard={t['guarded_callers']:>2} {t['size']:>7}B  {tag:<42}  {mod}")

# Save detailed JSON
import json
out = {'A_safe_restore': bucket['A'], 'B_needs_merge': bucket['B'], 'C_defer': bucket['C'], 'D_broken_snap': bucket['D']}
Path('_recovery_classification.json').write_text(json.dumps(out, indent=2, default=str), encoding='utf-8')
print(f'\nWrote _recovery_classification.json')