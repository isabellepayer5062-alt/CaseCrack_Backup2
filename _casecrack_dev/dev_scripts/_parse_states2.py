import json, os

WS = r'C:\Users\ya754\AppData\Roaming\Code\User\workspaceStorage\9e51499eea65fa44abab72645f162d00\chatEditingSessions'

SESSIONS = [
    'fe741aee-1c2f-4369-88dc-3b1ec98b7734',
    '251326ca-7dc0-4d81-9d57-58d76f6c32ba',
    '4ee01150-c401-4f48-8b23-ce30c85da2d0',
    '2d6e604f-d895-4e48-b184-5d506e917117',
    'c71db976-71f6-40b1-af22-022cc2ec09aa',
    'fae709ba-0fb2-4b2c-8623-87175702540e',
    '7f5add25-6da8-45d9-ba68-7b93d4d21849',
    '52a03906-3b78-4fef-a94f-2fb43f82e8d8',
]

for sid in SESSIONS:
    sjson = os.path.join(WS, sid, 'state.json')
    if not os.path.exists(sjson): continue
    with open(sjson, 'r', encoding='utf-8') as f:
        state = json.load(f)
    print(f"\n===== {sid} =====")
    rs = state.get('recentSnapshot')
    print(f"  recentSnapshot type: {type(rs).__name__}")
    if isinstance(rs, dict):
        print(f"  recentSnapshot keys: {list(rs.keys())[:20]}")
        # Look for resource->hash mapping
        for k,v in list(rs.items())[:30]:
            if 'recon-dashboard' in str(k) or (isinstance(v, dict) and 'recon-dashboard' in str(v)):
                print(f"    {k} -> {str(v)[:300]}")
    elif isinstance(rs, list):
        print(f"  recentSnapshot list len: {len(rs)}")
        for item in rs[:5]:
            print(f"    {str(item)[:300]}")
    tl = state.get('timeline', {})
    fb = tl.get('fileBaselines')
    print(f"  fileBaselines type: {type(fb).__name__}")
    if isinstance(fb, dict):
        for k, v in fb.items():
            if 'recon-dashboard' in k:
                print(f"    {k} -> {str(v)[:200]}")
    elif isinstance(fb, list):
        for item in fb:
            print(f"    {str(item)[:300]}")
    ops = tl.get('operations', [])
    print(f"  operations: {len(ops)}")
    if ops:
        print(f"    op sample keys: {list(ops[0].keys()) if isinstance(ops[0], dict) else 'list'}")
        # find latest op touching recon-dashboard.js
        last_js = None; last_css = None
        for op in ops:
            if not isinstance(op, dict): continue
            res = op.get('resource') or op.get('uri') or op.get('resourceUri') or ''
            if 'recon-dashboard.js' in res:
                last_js = op
            elif 'recon-dashboard.css' in res:
                last_css = op
        if last_js:
            print(f"    LAST JS op keys: {list(last_js.keys())}")
            for k,v in last_js.items():
                if k != 'patch' and k != 'edits':
                    print(f"      {k}: {str(v)[:200]}")
        if last_css:
            print(f"    LAST CSS op keys: {list(last_css.keys())}")
