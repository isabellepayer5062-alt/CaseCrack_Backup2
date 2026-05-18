import json, os

WS = r'C:\Users\ya754\AppData\Roaming\Code\User\workspaceStorage\9e51499eea65fa44abab72645f162d00\chatEditingSessions'

SESSIONS = [
    'fe741aee-1c2f-4369-88dc-3b1ec98b7734',  # 4/30 23:25
    '251326ca-7dc0-4d81-9d57-58d76f6c32ba',  # 4/30 21:57
    '4ee01150-c401-4f48-8b23-ce30c85da2d0',  # 4/30 16:38
    '2d6e604f-d895-4e48-b184-5d506e917117',  # 4/29 23:26
    'c71db976-71f6-40b1-af22-022cc2ec09aa',  # 4/29 17:45
    'fae709ba-0fb2-4b2c-8623-87175702540e',  # 4/29 16:29
    '7f5add25-6da8-45d9-ba68-7b93d4d21849',  # 4/29 14:00
]

def deep_find_uri_hash(obj, results, path=''):
    """Recursively find dict items that contain a URI/path with a hash field."""
    if isinstance(obj, dict):
        # Pattern 1: has 'resource' or 'uri' as a string and 'snapshot' or 'currentContentHash' or 'contentId'
        uri_val = None
        for k in ('resource','uri','resourceUri','externalUri'):
            v = obj.get(k)
            if isinstance(v, str) and 'recon-dashboard' in v:
                uri_val = v
                break
            if isinstance(v, dict):
                ext = v.get('external') or v.get('fsPath')
                if isinstance(ext, str) and 'recon-dashboard' in ext:
                    uri_val = ext
                    break
        if uri_val:
            for hk in ('currentContentHash','contentHash','hash','snapshot','contentId','snapshotHash'):
                if hk in obj and isinstance(obj[hk], str):
                    results.append((path, uri_val, hk, obj[hk]))
        for k,v in obj.items():
            deep_find_uri_hash(v, results, path + '/' + str(k))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            deep_find_uri_hash(item, results, path + f'[{i}]')

for sid in SESSIONS:
    sjson = os.path.join(WS, sid, 'state.json')
    if not os.path.exists(sjson): continue
    with open(sjson, 'r', encoding='utf-8') as f:
        state = json.load(f)
    print(f"\n===== {sid} =====")
    # Look at recentSnapshot.entries
    rs = state.get('recentSnapshot', {})
    entries = rs.get('entries', [])
    print(f"  recentSnapshot.entries len: {len(entries)}")
    # Each entry usually [resourceKey, snapshotInfo]
    for entry in entries[:50]:
        if isinstance(entry, list) and len(entry) >= 2:
            key, val = entry[0], entry[1]
            if isinstance(key, str) and 'recon-dashboard' in key:
                # Print val keys
                if isinstance(val, dict):
                    relevant = {k: (str(v)[:80] if not isinstance(v, (dict, list)) else type(v).__name__) for k,v in val.items()}
                    print(f"    {key[:80]}... -> {relevant}")
    # Also look at fileBaselines (list) for last hash per file for recon-dashboard
    tl = state.get('timeline', {})
    fb = tl.get('fileBaselines', [])
    print(f"  fileBaselines (list len): {len(fb)}")
    last_per_file = {}
    for entry in fb:
        if isinstance(entry, list) and len(entry) >= 2:
            key, val = entry[0], entry[1]
            if isinstance(key, str) and 'recon-dashboard' in key and ('::' in key):
                fpath = key.split('::')[0]
                # Find hash inside val
                if isinstance(val, dict):
                    for hk in ('currentContentHash','contentHash','snapshot','snapshotHash','hash'):
                        if hk in val and isinstance(val[hk], str):
                            last_per_file[fpath] = (val[hk], hk)
                            break
    print(f"  Last fileBaseline per recon-dashboard file:")
    for k,v in last_per_file.items():
        print(f"    {k}\n      -> hash={v[0]}, key={v[1]}")
    # Also the operations - find last op per recon-dashboard file
    ops = tl.get('operations', [])
    last_op = {}
    for op in ops:
        if not isinstance(op, dict): continue
        uri = op.get('uri')
        if isinstance(uri, dict):
            uri = uri.get('external') or uri.get('fsPath') or ''
        if isinstance(uri, str) and 'recon-dashboard' in uri:
            last_op[uri] = op
    print(f"  Last op per recon-dashboard file:")
    for k,v in last_op.items():
        keys = list(v.keys())
        print(f"    {k}")
        # Find hash-like keys
        for hk in ('currentContentHash','contentHash','snapshot','snapshotHash','hash','contentId'):
            if hk in v: print(f"      {hk}={v[hk]}")
        print(f"      keys: {keys}")
        # Print epoch
        if 'epoch' in v: print(f"      epoch={v['epoch']}")
