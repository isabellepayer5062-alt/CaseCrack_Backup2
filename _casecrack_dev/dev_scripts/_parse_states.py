import json, os, sys

WS = r'C:\Users\ya754\AppData\Roaming\Code\User\workspaceStorage\9e51499eea65fa44abab72645f162d00\chatEditingSessions'

# Sessions of interest (April 28 - May 1, all that had hits)
SESSIONS = [
    'fe741aee-1c2f-4369-88dc-3b1ec98b7734',  # 4/30 23:25 (LATEST)
    '251326ca-7dc0-4d81-9d57-58d76f6c32ba',  # 4/30 21:57
    '4ee01150-c401-4f48-8b23-ce30c85da2d0',  # 4/30 16:38
    '2d6e604f-d895-4e48-b184-5d506e917117',  # 4/29 23:26
    'c71db976-71f6-40b1-af22-022cc2ec09aa',  # 4/29 17:45
    'fae709ba-0fb2-4b2c-8623-87175702540e',  # 4/29 16:29
    '7f5add25-6da8-45d9-ba68-7b93d4d21849',  # 4/29 14:00
    '52a03906-3b78-4fef-a94f-2fb43f82e8d8',  # 4/28 20:32
]

def find_latest_for_resource(state, resource_substr):
    """Walk timeline checkpoints in order; for each find currentContentHash for matching resource."""
    initial = {}
    for uri, h in state.get('initialFileContents', []):
        initial[uri] = h
    last_hash = {}
    for uri, h in initial.items():
        if resource_substr in uri:
            last_hash[uri] = h
    timeline = state.get('timeline', {})
    checkpoints = timeline.get('checkpoints', [])
    # Look for resource changes per checkpoint
    for cp in checkpoints:
        # Common: 'resourceChanges' or 'changes' or 'snapshots'
        for key in ('resourceChanges', 'snapshots', 'changes', 'fileChanges'):
            arr = cp.get(key)
            if not arr: continue
            for item in arr:
                if isinstance(item, dict):
                    uri = item.get('resource') or item.get('uri') or item.get('resourceUri')
                    h = item.get('currentContentHash') or item.get('contentHash') or item.get('hash') or item.get('snapshot')
                    if uri and h and resource_substr in uri:
                        last_hash[uri] = h
    return last_hash

for sid in SESSIONS:
    sjson = os.path.join(WS, sid, 'state.json')
    if not os.path.exists(sjson):
        continue
    try:
        with open(sjson, 'r', encoding='utf-8') as f:
            state = json.load(f)
    except Exception as e:
        print(f"{sid}: ERROR {e}")
        continue
    js_hashes = find_latest_for_resource(state, 'recon-dashboard.js')
    css_hashes = find_latest_for_resource(state, 'recon-dashboard.css')
    print(f"\n===== {sid} =====")
    print(f"  JS  initial+latest hashes: {js_hashes}")
    print(f"  CSS initial+latest hashes: {css_hashes}")
    # Also dump top-level keys
    print(f"  top keys: {list(state.keys())}")
    tl = state.get('timeline', {})
    print(f"  timeline keys: {list(tl.keys())}")
    cps = tl.get('checkpoints', [])
    if cps:
        print(f"  checkpoints: {len(cps)}; sample keys of last: {list(cps[-1].keys())}")
