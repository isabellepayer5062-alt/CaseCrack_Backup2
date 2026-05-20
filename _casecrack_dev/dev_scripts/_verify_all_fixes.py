import importlib, traceback, sys

# 1. Package-level import tests (were previously broken)
pkgs = [
    'tools.burp_enterprise.graph',
    'tools.burp_enterprise.loop',
    'tools.burp_enterprise.swarm',
    'tools.burp_enterprise.cli.dynamic_chain',
    'tools.burp_enterprise.recon.tool_wrappers',
    'tools.burp_enterprise.recon.tool_wrappers._registry',
    'tools.burp_enterprise.mcp.tool_wrappers._base',
]
ok = fail = 0
for m in pkgs:
    try:
        importlib.import_module(m)
        print(f'OK    {m}')
        ok += 1
    except Exception as e:
        print(f'FAIL  {m}: {type(e).__name__}: {e}')
        fail += 1

print()
print(f'Result: {ok}/{len(pkgs)} packages importable')

# 2. Re-run full tree audit to confirm no regression
import subprocess
r = subprocess.run([sys.executable, '_full_tree_audit_v2.py'], capture_output=True, text=True, timeout=600)
out = r.stdout
# Extract summary lines only
for line in out.splitlines():
    if 'Tested:' in line or 'Failed:' in line or 'UNGUARDED' in line[:20] or 'Guarded' in line or 'Most-referenced' in line:
        print(line)
