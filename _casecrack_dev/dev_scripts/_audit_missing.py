import pathlib, sys
sys.path.insert(0, '.')
root = pathlib.Path('tools/burp_enterprise')

problem_packages = [
    ('graph', 'state'),
    ('inference', 'engine'),
    ('loop', 'world_state'),
    ('memory', 'embedder'),
    ('reasoning', 'prompt_chains'),
    ('swarm', 'message_bus'),
    ('tool_registry', 'registry'),
    ('agents', 'llm_types'),
]

print("Missing sub-modules needed by __init__.py files:")
for pkg, sub in problem_packages:
    pkg_dir = root / pkg
    sub_path = pkg_dir / (sub + '.py')
    init_path = pkg_dir / '__init__.py'
    init_exists = init_path.exists()
    sub_exists = sub_path.exists()
    status = "EXISTS" if sub_exists else "MISSING"
    print(f"  {pkg}/{sub}.py: {status}  (init={init_exists})")
    if init_exists and not sub_exists:
        lines = init_path.read_text(encoding='utf-8', errors='ignore').splitlines()
        for ln in lines[:8]:
            if ln.strip():
                print(f"    > {ln[:100]}")

print()
# Also check discovery_pkg/_js_patterns
djsp = root / 'discovery_pkg' / '_js_patterns.py'
print("discovery_pkg/_js_patterns.py:", "EXISTS" if djsp.exists() else "MISSING")
dkinit = root / 'discovery_pkg' / '__init__.py'
if dkinit.exists():
    src = dkinit.read_text(encoding='utf-8', errors='ignore')
    print("discovery_pkg/__init__.py exports _js_patterns:", '_js_patterns' in src)

# Check __main__.py recon_dashboard issue
rdm = root / 'recon_dashboard' / '__main__.py'
if rdm.exists():
    lines = rdm.read_text(encoding='utf-8', errors='ignore').splitlines()
    for i, l in enumerate(lines):
        if 'secrets' in l:
            print(f"recon_dashboard/__main__.py line {i+1}: {l.strip()}")

print()
# Check entire agents/ for what's actually native vs shim
agents_dir = root / 'agents'
native = []
shims = []
for p in sorted(agents_dir.glob('*.py')):
    if p.name.startswith('_'):
        continue
    src = p.read_text(encoding='utf-8', errors='ignore')
    code_lines = len([l for l in src.splitlines() if l.strip() and not l.strip().startswith('#')])
    if code_lines <= 12 and 'Relay shim' in src:
        shims.append(p.name)
    else:
        native.append((code_lines, p.name))

print(f"agents/ native modules: {len(native)}")
for loc, name in sorted(native, key=lambda x: x[0]):
    print(f"  {loc:6d} LOC  {name}")
print(f"\nagents/ relay shims: {len(shims)}")
for n in shims:
    print(f"  {n}")
