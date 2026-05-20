"""Comprehensive pipeline passthrough gap analysis."""
import ast, pathlib, re, sys

root = pathlib.Path('CaseCrack/tools/burp_enterprise')

# ─────────────────────────────────────────────
# GAP 1: Does pipeline/scanner_hooks.py exist?
# ─────────────────────────────────────────────
pipeline_hooks = root / 'pipeline' / 'scanner_hooks.py'
scanners_hooks = root / 'scanners' / 'scanner_hooks.py'
print('=== GAP 1: scanner_hooks import path ===')
print(f'  pipeline/scanner_hooks.py exists: {pipeline_hooks.exists()}')
print(f'  scanners/scanner_hooks.py exists: {scanners_hooks.exists()}')
if pipeline_hooks.exists():
    src = pipeline_hooks.read_text('utf-8', 'replace')
    if '_SCANNER_REGISTRY' in src:
        print('  pipeline/scanner_hooks.py has its own _SCANNER_REGISTRY')
    elif 'import' in src and 'scanners' in src:
        print('  pipeline/scanner_hooks.py forwards to scanners/')
    else:
        # Show first 400 chars
        print('  pipeline/scanner_hooks.py content:', src[:400])

# ─────────────────────────────────────────────
# GAP 2: Which scanners in _SCANNER_REGISTRY are NOT in _PHASE_MAP
# ─────────────────────────────────────────────
print()
print('=== GAP 2: scanners missing from _PHASE_MAP ===')
fso_src = (root / 'pipeline' / 'full_scan_orchestrator.py').read_text('utf-8', 'replace')
# Extract all scanner_names from _PHASE_MAP
phase_map_matches = re.findall(r'"([a-z_]+)":\s*ScanPhase\.', fso_src)
phase_map_names = set(phase_map_matches)

hooks_src = scanners_hooks.read_text('utf-8', 'replace')
# Matches ("module", "Cls", "method", "scanner_name")
reg_matches = re.findall(r'\("([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\)', hooks_src)
reg_by_name = {m[3]: m for m in reg_matches}
reg_names = set(reg_by_name.keys())

not_in_phase_map = sorted(reg_names - phase_map_names)
print(f'  _SCANNER_REGISTRY: {len(reg_names)} scanners, _PHASE_MAP: {len(phase_map_names)} entries')
print(f'  Scanners NOT in phase map (default ACTIVE): {len(not_in_phase_map)}')
for n in not_in_phase_map:
    print(f'    - {n}')

# ─────────────────────────────────────────────
# GAP 3: Phase map entries with no registry entry
# ─────────────────────────────────────────────
print()
print('=== GAP 3: phase map entries with NO registry entry ===')
dead = sorted(phase_map_names - reg_names)
print(f'  Dead entries: {len(dead)}')
for n in dead:
    print(f'    - {n}')

# ─────────────────────────────────────────────
# GAP 4: Correlation engine - are chains written back to findings?
# ─────────────────────────────────────────────
print()
print('=== GAP 4: Correlation chains written back to result.module_results? ===')
# Check _run_correlation_engine in orchestrator
corr_method = re.search(
    r'def _run_correlation_engine.*?(?=\n    def |\Z)',
    fso_src, re.DOTALL
)
if corr_method:
    body = corr_method.group(0)
    has_writeback = 'module_results' in body and 'append' in body
    has_correlation_report_only = 'correlation_report' in body
    chains_merged = 'all_findings' in body and ('extend' in body or 'findings' in body)
    print(f'  Chains merged back to module_results: {has_writeback}')
    print(f'  Chains stored in correlation_report only: {has_correlation_report_only}')
    print(f'  Chain findings passed to enrichment: UNKNOWN (need to check reporting layer)')
else:
    print('  ERROR: _run_correlation_engine not found')

# ─────────────────────────────────────────────
# GAP 5: ReconPipeline findings handoff
# ─────────────────────────────────────────────
print()
print('=== GAP 5: ReconPipeline findings handoff to enrichment ===')
rp_path = root / 'recon' / 'recon_pipeline.py'
if rp_path.exists():
    rp_src = rp_path.read_text('utf-8', 'replace')
    has_enrich = 'enrich_finding' in rp_src or 'enrich_findings' in rp_src
    has_correlation = 'correlate_finding' in rp_src or 'correlation_engine' in rp_src
    has_findings_store = 'findings_store' in rp_src or 'FindingsStore' in rp_src
    has_emit_finding = 'emit_finding' in rp_src or '_emit' in rp_src
    has_pipeline = 'finding_pipeline' in rp_src or 'finding_stream' in rp_src
    print(f'  enrich_finding called: {has_enrich}')
    print(f'  correlation_engine called: {has_correlation}')
    print(f'  findings_store used: {has_findings_store}')
    print(f'  emit_finding / _emit called: {has_emit_finding}')
    print(f'  finding_pipeline / finding_stream used: {has_pipeline}')

    # How does the pipeline return findings?
    returns = re.findall(r'return\s+([^\n]+)', rp_src)
    print(f'  return statements ({len(returns)} total), samples:')
    for r in returns[:8]:
        print(f'    return {r.strip()}')

# ─────────────────────────────────────────────
# GAP 6: _extract_findings — what return shapes might be missed
# ─────────────────────────────────────────────
print()
print('=== GAP 6: _extract_findings coverage of scanner return shapes ===')
extract_method = re.search(
    r'def _extract_findings.*?(?=\n    def |\Z)',
    fso_src, re.DOTALL
)
if extract_method:
    body = extract_method.group(0)
    print('  Keys checked:', re.findall(r'"([a-z_]+)"', body))
    has_dataclass = 'dataclass' in body or '__dataclass_fields__' in body
    has_namedtuple = 'namedtuple' in body or '_fields' in body
    print(f'  Handles dataclass output: {has_dataclass}')
    print(f'  Handles namedtuple output: {has_namedtuple}')

# ─────────────────────────────────────────────
# GAP 7: cross_cutting.py - process_finding vs enrich_finding
# ─────────────────────────────────────────────
print()
print('=== GAP 7: CrossCuttingMiddleware severity write-back ===')
cc_path = root / 'pipeline' / 'cross_cutting.py'
if cc_path.exists():
    cc_src = cc_path.read_text('utf-8', 'replace')
    has_sev_writeback = 'severity' in cc_src and ('assessment' in cc_src)
    has_escalate_only = 'new_rank < old_rank' in cc_src
    has_bidirectional = ('new_rank > old_rank' in cc_src and '_unverified' in cc_src)
    print(f'  Has severity write-back: {has_sev_writeback}')
    print(f'  Escalate-only (old bug): {has_escalate_only}')
    print(f'  Bidirectional (fixed): {has_bidirectional}')
else:
    print('  pipeline/cross_cutting.py not found')
    # Try output/cross_cutting.py
    cc_path2 = root / 'output' / 'cross_cutting.py'
    if cc_path2.exists():
        cc_src2 = cc_path2.read_text('utf-8', 'replace')
        has_sev = 'severity' in cc_src2
        print(f'  output/cross_cutting.py: exists, has severity handling: {has_sev}')

# ─────────────────────────────────────────────
# GAP 8: finding_dedup - does it drop findings?
# ─────────────────────────────────────────────
print()
print('=== GAP 8: finding_dedup policy ===')
dedup_path = root / 'output' / 'finding_dedup.py'
if dedup_path.exists():
    dedup_src = dedup_path.read_text('utf-8', 'replace')
    severity_demote = 'severity' in dedup_src and 'merge' in dedup_src.lower()
    hash_strategy = re.findall(r'hashlib\.\w+|sha\d+|md5', dedup_src)
    keeps_highest = 'max(' in dedup_src or 'highest' in dedup_src.lower()
    print(f'  Hash algorithms: {set(hash_strategy)}')
    print(f'  Severity: keeps highest on merge: {keeps_highest}')
    # Count drop points
    drops = len(re.findall(r'continue\b|return\s+None\b|return\s+\[\]', dedup_src))
    print(f'  Potential drop points (continue/return None/[]): {drops}')

print()
print('=== DONE ===')
