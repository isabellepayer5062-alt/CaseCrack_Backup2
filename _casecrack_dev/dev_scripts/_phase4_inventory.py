"""Comprehensive inventory of the 27 recovered modules + sibling reference scan.

Output:
  1. Per-module: LOC, classes, functions, public-method count, TODO count
  2. Sibling reference for each module (same package, similar name pattern,
     or larger LOC analog) for production-target comparison
  3. Capability matrix per module (presence of: async, retry, logging,
     metrics, validation, error handling, persistence, batching, streaming,
     thread-safety, event emit, tests)
"""
from __future__ import annotations
import ast
import re
from pathlib import Path
from collections import defaultdict

ROOT = Path('CaseCrack/tools/burp_enterprise')

RECOVERED = {
 'network': ['dns_resolver', 'http_fingerprint', 'proxy_chain', 'ssl_analyzer', 'traffic_analyzer'],
 'integrations': ['ci_cd_pipeline', 'defect_dojo', 'jira_client', 'slack_notifier', 'sonarqube', 'webhook_dispatcher'],
 'caap': ['caap_coordinator', 'chat_interface', 'compliance_checker', 'discovery_agent', 'exploitation_agent', 'hypothesis_engine', 'knowledge_graph', 'recon_agent', 'session_orchestrator'],
 'testing_tools': ['api_fuzzer', 'benchmark_runner', 'compliance_validator', 'integration_harness', 'load_tester', 'mock_server', 'regression_tracker'],
}

# Capability hints (regex patterns)
CAPS = {
    'async':       r'\basync\s+def|\bawait\s+|asyncio\b',
    'retry':       r'@\w*retry|tenacity|backoff',
    'metrics':     r'_rs_metrics|MetricsCollector|prometheus|increment\(',
    'validation':  r'jsonschema|pydantic|validate_|@validator',
    'persistence': r'sqlite3|sqlalchemy|json\.dump|pickle\.|\.save\(',
    'batching':    r'batch_|chunks|partition',
    'streaming':   r'yield |Iterator|Generator|stream',
    'threadsafe':  r'Lock\(|RLock\(|threading\.|asyncio\.Lock',
    'eventbus':    r'_emit\(|get_event_bus|BusEventType',
    'rate_limit':  r'RateLimiter|rate_limit|throttle',
    'caching':     r'lru_cache|@cache|TTL|self\._cache',
    'auth':        r'auth|token|credential|bearer',
    'pagination':  r'page=|cursor|next_page|limit=',
    'exceptions':  r'^class \w+(Error|Exception)',
    'config_obj':  r'@dataclass\s*\nclass \w*Config',
    'dry_run':     r'dry_run|dry-run|DRY_RUN',
    'logging':     r'logger\.|logging\.|self\._log',
    'lifecycle':   r'__TIER3_LIFECYCLE__|def health\(|def reset\(|def close\(',
    'instrument':  r'__TIER2_INSTRUMENTED__',
    'helpers_inj': r'__TIER2_HELPERS_INJECTED__',
    'todo':        r'TODO|FIXME|XXX|HACK',
}


def scan_module(p: Path) -> dict:
    src = p.read_text(encoding='utf-8')
    out = {
        'loc': len(src.splitlines()),
        'src': src,
    }
    # ast counts
    try:
        tree = ast.parse(src)
        out['classes'] = sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
        out['functions'] = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
        out['async_fns'] = sum(1 for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef))
        out['public_methods'] = 0
        out['private_methods'] = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if item.name.startswith('_'):
                            out['private_methods'] += 1
                        else:
                            out['public_methods'] += 1
        # Find main engine class (last non-dataclass)
        main = None
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                is_dc = any(
                    (isinstance(d, ast.Name) and d.id == 'dataclass') or
                    (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == 'dataclass')
                    for d in node.decorator_list
                )
                if not is_dc:
                    main = node
        if main:
            out['main_class'] = main.name
            out['main_methods'] = [
                item.name for item in main.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
        else:
            out['main_class'] = None
            out['main_methods'] = []
        # docstring presence
        out['has_module_docstring'] = bool(ast.get_docstring(tree))
        out['classes_with_docstring'] = sum(
            1 for n in ast.walk(tree)
            if isinstance(n, ast.ClassDef) and ast.get_docstring(n)
        )
    except SyntaxError as e:
        out['parse_error'] = str(e)
        out['classes'] = -1
        out['functions'] = -1

    # capability scan
    out['caps'] = {}
    for name, pat in CAPS.items():
        out['caps'][name] = bool(re.search(pat, src, re.M))
    # TODO count
    out['todo_count'] = len(re.findall(r'TODO|FIXME|XXX|HACK', src))
    # `pass` only-body methods
    out['pass_stubs'] = len(re.findall(r'^    def \w+\([^)]*\)[^:]*:\n(?:        """.*?"""\n)?        pass\b', src, re.M | re.DOTALL))

    return out


def find_siblings(sub: str, recovered_name: str, recovered_loc: int):
    """Find related siblings in the same subdir for size comparison."""
    out = []
    sub_dir = ROOT / sub
    for p in sub_dir.glob('*.py'):
        if p.stem in {'__init__', recovered_name}:
            continue
        try:
            loc = len(p.read_text(encoding='utf-8').splitlines())
            out.append((p.stem, loc))
        except Exception:
            pass
    out.sort(key=lambda x: -x[1])
    return out[:5]


def main():
    print('=' * 100)
    print('PHASE 4 PRODUCTION ALIGNMENT — DEEP MODULE INVENTORY')
    print('=' * 100)
    all_data = {}
    for sub, names in RECOVERED.items():
        for m in names:
            p = ROOT / sub / f'{m}.py'
            d = scan_module(p)
            d['siblings'] = find_siblings(sub, m, d['loc'])
            all_data[f'{sub}/{m}'] = d

    # Per-subsystem summary
    for sub in RECOVERED:
        print(f'\n[{sub.upper()}]')
        print(f'  {"module":<28} {"LOC":>5} {"Cls":>4} {"Fn":>4} {"Pub":>4} {"Priv":>4} {"Async":>5} {"Stubs":>5} {"TODO":>4}  Sibling-Top1')
        print('  ' + '-' * 110)
        for m in RECOVERED[sub]:
            k = f'{sub}/{m}'
            d = all_data[k]
            sib = d['siblings'][0] if d['siblings'] else ('-', 0)
            ratio = f'{d["loc"]}/{sib[1]}={int(100*d["loc"]/sib[1]) if sib[1] else 0}%' if sib[1] else '-'
            print(f'  {m:<28} {d["loc"]:>5} {d["classes"]:>4} {d["functions"]:>4} '
                  f'{d.get("public_methods",0):>4} {d.get("private_methods",0):>4} '
                  f'{d.get("async_fns",0):>5} {d["pass_stubs"]:>5} {d["todo_count"]:>4}  '
                  f'{sib[0]}({ratio})')

    # Capability matrix
    print(f'\n\n[CAPABILITY MATRIX]  (Y=present, .=absent)')
    cap_keys = list(CAPS.keys())
    print('  ' + ('module'.ljust(40)) + '  ' + '  '.join(c[:5] for c in cap_keys))
    for k, d in all_data.items():
        row = '  '.join('Y    ' if d['caps'][c] else '.    ' for c in cap_keys)
        print(f'  {k:<40}  {row}')

    # Aggregated gap counts
    print(f'\n\n[CROSS-CUTTING GAPS]')
    missing = defaultdict(list)
    for k, d in all_data.items():
        for cap, val in d['caps'].items():
            if not val:
                missing[cap].append(k)
    for cap in cap_keys:
        miss = missing[cap]
        print(f'  {cap:<14} missing in {len(miss):>2}/27: {", ".join(m.split("/")[-1] for m in miss[:6])}{"..." if len(miss)>6 else ""}')

    # Sibling reference table for size targets
    print(f'\n\n[SIBLING SIZE TARGETS]')
    print(f'  {"recovered":<40} {"current":>7} {"sib1":>7} {"sib2":>7} {"sib3":>7}  gap%')
    for k, d in all_data.items():
        sibs = d['siblings'][:3]
        s1 = sibs[0][1] if sibs else 0
        s2 = sibs[1][1] if len(sibs) > 1 else 0
        s3 = sibs[2][1] if len(sibs) > 2 else 0
        gap = int(100 * d['loc'] / s1) if s1 else 0
        print(f'  {k:<40} {d["loc"]:>7} {s1:>7} {s2:>7} {s3:>7}  {gap}%')

    return all_data


if __name__ == '__main__':
    main()
