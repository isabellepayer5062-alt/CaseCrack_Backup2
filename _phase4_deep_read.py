"""Per-module deep gap analysis — extract dataclasses, public methods,
docstrings, and surface gaps vs production sibling references.
"""
from __future__ import annotations
import ast
import re
from pathlib import Path

ROOT = Path('CaseCrack/tools/burp_enterprise')

RECOVERED = {
 'network': ['dns_resolver', 'http_fingerprint', 'proxy_chain', 'ssl_analyzer', 'traffic_analyzer'],
 'integrations': ['ci_cd_pipeline', 'defect_dojo', 'jira_client', 'slack_notifier', 'sonarqube', 'webhook_dispatcher'],
 'caap': ['caap_coordinator', 'chat_interface', 'compliance_checker', 'discovery_agent', 'exploitation_agent', 'hypothesis_engine', 'knowledge_graph', 'recon_agent', 'session_orchestrator'],
 'testing_tools': ['api_fuzzer', 'benchmark_runner', 'compliance_validator', 'integration_harness', 'load_tester', 'mock_server', 'regression_tracker'],
}


def analyze(p: Path) -> dict:
    src = p.read_text(encoding='utf-8')
    tree = ast.parse(src)
    out = {
        'module_doc': ast.get_docstring(tree) or '',
        'classes': [],
        'top_level_fns': [],
    }
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            cls_info = {
                'name': node.name,
                'is_dc': any(
                    (isinstance(d, ast.Name) and d.id == 'dataclass') or
                    (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == 'dataclass')
                    for d in node.decorator_list
                ),
                'doc': ast.get_docstring(node) or '',
                'bases': [ast.unparse(b) for b in node.bases],
                'fields': [],
                'methods': [],
            }
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    cls_info['fields'].append(item.target.id)
                elif isinstance(item, ast.Assign):
                    for tgt in item.targets:
                        if isinstance(tgt, ast.Name):
                            cls_info['fields'].append(tgt.id)
                elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name.startswith('__'):
                        continue
                    args = [a.arg for a in item.args.args if a.arg != 'self']
                    cls_info['methods'].append({
                        'name': item.name,
                        'args': args,
                        'is_async': isinstance(item, ast.AsyncFunctionDef),
                        'returns': ast.unparse(item.returns) if item.returns else None,
                        'doc': (ast.get_docstring(item) or '').split('\n')[0][:90],
                    })
            out['classes'].append(cls_info)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out['top_level_fns'].append(node.name)
    return out


def main():
    print('=' * 100)
    print('DEEP MODULE READING — public API surface per recovered module')
    print('=' * 100)
    for sub, names in RECOVERED.items():
        for m in names:
            p = ROOT / sub / f'{m}.py'
            d = analyze(p)
            print()
            print(f'### {sub}/{m}.py')
            print(f'    "{d["module_doc"].split(chr(10))[0][:90]}"')
            for c in d['classes']:
                kind = 'DC' if c['is_dc'] else 'CL'
                fields = ','.join(c['fields'][:8])
                more = '...' if len(c['fields']) > 8 else ''
                print(f'    [{kind}] {c["name"]}({fields}{more})')
                # only print methods for non-dataclass main class
                if not c['is_dc']:
                    public = [meth for meth in c['methods']
                              if not meth['name'].startswith('_')
                              and meth['name'] not in {'health','reset','close','metrics_snapshot'}]
                    for meth in public:
                        a = '(' + ','.join(meth['args']) + ')'
                        retn = f' -> {meth["returns"]}' if meth['returns'] else ''
                        async_pref = 'async ' if meth['is_async'] else ''
                        print(f'        {async_pref}{meth["name"]}{a}{retn}')
            if d['top_level_fns']:
                print(f'    [FN] {", ".join(d["top_level_fns"])}')


if __name__ == '__main__':
    main()
