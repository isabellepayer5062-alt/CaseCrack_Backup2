"""Tier 4A validation — imports all 27 modules, exercises new primitives."""
from __future__ import annotations
import importlib
import sys
import asyncio
import os
import tempfile
import traceback

sys.path.insert(0, os.path.abspath('CaseCrack'))

NETWORK = ['dns_resolver', 'http_fingerprint', 'proxy_chain', 'ssl_analyzer', 'traffic_analyzer']
INTEGRATIONS = ['ci_cd_pipeline', 'defect_dojo', 'jira_client', 'slack_notifier', 'sonarqube', 'webhook_dispatcher']
MODS = [
 ('network', NETWORK),
 ('integrations', INTEGRATIONS),
 ('caap', ['caap_coordinator', 'chat_interface', 'compliance_checker', 'discovery_agent', 'exploitation_agent', 'hypothesis_engine', 'knowledge_graph', 'recon_agent', 'session_orchestrator']),
 ('testing_tools', ['api_fuzzer', 'benchmark_runner', 'compliance_validator', 'integration_harness', 'load_tester', 'mock_server', 'regression_tracker']),
]

ok = 0
fail = []

# Phase 1: import all modules
for sub, names in MODS:
    for n in names:
        try:
            importlib.import_module(f'tools.burp_enterprise.{sub}.{n}')
            ok += 1
        except Exception as e:
            fail.append((f'{sub}/{n}', str(e)))
print(f'IMPORTS: {ok}/27 ok, {len(fail)} fail')
for k, e in fail:
    print(f'  FAIL {k}: {e}')

# Phase 2: verify each module exposes its 4 typed errors
print('\nERRORS (4A.1):')
err_ok = 0
for sub, names in MODS:
    for n in names:
        m = sys.modules[f'tools.burp_enterprise.{sub}.{n}']
        cap = ''.join(p.capitalize() for p in n.split('_'))
        missing = [k for k in [f'{cap}Error', f'{cap}ConfigError',
                               f'{cap}OperationError', f'{cap}TimeoutError']
                   if not hasattr(m, k)]
        if missing:
            print(f'  FAIL {sub}/{n}: missing {missing}')
        else:
            err_ok += 1
print(f'  {err_ok}/27 modules have 4 typed errors')

# Phase 3: instantiate main class + verify async mirrors + dry_run + lifecycle
print('\nMAIN CLASS instantiation + async + dry_run (4A.2, 4A.7):')
import inspect
main_classes = {
    'dns_resolver': 'DNSResolver', 'http_fingerprint': 'HTTPFingerprinter',
    'proxy_chain': 'ProxyChain', 'ssl_analyzer': 'SSLAnalyzer',
    'traffic_analyzer': 'TrafficAnalyzer',
    'ci_cd_pipeline': 'CICDPipeline', 'defect_dojo': 'DefectDojoClient',
    'jira_client': 'JiraClient', 'slack_notifier': 'SlackNotifier',
    'sonarqube': 'SonarClient', 'webhook_dispatcher': 'WebhookDispatcher',
    'caap_coordinator': 'CAAPCoordinator', 'chat_interface': 'ChatInterface',
    'compliance_checker': 'ComplianceChecker', 'discovery_agent': 'DiscoveryAgent',
    'exploitation_agent': 'ExploitationAgent', 'hypothesis_engine': 'HypothesisEngine',
    'knowledge_graph': 'KnowledgeGraph', 'recon_agent': 'ReconAgent',
    'session_orchestrator': 'SessionOrchestrator',
    'api_fuzzer': 'ApiFuzzer', 'benchmark_runner': 'BenchmarkRunner',
    'compliance_validator': 'ComplianceValidator', 'integration_harness': 'IntegrationHarness',
    'load_tester': 'LoadTester', 'mock_server': 'MockServer',
    'regression_tracker': 'RegressionTracker',
}
inst_ok = async_ok = dryrun_ok = lifecycle_ok = 0
for sub, names in MODS:
    for n in names:
        try:
            m = sys.modules[f'tools.burp_enterprise.{sub}.{n}']
            cls = getattr(m, main_classes[n])
            inst = cls()
            inst_ok += 1
            # async mirror check
            async_methods = [a for a in dir(inst) if a.endswith('_async') and callable(getattr(inst, a))]
            if async_methods:
                async_ok += 1
            # dry_run check
            if hasattr(inst, 'enable_dry_run') and hasattr(inst, '_check_dry_run'):
                inst.enable_dry_run()
                stub = inst._check_dry_run('test_method', x=1)
                if stub and stub.get('dry_run') is True:
                    dryrun_ok += 1
                inst.disable_dry_run()
            # lifecycle still works
            if hasattr(inst, 'health'):
                h = inst.health()
                if h.get('status') in ('ok', 'degraded'):
                    lifecycle_ok += 1
        except Exception as e:
            print(f'  FAIL {sub}/{n}: {type(e).__name__}: {e}')
print(f'  instantiated: {inst_ok}/27, async mirrors: {async_ok}/27, dry_run: {dryrun_ok}/27, lifecycle: {lifecycle_ok}/27')

# Phase 4: TTLCache (4A.5)
print('\nTTLCACHE (4A.5):')
ttl_ok = 0
for n in ['dns_resolver', 'http_fingerprint', 'sonarqube', 'jira_client', 'defect_dojo']:
    sub = 'network' if n in {'dns_resolver','http_fingerprint'} else 'integrations'
    m = sys.modules[f'tools.burp_enterprise.{sub}.{n}']
    cls = getattr(m, main_classes[n])
    inst = cls()
    if hasattr(inst, '_cache') and inst._cache is not None:
        inst._cache.set('k', 'v')
        if inst._cache.get('k') == 'v':
            ttl_ok += 1
print(f'  {ttl_ok}/5 have working TTLCache')

# Phase 5: RLock (4A.6)
print('\nRLOCK (4A.6):')
lock_ok = 0
RLOCK_TGTS = [('network','proxy_chain'), ('caap','knowledge_graph'),
              ('caap','session_orchestrator'), ('testing_tools','regression_tracker'),
              ('integrations','webhook_dispatcher')]
for sub, n in RLOCK_TGTS:
    m = sys.modules[f'tools.burp_enterprise.{sub}.{n}']
    cls = getattr(m, main_classes[n])
    inst = cls()
    if hasattr(inst, '_lock') and inst._lock is not None:
        lock_ok += 1
    else:
        print(f'  MISS: {sub}/{n}')
print(f'  {lock_ok}/5 have RLock')

# Phase 6: pagination (4A.8)
print('\nPAGINATION (4A.8):')
pag_ok = 0
for n in ['jira_client', 'sonarqube', 'defect_dojo']:
    m = sys.modules[f'tools.burp_enterprise.integrations.{n}']
    cls = getattr(m, main_classes[n])
    inst = cls()
    method = 'search_issues_paginated' if n != 'defect_dojo' else 'get_findings_paginated'
    if hasattr(inst, method):
        pag_ok += 1
print(f'  {pag_ok}/3 have paginated search')

# Phase 7: HMAC (4A.9)
print('\nHMAC (4A.9):')
hmac_ok = 0
for n in ['webhook_dispatcher', 'slack_notifier']:
    m = sys.modules[f'tools.burp_enterprise.integrations.{n}']
    cls = getattr(m, main_classes[n])
    inst = cls()
    if hasattr(inst, '_sign_payload'):
        sig = inst._sign_payload('s', {'x':1}) if n == 'webhook_dispatcher' else inst._sign_payload({'x':1}, signing_secret='s')
        if sig and sig.startswith('sha256='):
            hmac_ok += 1
print(f'  {hmac_ok}/2 sign payloads correctly')

# Phase 8: SQLite persist (4A.10)
print('\nPERSIST (4A.10):')
persist_ok = 0
db = os.path.join(tempfile.gettempdir(), 'tier4a_persist_test.db')
if os.path.exists(db): os.unlink(db)
PERSIST_TARGETS = [('caap','session_orchestrator'), ('caap','knowledge_graph'),
                   ('testing_tools','regression_tracker'), ('integrations','webhook_dispatcher')]
for sub, n in PERSIST_TARGETS:
    m = sys.modules[f'tools.burp_enterprise.{sub}.{n}']
    cls = getattr(m, main_classes[n])
    inst = cls()
    inst._persist_path = db
    has_p = hasattr(inst, '_persist') and hasattr(inst, '_restore')
    saved = inst._persist() if has_p else False
    if saved:
        persist_ok += 1
print(f'  {persist_ok}/4 persist to SQLite')

# Phase 9: validators (4A.4)
print('\nVALIDATORS (4A.4):')
val_ok = 0
for sub, names in MODS:
    for n in names:
        m = sys.modules[f'tools.burp_enterprise.{sub}.{n}']
        cls = getattr(m, main_classes[n])
        inst = cls()
        if hasattr(inst, '_validate_payload'):
            try:
                inst._validate_payload({'a': 1}, required_keys=['a'])
                val_ok += 1
            except Exception:
                pass
print(f'  {val_ok}/27 have working _validate_payload')

# Phase 10: blanket retry (4A.3) — count decorated methods on integrations + network
print('\nRETRY BLANKET (4A.3):')
import re as _re
for sub in ['network', 'integrations']:
    for n in [x for x in (NETWORK if sub == 'network' else INTEGRATIONS)]:
        from pathlib import Path
        src = Path(f'CaseCrack/tools/burp_enterprise/{sub}/{n}.py').read_text(encoding='utf-8')
        cnt = src.count('# __TIER4A_RETRY_BLANKET__')
        # Subtract 1 for the trailing marker line
        applied = src.count('@_rs_retry(') - src.count('# __TIER2_RETRY__')
        print(f'  {sub}/{n}: {cnt} blanket markers, total @_rs_retry = {src.count("@_rs_retry(")}')

# Async invocation smoke test
print('\nASYNC INVOCATION smoke:')
m = sys.modules['tools.burp_enterprise.network.dns_resolver']
inst = m.DNSResolver()
async def go():
    return await inst.bulk_resolve_async([])
print(f'  bulk_resolve_async([]) -> {asyncio.run(go())}')

print('\n=== TIER 4A VALIDATION COMPLETE ===')


# Need NETWORK constant for retry section above
NETWORK = ['dns_resolver', 'http_fingerprint', 'proxy_chain', 'ssl_analyzer', 'traffic_analyzer']
INTEGRATIONS = ['ci_cd_pipeline', 'defect_dojo', 'jira_client', 'slack_notifier', 'sonarqube', 'webhook_dispatcher']
