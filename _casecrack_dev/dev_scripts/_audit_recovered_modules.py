"""Audit recovered modules for LOC and complexity."""
import os

MODS = [
    # Network (5)
    'tools/burp_enterprise/network/dns_resolver.py',
    'tools/burp_enterprise/network/http_fingerprint.py',
    'tools/burp_enterprise/network/proxy_chain.py',
    'tools/burp_enterprise/network/ssl_analyzer.py',
    'tools/burp_enterprise/network/traffic_analyzer.py',
    # Integrations (6)
    'tools/burp_enterprise/integrations/ci_cd_pipeline.py',
    'tools/burp_enterprise/integrations/defect_dojo.py',
    'tools/burp_enterprise/integrations/jira_client.py',
    'tools/burp_enterprise/integrations/slack_notifier.py',
    'tools/burp_enterprise/integrations/sonarqube.py',
    'tools/burp_enterprise/integrations/webhook_dispatcher.py',
    # CAAP (9)
    'tools/burp_enterprise/caap/caap_coordinator.py',
    'tools/burp_enterprise/caap/chat_interface.py',
    'tools/burp_enterprise/caap/compliance_checker.py',
    'tools/burp_enterprise/caap/discovery_agent.py',
    'tools/burp_enterprise/caap/exploitation_agent.py',
    'tools/burp_enterprise/caap/hypothesis_engine.py',
    'tools/burp_enterprise/caap/knowledge_graph.py',
    'tools/burp_enterprise/caap/recon_agent.py',
    'tools/burp_enterprise/caap/session_orchestrator.py',
    # Testing tools (7)
    'tools/burp_enterprise/testing_tools/api_fuzzer.py',
    'tools/burp_enterprise/testing_tools/benchmark_runner.py',
    'tools/burp_enterprise/testing_tools/compliance_validator.py',
    'tools/burp_enterprise/testing_tools/integration_harness.py',
    'tools/burp_enterprise/testing_tools/load_tester.py',
    'tools/burp_enterprise/testing_tools/mock_server.py',
    'tools/burp_enterprise/testing_tools/regression_tracker.py',
]

import re

results = []
for m in MODS:
    if not os.path.exists(m):
        results.append((m, 0, 0, 0, 0, []))
        continue
    with open(m, encoding='utf-8') as f:
        content = f.read()
    loc = content.count('\n') + 1
    classes = len(re.findall(r'^class\s+\w+', content, re.M))
    methods = len(re.findall(r'^\s+def\s+\w+', content, re.M))
    funcs = len(re.findall(r'^def\s+\w+', content, re.M))
    # Find imports
    integ_imports = re.findall(r'from\s+(?:tools\.burp_enterprise\.|\.\.|\.)([\w.]+)', content)
    # Look for stub markers
    stubs = []
    if 'TODO' in content: stubs.append('TODO')
    if 'NotImplemented' in content: stubs.append('NotImpl')
    if 'pass$' in content or '\n        pass\n' in content: stubs.append('pass')
    if 'event_bus' not in content.lower(): stubs.append('NO_EVENTBUS')
    if 'logger' not in content: stubs.append('NO_LOGGER')
    results.append((m, loc, classes, methods + funcs, len(integ_imports), stubs))

# Group by subsystem
subsystems = {}
for r in results:
    sub = r[0].split('/')[2]
    subsystems.setdefault(sub, []).append(r)

print(f'{"Module":<55} {"LOC":>5} {"Cls":>4} {"Fn":>4} {"Imp":>4}  Issues')
print('-' * 100)
total_loc = 0
total_cls = 0
total_fn = 0
no_eb = 0
for sub, mods in subsystems.items():
    print(f'\n=== {sub} ===')
    for m, loc, cls, fn, imp, stubs in mods:
        name = m.split('/')[-1]
        total_loc += loc
        total_cls += cls
        total_fn += fn
        if 'NO_EVENTBUS' in stubs: no_eb += 1
        flags = ' '.join(stubs)
        print(f'  {name:<53} {loc:>5} {cls:>4} {fn:>4} {imp:>4}  {flags}')

print('-' * 100)
print(f'TOTAL: {len(MODS)} modules, {total_loc} LOC, {total_cls} classes, {total_fn} functions')
print(f'Average LOC: {total_loc // len(MODS)}')
print(f'Modules with NO EventBus integration: {no_eb}')
