"""Compare recovered modules vs sibling LOC."""
import os

SUBS = ['network', 'integrations', 'caap', 'testing_tools']

# Recovered modules to exclude from sibling stats
RECOVERED = {
    'network': {'dns_resolver.py', 'http_fingerprint.py', 'proxy_chain.py', 'ssl_analyzer.py', 'traffic_analyzer.py'},
    'integrations': {'ci_cd_pipeline.py', 'defect_dojo.py', 'jira_client.py', 'slack_notifier.py', 'sonarqube.py', 'webhook_dispatcher.py'},
    'caap': {'caap_coordinator.py', 'chat_interface.py', 'compliance_checker.py', 'discovery_agent.py',
             'exploitation_agent.py', 'hypothesis_engine.py', 'knowledge_graph.py', 'recon_agent.py', 'session_orchestrator.py'},
    'testing_tools': {'api_fuzzer.py', 'benchmark_runner.py', 'compliance_validator.py', 'integration_harness.py',
                      'load_tester.py', 'mock_server.py', 'regression_tracker.py'},
}

print(f'{"Subsystem":<16} {"Siblings":>9} {"AvgSib":>7} {"MedSib":>7} {"Recov":>6} {"AvgRec":>7} {"Ratio":>7}')
print('-' * 75)

for sub in SUBS:
    base = f'tools/burp_enterprise/{sub}'
    if not os.path.exists(base): continue
    siblings = []
    recovered = []
    for f in os.listdir(base):
        if not f.endswith('.py') or f == '__init__.py': continue
        fp = os.path.join(base, f)
        try:
            with open(fp, encoding='utf-8') as fh:
                loc = fh.read().count('\n') + 1
        except: continue
        if f in RECOVERED.get(sub, set()):
            recovered.append((f, loc))
        else:
            siblings.append((f, loc))

    sib_locs = [l for _, l in siblings]
    rec_locs = [l for _, l in recovered]
    if sib_locs and rec_locs:
        avg_sib = sum(sib_locs) // len(sib_locs)
        med_sib = sorted(sib_locs)[len(sib_locs)//2]
        avg_rec = sum(rec_locs) // len(rec_locs)
        ratio = avg_rec / avg_sib if avg_sib else 0
        print(f'{sub:<16} {len(siblings):>9} {avg_sib:>7} {med_sib:>7} {len(recovered):>6} {avg_rec:>7} {ratio:>6.1%}')
        print(f'  Top 3 largest siblings:')
        for name, l in sorted(siblings, key=lambda x: -x[1])[:3]:
            print(f'    {l:>5}  {name}')
