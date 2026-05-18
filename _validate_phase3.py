import sys, os
sys.path.insert(0, os.path.join(os.getcwd(), 'CaseCrack'))

mods = {
 'network': ['dns_resolver','http_fingerprint','proxy_chain','ssl_analyzer','traffic_analyzer'],
 'integrations': ['ci_cd_pipeline','defect_dojo','jira_client','slack_notifier','sonarqube','webhook_dispatcher'],
 'caap': ['caap_coordinator','chat_interface','compliance_checker','discovery_agent','exploitation_agent','hypothesis_engine','knowledge_graph','recon_agent','session_orchestrator'],
 'testing_tools': ['api_fuzzer','benchmark_runner','compliance_validator','integration_harness','load_tester','mock_server','regression_tracker'],
}
ok = fail = 0
no_helpers, no_lifecycle = [], []
for sub, items in mods.items():
    for m in items:
        try:
            mm = __import__(f'tools.burp_enterprise.{sub}.{m}', fromlist=['_emit'])
            ok += 1
            for h in ['_emit','_rs_logger','_rs_metrics','_rs_require_scope','_rs_session','_rs_retry','_rs_audit','_rs_timed']:
                if not hasattr(mm, h):
                    no_helpers.append(sub+'/'+m+':'+h)
                    break
            import inspect
            for name, obj in inspect.getmembers(mm, inspect.isclass):
                if obj.__module__ == mm.__name__ and all(hasattr(obj, x) for x in ('health','reset','close','metrics_snapshot','__enter__','__exit__')):
                    break
            else:
                no_lifecycle.append(sub+'/'+m)
        except Exception as e:
            print('  FAIL', sub+'/'+m, ':', e)
            fail += 1

print()
print('FINAL:', ok, '/27 import,', fail, 'fail')
print('Missing helpers:', no_helpers or 'none')
print('Missing lifecycle:', no_lifecycle or 'none')

from tools.burp_enterprise.event_bus import get_event_bus, BusEventType
events = []
bus = get_event_bus()
bus.on(BusEventType.MODULE_STARTED, lambda d: events.append(d))
from tools.burp_enterprise.network.dns_resolver import DNSResolver
with DNSResolver() as r:
    recs = r.resolve_all('localhost')
    h = r.health()
    snap = r.metrics_snapshot()
print()
print('Functional smoke: DNS=', len(recs), 'records, events=', len(events))
print('  health:', h)
print('  metrics_snapshot:', snap)

# integrations smoke
from tools.burp_enterprise.integrations.slack_notifier import SlackNotifier
sn = SlackNotifier()
print()
print('Slack notify (dry):', sn.notify_finding({'title':'test','severity':'low'}))
print('Slack health:', sn.health())

import tools.burp_enterprise as be
print()
print('Registry at package level:', len(be.RECOVERED_MODULES), 'modules')


class O:
    def __init__(self): self.r = {}
    def register(self, n, t): self.r[n] = t

o = O()
n = be.register_with_orchestrator(o)
print('Orchestrator registration:', n, '/27')

# LOC report
from pathlib import Path
total = 0
for sub, names in mods.items():
    for m in names:
        p = Path('CaseCrack/tools/burp_enterprise/'+sub+'/'+m+'.py')
        total += len(p.read_text(encoding='utf-8').splitlines())
print()
print('Total recovered LOC:', total, ' avg/module:', total // 27)
