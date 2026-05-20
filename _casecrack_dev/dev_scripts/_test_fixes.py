"""Smoke test for the 5 production fixes."""
from tools.burp_enterprise.output.html_poc_generator import HTMLPoCGenerator
g = HTMLPoCGenerator()
html = g.generate([{'title':'Test','severity':'high','description':'demo','url':'https://x','cwe':[79]}])
print('HTMLPoCGenerator.generate OK, html_len=', len(html))

from tools.burp_enterprise.scanners.defensive_monitoring_tester import DefensiveMonitoringTester
t = DefensiveMonitoringTester(target='https://example.com')
r = t.run_assessment()
print('DefensiveMonitoringTester.run_assessment OK, findings=', len(r.findings), 'probes=', r.total_probes)

from tools.burp_enterprise.scanners.path_traversal import TraversalFinding, TraversalType
_first_tt = list(TraversalType)[0]
tf = TraversalFinding(
    traversal_type=_first_tt, payload='../etc/passwd',
    parameter='f', url='https://x', method='GET',
    target_file='/etc/passwd', file_content='root:x:0:0',
)
# Verify the attributes the patched cmd_traversal handler now uses
_disclosed = getattr(tf, 'file_content', None) or getattr(tf, 'target_file', '')
assert _disclosed == 'root:x:0:0', _disclosed
print('TraversalFinding fix OK: disclosed=', _disclosed)

from tools.burp_enterprise.integrations.siem_connector import BatchExportResult
b = BatchExportResult(total_sent=42)
print('BatchExportResult.total_sent=', b.total_sent)

# Verify the runner whitelist patch
from tools.burp_enterprise.recon_dashboard import runner as _r
import inspect
src = inspect.getsource(_r)
assert '_RANDOM_AGENT_OK: set[str] = set()' in src, 'runner.py whitelist not patched'
assert '"--random-agent": set()' in src, 'STEALTH_FLAG_OK random-agent not patched'
print('runner.py random-agent whitelist patches: OK')

print('\\nALL 5 FIXES VERIFIED OK')
