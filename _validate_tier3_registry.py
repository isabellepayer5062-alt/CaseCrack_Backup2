import sys, os
sys.path.insert(0, os.path.join(os.getcwd(), 'CaseCrack'))
from tools.burp_enterprise.recovered_registry import (
    RECOVERED_MODULES, instantiate_all, health_report,
    iter_by_subsystem, find_engines_with_capability, register_with,
)

print(f'Registry: {len(RECOVERED_MODULES)} modules')
for sub in ['network','integrations','caap','testing_tools']:
    print(f'  {sub}: {len(iter_by_subsystem(sub))}')

print()
print(f'With health(): {len(find_engines_with_capability("health"))}')
print(f'With reset():  {len(find_engines_with_capability("reset"))}')
print(f'With close():  {len(find_engines_with_capability("close"))}')

report = health_report()
ok = sum(1 for r in report.values() if r.get('status') == 'ok')
print()
print(f'Health report: {ok}/{len(report)} OK')
for n, r in report.items():
    if r.get('status') != 'ok':
        print(f'  NON-OK {n}: {r}')


class MockOrch:
    def __init__(self):
        self.registered = {}

    def register(self, name, target):
        self.registered[name] = target


orch = MockOrch()
n = register_with(orch)
print()
print(f'Registered with mock orchestrator: {n}/{len(RECOVERED_MODULES)}')
