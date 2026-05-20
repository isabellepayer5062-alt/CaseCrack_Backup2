import sys
sys.path.insert(0, '.')
mods = [
    'tools.burp_enterprise.memory_control',
    'tools.burp_enterprise.persistent_agent',
    'tools.burp_enterprise.agent_roles',
    'tools.burp_enterprise.operator_feedback',
    'tools.burp_enterprise.outcome_narrative_engine',
    'tools.burp_enterprise.action_rationale_engine',
    'tools.burp_enterprise.event_driven_wakeup',
    'tools.burp_enterprise.frontier_intelligence',
    'tools.burp_enterprise.self_healing',
    'tools.burp_enterprise.decision_trace',
]
ok = fail = 0
for mod in mods:
    try:
        m = __import__(mod, fromlist=['__all__'])
        syms = len(getattr(m, '__all__', None) or [n for n in dir(m) if not n.startswith('_')])
        print(f'OK  ({syms:3} pub) {mod.split(".")[-1]}')
        ok += 1
    except Exception as e:
        print(f'FAIL {mod.split(".")[-1]}: {str(e)[:100]}')
        fail += 1
print(f'\n{ok} OK / {fail} FAIL')
