import pathlib
checks = [
    ('recon_dashboard/cross_target_intelligence.py', 627),
    ('exploit_chains/manual_audit_engine.py', 1640),
    ('recon_dashboard/target_scoring.py', 691),
    ('recon_dashboard/routes_persistent_agent.py', 1147),
    ('recon_dashboard/routes_multi_agent.py', 493),
    ('recon_dashboard/routes_cross_target.py', 335),
    ('recon_dashboard/routes_target_scoring.py', 249),
    ('recon_dashboard/routes_operator.py', 238),
    ('swarm/multi_gpu/topology.py', 710),
    ('swarm/multi_gpu/model_sharder.py', 499),
    ('swarm/multi_gpu/scheduler.py', 584),
    ('swarm/multi_gpu/messenger.py', 534),
    ('swarm/multi_gpu/governor.py', 466),
    ('graph/production.py', 573),
    ('adversarial_validation_agent.py', 1137),
    ('strategy_horizon_optimizer.py', 618),
    ('validation_fleet.py', 2578),
    ('database/data_migration.py', 559),
    ('inference/kv_cache.py', 277),
    ('intel/github_client_base.py', 388),
]

ROOT = pathlib.Path('tools/burp_enterprise')
total_missing_loc = 0
for rel, expected in checks:
    p = ROOT / rel
    if p.exists():
        lines = p.read_text(encoding='utf-8').splitlines()
        loc = sum(1 for l in lines if l.strip() and not l.strip().startswith('#'))
        pct = int(loc / expected * 100)
        gap = max(0, expected - loc)
        status = 'OK' if pct >= 80 else f'SHORT {pct}%'
        print(f'  {status:12s} {rel:55s} {loc:5d}/{expected} (gap: {gap})')
        if gap > 0:
            total_missing_loc += gap
    else:
        print(f'  MISSING      {rel:55s}     0/{expected} (gap: {expected})')
        total_missing_loc += expected

print(f'\nTotal LOC needed to close gaps: {total_missing_loc:,}')
