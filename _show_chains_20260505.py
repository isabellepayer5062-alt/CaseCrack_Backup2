import json, collections

with open('CaseCrack/reports/recon-correlation.json') as f:
    corr = json.load(f)

chains = corr.get('attack_chains', [])
sev_chains = collections.Counter(c.get('severity','?') for c in chains)
print('Attack chains by severity:', dict(sev_chains))
print()
for sev in ['critical','high','medium']:
    top = [c for c in chains if c.get('severity') == sev][:5]
    for c in top:
        conf = c.get('confidence', {})
        name = c.get('chain_name','?')
        desc = c.get('description','')[:80]
        score = conf.get('score','?')
        print('[' + sev.upper() + '] ' + name + ' | conf=' + str(score) + ' | ' + desc)
