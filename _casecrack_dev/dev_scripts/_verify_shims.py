import importlib, sys
for m in [
    'tools.burp_enterprise.cli.dynamic_chain',
    'tools.burp_enterprise.recon.tool_wrappers._registry',
    'tools.burp_enterprise.recon.tool_wrappers',
]:
    try:
        mod = importlib.import_module(m)
        n = len(getattr(mod, '__all__', []))
        print(f'OK  {m}: {n} exports')
    except Exception as e:
        print(f'FAIL {m}: {type(e).__name__}: {e}')

from tools.burp_enterprise.cli.dynamic_chain import DynamicChainOrchestrator, GenerationStrategy
print(f'OK  DynamicChainOrchestrator via cli.dynamic_chain: {DynamicChainOrchestrator.__module__}')

from tools.burp_enterprise.recon.tool_wrappers._registry import get_provider_class
print(f'OK  get_provider_class via recon.tool_wrappers._registry: {get_provider_class.__module__}')
