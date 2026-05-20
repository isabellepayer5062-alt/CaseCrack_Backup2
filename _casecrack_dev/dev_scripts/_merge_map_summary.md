# Merge Map — 42 REFACTORED files


## Bucket A: Behavior-critical — manual semantic merge required (16 files)

| File | Disk→Hist KB | disk-only | hist-only | sig-changes |
|------|--------------|-----------|-----------|-------------|
| `CaseCrack/tools/burp_enterprise/exploit_chains/weight_tuner.py` | 14→77 | 5 | 61 | 2 |
| `CaseCrack/tools/burp_enterprise/agents/llm_bridge.py` | 70→251 | 57 | 50 | 3 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/payload_arbiter.py` | 19→79 | 15 | 45 | 3 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/grammar_synthesizer.py` | 29→51 | 16 | 37 | 8 |
| `CaseCrack/tools/burp_enterprise/agents/advanced_agent_patterns.py` | 52→66 | 50 | 33 | 11 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/genetic_forge.py` | 25→36 | 19 | 27 | 19 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/payload_synthesis_engine.py` | 13→43 | 10 | 26 | 4 |
| `CaseCrack/tools/burp_enterprise/learning_loop_engine.py` | 66→97 | 1 | 17 | 1 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/synthesis_feedback.py` | 14→27 | 10 | 17 | 2 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/synthesis_context.py` | 21→41 | 11 | 15 | 4 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/execution_scheduler.py` | 7→18 | 4 | 13 | 4 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/llm_synthesizer.py` | 15→20 | 11 | 12 | 4 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/failure_pattern.py` | 10→21 | 10 | 10 | 5 |
| `CaseCrack/tools/burp_enterprise/hypothesis_engine.py` | 36→68 | 21 | 9 | 5 |
| `CaseCrack/tools/burp_enterprise/synthesis_safety.py` | 25→35 | 5 | 6 | 6 |
| `CaseCrack/tools/burp_enterprise/exploit_chains/synthesis_tracer.py` | 27→29 | 7 | 5 | 3 |

## Bucket B: Support logic — selective function-by-function merge (22 files)

| File | Disk→Hist KB | disk-only | hist-only | sig-changes |
|------|--------------|-----------|-----------|-------------|
| `CaseCrack/tools/burp_enterprise/tool_registry/output_parsers.py` | 26→44 | 11 | 46 | 19 |
| `CaseCrack/tools/burp_enterprise/reasoning/prompt_chains.py` | 16→65 | 15 | 45 | 4 |
| `CaseCrack/tools/burp_enterprise/inference/gpu_governor.py` | 8→52 | 7 | 40 | 3 |
| `CaseCrack/tools/burp_enterprise/tool_registry/registry.py` | 16→46 | 15 | 25 | 4 |
| `CaseCrack/tools/burp_enterprise/reasoning/kv_checkpoint.py` | 15→22 | 31 | 23 | 2 |
| `CaseCrack/tools/burp_enterprise/recon_dashboard/target_scoring.py` | 33→40 | 36 | 21 | 0 |
| `CaseCrack/tools/burp_enterprise/reasoning/context_budget.py` | 11→21 | 11 | 21 | 3 |
| `CaseCrack/tools/burp_enterprise/reasoning/hypothesis_manager.py` | 15→26 | 25 | 20 | 1 |
| `CaseCrack/tools/burp_enterprise/inference/engine.py` | 21→29 | 25 | 19 | 5 |
| `CaseCrack/tools/burp_enterprise/database/data_migration.py` | 10→24 | 14 | 17 | 1 |
| `CaseCrack/tools/burp_enterprise/inference/model_manager.py` | 9→28 | 7 | 16 | 2 |
| `CaseCrack/tools/burp_enterprise/memory/vector_index.py` | 9→20 | 10 | 16 | 1 |
| `CaseCrack/tools/burp_enterprise/inference/grammar.py` | 7→16 | 7 | 15 | 3 |
| `CaseCrack/tools/burp_enterprise/inference/model_management/model_registry.py` | 13→23 | 2 | 13 | 5 |
| `CaseCrack/tools/burp_enterprise/tool_registry/action_translator.py` | 8→19 | 5 | 12 | 2 |
| `CaseCrack/tools/burp_enterprise/tool_registry/fallback.py` | 6→20 | 6 | 10 | 2 |
| `CaseCrack/tools/burp_enterprise/inference/model_management/vram_selector.py` | 6→18 | 2 | 8 | 2 |
| `CaseCrack/tools/burp_enterprise/inference/model_management/model_downloader.py` | 9→18 | 3 | 8 | 1 |
| `CaseCrack/tools/burp_enterprise/inference/model_management/finetune_exporter.py` | 10→20 | 1 | 6 | 0 |
| `CaseCrack/tools/burp_enterprise/inference/kv_cache.py` | 6→14 | 9 | 3 | 0 |
| `CaseCrack/tools/burp_enterprise/memory/embedder.py` | 7→11 | 10 | 2 | 0 |
| `CaseCrack/tools/burp_enterprise/__init__.py` | 7→86 | 4 | 0 | 0 |

## Bucket C: Safe divergence — minimal merge or accept disk version (4 files)

| File | Disk→Hist KB | disk-only | hist-only | sig-changes |
|------|--------------|-----------|-----------|-------------|
| `CaseCrack/tests/test_cli_api_extended.py` | 25→38 | 39 | 23 | 45 |
| `CaseCrack/tests/strict_fakes.py` | 13→18 | 9 | 16 | 14 |
| `CaseCrack/tests/test_recon_transport.py` | 4→5 | 1 | 6 | 0 |
| `CaseCrack/tests/test_fix134_waf_phase14_degraded.py` | 34→41 | 8 | 4 | 0 |