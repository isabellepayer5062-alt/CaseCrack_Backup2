# End-to-End Test Harness Report

- Run ID: `20260416_160906Z`
- Output dir: `C:\Users\ya754\CaseCrack v1.0\e2e_harness_reports\20260416_160906Z`
- Target: `https://sugarrushed.ca`
- Start: `2026-04-16T16:09:06.519474+00:00`
- Total wall-clock: **834.2s**

## Wiring Self-Map

- Files scanned: 1667
- Modules: 1666  |  Edges: 3982
- Reachable from canonical entrypoints: 451
- **Orphan modules** (not reached): 1215
- **Dangling imports** (module refs not on disk): 209
- **Syntax errors**: 4

### Syntax Errors
- `tools.burp_enterprise.agents`:1 — invalid non-printable character U+FEFF (__init__.py, line 1)
- `tools.burp_enterprise.exploitation.verifier`:1 — invalid non-printable character U+FEFF (verifier.py, line 1)
- `tools.burp_enterprise.exploit_chains.exploit_verifier`:1 — invalid non-printable character U+FEFF (exploit_verifier.py, line 1)
- `tools.burp_enterprise.cli.commands.dynamic_chain`:1 — invalid non-printable character U+FEFF (dynamic_chain.py, line 1)

### Dangling Imports (first 50)
- `tools.action_rationale_engine`
- `tools.atlas.models`
- `tools.burp_enterprise._ai_api_proxy`
- `tools.burp_enterprise._api`
- `tools.burp_enterprise._assets`
- `tools.burp_enterprise._base`
- `tools.burp_enterprise._constants`
- `tools.burp_enterprise._detector`
- `tools.burp_enterprise._docker`
- `tools.burp_enterprise._hooks`
- `tools.burp_enterprise._llm_exfiltration`
- `tools.burp_enterprise._model_endpoint`
- `tools.burp_enterprise._models`
- `tools.burp_enterprise._phase1_loaders.exploitation.poc_generator`
- `tools.burp_enterprise._phase1_loaders.models`
- `tools.burp_enterprise._phase1_loaders.tool_abstraction`
- `tools.burp_enterprise._phase1_loaders.tool_chain_advisor`
- `tools.burp_enterprise._prompt_injection`
- `tools.burp_enterprise._rag_pipeline`
- `tools.burp_enterprise._recon`
- `tools.burp_enterprise._result_cache`
- `tools.burp_enterprise._sarif`
- `tools.burp_enterprise._scanner`
- `tools.burp_enterprise._serialization`
- `tools.burp_enterprise._tech_utils`
- `tools.burp_enterprise._types`
- `tools.burp_enterprise._utils`
- `tools.burp_enterprise._vector_db`
- `tools.burp_enterprise.action_translator`
- `tools.burp_enterprise.adapter`
- `tools.burp_enterprise.agents.atlas.adapter`
- `tools.burp_enterprise.agents.atlas.defense`
- `tools.burp_enterprise.agents.atlas.graph`
- `tools.burp_enterprise.agents.cli._base`
- `tools.burp_enterprise.agents.exploitation.engine`
- `tools.burp_enterprise.ai_directed_executor`
- `tools.burp_enterprise.alienvault_otx_client`
- `tools.burp_enterprise.async_exec`
- `tools.burp_enterprise.atlas.nexus`
- `tools.burp_enterprise.atlas_nexus`
- `tools.burp_enterprise.attack_graph`
- `tools.burp_enterprise.autonomous_loop`
- `tools.burp_enterprise.bgpview_client`
- `tools.burp_enterprise.bimi_deep`
- `tools.burp_enterprise.builder`
- `tools.burp_enterprise.campaign_strategy`
- `tools.burp_enterprise.chains`
- `tools.burp_enterprise.checkpointer_async`
- `tools.burp_enterprise.checks`
- `tools.burp_enterprise.circuit_breaker`

### Orphan Modules (first 50 of 1215)
- `tools.burp_enterprise`
- `tools.burp_enterprise._cli_dispatch`
- `tools.burp_enterprise._extract_data_to_json`
- `tools.burp_enterprise._finding_correlator_deprecated`
- `tools.burp_enterprise._phase1_loaders.data_loader`
- `tools.burp_enterprise._phase1_loaders.mcp_tools_loader`
- `tools.burp_enterprise._phase1_loaders.poc_generator_facade`
- `tools.burp_enterprise._scanner_http`
- `tools.burp_enterprise._scanner_providers_deprecated`
- `tools.burp_enterprise._shared_rendering`
- `tools.burp_enterprise._spa_shell`
- `tools.burp_enterprise.account`
- `tools.burp_enterprise.adaptive_learning`
- `tools.burp_enterprise.advanced_racer`
- `tools.burp_enterprise.adversarial_validation_agent`
- `tools.burp_enterprise.agent_sessions`
- `tools.burp_enterprise.agents`
- `tools.burp_enterprise.agents.advanced_agent_patterns`
- `tools.burp_enterprise.agents.advanced_orchestration`
- `tools.burp_enterprise.agents.auth_context`
- `tools.burp_enterprise.agents.autonomous_exploitation`
- `tools.burp_enterprise.agents.autonomy`
- `tools.burp_enterprise.agents.browser_workflow_extractor`
- `tools.burp_enterprise.agents.business_logic_scanner`
- `tools.burp_enterprise.agents.chain`
- `tools.burp_enterprise.agents.chain_impact_scorer`
- `tools.burp_enterprise.agents.chain_resolver`
- `tools.burp_enterprise.agents.collaborative_intelligence`
- `tools.burp_enterprise.agents.conflict_arbitration`
- `tools.burp_enterprise.agents.copilot`
- `tools.burp_enterprise.agents.copilot_loop`
- `tools.burp_enterprise.agents.copilot_sdk_discovery_tools`
- `tools.burp_enterprise.agents.copilot_sdk_exploit_cloud_tools`
- `tools.burp_enterprise.agents.copilot_sdk_infra_tools`
- `tools.burp_enterprise.agents.copilot_sdk_intel_tools`
- `tools.burp_enterprise.agents.copilot_sdk_vuln_tools`
- `tools.burp_enterprise.agents.core`
- `tools.burp_enterprise.agents.crawl_secrets_pipeline`
- `tools.burp_enterprise.agents.crawler`
- `tools.burp_enterprise.agents.creative_exploit_heuristics`
- `tools.burp_enterprise.agents.deterministic_replay`
- `tools.burp_enterprise.agents.discovery_bridge`
- `tools.burp_enterprise.agents.domain_knowledge_engine`
- `tools.burp_enterprise.agents.evolutionary_fuzzer`
- `tools.burp_enterprise.agents.exploit_graph`
- `tools.burp_enterprise.agents.fork_spawn`
- `tools.burp_enterprise.agents.fuzzer`
- `tools.burp_enterprise.agents.hierarchical_planner`
- `tools.burp_enterprise.agents.http_client`
- `tools.burp_enterprise.agents.init_wizard`

## Module Import Smoke Test

- Attempted: 1661
- OK: 1657
- **Failed: 4**

### Import Failures
- `tools.burp_enterprise._phase1_loaders.data_loader` — ModuleNotFoundError: No module named 'tools.burp_enterprise._phase1_loaders.models'
- `tools.burp_enterprise._phase1_loaders.mcp_tools_loader` — FileNotFoundError: [Errno 2] No such file or directory: 'C:\\Users\\ya754\\CaseCrack v1.0\\CaseCrack\\tools\\burp_enterprise\\_phase1_loaders\\mcp_tool_schemas.json'
- `tools.burp_enterprise._phase1_loaders.poc_generator_facade` — ModuleNotFoundError: No module named 'tools.burp_enterprise._phase1_loaders.exploitation'
- `tools.burp_enterprise.scanner_providers` — ImportError: scanner_providers has been removed — use tools.burp_enterprise.tool_wrappers.ZapToolProvider instead.

## Subsystem Probes

| Probe | OK | Elapsed | Detail |
|---|---|---|---|
| event_bus | ❌ | 0.001s | `AttributeError: 'EventBus' object has no attribute 'subscribe'` |
| llm_bridge | ✅ | 4.917s | `{"config_provider": "LLMProvider.OLLAMA", "config_model": "qwen2.5-coder:7b", "has_client": true, "router": "ModelRouter", "tracker": "CostTracker", "has_analyze_response": true, "has_generate_hypothe` |
| ml_stack | ✅ | 0.001s | `{"bayesian_prioritizer": "BayesianPrioritizer", "weight_tuner": "WeightTuner", "qtable_advisor_error": "QTableAdvisor.__init__() missing 1 required positional argument: 'learning_engine'", "hypothesis` |
| canonical_findings | ✅ | 0.0s | `{"normalized_keys": ["category", "cluster", "confidence", "confirmed", "curl_command", "cve_ids", "cvss_score", "cwe_ids", "description", "detail", "extra", "extracted_results", "id", "matcher_name", ` |
| tool_wrappers | ✅ | 0.219s | `{"bridge_class": "ToolWrapperBridge", "list_providers": ["amass", "arjun", "cloud_enum", "commix", "dalfox", "dnsx", "droopescan", "feroxbuster", "ffuf", "gf", "ghauri", "gitleaks", "gospider", "gotat` |
| runner_construction | ✅ | 0.0s | `{"class": "StandaloneReconRunner", "phase_count": 36, "parallel": false}` |
| config_loading | ✅ | 0.02s | `{"config_files": ["burp-config.yaml.example", "custom-detectors.yaml.example", "live_test_profile.yaml", "my-workflow.yaml", "policy.yaml"], "live_test_profile_keys": ["targets", "timeouts", "run_leve` |

### ❌ Probe: event_bus

```
Traceback (most recent call last):
  File "C:\Users\ya754\CaseCrack v1.0\e2e_test_harness.py", line 339, in _probe
    detail = fn()
  File "C:\Users\ya754\CaseCrack v1.0\e2e_test_harness.py", line 363, in probe_event_bus
    bus.subscribe("harness.test", lambda payload: received.append(payload))
    ^^^^^^^^^^^^^
AttributeError: 'EventBus' object has no attribute 'subscribe'

```

## Live Scan Against Target

- Target: `https://sugarrushed.ca`
- Elapsed: **805.4s**
- Phases completed: 10/10
- Total findings: **4**
- By severity: info=2, low=2

### Event Counts
- `log`: 177
- `console_batch`: 79
- `mcp_tool_started`: 72
- `mcp_tool_completed`: 72
- `endpoint`: 53
- `eta_tick`: 51
- `assessment_phase_changed`: 11
- `phase_start`: 10
- `assessment_progress`: 10
- `action_rationale`: 10
- `phase_complete`: 10
- `action_insight`: 10
- `final_analysis_step`: 5
- `finding`: 4
- `preflight`: 1
- `init`: 1
- `assessment_started`: 1
- `metric`: 1
- `decision_intelligence_summary`: 1
- `adaptive_chain_engine_summary`: 1
- `self_optimization_summary`: 1
- `unified_attack_graph_summary`: 1
- `assessment_completed`: 1
- `complete`: 1
- `learning_loop_summary`: 1

### Per-Phase Summary

| Phase | Events | Findings | Errors |
|---|---|---|---|
| observe | 6 | 0 | 0 |
| Fingerprinting & Technology | 57 | 2 | 0 |
| Endpoint & Asset Discovery | 2 | 0 | 0 |
| JS Analysis & Source Maps | 2 | 0 | 0 |
| Subdomain Discovery | 2 | 0 | 0 |
| DNS Resolution & Brute-force | 3 | 1 | 0 |
| TLS & Certificate Analysis | 2 | 0 | 0 |
| orient | 4 | 0 | 0 |
| WAF Detection & Fingerprinting | 2 | 0 | 0 |
| Secrets Scanning | 2 | 0 | 0 |
| CVE Correlation | 2 | 0 | 0 |
| OSINT Intelligence | 2 | 0 | 0 |
| decide | 1 | 0 | 0 |
| Cross-Phase Correlation | 1 | 1 | 0 |

## Unified Error Summary

- Total captured failures: **47**
- By category:
  - `NETWORK`: 21
  - `IMPORT`: 16
  - `LOGIC`: 4
  - `LLM`: 4
  - `OTHER`: 2

### Top Error Sources

- `log:py.warnings`: 30
- `log:burp_enterprise.llm_bridge`: 4
- `log:tools.burp_enterprise.recon_dashboard.runner`: 4
- `tools.burp_enterprise.agents`: 1
- `tools.burp_enterprise.exploitation.verifier`: 1
- `tools.burp_enterprise.exploit_chains.exploit_verifier`: 1
- `tools.burp_enterprise.cli.commands.dynamic_chain`: 1
- `tools.burp_enterprise._phase1_loaders.data_loader`: 1
- `tools.burp_enterprise._phase1_loaders.mcp_tools_loader`: 1
- `tools.burp_enterprise._phase1_loaders.poc_generator_facade`: 1
- `tools.burp_enterprise.scanner_providers`: 1
- `probe:event_bus`: 1

(Full error detail in `errors.jsonl` and `all.log`.)
