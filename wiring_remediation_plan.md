# Commercial-Grade Wiring Remediation Plan

**Total dead modules: 1195**

## Tier Summary

| Tier | Count | Action | Description |
|------|-------|--------|-------------|
| TIER-1 | 241 | `wire_back` | Substantial production code NOT wired — **URGENT** |
| TIER-2 | 280 | `update_reality` | Dynamically imported — reachable at runtime |
| TIER-3 | 98 | `wire_back/map` | Medium or registry-referenced |
| TIER-4 | 570 | `keep/review` | Stubs / helpers |
| DELETE | 6 | `deprecate` | Legacy / archive |

## TIER-1 Urgent Remediation (241 modules)

Substantial (>100 LOC, with classes) modules NOT reachable statically OR dynamically.
These represent real disconnected commercial subsystems.

### `tool_wrappers` (50 modules, 12,399 LOC)

**Wiring target:** Add to tool_wrapper_bridge._providers dict

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `tool_wrappers.vhostfinder_provider` | 1194 | 1 | 3 |
| `tool_wrappers.jsluice_provider` | 516 | 1 | 3 |
| `tool_wrappers.mitmproxy_provider` | 512 | 1 | 11 |
| `tool_wrappers.sourcemapper_provider` | 453 | 1 | 3 |
| `tool_wrappers.nmap_provider` | 434 | 1 | 3 |
| `tool_wrappers.puredns_provider` | 395 | 1 | 3 |
| `tool_wrappers.ghauri_provider` | 355 | 1 | 3 |
| `tool_wrappers.trufflehog_provider` | 347 | 1 | 3 |
| `tool_wrappers.dnsx_provider` | 329 | 1 | 4 |
| `tool_wrappers.gf_provider` | 326 | 1 | 5 |
| `tool_wrappers.nomore403_provider` | 307 | 1 | 3 |
| `tool_wrappers.zap_provider` | 284 | 1 | 5 |
| `tool_wrappers.wafw00f_provider` | 266 | 2 | 6 |
| `tool_wrappers.tlsx_provider` | 264 | 1 | 3 |
| `tool_wrappers.commix_provider` | 263 | 1 | 3 |
| `tool_wrappers.sslyze_provider` | 248 | 1 | 3 |
| `tool_wrappers.sqlmap_provider` | 243 | 1 | 3 |
| `tool_wrappers.cloud_enum_provider` | 242 | 1 | 3 |
| `tool_wrappers.wpscan_provider` | 238 | 1 | 3 |
| `tool_wrappers.testssl_provider` | 224 | 1 | 3 |
| `tool_wrappers.gitleaks_provider` | 218 | 1 | 3 |
| `tool_wrappers.gotator_provider` | 210 | 1 | 3 |
| `tool_wrappers.rustscan_provider` | 210 | 1 | 3 |
| `tool_wrappers.droopescan_provider` | 208 | 1 | 3 |
| `tool_wrappers.interactsh_provider` | 205 | 2 | 6 |
| `tool_wrappers.feroxbuster_provider` | 203 | 1 | 3 |
| `tool_wrappers.gospider_provider` | 197 | 1 | 3 |
| `tool_wrappers.nuclei_provider` | 189 | 1 | 4 |
| `tool_wrappers.httpx_provider` | 188 | 1 | 4 |
| `tool_wrappers.meg_provider` | 184 | 1 | 3 |
| `tool_wrappers.dalfox_provider` | 182 | 1 | 3 |
| `tool_wrappers._policy` | 181 | 2 | 5 |
| `tool_wrappers.naabu_provider` | 178 | 1 | 3 |
| `tool_wrappers.ffuf_provider` | 176 | 1 | 3 |
| `tool_wrappers.katana_provider` | 168 | 1 | 3 |
| `tool_wrappers.kiterunner_provider` | 159 | 1 | 3 |
| `tool_wrappers.grpcurl_provider` | 158 | 1 | 3 |
| `tool_wrappers.paramspider_provider` | 158 | 1 | 3 |
| `tool_wrappers._lockfile` | 150 | 0 | 4 |
| `tool_wrappers.trivy_provider` | 144 | 1 | 4 |
| `tool_wrappers._capabilities` | 143 | 0 | 10 |
| `tool_wrappers._retry` | 142 | 1 | 8 |
| `tool_wrappers.arjun_provider` | 136 | 1 | 3 |
| `tool_wrappers.hakrawler_provider` | 133 | 1 | 3 |
| `tool_wrappers.semgrep_provider` | 130 | 1 | 3 |
| `tool_wrappers.amass_provider` | 125 | 1 | 3 |
| `tool_wrappers.jwt_tool_provider` | 123 | 1 | 3 |
| `tool_wrappers.qsreplace_provider` | 122 | 1 | 3 |
| `tool_wrappers.subfinder_provider` | 121 | 1 | 3 |
| `tool_wrappers._preflight` | 118 | 2 | 9 |

### `cli` (21 modules, 24,858 LOC)

**Wiring target:** Add dispatch in cli/commands/__init__.py CMD_HANDLERS

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `cli.commands.injection` | 2287 | 0 | 19 |
| `cli.commands.intel` | 2148 | 0 | 10 |
| `cli.commands.core` | 2098 | 0 | 27 |
| `cli.commands.agent_orchestration` | 1722 | 0 | 5 |
| `cli.commands.recon_advanced` | 1665 | 0 | 13 |
| `cli.commands.agent_cognition` | 1441 | 0 | 5 |
| `cli.commands.recon_tier2` | 1398 | 0 | 33 |
| `cli.commands.recon_scanning` | 1385 | 0 | 10 |
| `cli.commands.agent_integration` | 1344 | 0 | 7 |
| `cli.commands.devsecops` | 1322 | 0 | 6 |
| `cli.commands.recon_web_security` | 1216 | 1 | 7 |
| `cli.commands.api` | 1207 | 0 | 11 |
| `cli.commands.auth` | 1125 | 0 | 8 |
| `cli.commands.recon_discovery` | 1124 | 0 | 12 |
| `cli.commands.p7_commands` | 889 | 0 | 34 |
| `cli.commands.recon_fingerprint` | 766 | 0 | 6 |
| `cli.commands.agent_strategy` | 691 | 0 | 5 |
| `cli.daemon` | 377 | 1 | 9 |
| `cli.commands.graph` | 328 | 0 | 9 |
| `cli.commands.gap_r` | 177 | 0 | 7 |
| `cli.commands.osint` | 148 | 0 | 8 |

### `recon_dashboard` (19 modules, 7,820 LOC)

**Wiring target:** Hook into runner.py phase dispatch or server.py routes

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `recon_dashboard.routes_persistent_agent` | 1147 | 0 | 47 |
| `recon_dashboard.target_scoring` | 691 | 4 | 9 |
| `recon_dashboard.state_serializers` | 662 | 0 | 4 |
| `recon_dashboard.cross_target_intelligence` | 627 | 5 | 15 |
| `recon_dashboard.routes_sdk_engine` | 617 | 1 | 9 |
| `recon_dashboard.routes_provider_vault` | 512 | 1 | 10 |
| `recon_dashboard.routes_multi_agent` | 493 | 0 | 8 |
| `recon_dashboard.infra_monitor` | 387 | 0 | 4 |
| `recon_dashboard.routes_agent` | 376 | 0 | 10 |
| `recon_dashboard.routes_cross_target` | 335 | 0 | 11 |
| `recon_dashboard.routes_intelligence_experience` | 335 | 0 | 5 |
| `recon_dashboard.routes_exploit_graph` | 262 | 0 | 8 |
| `recon_dashboard.routes_target_scoring` | 249 | 0 | 4 |
| `recon_dashboard.routes_operator` | 238 | 0 | 9 |
| `recon_dashboard.routes_assessment` | 219 | 0 | 16 |
| `recon_dashboard.session_store` | 210 | 0 | 4 |
| `recon_dashboard.routes_reasoning` | 198 | 0 | 5 |
| `recon_dashboard.routes_findings` | 153 | 0 | 6 |
| `recon_dashboard.llm_helpers` | 109 | 0 | 4 |

### `agents` (12 modules, 8,762 LOC)

**Wiring target:** Register in agent_factory / add to unified_agent pipeline

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `agents.advanced_agent_patterns` | 1321 | 22 | 51 |
| `agents.advanced_orchestration` | 1127 | 24 | 56 |
| `agents.fork_spawn` | 1099 | 12 | 46 |
| `agents.copilot_sdk_vuln_tools` | 1060 | 32 | 32 |
| `agents.speculative_executor` | 768 | 8 | 31 |
| `agents.conflict_arbitration` | 685 | 16 | 31 |
| `agents.role_registry` | 634 | 5 | 14 |
| `agents.copilot_sdk_discovery_tools` | 608 | 13 | 17 |
| `agents.deterministic_replay` | 606 | 8 | 40 |
| `agents.copilot_sdk_infra_tools` | 345 | 9 | 9 |
| `agents.copilot_sdk_intel_tools` | 269 | 7 | 7 |
| `agents.copilot_sdk_exploit_cloud_tools` | 240 | 6 | 6 |

### `osint_providers` (12 modules, 3,308 LOC)

**Wiring target:** Register in provider_registry

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `osint_providers.netintel_client` | 615 | 1 | 9 |
| `osint_providers.schemas` | 346 | 8 | 11 |
| `osint_providers.email_intel_client` | 320 | 1 | 5 |
| `osint_providers.provider_registry` | 281 | 4 | 21 |
| `osint_providers.bgpview_client` | 269 | 1 | 7 |
| `osint_providers.alienvault_otx_client` | 256 | 1 | 6 |
| `osint_providers.subdomain_aggregator` | 235 | 1 | 3 |
| `osint_providers.rdap_client` | 226 | 1 | 5 |
| `osint_providers.xposedornot_client` | 219 | 1 | 5 |
| `osint_providers.crtsh_client` | 211 | 1 | 6 |
| `osint_providers.circuit_breaker` | 190 | 3 | 6 |
| `osint_providers._common` | 140 | 1 | 6 |

### `platforms` (10 modules, 2,134 LOC)

**Wiring target:** Register via platforms/_detector.py dispatch

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `platforms.spring` | 251 | 0 | 4 |
| `platforms.rails` | 225 | 0 | 4 |
| `platforms.joomla` | 223 | 0 | 4 |
| `platforms.express` | 218 | 0 | 4 |
| `platforms.laravel` | 214 | 0 | 4 |
| `platforms.fastapi` | 207 | 0 | 4 |
| `platforms.django` | 205 | 0 | 4 |
| `platforms.aspnet` | 203 | 0 | 4 |
| `platforms.drupal` | 197 | 0 | 4 |
| `platforms._base` | 191 | 11 | 6 |

### `loop` (9 modules, 3,310 LOC)

**Wiring target:** Wire into autonomous_loop dispatch

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `loop.exploit_report` | 478 | 3 | 6 |
| `loop.target_selection` | 471 | 4 | 10 |
| `loop.attack_graph` | 458 | 7 | 13 |
| `loop.session_matrix` | 426 | 7 | 11 |
| `loop.race_engine` | 384 | 7 | 8 |
| `loop.target_specialization` | 327 | 3 | 6 |
| `loop.value_scorer` | 322 | 5 | 10 |
| `loop.graph_pruner` | 226 | 3 | 4 |
| `loop.exploration_bias` | 218 | 3 | 5 |

### `ai_ml` (8 modules, 2,068 LOC)

**Wiring target:** Register ML model in model_management

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `ai_ml._prompt_injection` | 442 | 1 | 2 |
| `ai_ml._rag_pipeline` | 344 | 1 | 2 |
| `ai_ml._model_endpoint` | 279 | 1 | 2 |
| `ai_ml._ai_api_proxy` | 253 | 1 | 2 |
| `ai_ml._serialization` | 226 | 1 | 1 |
| `ai_ml._vector_db` | 209 | 1 | 2 |
| `ai_ml._llm_exfiltration` | 158 | 1 | 2 |
| `ai_ml._models` | 157 | 10 | 1 |

### `compliance_pkg` (7 modules, 1,862 LOC)

**Wiring target:** Register compliance checks with compliance orchestrator

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `compliance_pkg.enterprise` | 392 | 1 | 25 |
| `compliance_pkg.mapper` | 316 | 1 | 18 |
| `compliance_pkg.models` | 312 | 9 | 11 |
| `compliance_pkg.checks.nist` | 249 | 4 | 9 |
| `compliance_pkg.checks.soc2` | 201 | 4 | 9 |
| `compliance_pkg.checks.owasp_asvs` | 198 | 4 | 10 |
| `compliance_pkg.checks.pci_dss` | 194 | 4 | 9 |

### `inference` (7 modules, 3,090 LOC)

**Wiring target:** Register in model_management subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `inference.model_manager` | 583 | 4 | 11 |
| `inference.model_management.model_registry` | 519 | 6 | 22 |
| `inference.model_management.model_benchmarker` | 491 | 5 | 11 |
| `inference.model_management.finetune_exporter` | 431 | 6 | 23 |
| `inference.model_management.model_downloader` | 412 | 5 | 17 |
| `inference.model_management.vram_selector` | 377 | 5 | 12 |
| `inference.kv_cache` | 277 | 5 | 11 |

### `vuln_intel` (7 modules, 3,304 LOC)

**Wiring target:** Add to vuln_intel pipeline

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `vuln_intel.clients` | 924 | 7 | 16 |
| `vuln_intel.correlator` | 719 | 4 | 13 |
| `vuln_intel.mapper` | 479 | 1 | 5 |
| `vuln_intel.database` | 418 | 1 | 12 |
| `vuln_intel.hub` | 319 | 1 | 8 |
| `vuln_intel.models` | 316 | 16 | 16 |
| `vuln_intel.cvss` | 129 | 1 | 5 |

### `email_hardening` (6 modules, 1,293 LOC)

**Wiring target:** Wire into email scanner chain

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `email_hardening.bimi_deep` | 255 | 1 | 1 |
| `email_hardening._types` | 247 | 13 | 9 |
| `email_hardening.dane_tlsa` | 219 | 1 | 2 |
| `email_hardening.starttls_downgrade` | 197 | 1 | 1 |
| `email_hardening.mta_sts` | 193 | 1 | 1 |
| `email_hardening.spf_loops` | 182 | 1 | 1 |

### `notifications` (6 modules, 816 LOC)

**Wiring target:** Register as notification channel

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `notifications.email_smtp` | 198 | 1 | 4 |
| `notifications.ntfy_client` | 131 | 1 | 4 |
| `notifications.slack` | 131 | 1 | 5 |
| `notifications.teams` | 126 | 1 | 6 |
| `notifications.webhook` | 118 | 1 | 5 |
| `notifications.discord` | 112 | 1 | 5 |

### `core_infra` (5 modules, 3,563 LOC)

**Wiring target:** Import into recon_dashboard/__init__.py for runner initialization

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `core_infra.chaos_testing` | 1032 | 15 | 50 |
| `core_infra.chaos_testing_v2` | 1032 | 15 | 50 |
| `core_infra.self_healing` | 780 | 8 | 24 |
| `core_infra.metrics_collector` | 524 | 10 | 38 |
| `core_infra.production_utils` | 195 | 0 | 6 |

### `strategy` (5 modules, 8,231 LOC)

**Wiring target:** Wire into DecisionOrchestrator or strategy registry

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `strategy.discovery` | 2023 | 13 | 20 |
| `strategy.models` | 1865 | 13 | 8 |
| `strategy.core` | 1811 | 11 | 32 |
| `strategy.store` | 1551 | 10 | 34 |
| `strategy.async_exec` | 981 | 13 | 30 |

### `swarm` (5 modules, 2,793 LOC)

**Wiring target:** Wire into swarm agent registry

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `swarm.multi_gpu.topology` | 710 | 7 | 28 |
| `swarm.multi_gpu.scheduler` | 584 | 8 | 26 |
| `swarm.multi_gpu.messenger` | 534 | 8 | 20 |
| `swarm.multi_gpu.model_sharder` | 499 | 6 | 19 |
| `swarm.multi_gpu.governor` | 466 | 4 | 27 |

### `wasm_analysis` (5 modules, 2,320 LOC)

**Wiring target:** Wire into wasm discovery phase

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `wasm_analysis.wat_decompiler` | 871 | 1 | 1 |
| `wasm_analysis.wasi_deep` | 374 | 1 | 1 |
| `wasm_analysis.data_flow` | 368 | 1 | 1 |
| `wasm_analysis._types` | 365 | 21 | 17 |
| `wasm_analysis.side_channel` | 342 | 1 | 1 |

### `exploitation` (3 modules, 1,502 LOC)

**Wiring target:** Review and wire into exploitation subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `exploitation.engine` | 628 | 1 | 7 |
| `exploitation.impact` | 548 | 1 | 1 |
| `exploitation.chains` | 326 | 1 | 4 |

### `graph` (3 modules, 1,432 LOC)

**Wiring target:** Register as graph node/edge type

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `graph.production` | 573 | 5 | 20 |
| `graph.multi_agent.tests.test_multi_agent` | 431 | 9 | 39 |
| `graph.checkpointer_async` | 428 | 3 | 24 |

### `graphql` (3 modules, 1,798 LOC)

**Wiring target:** Wire into GraphQL phase handlers

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `graphql._recon` | 1382 | 1 | 2 |
| `graphql._models` | 232 | 8 | 9 |
| `graphql._api` | 184 | 0 | 4 |

### `passive_templates` (3 modules, 1,007 LOC)

**Wiring target:** Register in passive template loader

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `passive_templates.scanner` | 502 | 3 | 12 |
| `passive_templates.loader` | 300 | 0 | 5 |
| `passive_templates.models` | 205 | 11 | 4 |

### `reporting` (3 modules, 829 LOC)

**Wiring target:** Add to report_generator outputs

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `reporting.jira_client` | 466 | 2 | 11 |
| `reporting.defectdojo_client` | 213 | 1 | 6 |
| `reporting.sarif_reporter` | 150 | 1 | 7 |

### `tool_registry` (3 modules, 1,768 LOC)

**Wiring target:** Review and wire into tool_registry subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `tool_registry.output_parsers` | 1002 | 21 | 57 |
| `tool_registry.fallback` | 414 | 5 | 8 |
| `tool_registry.action_translator` | 352 | 3 | 12 |

### `exploit_chains` (2 modules, 2,227 LOC)

**Wiring target:** Register via exploit_graph.register_chain() or chain_handlers

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `exploit_chains.manual_audit_engine` | 1640 | 17 | 12 |
| `exploit_chains.exploit_progression` | 587 | 5 | 13 |

### `memory` (2 modules, 692 LOC)

**Wiring target:** Review and wire into memory subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `memory.vector_index` | 467 | 3 | 13 |
| `memory.embedder` | 225 | 2 | 8 |

### `reasoning` (2 modules, 1,038 LOC)

**Wiring target:** Review and wire into reasoning subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `reasoning.hypothesis_manager` | 525 | 5 | 18 |
| `reasoning.kv_checkpoint` | 513 | 4 | 17 |

### `_extract_data_to_json` (1 modules, 346 LOC)

**Wiring target:** Review and wire into _extract_data_to_json subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `_extract_data_to_json` | 346 | 0 | 9 |

### `_phase1_loaders` (1 modules, 206 LOC)

**Wiring target:** Review and wire into _phase1_loaders subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `_phase1_loaders.data_loader` | 206 | 7 | 7 |

### `_scanner_http` (1 modules, 204 LOC)

**Wiring target:** Review and wire into _scanner_http subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `_scanner_http` | 204 | 1 | 6 |

### `adversarial_validation_agent` (1 modules, 1,137 LOC)

**Wiring target:** Review and wire into adversarial_validation_agent subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `adversarial_validation_agent` | 1137 | 9 | 16 |

### `analyzer` (1 modules, 302 LOC)

**Wiring target:** Review and wire into analyzer subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `analyzer` | 302 | 4 | 4 |

### `architecture_evolver` (1 modules, 779 LOC)

**Wiring target:** Review and wire into architecture_evolver subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `architecture_evolver` | 779 | 9 | 30 |

### `atlas` (1 modules, 800 LOC)

**Wiring target:** Review and wire into atlas subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `atlas.adapter` | 800 | 1 | 28 |

### `attacker_memory` (1 modules, 589 LOC)

**Wiring target:** Review and wire into attacker_memory subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `attacker_memory` | 589 | 4 | 23 |

### `causal_bridge` (1 modules, 620 LOC)

**Wiring target:** Review and wire into causal_bridge subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `causal_bridge` | 620 | 4 | 17 |

### `data` (1 modules, 659 LOC)

**Wiring target:** Review and wire into data subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `data.postgres` | 659 | 1 | 18 |

### `database` (1 modules, 559 LOC)

**Wiring target:** Wire into db_persistence layer

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `database.data_migration` | 559 | 3 | 6 |

### `defender_adversary_model` (1 modules, 719 LOC)

**Wiring target:** Review and wire into defender_adversary_model subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `defender_adversary_model` | 719 | 8 | 25 |

### `discovery_pkg` (1 modules, 273 LOC)

**Wiring target:** Add to discovery phase handlers

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `discovery_pkg.subdomain_external` | 273 | 1 | 3 |

### `intel` (1 modules, 388 LOC)

**Wiring target:** Wire into vuln_intel pipeline or mark optional

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `intel.github_client_base` | 388 | 2 | 16 |

### `knowledge_resilience` (1 modules, 1,163 LOC)

**Wiring target:** Review and wire into knowledge_resilience subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `knowledge_resilience` | 1163 | 7 | 18 |

### `logger` (1 modules, 450 LOC)

**Wiring target:** Review and wire into logger subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `logger` | 450 | 4 | 37 |

### `network` (1 modules, 414 LOC)

**Wiring target:** Register via network phase handlers

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `network.tls_posture_report` | 414 | 4 | 13 |

### `objective_engine` (1 modules, 658 LOC)

**Wiring target:** Review and wire into objective_engine subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `objective_engine` | 658 | 7 | 18 |

### `operator_trust_dashboard` (1 modules, 449 LOC)

**Wiring target:** Review and wire into operator_trust_dashboard subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `operator_trust_dashboard` | 449 | 4 | 10 |

### `signal_contracts` (1 modules, 578 LOC)

**Wiring target:** Review and wire into signal_contracts subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `signal_contracts` | 578 | 5 | 1 |

### `signal_tracer` (1 modules, 222 LOC)

**Wiring target:** Review and wire into signal_tracer subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `signal_tracer` | 222 | 3 | 15 |

### `strategy_horizon_optimizer` (1 modules, 618 LOC)

**Wiring target:** Review and wire into strategy_horizon_optimizer subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `strategy_horizon_optimizer` | 618 | 8 | 37 |

### `validation_fleet` (1 modules, 2,578 LOC)

**Wiring target:** Review and wire into validation_fleet subsystem

| Module | LOC | Classes | Funcs |
|--------|-----|---------|-------|
| `validation_fleet` | 2578 | 20 | 42 |

## TIER-2 Reality Map Update (280 modules)

These modules are **dynamically imported** but not detected by static AST analysis.
Fix by adding their loader sites to `CANONICAL_ENTRYPOINTS` in `execution_reality_map.py`.

| Subsystem | Count |
|-----------|-------|
| `scanners` | 65 |
| `discovery_pkg` | 23 |
| `testing_tools` | 19 |
| `secrets` | 16 |
| `intel` | 15 |
| `agents` | 14 |
| `output` | 14 |
| `integrations` | 13 |
| `network` | 13 |
| `caap` | 12 |
| `exploit_chains` | 12 |
| `misc` | 12 |
| `pipeline` | 12 |
| `core_infra` | 11 |
| `cloud` | 10 |
| `session_auth` | 8 |
| `recon` | 5 |
| `database` | 3 |
| `collaborator` | 1 |
| `compliance_pkg` | 1 |

## TIER-3 Medium / String-Referenced (98 modules)

Either medium-sized helpers or referenced via registry strings.
Mostly reachable through plugin registries — verify loader exists.

## Execution Roadmap

### Week 1: TIER-2 Reality Map Fix (Quick Win)
- Identify 280 dynamically-imported modules
- Add their registry/loader modules to `CANONICAL_ENTRYPOINTS`
- Rerun `execution_reality_map.py` — expect reachability to jump significantly

### Week 2-3: TIER-1 Subsystem-by-Subsystem Wiring
Priority order based on production value:
2. `exploit_chains` — 2 modules, 2,227 LOC
3. `agents` — 12 modules, 8,762 LOC
5. `recon_dashboard` — 19 modules, 7,820 LOC
7. `core_infra` — 5 modules, 3,563 LOC
9. `tool_wrappers` — 50 modules, 12,399 LOC
10. `cli` — 21 modules, 24,858 LOC

### Week 4: TIER-3 Registry Verification
- Verify all 98 registry-referenced modules are actually loaded
- Add missing loaders to plugin dispatch

### Week 5: TIER-4 / DELETE Cleanup
- Review 570 stub modules
- Remove 6 legacy modules
