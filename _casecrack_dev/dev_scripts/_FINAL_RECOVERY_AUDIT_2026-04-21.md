# Final Comprehensive Recovery Audit — 2026-04-21

## Scope
Full VS Code history cross-check of all 2370 `.py` files under
`CaseCrack/` to catch (a) modules still missing after prior recovery
sprints, (b) modules restored from *corrupted/older* history snapshots,
and (c) rough disk reimplementations that lost features present in
history ("rough duplicates still in use").

## Tooling (workspace root, retained)
- `_final_recovery_audit_v3.py` — main audit. Indexes all history
  snapshots, **rejects snapshots that are concatenation-corrupt
  (>1 `from __future__`) or fail AST-parse**, then picks the largest
  valid snapshot per resource. Classifies disk vs history into
  PURE_REGRESSION / REFACTORED / MINOR by top-level symbol diff.
- `_final_symbol_diff.py` / `_final_classify.py` — per-file detail.
- `_find_clean_snapshot.py <rel>` — lists every snapshot for a
  single resource with VALID / CORRUPT / SYNERR tag.
- `_final_restore_pure.py` / `_fix_corrupt_restores.py` — restorer
  with backup to `*.preregression.bak`.
- Reports: `_final_audit_regressions_v2.tsv`,
  `_final_audit_missing_v2.tsv`.

## Key discovery: corrupt history snapshots
Several history snapshots contain the *same file concatenated 2–3
times* (detected by `from __future__` appearing more than once). The
original audit's "largest snapshot per resource" heuristic silently
picked these corrupt blobs. **Always filter history candidates for
AST-validity before trusting them.** Example: latest snapshot of
`intel/github_client_base.py` was 38 KB with 3× `__future__`;
the largest valid one was 16.7 KB.

## Results

### Missing modules still referenced on disk: **0**
All 417 "missing" resources that have history snapshots are monolith
files that were intentionally split into subpackages (0 imports
remain). Verified with raw grep across the codebase:
`agent_roles`, `compliance`, `validation_fleet`, `persistent_agent`,
`world_model`, `confidence_ensemble`, `multi_agent_debate`,
`lookahead_engine`, `self_healing`, `adversarial_validation_agent`,
`persona_engine`, `target_mental_model`, `xss`, `strategic_llm_layer`,
`hierarchical_decomposition`, `tool_intelligence`, `memory_control`
all have 0 live imports (0 refs). `recon_dashboard` still has 247
imports but is satisfied by the same-named package directory.

### Pure regressions restored from valid history: **8**
History was a strict superset of disk; safe to overwrite.

| File | Disk→Hist | Refs |
|------|-----------|------|
| `tools/burp_enterprise/decision_orchestrator.py` | 111→201 KB | 6 |
| `tools/burp_enterprise/inference/model_management/model_cli.py` | 7→19 KB | 1 |
| `tools/burp_enterprise/inference/model_management/model_benchmarker.py` | 9→23 KB | 1 |
| `tests/test_organism_health_gaps.py` | 16→29 KB (valid) | 0 |
| `tools/burp_enterprise/intel/github_client_base.py` | 6→16 KB (valid) | 0 |
| `tools/burp_enterprise/output/findings_formatter.py` | 10→15 KB | 0 |
| `tools/burp_enterprise/mcp/mcp_server.py` | 31→46 KB | 0 |
| `tools/burp_enterprise/agents/bayesian_prioritizer.py` | 18→25 KB | 0 |

Plus dependency rescue: `tools/burp_enterprise/mcp/cognitive_tools.py`
(22 KB) — required by the restored `mcp_server.py`, fetched from
history. All 8 + dependency import cleanly under the workspace path
`CaseCrack/`.

Backups preserved at `<path>.preregression.bak`.

### "Rough duplicates" (REFACTORED): **38 files — manual review only**
Disk version was reimplemented during recovery sprints; has SOME
unique symbols AND is missing MANY symbols from history. These cannot
be safely auto-overwritten (doing so would lose the newer work). List
ordered by reference count and lost-symbol count is in
`_final_audit_regressions_v2.tsv`. Highest-impact:

| refs | lost / added | file |
|------|--------------|------|
| 15 | -15/+11 | `exploit_chains/synthesis_context.py` |
| 14 | -0/+4  | `burp_enterprise/__init__.py` (disk added lazy-registry) |
| 12 | -17/+10| `exploit_chains/synthesis_feedback.py` |
| 11 | -45/+15| `exploit_chains/payload_arbiter.py` |
| 9  | -61/+5 | `exploit_chains/weight_tuner.py` |
| 5  | -9/+21 | `hypothesis_engine.py` (disk actually improved) |
| 3  | -50/+57| `agents/llm_bridge.py` (disk added AnthropicClient) |
| 3  | -27/+19| `exploit_chains/genetic_forge.py` |
| 3  | -19/+1 | `recon_dashboard/server.py` |
| 2  | -46/+11| `tool_registry/output_parsers.py` |
| 2  | -45/+15| `reasoning/prompt_chains.py` |
| 2  | -40/+7 | `inference/gpu_governor.py` |
| …  | …      | (33 more in TSV) |

Strategy per file: open history snapshot alongside disk, merge missing
helpers/constants manually, keep disk's new symbols.

### MINOR diffs (3 files) — left alone
`tool_wrappers/dalfox_provider.py`, `platforms/generic.py`,
`recon_dashboard/atlas_api.py` — ≤3 symbols differ, likely
intentional.

## Rule
Before restoring any file from history, verify:
1. Snapshot AST-parses.
2. Snapshot contains **≤ 1** `from __future__ import` (guard against
   concatenation corruption — seen on ≥ 3 files in this workspace).
3. Snapshot is strictly largest among AST-valid candidates (not
   largest overall).

Then diff top-level symbols — if disk has any unique non-trivial
symbols, **do not overwrite**; merge manually.
