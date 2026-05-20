# Recovery Report — 2026-04-16

## Summary

A bug in `dead_module_cleanup.py` (`shutil.rmtree` on any directory returned by
`module_to_paths`) over-deleted ~770 modules instead of the intended 278
garbage entries. Recovery via **VS Code local history**
(`%APPDATA%\Code\User\History`) restored 407 files, including **all 50
reconnect candidates** and the `_cold_storage/` set.

## Final State

| Metric | Pre-damage | Post-damage | Post-recovery |
|---|---|---|---|
| Total modules | 1666 | 686 | **1092** |
| Reachable from 19 entrypoints | 810 | 500 | **721** |
| Dangling imports | 30 | 124 | 372 |
| `_cold_storage/` files | — | 56 | 56 (intact) |
| Reconnect candidates alive | 50 | 30 | **50** |

## Recovery Sources Evaluated

| Source | Useful? | Details |
|---|---|---|
| Git history | ❌ | Not a git repo |
| Backup: `CaseCrack v1.0 - Copy` | ❌ | 217 files, zero overlap with missing set |
| Backup: `CaseCrack v1.0 - Coinbase` | ❌ | 214 files, zero overlap |
| Backup: `CaseCrack v1.0 - PayPal` | ❌ | 215 files, zero overlap |
| Recycle Bin | ❌ | Empty |
| Orphan `.pyc` files | ❌ | 170 at top-level only, none in deleted subdirs |
| **VS Code local history** | ✅ | **407 files restored from 562 available** |

## Still Missing (Permanently Lost)

**283 modules** classified as runtime-reachable (108) or conditionally
reachable (175) have no recovery source. These were files never opened in
VS Code on this machine (so no local history) and not in any backup. They
manifest as the 372 dangling imports in the current reality map.

Notable lost subsystems (partial):
- `agents/` — autonomous_exploitation, autonomy, copilot
- `caap/` — browser_exploitation_engine, caap_formatter
- `cloud/` — bucket_scanner, cloud_asset_discovery, cloud_inventory, container_recon, iam_attack_paths
- `discovery_pkg/` — browser_extension_recon, postman_scanner, template_fingerprint
- `exploit_chains/` — chain_includes, chain_matcher, chain_output, chain_packs
- `integrations/` — ci_cd_integration, dependency_health, notification_webhooks, nuclei_template_generator, updater, vcs_integration
- `intel/` — asn_intel, azure_devops_deep_recon, many others
- Full list: run `_verify_recovery.py`

Design intent for most of these is preserved in `/memories/repo/` notes
(e.g. `ci-cd-integration-*`, `cloud-asset-*`, `integrations-*`).
Reconstruction from memory + requirements is the only path forward for
these modules.

## Bug Fix Applied

`dead_module_cleanup.py::delete_garbage` — removed the `shutil.rmtree(src)`
branch entirely. Now only deletes `.py` files (including a package's
`__init__.py`), never directories. Empty dirs are cleaned up later by the
existing `cleanup_empty_dirs()` which already had the right safety rails.
Added a prominent docstring warning documenting the 2026-04-16 incident.

## Artifacts

- `_recovery_plan.json` — 562 files mapped from VS Code history
- `_execute_recovery.py` — restoration script (idempotent; filters garbage/cold)
- `_verify_recovery.py` — confirms what's still missing and what was saved
- `dead_module_cleanup_log.json` — original incident log (pre-fix)
- `_cold_storage/` — 56 cold-archive files (unharmed)

## Next Step

User's pending request: **"create a comprehensive roadmap for reconnecting
all of the candidate identified in both the 'True Dead Module Classifier'
and the '3-Bucket Triage'"**.

Now unblocked — proceeding to roadmap.
