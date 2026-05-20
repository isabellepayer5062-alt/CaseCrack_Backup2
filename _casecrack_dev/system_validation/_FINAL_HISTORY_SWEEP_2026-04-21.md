# Comprehensive History Sweep — Final (2026-04-21 session 3)

Third-pass audit after `vscode-history-recovery-scan-2026-04-21` and
`final-comprehensive-recovery-audit-2026-04-21`. Extends the audit to
**all file extensions** (.css, .js, .html, .ts, .tsx, .md, .json, etc.)
not just `.py`.

## Method
- Indexed all `%APPDATA%\Code\User\History\*\entries.json` (10,467 dirs,
  32,232 snapshots).
- URL-decoded URIs (`urllib.parse.unquote`) — covers `CaseCrack v1.0`
  space-encoded paths.
- Keyed by **path tail2** (`parent/file.ext`).
- Filtered history results to URIs containing workspace hints
  (`casecrack/`, `casecrack v1.0/`, `tools/burp_enterprise/`, etc.).
- Compared against 3,247 disk files across the workspace.
- Script: `_audit_history_final_sweep.py`; reports
  `_final_sweep_missing.tsv`, `_final_sweep_regressed.tsv`,
  `_final_sweep_summary.txt`.

## Results

| Bucket | Raw | Workspace-scoped | Actionable |
|--------|-----|------------------|------------|
| Missing on disk | 1688 | 7 | 3 |
| Disk smaller than history | 12 | 11 | 4 |

Most "missing" hits were from other VS Code projects sharing the same
history store (`shopigy/`, `redactify/`, `lib/`, `paypal-checkout/`,
`stockitai-main`, etc.).

## Actionable findings — all FRONTEND assets

**Prior `.py` audits already restored 116 backend modules.** This sweep
revealed the **frontend pair was missed**: backends were recovered but
matching dashboard panels were never re-restored.

### Frontend regressions (4)
| File | Disk | History | Lost |
|------|------|---------|------|
| `static/css/panel-dashboard.css` | 14 KB | 106 KB | 568 CSS classes (`ach-*`, `ai-insight*`, `ai-graph-mini`, …); only 20/588 absorbed by `recon-dashboard.css` |
| `static/js/panel-dashboard.js` | 86 KB | 236 KB | 47 functions (`_buildConsoleHtml`, `_refreshAll`, `_initContextMenu`, sparkline/console/keyboard helpers); only 15/62 absorbed by `recon-dashboard.js` |
| `static/css/intelligence-experience.css` | 18 KB | 34 KB | 57 `ix-*` classes (badge variants, learning-stat, error states); 0 absorbed elsewhere |
| `static/html/recon-dashboard-body.html` | 92 KB | 190 KB (path was `caap/static/html/...`) | Parallel richer variant: 564 unique IDs incl. full `acMcb*` model-control-bar, `acModelSelector*`, `acSession*` (Anthropic model selector UI) |

### Missing frontend files (3)
| File | Size | Notes |
|------|------|-------|
| `recon_dashboard/static/js/persistent-agent.js` | 81 KB | Frontend for `persistent_agent.py` (restored as backend in prior session — orphan backend) |
| `static/js/operator-intelligence.js` | 36 KB | Frontend for restored `operator_feedback.py` + `outcome_narrative_engine.py` + `action_rationale_engine.py` (orphan backends) |
| `.github/agents/recon.agent.md` | 54 KB | Copilot Recon agent definition |

## False positives confirmed (not regressions)
- 7 Python splits previously documented as intentional refactors:
  `routes_llm.py`, `routes_standalone.py`, `llm_helpers.py`,
  `finding_pipeline.py`, `atlas_api.py`, `payload_synthesis_engine.py`,
  `graph_suggestions.py`.
- `panel-dashboard.new.js` (history) — sha256 identical to current
  `panel-dashboard.js`; just an older draft name.
- `types/index.ts` — `.runs/sourcemapper_output/...` scan artifact
  matched a stockitai-main snapshot.
- `_archive/*` files — intentionally archived.
- `tools/burp_enterprise/cli.py` from `shopigy/` URI — different project.

## Conclusion
Backend (Python) recovery is complete. **Frontend assets have a real,
moderate gap** — three orphan backend subsystems (persistent agent,
operator override, outcome narratives) restored without their UI panels,
plus shrunken `panel-dashboard.css/js` and `intelligence-experience.css`.
Restoring these would re-enable the v3 panel dashboard UI and the
operator-intelligence overlays.

## Rule for future sweeps
Always extend extension set beyond `.py`. URL-decode + tail-key alone
isn't enough — must also filter to workspace-scoped URIs to discard the
~95% of history snapshots from other projects sharing the store.
