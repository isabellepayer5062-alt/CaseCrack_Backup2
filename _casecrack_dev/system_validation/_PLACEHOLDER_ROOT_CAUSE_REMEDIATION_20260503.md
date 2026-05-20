# Placeholder JSON Root Cause and Remediation - 2026-05-03

## Summary

108 of 285 scan report JSON files remained as runner-created placeholders:

```json
{"_placeholder": true, "findings": [], "errors": []}
```

The tools were registered and several worked when invoked directly. The failures came from orchestration and timeout behavior around pre-created output files, not missing CLI handlers.

## Confirmed Root Causes

1. Broken Docker command-cap propagation
   - File: `CaseCrack/tools/burp_enterprise/tool_wrappers/_base.py`
   - `VENATOR_CMD_TIMEOUT` was only applied when `timeout is None`.
   - Providers always pass an explicit `scan_timeout`, usually `self.timeout`, so the cap branch never ran.
   - Docker tools such as katana, gospider, feroxbuster, paramspider, jsluice, nomore403, sourcemapper, and httpx could run longer than the runner `cmd_cap` and be killed mid-write.

2. Timeout kill left placeholders on disk
   - File: `CaseCrack/tools/burp_enterprise/recon_dashboard/command_executor.py`
   - The executor salvaged a non-placeholder file after timeout, but if the output file was still a placeholder it returned `None` without replacing the file.

3. LLM-required command gating was provider-blind
   - File: `CaseCrack/tools/burp_enterprise/recon_dashboard/runner.py`
   - The runner treated LLM availability as API-key-only.
   - Local Ollama could be running and usable, but AI phases were still skipped before LLM auto-detection could run.

4. GitHub Models and Ollama fallback were present but priority/defaults were mismatched
   - File: `CaseCrack/tools/burp_enterprise/agents/llm_bridge.py`
   - Existing bridge had GitHub Models and Ollama clients.
   - Auto-detection preferred Ollama before GitHub Models.
   - Ollama defaulted to `llama3`, which was not installed in the verified environment.
   - GitHub Models fallback endpoint required model names without provider prefix.

5. Execution orchestrator slow-start whitelist missed several Docker tools
   - File: `CaseCrack/tools/burp_enterprise/recon_dashboard/execution_orchestrator.py`
   - Docker startup can be silent long enough to trigger false early-stall decisions under parallel load.

6. Disk space phase abort
   - Scan log showed Phase 17 aborts from the 2 GB disk floor.
   - This is operational, not a handler-registration issue. Current free space was later verified above the threshold.

## Remediations Applied

1. `FIX-CMDCAP-SYS-2`
   - `VENATOR_CMD_TIMEOUT` is now applied regardless of whether a provider passed an explicit timeout.
   - Effective Docker timeout is `min(local_timeout, VENATOR_CMD_TIMEOUT - 10s)`, with a 30s floor.
   - This makes Docker finish before the runner hard-kills the Python subprocess.

2. `FIX-TIMEOUT-PLACEHOLDER`
   - Timeout paths now overwrite lingering placeholder JSON with:
     - `skipped: true`
     - `errors: ["Command timed out after Ns"]`
     - `findings: []`
   - This prevents stale placeholders from being miscounted as degraded command output.

3. `FIX-EO-PLACEHOLDER`
   - Execution-orchestrator termination now also overwrites a lingering placeholder or invalid output file.
   - The disk file receives `skipped: true`, `_eo_terminated: true`, and an explicit termination error.
   - This closes the path where EO returned an in-memory success-like result while the report directory still contained `_placeholder: true`.

4. `FIX-LLM-SKIP-PLACEHOLDER`
   - LLM-dependent command skips now write a skip marker when a placeholder path already exists.
   - Skip reason changed from API-key-only language to provider availability.

5. GitHub Models first, Ollama second fallback
   - `LLM_PROVIDER=github`, `github_models`, `copilot`, `github_copilot`, and `github-copilot` now normalize to `github_models`.
   - Auto-detection priority is now:
     1. GitHub Models / Copilot-style free external LLM using `GITHUB_MODELS_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN`
     2. Paid external providers (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`)
     3. Local Ollama if reachable
     4. Mock
   - Ollama fallback dynamically selects the best installed model, preferring `qwen2.5-coder:7b`.
   - GitHub Models now strips provider prefixes such as `openai/` before calling fallback inference endpoints.

6. Runner LLM gate now accepts local provider availability
   - `StandaloneReconRunner._check_llm_key()` now checks the canonical agent LLM config.
   - Ollama/local providers enable AI phases even without API keys.

7. Docker slow-start whitelist expanded
   - Added or extended grace windows for `katana`, `gospider`, `feroxbuster`, `jsluice`, `sourcemapper`, `nomore403`, `paramspider`, `httpx`, and `vhostfinder`.

## Verification

- GitHub Models probe succeeded with current `GITHUB_TOKEN`:
  - Provider: `github_models`
  - Model configured: `openai/gpt-4o-mini`
  - Effective model: `gpt-4o-mini-2024-07-18`
  - Response: `OK`

- Simulated no external LLM credentials:
  - Provider: `ollama`
  - Model: `qwen2.5-coder:7b`
  - Runner LLM availability: enabled

- Scratch cleanup:
  - No `CaseCrack/reports/_test-*.json` files were present.

- Python validation:
   - Pylance found no syntax errors in touched Python files.
   - `py_compile` succeeded for `_base.py`, `command_executor.py`, `runner.py`, `execution_orchestrator.py`, `llm_helpers.py`, and `llm_bridge.py`.

- Docker timeout cap probe:
   - With `VENATOR_CMD_TIMEOUT=240` and provider timeout `260`, effective Docker timeout is `230`.
   - With `VENATOR_CMD_TIMEOUT=20`, the safety floor keeps effective timeout at `30`.

## Notes

- This uses GitHub Models free-tier API semantics, not an unattended call into the VS Code Copilot Chat session. The repo already had GitHub Models client support, and the verified token path works without scraping editor authentication state.
- If all external credentials are removed and Ollama is stopped, LLM-required phases are skipped with explicit skip JSON instead of leaving placeholders.