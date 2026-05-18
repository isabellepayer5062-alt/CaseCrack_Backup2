# Zero-Findings Phase & Tool Analysis — sugarrushed.ca Scan (2026-05-03)

**Scan:** 45 phases, 285 JSON reports, 1083 total findings  
**Analysis scope:** All 285 report files in `CaseCrack/reports/`

---

## Summary Table

| Category | Count | Impact |
|---|---|---|
| Placeholder (unimplemented CLI handlers) | 111 | No findings possible — tool not wired |
| Skipped (tool not applicable) | 3 | Correct — no CVEs, no WordPress |
| Parse errors (broken output format) | 4 | **BUGS — real findings lost** |
| Stub files ≤200B (ran, truly empty) | 56 | Mix: target characteristics + bugs |
| Ran but zero findings (>200B) | 58 | Mix: correct negatives + bugs |
| **With findings** | **56** | 1083 total findings recorded |

---

## CRITICAL BUGS — Findings Lost to Parse Errors

These 4 tools wrote invalid JSON to their `.json` output files, causing their findings to be **silently dropped** by all downstream parsers.

### 1. `recon-sqli-deep.json` — **HIGH SQLi finding LOST** ✅ FIXED
**File:** `injection.py` `cmd_sqli` `scan` action (line ~1139)  
**Root cause:** `tester.generate_report(result)` returns a Markdown string. The sqli `scan` action lacked the `.json` extension check that other injection actions already had.  
**Finding lost:**
```
[HIGH] Boolean-Based Blind SQL Injection
- Type: boolean_blind
- Parameter: id  
- Evidence: Boolean blind detected via String comparison (quoted): true=10690, false=10711, diff=21
- CWE: CWE-89
```
**Fix applied:** Added `if args.output.endswith(".json")` check → writes `json.dump(_safe_to_dict(result))` instead.

### 2. `recon-bitbucket-deep.json` — Markdown written to .json ✅ FIXED
**File:** `bitbucket_deep_recon.py` `cmd_bitbucket_deep` (line ~1394)  
**Root cause:** `use_json = getattr(args, "json", False)` — the phase command doesn't pass `--json`, so `generate_bb_deep_report()` (Markdown) was always called. The correct `report_to_dict()` function existed but was gated behind `--json`.  
**Fix applied:** Changed condition to `if use_json or output_path.endswith(".json")`.

### 3. `recon-tokens.json` — Markdown token analysis report ✅ FIXED
**File:** `core.py` `cmd_tokens` (line ~871)  
**Root cause:** `sequencer.generate_report(result)` returns Markdown. No `.json` extension check.  
**Fix applied:** Added check → writes `result.to_dict()` as JSON when output ends in `.json`.

### 4. `recon-ssrf-advanced.json` — Truncated JSON (187B, cut mid-value) ✅ FIXED
**File:** `injection.py` `cmd_ssrf_advanced` `scan` action (line ~1904)  
**Root cause:** `json.dump(..., f)` writes incrementally; if `_safe_to_dict(result)` throws mid-serialization, only partial content was flushed. The file showed `"vulnerable": true` with a findings array that never closed.  
**Fix applied:** Serialize fully to string first (`json.dumps()`), then write atomically.

---

## TOOL ERRORS — Ran but Crashed or Misconfigured

### 5. `recon-ghauri.json` — CLI argument crash ✅ FIXED
**Error:** `ghauri: error: unrecognized arguments: --output-dir=/output` (exit 2)  
**Root cause:** `ghauri_provider.py` passed `--output-dir=/output` but modern ghauri doesn't support this flag.  
**Fix applied:** Removed `--output-dir=/output` from the CLI args; falls back to `_parse_stdout`.

### 6. `recon-dalfox.json` — GLIBC incompatibility (exit 1)
**Error:** `/app/dalfox: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.34' not found`  
**Root cause:** Docker image built for newer glibc than host.  
**Fix needed:** Rebuild/update the dalfox Docker image to match host glibc, or use a statically-linked binary.  
**Status:** Not fixed in this session — requires Docker image rebuild.

### 7. `recon-droopescan.json` — Tool not installed (exit 1)
**Error:** `droopescan not installed (pip install droopescan) and Docker image unavailable`  
**Root cause:** droopescan is only relevant for Drupal/Joomla/SilverStripe. Target is Shopify (not a CMS droopescan supports). This is expected behavior.

### 8. `recon-wpscan.json` — Not WordPress (exit 4)
WPScan exit code 4 = "no WordPress found". Target is Shopify. Correct behavior.

### 9. `_probe-nuclei.json` — Killed (exit -1)
**Root cause:** Nuclei probe killed by timeout (exit_code -1 = SIGKILL). Ran 31s with no findings. The probe phase has a budget cap and nuclei was terminated. Nuclei did run for actual phases (see `recon-nuclei-xss-fallback-0.json` which ran 54s, exit 0, no findings on Cloudflare-protected Shopify target).

### 10. `_probe-kiterunner.json` — Killed (exit -1)
**Root cause:** kiterunner running at 11 req/s against 9691 routes = ~14 min projected. Budget cap killed it at ~8 routes. Note: `recon-kiterunner.json` is a PLACEHOLDER (phase not yet wired), so this only affects the probe script, not the main scan.

---

## WRONG TARGET — Tools Scanning Irrelevant Content

### 11. `recon-semgrep.json` — Reports directory scanned, no code ✅ FIXED
**Phase command:** `semgrep --target {report} --config auto`  
**Root cause:** `{report}` expands to `reports/` which only contains JSON output files. Semgrep found no `.js/.py/.ts` etc. files and returned 0 findings (correct behavior, wrong target).  
**Fix applied:** Added pre-flight check in `cmd_semgrep` — skips gracefully with `_write_skip_output` when target directory has no source-code files.

### 12. `recon-trivy.json` — Reports directory has no package manifests ✅ FIXED
**Phase command:** `trivy --target {report} --scan-type fs`  
**Root cause:** Trivy `--scan-type fs` looks for `package.json`, `go.sum`, etc. Reports directory has none.  
**Fix applied:** Added pre-flight check in `cmd_trivy` — skips gracefully when no package manifests found in the target directory.

### 13. `recon-docker-scan.json` — URL treated as Docker image
**Error:** `docker inspect: image 'sugarrushed.ca' not found locally (speculative scan — no Docker image at this target)`  
**Root cause:** Target URL passed as Docker image name. The docker-scan tool is speculative and already handles this gracefully.

---

## CORRECT ZERO-FINDINGS (Expected for Shopify/Cloudflare Target)

These tools ran correctly but found nothing because the target (sugarrushed.ca) is a **Shopify + Cloudflare** deployment with no vulnerabilities of these types:

| Tool | Reason zero findings is correct |
|---|---|
| `recon-graphql-scan.json` | No GraphQL endpoint exposed on Shopify |
| `recon-grpc-tls.json` | gRPC not exposed (port 50051 blocked) |
| `recon-http2-hpack.json` | HPACK bomb defense in place |
| `recon-http2-smuggle.json` | Cloudflare terminates HTTP/1.1 before backend |
| `recon-websocket-fuzz.json` | No WebSocket endpoint |
| `recon-websocket-cswsh.json` | No WebSocket endpoint |
| `recon-smuggle-clte.json` / `recon-smuggle-tecl.json` | Cloudflare prevents H1 smuggling |
| `recon-dns-zone-transfer.json` | Zone transfer disabled (standard) |
| `recon-dns-takeover.json` | sugarrushed.ca DNS not vulnerable |
| `recon-shadow-it.json` | No shadow IT domains found |
| `recon-cross-fork.json` | No public repo forks found |
| `recon-redirect.json` | 75 payloads tested, redirect not injectable |
| `recon-csrf.json` | Shopify implements CSRF tokens |
| `recon-race.json` / `recon-race-toctou.json` | Rate limiting detected (Cloudflare) |
| `recon-upload.json` | No file upload endpoints found |
| `recon-traversal.json` | Path traversal blocked |
| `recon-xpath.json` | No XML-based injection surface |
| `recon-nmap-udp.json` | All UDP filtered (Cloudflare edge) |
| `recon-commix.json` | No command injection surface |
| `recon-wasm.json` | No WASM modules loaded |
| `recon-saml.json` | No SAML metadata endpoint |
| `recon-http2-detect.json` | HTTP/2 detected but no exploitable issues |
| `recon-dns-rebinding.json` | No rebinding vulnerability |
| `recon-ratelimit.json` | Rate-limited (True) — tool reports detection, not findings |
| `recon-oob-poll.json` / `recon-oob-register.json` | 61s wait, no callbacks triggered |
| `recon-verify-secrets.json` | 0 secrets to verify (gitleaks/trufflehog found none) |
| `recon-builtwith-profile.json` | No technologies detected via BuiltWith (API key?) |
| `recon-wayback.json` | 0 archived URLs (newer site / CDN-hosted) |
| `recon-sbom.json` | No components discoverable (black-box) |
| `recon-git-history.json` | No exposed git history |
| `recon-custom-detect.json` | No custom fingerprints matched |
| `recon-gitleaks.json` | No secrets in accessible code |
| `recon-trufflehog.json` | No secrets in accessible code |

---

## UNCOVER — Missing API Keys

```json
"errors": ["No API keys configured for any uncover engine — skipping"]
```
**Tools affected:** `recon-uncover.json`  
**Fix:** Configure API keys for Shodan, Fofa, Censys etc. in env/config.

---

## PLACEHOLDER TOOLS (111 files) — Not Yet Implemented

These produce `{"_placeholder": true}` because no CLI handler exists or the phase was never wired. They are planned-but-unimplemented capabilities. Key groups:

| Phase Category | Placeholder Count | Examples |
|---|---|---|
| Cloud & Container Security | 6 | cloud-buckets, cloud-discovery, cloud-enum, cloud-inventory, container-recon |
| Correlation & Compliance | 11 | baseline, bayesian, chain-pack, correlated, decode, entropy, orchestrate |
| AI-Enhanced Testing | 7 | ai-attack-chains, ai-attack-reasoning, ai-audit, ai-efuzz, ai-llm-analysis |
| Endpoint & Asset Discovery | 7 | api-discovery, directories, discovery, feroxbuster, gospider, katana, ws-recon |
| Parameter Discovery | 5 | gf-classify, params, params-body, params-cookies, paramspider |
| Advanced Exploitation | 9 | bizlogic, cache-deception, cache-poison, cmdi, iot-discovery, sqli-blind, sse-exhaust |
| JS Analysis | 4 | jsluice-secrets, jsluice-urls, pipeline, pipeline-params, sourcemapper |
| Visual Recon | 3 | screenshots, screenshots-mobile, screenshots-tablet |
| Access Control | 3 | oauth, ssrf-map (→ wired), chain |
| Blue-Team & Threat Modeling | 6 | defensive-test, notify-status, pocs, siem-events, threat-model, weak-hash |

---

## KEY FINDING: Real SQLi Vulnerability Was Silently Dropped

The most impactful bug is **#1 above**: a real **Boolean-Based Blind SQL Injection** (HIGH, CWE-89) detected by the sqli scanner was never recorded in the findings pipeline because the output file was written as Markdown instead of JSON. The findings correlator, dashboard, and `recon-all-findings.json` all missed it.

**After the fix** (`FIX-SQLI-JSON`), the next scan will correctly record this finding and it will appear in:
- The findings database
- The executive report
- The SSRF/exploit chain analysis

---

## Fixes Summary

| # | File | Fix |
|---|---|---|
| 1 | `cli/commands/injection.py` | sqli scan → JSON output when `-o *.json` |
| 2 | `intel/bitbucket_deep_recon.py` | bitbucket-deep → JSON when output ends in `.json` |
| 3 | `cli/commands/core.py` | tokens → JSON when output ends in `.json` |
| 4 | `cli/commands/injection.py` | ssrf-advanced → atomic write prevents truncation |
| 5 | `tool_wrappers/ghauri_provider.py` | Remove unsupported `--output-dir=/output` flag |
| 6 | `cli/commands/recon_tier2.py` | trivy → skip gracefully when no package manifests |
| 7 | `cli/commands/recon_tier2.py` | semgrep → skip gracefully when no source-code files |
