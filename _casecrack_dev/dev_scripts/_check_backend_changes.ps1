Set-Location 'c:\Users\ya754\CaseCrack v1.0\CaseCrack'

function Check-Symbol {
  param($file, $pattern, $label)
  $hit = Select-String -Path $file -Pattern $pattern -SimpleMatch -List -ErrorAction SilentlyContinue
  if ($hit) { Write-Host ("  OK  [{0}] in {1}" -f $label, $file) }
  else       { Write-Host ("  MISS[{0}] in {1}" -f $label, $file) }
}

function Check-Regex {
  param($file, $pattern, $label)
  $hit = Select-String -Path $file -Pattern $pattern -List -ErrorAction SilentlyContinue
  if ($hit) { Write-Host ("  OK  [{0}] in {1}" -f $label, $file) }
  else       { Write-Host ("  MISS[{0}] in {1}" -f $label, $file) }
}

Write-Host "`n=== runner.py — phase 42 pre-hook + deque 10000 ==="
$runner = "tools/burp_enterprise/recon_dashboard/runner.py"
Check-Regex $runner "42" "phase 42 in pre-hook set"
Check-Regex $runner "maxlen=10000" "deque maxlen=10000"

Write-Host "`n=== recon_context.py — normalize_finding + coverage_degradations ==="
$ctx = "tools/burp_enterprise/recon_context.py"
if (-not (Test-Path $ctx)) { $ctx = "tools/burp_enterprise/recon/recon_context.py" }
Check-Symbol $ctx "normalize_finding" "normalize_finding"
Check-Symbol $ctx "coverage_degradations" "coverage_degradations"
Check-Symbol $ctx "phases_succeeded" "phases_succeeded"
Check-Symbol $ctx "challenge_suppression" "challenge_suppression"

Write-Host "`n=== finding_parsers.py — _is_dns_phase + source map url ==="
$fp = "tools/burp_enterprise/recon_dashboard/finding_parsers.py"
Check-Symbol $fp "_is_dns_phase" "_is_dns_phase guard"
Check-Regex  $fp '"url": sm_endpoint' "source map url field"

Write-Host "`n=== scheduler.py — multi-weight admission lock ==="
$sched = "tools/burp_enterprise/recon_dashboard/scheduler.py"
Check-Symbol $sched "_multi_acquire_lock" "_multi_acquire_lock"
Check-Symbol $sched "TestFix138" "regression test comment ref"
Check-Regex  $sched "admission" "admission lock"

Write-Host "`n=== unified_attack_graph.py — start_session clear ==="
$uag = "tools/burp_enterprise/unified_attack_graph.py"
Check-Symbol $uag "start_session" "start_session"
Check-Regex  $uag "nodes.*clear|clear.*nodes" "clear nodes/edges"

Write-Host "`n=== db_registry.py — DROP+CREATE recovery ==="
$db = "tools/burp_enterprise/database/db_registry.py"
Check-Symbol $db "malformed" "malformed detection"
Check-Symbol $db "DROP TABLE" "DROP TABLE recovery"

Write-Host "`n=== path_traversal.py — _FILE_CONTENT_MARKERS ==="
$pt = "tools/burp_enterprise/scanners/path_traversal.py"
Check-Symbol $pt "_FILE_CONTENT_MARKERS" "_FILE_CONTENT_MARKERS"
Check-Symbol $pt "_detect_base64_content" "_detect_base64_content"

Write-Host "`n=== email_security.py — EmailFinding url field ==="
$em = "tools/burp_enterprise/integrations/email_security.py"
Check-Regex  $em '"url".*domain' "url field in EmailFinding.to_dict"

Write-Host "`n=== dom_xss_analyzer.py — CDN JS host check ==="
$dxss = "tools/burp_enterprise/scanners/dom_xss_analyzer.py"
Check-Symbol $dxss "cdn" "CDN host check (lower)"
Check-Regex  $dxss "CRITICAL.*MEDIUM|downgrade" "severity downgrade"

Write-Host "`n=== recon_pipeline.py — email auth url field ==="
$rp = "tools/burp_enterprise/recon/recon_pipeline.py"
Check-Regex  $rp '"url".*domain.*@\|domain' "email stage url field"

Write-Host "`n=== gateway_core.py — shared gateway core ==="
$gc = "tools/burp_enterprise/mcp/gateway_core.py"
Check-Symbol $gc "def build_sse_payload" "build_sse_payload"
Check-Symbol $gc "def map_status_code" "map_status_code"

Write-Host "`n=== mcp_http_server.py — delegates to gateway_core ==="
$mcp = "tools/burp_enterprise/mcp/mcp_http_server.py"
Check-Symbol $mcp "gateway_core" "imports gateway_core"

Write-Host "`n=== server.py — persistent agent routes + gateway_core ==="
$srv = "tools/burp_enterprise/recon_dashboard/server.py"
Check-Symbol $srv "gateway_core" "imports gateway_core"
Check-Symbol $srv "register_persistent_agent_routes" "persistent agent routes"

Write-Host "`n=== attack_strategy_engine.py — target scoring ==="
$ase = "tools/burp_enterprise/recon_dashboard/attack_strategy_engine.py"
if (-not (Test-Path $ase)) { Write-Host "  MISS  attack_strategy_engine.py not found" }
else {
  Check-Symbol $ase "score_target_value" "score_target_value"
  Check-Symbol $ase "target_scoring" "target_scoring import"
}

Write-Host "`n=== cli/commands/findings.py — from-file fallthrough ==="
$cfind = "tools/burp_enterprise/cli/commands/findings.py"
if (-not (Test-Path $cfind)) { Write-Host "  MISS  cli/commands/findings.py not found" }
else {
  Check-Regex  $cfind "fall.*through|fallthrough|from.file.*fall" "from-file fallthrough"
}

Write-Host "`n=== paramspider Dockerfile — github install ==="
$dock = "tools/docker/paramspider/Dockerfile"
Check-Symbol $dock "git+" "git+github install"

Write-Host "`n=== dorking.py — MISSING? ==="
$dork_paths = @(
  "tools/burp_enterprise/recon/dorking.py",
  "tools/burp_enterprise/recon_dashboard/dorking.py",
  "tools/burp_enterprise/dorking.py"
)
$found = $false
foreach ($p in $dork_paths) {
  if (Test-Path $p) { Write-Host "  OK  $p  $((Get-Item $p).Length) B"; $found=$true }
}
if (-not $found) { 
  Write-Host "  MISS  dorking.py not found at any standard path"
}
