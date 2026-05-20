Set-Location 'c:\Users\ya754\CaseCrack v1.0\CaseCrack'

$PASS = 0
$FAIL = 0

function chk {
  param([string]$file, [string]$pattern, [string]$label, [switch]$regex)
  if (-not (Test-Path $file)) { 
    Write-Host ("  MISSING_FILE [{0}] ({1})" -f $label, $file)
    $script:FAIL++
    return
  }
  if ($regex) { $hit = Select-String -Path $file -Pattern $pattern -List -ErrorAction SilentlyContinue }
  else         { $hit = Select-String -Path $file -Pattern $pattern -SimpleMatch -List -ErrorAction SilentlyContinue }
  if ($hit) { Write-Host ("  OK   [{0}]" -f $label); $script:PASS++ }
  else       { Write-Host ("  MISS [{0}] in {1}" -f $label, $file); $script:FAIL++ }
}

Write-Host "`n--- runner.py ---"
chk "tools/burp_enterprise/recon_dashboard/runner.py" "maxlen=10000" "deque(maxlen=10000)"
chk "tools/burp_enterprise/recon_dashboard/runner.py" "(30, 34, 42)" "phase 42 in pre-hook"

Write-Host "`n--- recon_context.py ---"
$ctx = if (Test-Path "tools/burp_enterprise/recon/recon_context.py") {"tools/burp_enterprise/recon/recon_context.py"} else {"tools/burp_enterprise/recon_context.py"}
chk $ctx "normalize_finding" "normalize_finding"
chk $ctx "coverage_degradations" "coverage_degradations"
chk $ctx "phases_succeeded" "phases_succeeded"
chk $ctx "challenge_suppression" "challenge_suppression"

Write-Host "`n--- finding_parsers.py ---"
chk "tools/burp_enterprise/recon_dashboard/finding_parsers.py" "_is_dns_phase" "_is_dns_phase guard"
chk "tools/burp_enterprise/recon_dashboard/finding_parsers.py" "sm_endpoint" "source map url field"

Write-Host "`n--- scheduler.py ---"
chk "tools/burp_enterprise/recon_dashboard/scheduler.py" "_multi_acquire_lock" "_multi_acquire_lock"
chk "tools/burp_enterprise/recon_dashboard/scheduler.py" "admission" "admission lock logic" -regex

Write-Host "`n--- unified_attack_graph.py ---"
chk "tools/burp_enterprise/unified_attack_graph.py" "start_session" "start_session method"
chk "tools/burp_enterprise/unified_attack_graph.py" ".clear()" "clear() call in start_session" -regex

Write-Host "`n--- db_registry.py ---"
chk "tools/burp_enterprise/database/db_registry.py" "malformed" "malformed detection"
chk "tools/burp_enterprise/database/db_registry.py" "DROP TABLE" "DROP TABLE recovery"

Write-Host "`n--- path_traversal.py ---"
chk "tools/burp_enterprise/scanners/path_traversal.py" "_FILE_CONTENT_MARKERS" "_FILE_CONTENT_MARKERS"
chk "tools/burp_enterprise/scanners/path_traversal.py" "_detect_base64_content" "_detect_base64_content"

Write-Host "`n--- email_security.py ---"
chk "tools/burp_enterprise/integrations/email_security.py" "url.*domain" "url field in to_dict" -regex

Write-Host "`n--- dom_xss_analyzer.py ---"
chk "tools/burp_enterprise/scanners/dom_xss_analyzer.py" "cdn" "CDN host check" -regex
chk "tools/burp_enterprise/scanners/dom_xss_analyzer.py" "MEDIUM" "CDN downgrade to MEDIUM"

Write-Host "`n--- recon_pipeline.py ---"
chk "tools/burp_enterprise/recon/recon_pipeline.py" "_stage_email_security" "_stage_email_security"

Write-Host "`n--- gateway_core.py ---"
chk "tools/burp_enterprise/mcp/gateway_core.py" "build_sse_payload" "build_sse_payload"
chk "tools/burp_enterprise/mcp/gateway_core.py" "map_status_code" "map_status_code"

Write-Host "`n--- mcp_http_server.py ---"
chk "tools/burp_enterprise/mcp/mcp_http_server.py" "gateway_core" "imports gateway_core"

Write-Host "`n--- server.py ---"
chk "tools/burp_enterprise/recon_dashboard/server.py" "gateway_core" "imports gateway_core"
chk "tools/burp_enterprise/recon_dashboard/server.py" "register_persistent_agent_routes" "persistent agent routes"

Write-Host "`n--- attack_strategy_engine.py ---"
$ase = "tools/burp_enterprise/recon_dashboard/attack_strategy_engine.py"
chk $ase "score_target_value" "score_target_value"
chk $ase "target_scoring" "target_scoring import"

Write-Host "`n--- cli/commands/findings.py ---"
$cfind = "tools/burp_enterprise/cli/commands/findings.py"
if (Test-Path $cfind) {
  chk $cfind "from.file" "from-file handling" -regex
  chk $cfind "RequestStore" "fallthrough to RequestStore" -regex
} else {
  Write-Host ("  MISSING_FILE [findings.py] ({0})" -f $cfind); $script:FAIL++
}

Write-Host "`n--- paramspider Dockerfile ---"
chk "tools/docker/paramspider/Dockerfile" "git+" "git+github install"

Write-Host "`n--- dorking.py ---"
$dorkPaths = @(
  "tools/burp_enterprise/recon/dorking.py",
  "tools/burp_enterprise/recon_dashboard/dorking.py",
  "tools/burp_enterprise/dorking.py"
)
$dorkFound = $false
foreach ($dp in $dorkPaths) {
  if (Test-Path $dp) {
    Write-Host ("  OK   [dorking.py exists at {0}]" -f $dp)
    $dorkFound = $true
    $script:PASS++
    chk $dp "max_retries.*5" "max_retries=5" -regex
    chk $dp "_BACKOFF_MAX" "_BACKOFF_MAX"
  }
}
if (-not $dorkFound) {
  Write-Host "  MISS [dorking.py] - file completely absent from repo"
  $script:FAIL++
}

Write-Host ("`n=== RESULT: {0} OK  {1} MISSING ===" -f $PASS, $FAIL)
