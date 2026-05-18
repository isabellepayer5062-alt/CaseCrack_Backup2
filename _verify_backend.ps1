$root = "c:\Users\ya754\CaseCrack v1.0\CaseCrack"
Set-Location $root
$files = @(
  "tools/burp_enterprise/recon_dashboard/runner.py",
  "tools/burp_enterprise/recon_dashboard/server.py",
  "tools/burp_enterprise/mcp/gateway_core.py",
  "tools/burp_enterprise/recon_dashboard/recon_context.py",
  "tools/burp_enterprise/scanners/path_traversal.py",
  "tools/burp_enterprise/integrations/email_security.py",
  "tools/burp_enterprise/recon_dashboard/finding_parsers.py",
  "tools/burp_enterprise/recon/recon_pipeline.py",
  "tools/burp_enterprise/scanners/dom_xss_analyzer.py",
  "tools/burp_enterprise/database/db_registry.py",
  "tools/burp_enterprise/recon_dashboard/scheduler.py",
  "tools/burp_enterprise/unified_attack_graph.py",
  "cli/commands/findings.py",
  "tools/burp_enterprise/recon/dorking.py",
  "tools/burp_enterprise/attack_strategy_engine.py",
  "tools/burp_enterprise/mcp/mcp_http_server.py",
  "tools/docker/paramspider/Dockerfile"
)
foreach ($f in $files) {
  if (Test-Path $f) {
    Write-Host ("OK    {0,-70} {1,8} B" -f $f, (Get-Item $f).Length)
  } else {
    Write-Host ("MISS  {0}" -f $f)
  }
}
