cd "c:\Users\ya754\CaseCrack v1.0"
$portFile = "CaseCrack\.dashboard_port.json"
if (Test-Path $portFile) {
  $port = (Get-Content $portFile -Raw | ConvertFrom-Json).port
  Write-Host "Recorded port: $port"
}
$conn = Get-NetTCPConnection -LocalPort 8770 -State Listen -ErrorAction SilentlyContinue
if ($conn) {
  foreach ($c in $conn) {
    Write-Host "Killing PID $($c.OwningProcess) listening on 8770"
    Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
  }
}
Start-Sleep -Seconds 2
Write-Host "Done."
