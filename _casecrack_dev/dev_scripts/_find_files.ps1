Set-Location 'c:\Users\ya754\CaseCrack v1.0\CaseCrack'

Write-Host "=== findings.py ==="
Get-ChildItem . -Recurse -Filter 'findings.py' -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize

Write-Host "=== recon_context.py ==="
Get-ChildItem . -Recurse -Filter 'recon_context.py' -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize

Write-Host "=== attack_strategy_engine.py ==="
Get-ChildItem . -Recurse -Filter 'attack_strategy_engine.py' -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize

Write-Host "=== dorking* ==="
Get-ChildItem . -Recurse -Filter 'dorking*' -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize
