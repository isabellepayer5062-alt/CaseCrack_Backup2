$ws = 'C:\Users\ya754\AppData\Roaming\Code\User\workspaceStorage\9e51499eea65fa44abab72645f162d00'
# Also include the latest sessions
$sessions = @(
  'fe741aee-1c2f-4369-88dc-3b1ec98b7734',
  '251326ca-7dc0-4d81-9d57-58d76f6c32ba',
  '4ee01150-c401-4f48-8b23-ce30c85da2d0',
  'fae709ba-0fb2-4b2c-8623-87175702540e',
  '2d6e604f-d895-4e48-b184-5d506e917117',
  'c71db976-71f6-40b1-af22-022cc2ec09aa'
)
foreach ($sid in $sessions) {
  $sjson = Join-Path $ws "chatEditingSessions\$sid\state.json"
  if (-not (Test-Path $sjson)) { continue }
  Write-Host "===== $sid ====="
  try {
    $j = Get-Content $sjson -Raw | ConvertFrom-Json
    # Walk JSON for any property named 'resourceId' or 'currentContentHash' or similar
    $j | ConvertTo-Json -Depth 6 -Compress | Out-File "c:\Users\ya754\CaseCrack v1.0\_state_$sid.json"
    Write-Host "  saved state to _state_$sid.json (size $((Get-Item "c:\Users\ya754\CaseCrack v1.0\_state_$sid.json").Length))"
  } catch { Write-Host "  ERROR parsing: $_" }
}
