$ws='C:\Users\ya754\AppData\Roaming\Code\User\workspaceStorage\9e51499eea65fa44abab72645f162d00'
$sids = @('4ee01150-c401-4f48-8b23-ce30c85da2d0','fae709ba-0fb2-4b2c-8623-87175702540e','2d6e604f-d895-4e48-b184-5d506e917117','c71db976-71f6-40b1-af22-022cc2ec09aa')
foreach ($sid in $sids) {
  $cdir = "$ws\chatEditingSessions\$sid\contents"
  if (-not (Test-Path $cdir)) { continue }
  Write-Host "===== $($sid.Substring(0,8)) ====="
  Get-ChildItem $cdir -File | Where-Object { $_.Length -lt 1000000 -and $_.Length -gt 100000 } | ForEach-Object {
    $head = (Get-Content $_.FullName -TotalCount 1 -ErrorAction SilentlyContinue)
    if ($head -is [array]) { $head = $head[0] }
    if ($null -eq $head) { return }
    $first = $head.Substring(0,[Math]::Min(80,$head.Length))
    if ($first -match 'panel|--cc|:root|^\.|^/\*|^\@') {
      $hasLeft = Select-String -Path $_.FullName -Pattern 'panel-resize-left' -SimpleMatch -List -ErrorAction SilentlyContinue
      $hasTop = Select-String -Path $_.FullName -Pattern 'panel-resize-top' -SimpleMatch -List -ErrorAction SilentlyContinue
      Write-Host ("  {0}  size={1,8}  L={2} T={3}  first=[{4}]" -f $_.Name, $_.Length, [bool]$hasLeft, [bool]$hasTop, $first)
    }
  }
}
