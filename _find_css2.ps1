$ws='C:\Users\ya754\AppData\Roaming\Code\User\workspaceStorage\9e51499eea65fa44abab72645f162d00'
$cdir = "$ws\chatEditingSessions\4ee01150-c401-4f48-8b23-ce30c85da2d0\contents"
Get-ChildItem $cdir -File | Sort-Object Length -Descending | Select-Object -First 25 | ForEach-Object {
  $head = (Get-Content $_.FullName -TotalCount 1 -ErrorAction SilentlyContinue)
  if ($head -is [array]) { $head = $head[0] }
  if ($null -eq $head) { $head = '' }
  $first = $head.Substring(0,[Math]::Min(100,$head.Length))
  $hasLeft = (Select-String -Path $_.FullName -Pattern 'panel-resize-left' -SimpleMatch -List -ErrorAction SilentlyContinue) -ne $null
  Write-Host ("{0}  sz={1,8}  L={2}  [{3}]" -f $_.Name, $_.Length, $hasLeft, $first)
}
