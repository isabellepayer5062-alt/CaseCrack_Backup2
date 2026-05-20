$ws='C:\Users\ya754\AppData\Roaming\Code\User\workspaceStorage\9e51499eea65fa44abab72645f162d00'
$candidates = @(
  @{S='4ee01150-c401-4f48-8b23-ce30c85da2d0'; F='5324d6c'},
  @{S='4ee01150-c401-4f48-8b23-ce30c85da2d0'; F='9963a5a'},
  @{S='4ee01150-c401-4f48-8b23-ce30c85da2d0'; F='dec7ac9'},
  @{S='4ee01150-c401-4f48-8b23-ce30c85da2d0'; F='99b0d1a'},
  @{S='4ee01150-c401-4f48-8b23-ce30c85da2d0'; F='a7f6c17'},
  @{S='2d6e604f-d895-4e48-b184-5d506e917117'; F='9963a5a'},
  @{S='2d6e604f-d895-4e48-b184-5d506e917117'; F='1d605f8'},
  @{S='2d6e604f-d895-4e48-b184-5d506e917117'; F='39afe71'},
  @{S='2d6e604f-d895-4e48-b184-5d506e917117'; F='470334f'},
  @{S='2d6e604f-d895-4e48-b184-5d506e917117'; F='bd5ba86'},
  @{S='fae709ba-0fb2-4b2c-8623-87175702540e'; F='5324d6c'},
  @{S='fae709ba-0fb2-4b2c-8623-87175702540e'; F='14fc12d'}
)
foreach ($c in $candidates) {
  $p = "$ws\chatEditingSessions\$($c.S)\contents\$($c.F)"
  if (Test-Path $p) {
    $sz = (Get-Item $p).Length
    $h = Get-Content $p -TotalCount 1 -ErrorAction SilentlyContinue
    if ($h -is [array]) { $h = $h[0] }
    if ($null -eq $h) { $h = '' }
    $hp = $h.Substring(0, [Math]::Min(120, $h.Length))
    Write-Host ("{0}/{1}  size={2}  first=[{3}]" -f $c.S.Substring(0,8), $c.F, $sz, $hp)
  }
}
