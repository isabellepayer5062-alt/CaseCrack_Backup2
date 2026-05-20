$ws='C:\Users\ya754\AppData\Roaming\Code\User\workspaceStorage\9e51499eea65fa44abab72645f162d00'
$cdir = "$ws\chatEditingSessions\4ee01150-c401-4f48-8b23-ce30c85da2d0\contents"
$jsSrc = "$cdir\5324d6c"
$cssSrc = "$cdir\14fc12d"
$root = "c:\Users\ya754\CaseCrack v1.0\CaseCrack\tools\burp_enterprise\static"
$jsDst = "$root\js\recon-dashboard.js"
$cssDst = "$root\css\recon-dashboard.css"
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'

Copy-Item $jsDst "$jsDst.before_recovery_$ts.bak"
Copy-Item $cssDst "$cssDst.before_recovery_$ts.bak"
Write-Host "Backed up current files (.before_recovery_$ts.bak)"

Copy-Item $jsSrc $jsDst -Force
Copy-Item $cssSrc $cssDst -Force

$jsLines = (Get-Content $jsDst | Measure-Object -Line).Lines
$cssLines = (Get-Content $cssDst | Measure-Object -Line).Lines
Write-Host "JS:  $((Get-Item $jsDst).Length) bytes, $jsLines lines"
Write-Host "CSS: $((Get-Item $cssDst).Length) bytes, $cssLines lines"

$syms = '_syncResizeHandleState','_applyResizeDelta','_persistResizeResult','_buildSnapshotFromPreset','dockWidth','dockHeight','panel-resize-left','panel-resize-top','pointerdown','floating'
foreach ($s in $syms) {
  $jsCount = (Select-String -Path $jsDst -Pattern $s -SimpleMatch -ErrorAction SilentlyContinue | Measure-Object).Count
  $cssCount = (Select-String -Path $cssDst -Pattern $s -SimpleMatch -ErrorAction SilentlyContinue | Measure-Object).Count
  Write-Host ("  {0,-32} JS={1,3}  CSS={2,3}" -f $s, $jsCount, $cssCount)
}
