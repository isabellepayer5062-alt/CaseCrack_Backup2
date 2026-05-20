$ws = 'C:\Users\ya754\AppData\Roaming\Code\User\workspaceStorage\9e51499eea65fa44abab72645f162d00'
$sessions = @(
  'fe741aee-1c2f-4369-88dc-3b1ec98b7734',
  '251326ca-7dc0-4d81-9d57-58d76f6c32ba',
  '4ee01150-c401-4f48-8b23-ce30c85da2d0',
  '2d6e604f-d895-4e48-b184-5d506e917117',
  'c71db976-71f6-40b1-af22-022cc2ec09aa',
  'fae709ba-0fb2-4b2c-8623-87175702540e',
  '7f5add25-6da8-45d9-ba68-7b93d4d21849',
  '52a03906-3b78-4fef-a94f-2fb43f82e8d8'
)
$symbols = @(
  '_syncResizeHandleState',
  '_applyResizeDelta',
  '_persistResizeResult',
  'panel-resize-left',
  'panel-resize-top',
  '_buildSnapshotFromPreset',
  '6ea4f56b19d6'
)
$results = @()
foreach ($sid in $sessions) {
  $contents = Join-Path $ws "chatEditingSessions\$sid\contents"
  if (-not (Test-Path $contents)) { Write-Host "SKIP (no contents): $sid"; continue }
  $files = Get-ChildItem $contents -File -ErrorAction SilentlyContinue
  Write-Host "Session $sid : $($files.Count) files"
  foreach ($sym in $symbols) {
    $hits = Select-String -Path $files.FullName -Pattern $sym -SimpleMatch -List -ErrorAction SilentlyContinue
    foreach ($h in $hits) {
      $msg = "  HIT $sym -> $(Split-Path $h.Path -Leaf) ($((Get-Item $h.Path).Length) bytes)"
      Write-Host $msg
      $results += [PSCustomObject]@{Session=$sid; Symbol=$sym; File=(Split-Path $h.Path -Leaf); Path=$h.Path}
    }
  }
}
Write-Host "===DONE==="
$results | Export-Csv -NoTypeInformation -Path 'c:\Users\ya754\CaseCrack v1.0\_chat_session_hits.csv'
Write-Host "Total hits: $($results.Count)"
