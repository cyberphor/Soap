function Get-DscResourcesRequired {
  Param([string[]]$Resources = @("AuditPolicyDsc","xBitLocker","NetworkingDsc"))
  $DownloadStartTime = Get-Date
  $OutputFile = "DscResources.zip"
  Install-Module -Name $Resources -Scope CurrentUser -Force
  if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }
  $env:PSModulePath -split ';' | 
  Where-Object { $_ -like "*$env:USERNAME*" } |
  Get-ChildItem | 
  Where-Object { $_.LastWriteTime -gt $DownloadStartTime } |
  Select-Object -ExpandProperty FullName |
  Compress-Archive -DestinationPath "DscResources.zip"
}