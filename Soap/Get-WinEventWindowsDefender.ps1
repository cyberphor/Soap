function Get-WinEventWindowsDefender {
  Param(
      [string]$Whitelist,
      [switch]$Verbose
  )
  if ($Whitelist) {
      $Exclusions = Get-Content $Whitelist -ErrorAction Stop
  }
  $FilterHashTable = @{
      LogName = "Microsoft-Windows-Windows Defender/Operational"
      Id = 1116,1117
  }
  if ($Verbose) {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Where-Object { $_."Threat Name" -notin $Exclusions }
  } else {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent | 
      Where-Object { $_."Threat Name" -notin $Exclusions } |
      Group-Object -Property "Threat Name" -NoElement |
      Sort-Object -Property "Count" -Descending |
      Format-Table -AutoSize
  }
}