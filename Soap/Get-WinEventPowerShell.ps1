function Get-WinEventPowerShell {
  Param(
      [string]$Whitelist,
      [switch]$Verbose    
  )
  if ($Whitelist) {
      $Exclusions = Get-Content $Whitelist -ErrorAction Stop
  }
  $FilterHashTable = @{
      LogName = "Microsoft-Windows-PowerShell/Operational"
      Id = 4104
  }
  if ($Verbose) {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Where-Object { $_.ScriptBlockText -notin $Exclusions }
  } else {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent  | 
      Where-Object { $_.ScriptBlockText -notin $Exclusions } |
      Group-Object -Property ScriptBlockText -NoElement |
      Sort-Object -Property Count -Descending |
      Format-Table -AutoSize
  }
}