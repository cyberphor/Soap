function Get-WinEventProcessCreation {
  Param(
      [string]$Whitelist,
      [switch]$Verbose    
  )
  if ($Whitelist) {
      $Exclusions = Get-Content $Whitelist -ErrorAction Stop
  }
  $FilterHashTable = @{
      LogName = "Security"
      Id = 4688
  }
  if ($Verbose) {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Where-Object { $_.NewProcessName -notin $Exclusions }
  } else {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Where-Object { $_.NewProcessName -notin $Exclusions } |
      Group-Object -Property NewProcessName -NoElement |
      Sort-Object -Property Count -Descending |
      Format-Table -AutoSize
  }
}