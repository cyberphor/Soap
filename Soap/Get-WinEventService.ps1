function Get-WinEventService {
  Param(
      [string]$Whitelist,
      [switch]$Verbose
  )
  if ($Whitelist) {
      $Exclusions = Get-Content $Whitelist -ErrorAction Stop
  }
  $FilterHashTable = @{
      LogName = "System"
      Id = 7045
  }
  if ($Verbose) {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Where-Object { $_.ServiceName -notin $Exclusions }
  } else {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent  | 
      Where-Object { $_.ServiceName -notin $Exclusions }
      Group-Object -Property ServiceName -NoElement |
      Sort-Object -Property Count -Descending |
      Format-Table -AutoSize
  }
}