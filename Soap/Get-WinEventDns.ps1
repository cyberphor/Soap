function Get-WinEventDns {
  Param(
      [string]$Whitelist,
      [switch]$Verbose
  )
  if ($Whitelist) {
      $Exclusions = Get-Content $Whitelist -ErrorAction Stop
  }
  $FilterHashTable = @{
      LogName = "Microsoft-Windows-DNS-Client/Operational"
      Id = 3006
  }
  if ($Verbose) {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Where-Object { $_.QueryName -notin $Exclusions }
  } else {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Where-Object { $_.QueryName -notin $Exclusions } |
      Group-Object -Property QueryName -NoElement |
      Sort-Object -Property Count -Descending |
      Format-Table -AutoSize
  }
}