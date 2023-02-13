function Get-WinEventUsb {
  Param(
      [string]$Whitelist,
      [switch]$Verbose
  )
  if ($Whitelist) {
      $Exclusions = Get-Content $Whitelist -ErrorAction Stop
  }
  $FilterHashTable = @{
      LogName = "Security"
      Id = 6416
  }
  if ($Verbose) {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent | 
      Where-Object { 
          ($_.ClassName -notin $Exclusions) -and 
          ($_.ClassName -ne $null)
      } 
  } else {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent | 
      Where-Object { 
          ($_.ClassName -notin $Exclusions) -and 
          ($_.ClassName -ne $null)
      } |
      Group-Object -Property ClassName -NoElement |
      Sort-Object -Property Count -Descending |
      Format-Table -AutoSize
  } 
}