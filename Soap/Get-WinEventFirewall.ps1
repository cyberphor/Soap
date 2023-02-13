function Get-WinEventFirewall {
  Param(
      [ValidateSet("SourceAddress","DestAddress")]$Direction = "DestAddress",
      [string]$Whitelist,
      [switch]$Verbose
  )
  if ($Whitelist) {
      $Exclusions = Get-Content $Whitelist -ErrorAction Stop
  }
  $FilterHashTable = @{
      LogName = "Security"
      Id = 5156
  }
  if ($Verbose) {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Where-Object { $_.$Direction -notin $Exclusions }
  } else {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent | 
      Where-Object { $_.$Direction -notin $Exclusions } |
      Group-Object -Property $Direction -NoElement |
      Sort-Object -Property Count -Descending |
      Format-Table -AutoSize
  }
}