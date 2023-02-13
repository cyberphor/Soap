function Get-WinEventLogon {
  Param(
      [ValidateSet("Failed","Successful")]$Type = "Failed",
      [switch]$Verbose
  )
  if ($Type -eq "Failed") {
      $Id = 4625
  } elseif ($Type -eq "Successful") {
      $Id = 4624
  }
  $FilterHashTable = @{
      LogName = "Security"
      Id = $Id
  }
  if ($Verbose) {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent
  } else {
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Group-Object -Property TargetUserName -NoElement |
      Sort-Object -Property Count -Descending |
      Format-Table -AutoSize
  }
}