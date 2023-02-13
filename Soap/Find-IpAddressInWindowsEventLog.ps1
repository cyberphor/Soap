function Find-IpAddressInWindowsEventLog {
  param(
      [string]$IpAddress
  )
  $FilterHashTable = @{
      LogName = "Security"
      Id = 5156
  }
  Get-WinEvent -FilterHashtable $FilterHashTable | 
  Read-WinEvent  | 
  Where-Object { 
      ($_.DestAddress -eq $IpAddress) -or 
      ($_.SourceAddress -eq $IpAddress) } | 
  Select-Object TimeCreated, EventRecordId, SourceAddress, DestAddress
}