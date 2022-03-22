$Computers = Get-AdComputer -Filter * | Select-Object -ExpandProperty DnsHostname

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -ScriptBlock {
  Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.Name -like '*Wireless*' }
}
