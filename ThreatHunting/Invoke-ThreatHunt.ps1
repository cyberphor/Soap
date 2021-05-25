$SearchBaseDefault = (Get-AdDomain).DistinguishedName
$SearchBase = ""
$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Get-IpAddressFromFirewallLog.ps1 |
Select Hostname, Username, Model, SerialNumber, LogRecordId
