$SearchBaseDefault = (Get-AdDomain).DistinguishedName
$SearchBase = ""
$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Get-WirelessComputers.ps1 |
Select Hostname, Username, Model, SerialNumber | Format-Table -AutoSize

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Get-WirelessComputers.ps1 |
Select Hostname, Username, Model, SerialNumber, Administrator | Format-Table -AutoSize
