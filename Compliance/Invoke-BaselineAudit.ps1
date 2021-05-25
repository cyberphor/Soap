$SearchBaseDefault = (Get-AdDomain).DistinguishedName
$SearchBase = ""
$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name


Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Get-NewLocalAdmins.ps1 |
Select Hostname, Username, Model, SerialNumber, Administrator | Format-Table -AutoSize

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Get-OpenPorts.ps1 |
Select Hostname, Username, Model, SerialNumber, OpenPorts | Format-Table -AutoSize

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Get-Shares.ps1 |
Select Hostname, Username, Model, SerialNumber, Shares | Format-Table -AutoSize

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Get-WirelessComputers.ps1 |
Select Hostname, Username, Model, SerialNumber | Format-Table -AutoSize
