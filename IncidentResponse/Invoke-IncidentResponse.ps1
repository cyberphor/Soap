$SearchBaseDefault = (Get-AdDomain).DistinguishedName
$SearchBase = ""
$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Get-SuspiciousFile.ps1 |
Select Hostname, Username, Model, SerialNumber, FilePath, Sha256Hash
