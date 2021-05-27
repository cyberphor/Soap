Param(
    [switch]$AssetInventory,
    [switch]$DiskSpace,
    [string]$SearchBase = (Get-AdDomain).DistinguishedName
)

if ($AssetInventory) {
    $Script = ".\Get-Asset.ps1"
    $Output = "Hostname", "Username", "Model", "SerialNumber", "FilePath", "Sha256Hash"
} elseif ($DiskSpace) {
    $Script = ".\Get-DiskSpace.ps1"
    $Output = "Hostname", "Username", "Model", "SerialNumber"
} else {
    exit
}

$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name
Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath $Script |
Select $Output
