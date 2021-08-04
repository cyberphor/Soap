Param(
    [switch]$AssetInventory,
    [switch]$DiskSpace,
    [string]$RemoveProgram
    [string]$SearchBase = (Get-AdDomain).DistinguishedName
)

if ($AssetInventory) {
    $Script = ".\Get-Asset.ps1"
    $Output = "IpAddress","Hostname","Version","Make","Model","SerialNumber","Architecture","OperatingSystem"
    # Sort-Object { $_.IpAddress -as [Version] } | Format-Table -AutoSize 
} elseif ($DiskSpace) {
    $Script = ".\Get-DiskSpace.ps1"
    $Output = "Hostname", "Username", "Model", "SerialNumber"
} elseif ($RemoveProgram) {
    $Script = ".\Remove-Program.ps1"
    $Output = "Hostname"
} else {
    exit
}

$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name
Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath $Script |
Select $Output | Format-Table -AutoSize
