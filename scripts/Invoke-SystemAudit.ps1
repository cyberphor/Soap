Param(
    [switch]$LocalAdmins,
    [switch]$OpenPorts,
    [switch]$Shares,
    [switch]$WirelessComputers,
    [string]$SearchBase = (Get-AdDomain).DistinguishedName
)

if ($LocalAdmins) {
    $Script = ".\Get-LocalAdmins.ps1"
    $Output = "Hostname", "Username", "Model", "SerialNumber", "Administrator"
} elseif ($OpenPorts) {
    $Script = ".\Get-OpenPorts.ps1"
    $Output = "Hostname", "Username", "Model", "SerialNumber","OpenPorts"
} elseif ($Shares) {
    $Script = ".\Get-Shares.ps1"
    $Output = "Hostname", "Username", "Model", "SerialNumber","Shares"
} elseif ($WirelessComputers) {
    $Script = ".\Get-WirelessComputers.ps1"
    $Output = "Hostname", "Username", "Model", "SerialNumber"
} else {
    exit
}

$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name
Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath $Script |
Select $Output | Format-Table -AutoSize
