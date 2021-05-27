Param(
    [switch]$IpAddressFromFirewallLog,
    [string]$SearchBase = (Get-AdDomain).DistinguishedName
)

if ($IpAddressFromFirewallLog) {
    $Script = ".\Get-IpAddressFromFirewallLog.ps1"
    $Output = "Hostname", "Username", "Model", "SerialNumber", "LogRecordId"
} else {
    exit
}

$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name
Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath $Script |
Select $Output | Format-Table -AutoSize
