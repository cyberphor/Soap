Import-Module DnsServer

$Domain = Read-Host -Prompt 'Domain Name'
$30_Days_Ago = (Get-Date).AddDays(-30)

Get-DnsServerResourceRecord -Zone $Domain -RRType A | 
Where-Object { $_.TimeStamp -le $30_Days_Ago } | 
Remove-DnsServerResourceRecord -ZoneName $Domain -Force

<#
    # REFERENCES
    # https://adamtheautomator.com/powershell-dns/
#>
