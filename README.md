# soap
![GitHub](https://img.shields.io/github/license/cyberphor/soap)  
soap is a PowerShell module with cyber-security functions.

### Installation
Copy/paste the commands below into an elevated PowerShell session to automatically download, install, and import the soap PowerShell module.
```pwsh
$Uri = "https://github.com/cyberphor/soap/archive/refs/heads/main.zip"
$Destination = "C:\Program Files\WindowsPowerShell\Modules\soap"
Invoke-WebRequest -Uri $Uri -OutFile "soap.zip"
Expand-Archive -Path "soap.zip"
Move-Item -Path "soap\soap-main" -Destination $Destination
Remove-Item -Path "soap.zip"
Remove-Item -Path "soap"
Import-Module -Name "soap"
```

### Functions
Block-TrafficToIpAddress
ConvertFrom-Base64
ConvertFrom-CsvToMarkdownTable
ConvertTo-Base64
ConvertTo-BinaryString
ConvertTo-IpAddress
Edit-CustomModule
Enable-WinRm
Get-App
Get-Asset
Get-CallSign
Get-CustomModule
Get-DiskSpace
Get-DomainAdministrators
Get-EnterpriseVisbility
Get-EventForwarders
Get-Indicator
Get-IpAddressRange
Get-LocalAdministrators
Get-ModuleFunctions
Get-Permissions
Get-Privileges
Get-ProcessToKill
Get-Shares
Get-TcpPort
Get-WinRmClients
Get-WirelessNetAdapter
Import-AdUsersFromCsv
Import-CustomViews
Invoke-WinEventParser
New-CustomModule
Read-WinEvent
Remove-App
Remove-CustomModule
Start-AdBackup
Start-AdScrub
Start-Coffee
Start-ImperialMarch
Start-Panic
Start-RollingReboot
Test-Connections
Test-TcpPort
Unblock-TrafficToIpAddress
Update-AdDescriptionWithLastLogon
Update-GitHubRepo