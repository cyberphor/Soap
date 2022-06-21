## Soap
![GitHub](https://img.shields.io/github/license/cyberphor/Soap?color=Green) ![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Soap?color=Green&label=PowerShell%20Gallery%20Downloads)  
Soap is a PowerShell module with system hardening, log analysis, and incident response functions. To install it, copy/paste the command below into an elevated PowerShell session.

```pwsh
Install-Module -Name Soap -Force
```

Below is a list of functions currently provided by Soap (as of 20 JUN 22). 
```pwsh
Block-Traffic
Clear-AuditPolicy
ConvertFrom-Base64
ConvertTo-Base64
ConvertTo-BinaryString
ConvertTo-IpAddress
Disable-Firewall
Disable-Ipv6
Disable-StaleAdAccounts
Disable-StaleAdComputers
Edit-Module
Enable-Firewall
Enable-Ipv6
Enable-WinRm
Export-Gpo
Find-IpAddressInWindowsEventLog
Find-WirelessComputers
Format-Color
Get-App
Get-Asset
Get-AuditPolicy
Get-AutoRuns
Get-BaselineConnections
Get-BaselinePorts
Get-BaselineProcesses
Get-DiskSpace
Get-DnsEvents
Get-DomainAdministrators
Get-DscResourcesRequired
Get-EnterpriseVisbility
Get-EventForwarders
Get-EventViewer
Get-FirewallEvents
Get-GitHubRepo
Get-IpAddressRange
Get-LocalAdministrators
Get-LogonEvents
Get-PowerShellEvents
Get-ProcessByNetworkConnection
Get-ProcessCreationEvents
Get-ProcessCreationReport
Get-SerialNumberAndCurrentUser
Get-ServiceEvents
Get-Stig
Get-TrafficLights
Get-UsbEvents
Get-WindowsDefenderEvents
Get-WinRmClients
Get-WirelessNetAdapter
Get-WordWheelQuery
Import-AdUsersFromCsv
Install-RSAT
Install-Sysmon
Invoke-What2Log
New-AdForest
New-CustomViewsForSysmon
New-CustomViewsForTheSexySixEventIds
New-GpoWallpaper
Read-WinEvent
Remove-App
Remove-StaleDnsRecords
Send-Alert
Set-AuditPolicy
Set-FirewallPolicy
Start-AdBackup
Start-AdScrub
Start-Eradication
Start-Heartbeat
Start-Panic
Unblock-TrafficToIpAddress
```

### Copyright
This project is licensed under the terms of the [MIT license](/LICENSE).
