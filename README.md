## Soap
![GitHub](https://img.shields.io/github/license/cyberphor/Soap?color=Green) ![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Soap?color=Green&label=PowerShell%20Gallery%20Downloads)  
Soap is a PowerShell module with system hardening, log analysis, and incident response functions. To install it, open PowerShell as an administrator and execute the command below. 

```pwsh
Install-Module -Name Soap -Force
```

Below is a list of functions provided by Soap. 
```pwsh
Block-Traffic
Clear-AuditPolicy
Disable-Firewall
Disable-Ipv6
Disable-StaleAdAccounts
Disable-StaleAdComputers
Edit-Module
Enable-Firewall
Enable-Ipv6
Find-IpAddressInWindowsEventLog
Get-AuditPolicy
Get-AutoRuns
Get-DiskSpace
Get-DnsEvents
Get-DomainAdministrators
Get-FirewallEvents
Get-LocalAdministrators
Get-LogonEvents
Get-PowerShellEvents
Get-ProcessByNetworkConnection
Get-ProcessCreationEvents
Get-ServiceEvents
Get-UsbEvents
Get-WindowsDefenderEvents
Get-WinRmClients
Get-WordWheelQuery
Read-WinEvent
Set-AuditPolicy
Start-Eradication
Start-Heartbeat
```

Below is a list of functions provided by Soap, but marked for review (i.e., I'm considering putting them in a different module to keep Soap tidy and focused). 
```pwsh
ConvertFrom-Base64
ConvertTo-Base64
ConvertTo-BinaryString
ConvertTo-IpAddress
Export-Gpo
Format-Color
Get-GitHubRepo
Get-IpAddressRange
Get-ProcessCreationReport
Get-SerialNumberAndCurrentUser
Install-RSAT
New-AdForest
New-GpoWallpaper
Remove-StaleDnsRecords
```

Below is a list of functions provided by Soap, but should be used with caution as they are not finished. 
```pwsh
Enable-WinRm
Find-WirelessComputers
Get-App
Get-Asset
Get-BaselineConnections
Get-BaselinePorts
Get-BaselineProcesses
Get-DscResourcesRequired
Get-EnterpriseVisbility
Get-EventForwarders
Get-EventViewer
Get-Stig
Get-TrafficLights
Get-WirelessNetAdapter
Import-AdUsersFromCsv
Install-Sysmon
Invoke-What2Log
New-CustomViewsForSysmon
New-CustomViewsForTheSexySixEventIds
Remove-App
Send-Alert
Set-FirewallPolicy
Start-AdBackup
Start-AdScrub
Start-Panic
Unblock-TrafficToIpAddress
```

### Copyright
This project is licensed under the terms of the [MIT license](/LICENSE).
