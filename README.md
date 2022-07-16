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
Edit-Module
Enable-Firewall
Enable-Ipv6
Find-IpAddressInWindowsEventLog
Get-AuditPolicy
Get-AutoRuns
Get-DiskSpace
Get-DnsEvent
Get-DomainAdministrator
Get-FirewallEvent
Get-LocalAdministrator
Get-LogonEvent
Get-PowerShellEvent
Get-ProcessByNetworkConnection
Get-ProcessCreationEvent
Get-ServiceEvent
Get-UsbEvent
Get-WindowsDefenderEvent
Get-WinRmClient
Get-WordWheelQuery
Read-WinEvent
Set-AuditPolicy
Start-Eradication
Start-Heartbeat
Start-AdAccountAudit
```

Below is a list of functions provided by Soap, but marked for review (i.e., I'm considering putting them in a different module to keep Soap tidy and focused). 
```pwsh
ConvertFrom-Base64
ConvertTo-Base64
ConvertTo-BinaryString
ConvertTo-IpAddress
Export-Gpo
Get-IpAddressRange
Get-ProcessCreationReport
Get-SerialNumberAndCurrentUser
Install-RSAT
New-AdForest
New-GpoWallpaper
Remove-StaleDnsRecord
```

Below is a list of functions provided by Soap, but should be used with caution as they are not finished. 
```pwsh
Enable-WinRm
Find-WirelessComputer
Get-DscResourcesRequired
Get-EnterpriseVisbility
Get-EventForwarder
Get-EventViewer
Get-Stig
Get-WirelessNetAdapter
Import-AdUsersFromCsv
Invoke-SecurityBaseline
Install-Sysmon
New-CustomViewsForSysmon
Send-Alert
Set-FirewallPolicy
Start-AdBackup
Start-Panic
Unblock-TrafficToIpAddress
```

### Copyright
This project is licensed under the terms of the [MIT license](/LICENSE).
