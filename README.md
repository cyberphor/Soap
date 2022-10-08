## Soap
![GitHub](https://img.shields.io/github/license/cyberphor/Soap?color=Green) ![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Soap?color=Green&label=PowerShell%20Gallery%20Downloads)  
Soap is a PowerShell module with threat hunting, incident response, log management, and server management functions.  To install it, open PowerShell as an administrator and execute the command below. 
```pwsh
Install-Module -Name Soap -Force
```

**Threat Hunting**
```
Find-IpAddressInWindowsEventLog
Get-AutoRuns
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
Get-WordWheelQuery
Read-WinEvent
```

**Incident Response**
```
Block-Traffic
Enable-Firewall
Start-Eradication
```

**Log Management**
```
Clear-AuditPolicy
Get-AuditPolicy
Set-AuditPolicy
Get-DiskSpace
```

**Server Management**
```
Disable-Firewall
Disable-Ipv6
Edit-Module
Enable-Ipv6
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
