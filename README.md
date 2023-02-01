## Soap
![GitHub](https://img.shields.io/github/license/cyberphor/Soap?color=Green) ![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Soap?color=Green&label=PowerShell%20Gallery%20Downloads)  
Soap is a PowerShell module with incident response and threat hunting functions. To install it, open PowerShell as an administrator and execute the command below. 
```pwsh
Install-Module -Name Soap
```

**Functions**
```pwsh
Clear-AuditPolicy
Disable-Firewall
Disable-Ipv6
Edit-Module
Enable-Firewall
Enable-Ipv6
Enable-WinRm
Find-IpAddressInWindowsEventLog
Find-WirelessComputer # work-in-progress (use with caution)
Get-AuditPolicy
Get-AutoRuns
Get-DiskSpace
Get-DomainAdministrator
Get-EnterpriseVisbility # work-in-progress (use with caution)
Get-EventForwarder # work-in-progress (use with caution)
Get-LocalAdministrator
Get-ProcessByNetworkConnection
Get-WinEventDns
Get-WinEventFirewall
Get-WinEventLogon
Get-WinEventPowerShell
Get-WinEventProcessCreation
Get-WinEventService
Get-WinEventUsb
Get-WinEventWindowsDefender
Get-WinRmClient
Get-WirelessNetAdapter # work-in-progress (use with caution)
Get-WordWheelQuery
New-Alert
New-CustomViewsForSysmon # work-in-progress (use with caution)
Read-WinEvent
Send-Alert # work-in-progress (use with caution)
Set-AuditPolicy
Set-FirewallPolicy # work-in-progress (use with caution)
Start-AdAccountAudit
Start-Eradication
Start-Heartbeat
Start-Panic # work-in-progress (use with caution)
```

This repository includes another PowerShell module called "Suds." It includes functions auxillary to incident response and threat hunting. 
```pwsh
ConvertFrom-Base64
ConvertTo-Base64
ConvertTo-BinaryString
ConvertTo-IpAddress
Export-Gpo
Get-DscResourcesRequired # work-in-progress (use with caution)
Get-EventViewer # work-in-progress (use with caution)
Get-IpAddressRange
Get-ProcessCreationReport
Get-SerialNumberAndCurrentUser
Get-Stig # work-in-progress (use with caution)
Import-AdUsersFromCsv # work-in-progress (use with caution)
Install-RSAT
Install-Sysmon # work-in-progress (use with caution)
Invoke-SecurityBaseline # work-in-progress (use with caution)
New-AdDomainAdmin
New-AdForest
New-GpoWallpaper
Remove-StaleDnsRecord
Start-AdBackup # work-in-progress (use with caution)
Uninstall-Sysmon
```

### Copyright
This project is licensed under the terms of the [MIT license](/LICENSE).
