## Soap
![GitHub](https://img.shields.io/github/license/cyberphor/Soap?color=Green) ![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Soap?color=Green&label=PowerShell%20Gallery%20Downloads)  
Soap is a PowerShell module with incident response and threat hunting functions. To install it, open PowerShell as an administrator and execute the command below. 
```pwsh
Install-Module -Name Soap
```

My favorite and most-used function provided by Soap is `Read-WinEvent`. 
```pwsh
Get-WinEvent -FilterHashtable @{ Id = 4625; Logname = "Security" } | 
Read-WinEvent | 
Where-Object { $_.LogonType -eq 2 } | 
Select-Object -First 10 -Property TimeCreated, EventRecordId, TargetUserName, IpAddress

TimeCreated         EventRecordID TargetUserName IpAddress
-----------         ------------- -------------- ---------
2023-01-26 10:28:51 6281781       Victor         192.168.1.23
2023-01-24 10:39:13 6263793       Dolores        156.74.251.21
2023-01-24 10:39:10 6263792       Dolores        156.74.251.21
2023-01-24 10:39:08 6263790       Dolores        156.74.251.21
2023-01-24 10:39:06 6263787       Dolores        156.74.251.21
2023-01-21 06:46:36 6255349       Dolores        156.74.251.21
2023-01-17 06:13:32 6223553       Hunter         156.74.251.21
2023-01-16 11:12:25 6218380       Hunter         156.74.251.21
2023-01-16 11:11:46 6218374       Hunter         156.74.251.21
2023-01-16 11:11:04 6218372       Hunter         156.74.251.21
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
