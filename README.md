## Soap
![GitHub](https://img.shields.io/github/license/cyberphor/Soap?color=Green) ![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Soap?color=Green&label=PowerShell%20Gallery%20Downloads)  
Soap is a PowerShell module with incident response and threat hunting functions. To install it, open PowerShell as an administrator and execute the command below. 
```pwsh
Install-Module -Name Soap -Force
```

**Functions**
```                              
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
Get-DomainAdministrators            
Get-DscResourcesRequired            
Get-EnterpriseVisbility             
Get-EventForwarders                 
Get-EventViewer                     
Get-GitHubRepo                      
Get-IpAddressRange                  
Get-LocalAdministrators             
Get-ProcessByNetworkConnection      
Get-ProcessCreationReport           
Get-SerialNumberAndCurrentUser                   
Get-Stig                            
Get-TrafficLights                   
Get-WinEventDns
Get-WinEventFirewall         
Get-WinEventLogon    
Get-WinEventPowerShell
Get-WinEventProcessCreation
Get-WinEventService
Get-WinEventUsb
Get-WinEventWindowsDefender
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
Uninstall-Sysmon                    
```

This repository includes another PowerShell module called "Suds." It includes functions auxillary to incident response and threat hunting. 
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
