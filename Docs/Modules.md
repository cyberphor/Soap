## Identify
The "Identity" module contains functions to help focus and prioritize risk management efforts. 

**Asset Management**  
Inventory hardware and software.  
- [x] Get-App
- [x] Get-Asset
- [x] Get-EnterpriseVisbility
- [x] Get-EventForwarders
- [x] Get-IpAddressRange
- [x] Get-WinRmClients
- [x] Get-WirelessNetAdapter
- [x] Test-Connections
- [x] Test-TcpPort

**Risk Assessment**  
Identify asset vulnerabilities, receive cyber threat intelligence, identify internal threats, and identify external threats.  
- [ ] Get-Vulnerability

## Protect
The "Protect" module contains functions to prevent cyber-security events.

**Access Control**  
Manage identities, manage physical access, manage remote access, manage permissions, and implement network segmentation. 
- [x] Get-DomainAdmins
- [x] Get-LocalAdministrators
- [ ] Get-Permissions
- [ ] Get-Privileges
- [x] Start-AdScrub

**Data Security**  
Protect data-at-rest, protect data-in-transit, maintain capacity, and implement integrity checking mechanisms to verify software and information. 
- [x] Get-DiskSpace
- [ ] Import-IPSecGPO

**Information Protection**  
Maintain a baseline configuration of information systems, implement change control, conduct information backups, destroy data according to policy, and implement vulnerability management.
- [x] Get-TcpPort
- [x] Get-Shares

**Maintenance**  
Perform maintenance and perform remote maintenance in a manner that prevents unauthorized access. 
- [x] Enable-WinRm
- [x] Remove-App

**Protective Technology**  
Implement an audit policy, restrict the use of removable media, configure information systems to provide only essential capabilities, and implement fail-safe, load balancing,  and hot-swap mechanisms to achieve resilience. 
- [ ] Import-AuditPolicyGPO

## Detect
The “Detect” module contains functions to enable the discovery of cyber-security events.

**Anomalies and Events**  
Analyze events, collect events from multiple sources, and establish alert thresholds. 
- [x] Get-Indicator
- [ ] Invoke-WinEventParser
- [ ] Move-ForwardedEventsLog

**Continuous Monitoring**  
Monitor the network for cyber-security events, monitor the physical enviroment for cyber-security events, detect malicious code, scan for vulnerabilities, and monitor for unauthorized personnel, connections, devices, and software. 
- [ ] Get-Malware

**Detection Processes**  
Test detection processes. 
- [ ] Test-DetectionProcess

## Respond
The "Respond" module contains functions to contain the impact of a cyber-security event.

**Analysis**  
Investigate notifications from detection systems, perform forensics, and respond to vulnerabilities disclosed from internal and external sources. 
- [x] ConvertFrom-Base64
- [x] ConvertTo-Base64
- [x] ConvertTo-BinaryString
- [x] ConvertTo-IpAddress
- [x] Read-WinEvent

**Mitigation**  
Contain and mitigate incidents. 
- [x] Block-TrafficToIpAddress
- [x] Get-ProcessToKill
- [ ] Start-Panic
- [x] Unblock-TrafficToIpAddress

## Recover
The "Recover" module contains functions to maintain resilience and restore information services impaired by an incident. 

**Recovery Planning**  
Execute recovery plans.
- [x] Import-AdUsersFromCsv
- [x] Start-AdBackup
- [ ] Start-AdRestore 

## Misc
**Fun**  
The "Fun" module contains functions for entertainment. 
- [x] Get-CallSign
- [x] Start-ImperialMarch
- [x] Start-RollingReboot

**Work-in-Progress**  
The "Work-in-Progress" module contains incomplete functions. 