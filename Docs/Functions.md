### SOAP Functions
**Table of Contents**  
* [Get-LocalAdministrators](#get-localadministrators)

### Get-LocalAdministrators
```pwsh
Get-LocalAdministrators
```
```pwsh
# output

Name         
----         
Administrator
Cristal      
Victor       


```

```pwsh
Invoke-Command -ComputerName "evilcorpdc1","evilcorpwk1","evilcorpwk2" -ScriptBlock ${function:Get-LocalAdministrators}
```
```pwsh
# output
```

### Planned
I have and/or plan to include the functions listed below in the SOAP PowerShell module. 
- [ ] Start-LogEnrichment
- [ ] Start-ProcessReaper
- [ ] Invoke-APT1 
- [ ] Invoke-AdScrub
- [ ] Invoke-SystemAudit
- [ ] Get-LogonRights
- [ ] Get-FilePermissions
- [ ] Get-IntegrityLevels 
- [x] Get-LocalAdministrators
- [ ] Get-OpenPorts
- [ ] Get-Shares
- [x] Get-WirelessNetAdapter
- [ ] Get-DomainAdmins
- [ ] Get-Privileges
- [ ] Invoke-CyberEffect
- [ ] Start-RollingReboot
- [ ] Start-Scareware
- [ ] Get-SuspiciousFile 
- [ ] Start-Panic
- [ ] Stop-EvilProcess
- [x] Block-TrafficToIpAddress
- [x] Unblock-TrafficToIpAddress
- [ ] Enable-WinRm
- [ ] Get-Asset
- [ ] Get-DiskSpace
- [ ] Move-Logs
- [ ] Remove-Program
- [ ] Get-IpAddressFromFirewallLog  
