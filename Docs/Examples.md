## Examples
### Table of Contents
* [Block-TrafficToIpAddress](#block-traffictoipaddress)
* [Get-LocalAdministrators](#get-localadministrators)
* [Get-WirelessNetAdapter](#get-wirelessnetadapter)
* [Invoke-WinEventParser](#invoke-wineventparser)
* [Read-WinEvent](#read-winevent)
* [Unblock-TrafficToIpAddress](#unblock-traffictoipaddress)

### Block-TrafficToIpAddress
```pwsh
Block-TrafficToIpAddress
```
```pwsh
# output

```

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
$Computers = (Get-AdComputer -Filter *).Name
Invoke-Command -ComputerName $Computers -ScriptBlock ${function:Get-LocalAdministrators} |
Select-Object Name,PsComputerName
```
```pwsh
# output

```

### Get-WirelessNetAdapter
```pwsh
Get-WirelessNetAdapter
```
```pwsh
# output

ServiceName      : RtlWlanu
MACAddress       : 00:13:EF:F3:6F:F5
AdapterType      : Ethernet 802.3
DeviceID         : 16
Name             : Realtek 8812BU Wireless LAN 802.11ac USB NIC
NetworkAddresses : 
Speed            : 144400000

ServiceName      : vwifimp
MACAddress       : 02:13:EF:F3:6F:F5
AdapterType      : Ethernet 802.3
DeviceID         : 17
Name             : Microsoft Wi-Fi Direct Virtual Adapter #2
NetworkAddresses : 
Speed            : 9223372036854775807

ServiceName      : vwifimp
MACAddress       : 00:13:EF:F3:6F:F5
AdapterType      : Ethernet 802.3
DeviceID         : 18
Name             : Microsoft Wi-Fi Direct Virtual Adapter #3
NetworkAddresses : 
Speed            : 9223372036854775807
```

### Invoke-WinEventParser
```pwsh
Invoke-WinEventParser -ComputerName WindowsEventCollector01 -LogName ForwardedEvents -EventId 4624 -Days 3
```
```bash
# output

TimeCreated          Hostname Username        LogonType
-----------          -------- --------        ---------
8/19/2021 5:59:32 AM Windows  SYSTEM          5        
8/19/2021 5:59:28 AM Windows  SYSTEM          5        
8/19/2021 5:59:13 AM Windows  SYSTEM          5        
8/19/2021 5:59:13 AM Windows  SYSTEM          5        
8/19/2021 5:59:12 AM Windows  Victor          2        
8/19/2021 5:59:12 AM Windows  Victor          2        
8/19/2021 5:59:06 AM Windows  SYSTEM          5        
8/19/2021 5:59:05 AM Windows  DWM-2           2        
8/19/2021 5:59:05 AM Windows  DWM-2           2        
8/19/2021 5:59:05 AM Windows  UMFD-2          2        
8/19/2021 5:59:05 AM Windows  SYSTEM          5        
8/19/2021 5:59:04 AM Windows  SYSTEM          5        
8/19/2021 5:58:43 AM Windows  SYSTEM          5        
8/19/2021 5:58:38 AM Windows  SYSTEM          5        
8/19/2021 5:58:38 AM Windows  SYSTEM          5        
8/19/2021 5:58:38 AM Windows  SYSTEM          5        
8/19/2021 5:58:38 AM Windows  SYSTEM          5        
8/19/2021 5:58:38 AM Windows  SYSTEM          5        
8/19/2021 5:58:38 AM Windows  NETWORK SERVICE 5        
```

### Read-WinEvent
```pwsh
Get-WinEvent -FilterXml ([xml](Get-Content C:\Users\Victor\Documents\EventXmlFilters\Last24Hrs-Security-Logons.xml)) | 
Read-WinEvent | 
Select-Object -Property TimeCreated,Hostname,TargetUserName,LogonType | Format-Table -AutoSize
```
```bash
# output

TimeCreated          Hostname TargetUserName LogonType
-----------          -------- -------------- ---------
9/12/2021 8:23:27 AM Windows  Victor         2        
9/12/2021 8:23:27 AM Windows  Victor         2        
9/12/2021 7:49:37 AM Windows  Victor         2        
9/12/2021 7:49:37 AM Windows  Victor         2
```

### Unblock-TrafficToIpAddress
```pwsh
Unblock-TrafficToIpAddress
```
```pwsh
# output

```
