## Examples
### Table of Contents
* [Get-LocalAdministrators](#get-localadministrators)
* [Get-WirelessNetAdapter](#get-wirelessnetadapter)

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
