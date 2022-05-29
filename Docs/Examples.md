## Examples
### Table of Contents
* [Block-TrafficToIpAddress](#block-traffictoipaddress)
* [ConvertFrom-Base64](#convertfrom-base64)
* [ConvertTo-Base64](#convertto-base64)
* [Get-Indicator](#get-indicator)
* [Get-LocalAdministrators](#get-localadministrators)
* [Get-WirelessNetAdapter](#get-wirelessnetadapter)
* [Invoke-WinEventParser](#invoke-wineventparser)
* [Read-WinEvent](#read-winevent)
* [Unblock-TrafficToIpAddress](#unblock-traffictoipaddress)
* [Update-GitHubRepo](#update-githubrepo)
* [Get-EventViewer](#get-eventviewer)

### Block-TrafficToIpAddress
```pwsh
Block-TrafficToIpAddress
```
```pwsh
# output

```

### ConvertFrom-Base64
```pwsh
ConvertFrom-Base64
```
```pwsh
# output

```

### ConvertTo-Base64
```pwsh
ConvertTo-Base64
```
```pwsh
# output

```

### Get-Indicator
```pwsh
Get-Indicator
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
Example 1
```pwsh
Get-WinEvent -FilterXml ([xml](Get-Content C:\Users\Victor\Documents\EventXmlFilters\Last24Hrs-Security-Logons.xml)) | 
Read-WinEvent | 
Select-Object -Property TimeCreated,Hostname,TargetUserName,LogonType | Format-Table -AutoSize
```
```
TimeCreated          Hostname TargetUserName LogonType
-----------          -------- -------------- ---------
9/12/2021 8:23:27 AM Windows  Victor         2        
9/12/2021 8:23:27 AM Windows  Victor         2        
9/12/2021 7:49:37 AM Windows  Victor         2        
9/12/2021 7:49:37 AM Windows  Victor         2
```

Example 2
```pwsh
$SearchCriteria = @{ LogName = "Security"; Id = 4688 } 
Get-WinEvent -FilterHashtable $SearchCriteria |
Read-WinEvent | 
Select-Object `
    @{ Name="TimeCreated"; Expression = { Get-Date -Format "yyyy-MM-dd HH:mm:ss" $_.TimeCreated.SystemTime } },`
    TargetUserName,`
    ParentProcessName,`
    CommandLine |
Where-Object {
    ($_.TargetUserName -notlike "-") -and
    ($_.TargetUserName -notlike "*$") -and
    ($_.TargetUserName -notlike "LOCAL*") -and
    ($_.ParentProcessName -notlike "C:\Windows\System32\*") #-and
}
```
```
TimeCreated         TargetUserName ParentProcessName                                            CommandLine                                                                   
-----------         -------------- -----------------                                            -----------                                                                   
2022-02-17 05:45:17 Victor         C:\Windows\explorer.exe                                      "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"               
2022-02-16 17:14:49 Victor         C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\NGenTask.exe" /StopEvent:1532
2022-02-16 17:14:36 Victor         C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngentask.exe   "C:\Windows\Microsoft.NET\Framework\v4.0.30319\NGenTask.exe" /StopEvent:1460  
2022-02-16 06:19:24 Victor         C:\Program Files\WindowsApps\Microsoft.PowerShell_7.2.1.0... "C:\Users\Victor\Documents\GitHub\ctfconsole\ctfconsole.exe"    
```

### Unblock-TrafficToIpAddress
```pwsh
Unblock-TrafficToIpAddress
```
```pwsh
# output

```

### Update-GitHubRepo
```pwsh
Update-GitHubRepo -Author "cyberphor" -Repo "SOAP-Modules" -Branch "main" -Path "C:\Users\cyberphor\Documents\GitHub\SOAP-Modules"
```
```pwsh
# output
[!] Updating the local branch of scripts.
```

### Get-EventViewer
Get-EventViewer.ps1 is a PowerShell script that parses your local Windows Event logs and adds events to an Excel workbook, organizing the data into different tabs. I developed this tool to make it easier for me to review successful logons, process creation, and PowerShell events on my personal computer. Below are screenshots of the end-result.

**Screenshot #1**
![Screenshot1](/Screenshots/Screenshot1.PNG)

**Screenshot #2**
![Screenshot2](/Screenshots/Screenshot2.PNG)

**Screenshot #3**
![Screenshot3](/Screenshots/Screenshot3.PNG)