```
   _____   ____     ___      ____ 
  / ___/  / __ \   /   |    / __ \
  \__ \  / / / /  / /| |   / /_/ /
 ___/ / / /_/ /  / ___ |  / ____/ 
/____/  \____/  /_/  |_| /_/      
   
```
SOAP is a PowerShell module with incident handling functions. 

### How to Install the SOAP PowerShell Module
Copy/paste the commands below into an elevated PowerShell session to automatically download and import SOAP.
```pwsh
Invoke-WebRequest -Uri "https://github.com/cyberphor/soap/archive/refs/heads/main.zip" -OutFile "soap.zip"
Expand-Archive -Path ".\soap.zip" -DestinationPath ".\soap"
Move-Item -Path ".\soap\soap-main\*" -Destination "C:\Program Files\WindowsPowerShell\Modules\soap"
Import-Module -Name "soap" -Force
Remove-Item ".\soap.zip"
Remove-Item ".\soap" -Recurse
```

### How to Use the SOAP PowerShell Module
Once SOAP is imported, a number of functions will become available. See below for usage examples.

#### Read-WinEvent
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

#### Invoke-WinEventParser
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
