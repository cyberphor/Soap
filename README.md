```
   _____   ____     ___      ____ 
  / ___/  / __ \   /   |    / __ \
  \__ \  / / / /  / /| |   / /_/ /
 ___/ / / /_/ /  / ___ |  / ____/ 
/____/  \____/  /_/  |_| /_/      
   
```
SOAP is a PowerShell module with incident handling and penetration testing functions. 

## Installation
Execute the commands below in PowerShell to automatically download and import SOAP.
```pwsh
$Owner = "cyberphor"
$Repo = "soap"
$RepoFolder = "$Repo\$Repo-main\"
$RepoContents = $RepoFolder + "*"
$Download = $Repo + ".zip"
$ModulesFolder = "C:\Program Files\WindowsPowerShell\Modules\"
$Uri = "https://github.com/$Owner/$Repo/archive/refs/heads/main.zip"
Invoke-WebRequest -Uri $Uri -OutFile $Download
Expand-Archive -Path $Download -DestinationPath $Repo
Move-Item -Path $RepoContents -Destination $Repo
Remove-Item $Download 
Remove-Item $RepoFolder
Move-Item -Path $Repo -Destination $ModulesFolder
Import-Module $Repo -Force
```

## Usage
Once SOAP is imported, a number of functions will become available. See below for usage examples.
```pwsh
Invoke-WinEventParser -ComputerName WindowsEventCollector01 -LogName ForwardedEvents -EventId 4624 -Days 3

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
