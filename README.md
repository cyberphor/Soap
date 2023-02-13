## Soap
![GitHub](https://img.shields.io/github/license/cyberphor/Soap?color=Green) ![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Soap?color=Green&label=PowerShell%20Gallery%20Downloads)  
Soap is a PowerShell module with incident response and threat hunting functions. To install it, open PowerShell as an administrator and execute the command below. 
```pwsh
Install-Module -Name Soap
```

My favorite and most-used function provided by Soap is [Read-WinEvent](/Soap/Read-WinEvent.ps1). 
```pwsh
Get-WinEvent -FilterHashtable @{ Id = 4625; Logname = "Security" } | 
Read-WinEvent | 
Where-Object { $_.LogonType -eq 3 } | 
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

### Copyright
This project is licensed under the terms of the [MIT license](/LICENSE).
