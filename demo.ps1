Import-Module .\Soap.psm1

Get-WinEvent -FilterHashtable @{ Id = 4625; Logname = "Security" } | 
Read-WinEvent | 
Where-Object { $_.LogonType -eq 2 } | 
Select-Object -First 10 -Property TimeCreated, EventRecordId, TargetUserName, IpAddress