## Event ID 4688
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
