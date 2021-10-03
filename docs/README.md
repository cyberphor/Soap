## How to Enable Specific Event Logs
### The Sexy Six
Event IDs: 4624, 4663, 4688, 5140, 5156, 7040, 7045
```cmd
auditpol /get /category:'*'
auditpol /set /subcategory:"Logon" /success:enable /failue:enable
auditpol /set /subcategory:"File System" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"File Share" /success:enable
auditpol /set /subcategory:"Registry" /success:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
```

### Removable Media
Event IDs: 6416
```cmd
auditpol /get /subcategory:"Plug and Play Events"
auditpol /set /subcategory:"Plug and Play Events" /success:enable
```

### Powershell
Event IDs: 4103, 4104
```pwsh
$BlockLogging = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 
New-Item $BlockLogging
New-ItemProperty $BlockLogging -Name 'EnableBlockLogging' -PropertyType Dword
Set-ItemProperty $BlockLogging -Name 'EnableBlockLogging' -Value '1'

$ModuleLogging = 'HKLM:\Software\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item $ModuleLogging
New-ItemProperty $ModuleLogging -Name 'EnableModuleLogging' -PropertyType Dword
Set-ItemProperty $ModuleLogging -Name 'EnableModuleLogging' -Value '1'
```

### DNS
Event IDs: 3006
```pwsh
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
```
