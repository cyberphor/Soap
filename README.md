# SOAP Modules
![GitHub](https://img.shields.io/github/license/cyberphor/soap-modules)  
Security Operations and Automation via PowerShell (SOAP) Modules

### Installation
Copy/paste the commands below into an elevated PowerShell session to automatically download, install, and import the SOAP modules.
```pwsh
$Uri = "https://github.com/cyberphor/SOAP-Modules/archive/refs/heads/main.zip"
$Destination = "C:\Program Files\WindowsPowerShell\Modules\SOAP-Modules"
Invoke-WebRequest -Uri $Uri -OutFile "SOAP-Modules.zip"
Expand-Archive -Path "SOAP-Modules.zip"
Move-Item -Path "SOAP-Modules\SOAP-Modules-main" -Destination $Destination
Remove-Item -Path "SOAP-Modules.zip"
Remove-Item -Path "SOAP-Modules"
Import-Module -Name "SOAP-Modules"
```
