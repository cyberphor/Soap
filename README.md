# SOAP Modules
![GitHub](https://img.shields.io/github/license/cyberphor/soap-modules)  
Security Operations and Automation via PowerShell (SOAP) Modules

### How to Install the SOAP Modules
Copy/paste the commands below into an elevated PowerShell session to automatically download and import the SOAP modules.
```pwsh
Invoke-WebRequest -Uri "https://github.com/cyberphor/soap-modules/archive/refs/heads/main.zip" -OutFile "soap-modules.zip"
Expand-Archive -Path ".\soap-modules.zip" -DestinationPath ".\soap-modules"
Move-Item -Path ".\soap\soap-main\*" -Destination "C:\Program Files\WindowsPowerShell\Modules\soap-modules"
Import-Module -Name "soap-modules" -Force
Remove-Item ".\soap-modules.zip"
Remove-Item ".\soap-modules" -Recurse
```
