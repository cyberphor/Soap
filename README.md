# SOAP
![GitHub](https://img.shields.io/github/license/cyberphor/soap)  
SOAP is a PowerShell module with cyber-security functions. The acronym stands for "Security Operations and Automation via PowerShell."  

### How to Install the SOAP Module
Copy/paste the commands below into an elevated PowerShell session to automatically download and import the SOAP module.
```pwsh
Invoke-WebRequest -Uri "https://github.com/cyberphor/soap/archive/refs/heads/main.zip" -OutFile "soap.zip"
Expand-Archive -Path ".\soap.zip" -DestinationPath ".\soap"
Move-Item -Path ".\soap\soap-main\*" -Destination "C:\Program Files\WindowsPowerShell\Modules\soap"
Import-Module -Name "soap" -Force
Remove-Item ".\soap.zip"
Remove-Item ".\soap" -Recurse
```

 
