# soap
![GitHub](https://img.shields.io/github/license/cyberphor/soap)  

### Installation
Copy/paste the commands below into an elevated PowerShell session to automatically download, install, and import the soap PowerShell module.
```pwsh
$Uri = "https://github.com/cyberphor/soap/archive/refs/heads/main.zip"
$Destination = "C:\Program Files\WindowsPowerShell\Modules\soap"
Invoke-WebRequest -Uri $Uri -OutFile "soap.zip"
Expand-Archive -Path "soap.zip"
Move-Item -Path "soap\soap-main" -Destination $Destination
Remove-Item -Path "soap.zip"
Remove-Item -Path "soap"
Import-Module -Name "soap"
```
