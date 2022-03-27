# soap
![GitHub](https://img.shields.io/github/license/cyberphor/soap)  
soap is a PowerShell module with functions relating to cyber-security. This repository also contains a few PowerShell scripts. I may or may not merge these scripts into the main "soap" module in the future. 

### Installation
Copy and paste the commands below into a PowerShell session to download, install, and import the "soap" PowerShell module.
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

### Functions
For a list of the functions included in the "soap" PowerShell module, [read the doc](/docs/Functions.md).

### Get-EventViewer.ps1
Get-EventViewer.ps1 is a PowerShell script that parses your local Windows Event logs and adds events to an Excel workbook, organizing the data into different tabs. I developed this tool to make it easier for me to review successful logons, process creation, and PowerShell events on my personal computer. Below are screenshots of the end-result.

**Screenshot #1**
![Screenshot1](/Screenshots/Screenshot1.PNG)

**Screenshot #2**
![Screenshot2](/Screenshots/Screenshot2.PNG)

**Screenshot #3**
![Screenshot3](/Screenshots/Screenshot3.PNG)
