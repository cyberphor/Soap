## soap
![GitHub](https://img.shields.io/github/license/cyberphor/soap)  
soap is a PowerShell module with functions relating to cyber-security. This repository also contains a few PowerShell scripts. I may or may not merge these scripts into the main "soap" module in the future. 

### Table of Contents
* [How to Install soap Using Git](#how-to-install-soap-using-git)
* [How to Install soap Using PowerShell](#how-to-install-soap-using-powershell)
* [soap Functions](#soap-functions)
* [Scripts](#scripts)
  * [Get-EventViewer.ps1](#get-eventviewerps1)
* [References](#references)

### How to Install soap Using git
```bash
git clone https:///github.com/cyberphor/soap
```

### How to Install soap Using PowerShell
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

### soap Functions
For a list of the functions included in the "soap" PowerShell module, [read the doc](/Docs/Functions.md).

### Scripts
#### Get-EventViewer.ps1
Get-EventViewer.ps1 is a PowerShell script that parses your local Windows Event logs and adds events to an Excel workbook, organizing the data into different tabs. I developed this tool to make it easier for me to review successful logons, process creation, and PowerShell events on my personal computer. Below are screenshots of the end-result.

**Screenshot #1**
![Screenshot1](/Screenshots/Screenshot1.PNG)

**Screenshot #2**
![Screenshot2](/Screenshots/Screenshot2.PNG)

**Screenshot #3**
![Screenshot3](/Screenshots/Screenshot3.PNG)

### References
* [https://powershell.org/2019/08/a-better-way-to-search-events/](https://powershell.org/2019/08/a-better-way-to-search-events/)
* [https://powershell.one/powershell-internals/scriptblocks/support-pipeline](https://powershell.one/powershell-internals/scriptblocks/support-pipeline)
* [https://regexone.com/](https://regexone.com/)
* [https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.1](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.1)
* [https://devblogs.microsoft.com/scripting/understanding-xml-and-xpath/](https://devblogs.microsoft.com/scripting/understanding-xml-and-xpath/)
* [https://www.sapien.com/blog/2019/05/13/advanced-powershell-functions-begin-to-process-to-end/](https://www.sapien.com/blog/2019/05/13/advanced-powershell-functions-begin-to-process-to-end/)
