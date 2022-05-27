## Soap
![GitHub](https://img.shields.io/github/license/cyberphor/soap)  
Soap is a PowerShell module with cybersecurity-related functions. This repository also contains a few PowerShell scripts. I plan to merge these scripts into the main Soap module in the future. 

### Table of Contents
* [How to Install Soap Using Git](#how-to-install-soap-using-git)
* [How to Install Soap Using PowerShell](#how-to-install-soap-using-powershell)
* [Soap Functions](#soap-functions)
* [Scripts](#scripts)
  * [Get-EventViewer.ps1](#get-eventviewerps1)
* [References](#references)

### How to Install Soap Using Git and PowerShell
```
git clone https://github.com/cyberphor/soap
cd soap
import-module -name .\soap.psm1
```

### How to Install Soap Using PowerShell Only
```
$Uri = "https://github.com/cyberphor/soap/archive/refs/heads/main.zip"
$Destination = "C:\Program Files\WindowsPowerShell\Modules\soap"
Invoke-WebRequest -Uri $Uri -OutFile "soap.zip"
Expand-Archive -Path "soap.zip"
Move-Item -Path "soap\soap-main" -Destination $Destination
Remove-Item -Path "soap.zip"
Remove-Item -Path "soap"
Import-Module -Name "soap"
```

### Soap Functions
For a list of the functions included in the Soap PowerShell module, [read the doc](/Docs/Functions.md).

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
