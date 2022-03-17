# soap
![GitHub](https://img.shields.io/github/license/cyberphor/soap)  
soap is a PowerShell module with cyber-security functions.

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

### Functions
- [x] Block-TrafficToIpAddress
- [x] ConvertFrom-Base64
- [x] ConvertFrom-CsvToMarkdownTable
- [x] ConvertTo-Base64
- [x] ConvertTo-BinaryString
- [x] ConvertTo-IpAddress
- [x] Edit-CustomModule
- [x] Enable-WinRm
- [x] Get-App
- [x] Get-Asset
- [x] Get-CallSign
- [x] Get-CustomModule
- [x] Get-DiskSpace
- [x] Get-DomainAdministrators
- [x] Get-EnterpriseVisbility
- [x] Get-EventForwarders
- [x] Get-Indicator
- [x] Get-IpAddressRange
- [x] Get-LocalAdministrators
- [x] Get-ModuleFunctions
- [x] Get-Permissions
- [x] Get-Privileges
- [x] Get-ProcessToKill
- [x] Get-Shares
- [x] Get-TcpPort
- [x] Get-WinRmClients
- [x] Get-WirelessNetAdapter
- [x] Get-WordWheelQuery
- [x] Import-AdUsersFromCsv
- [x] Import-CustomViews
- [x] Invoke-WinEventParser
- [x] New-CustomModule
- [x] Read-WinEvent
- [x] Remove-App
- [x] Remove-CustomModule
- [x] Start-AdBackup
- [x] Start-AdScrub
- [x] Start-Coffee
- [x] Start-ImperialMarch
- [ ] Start-Panic
- [x] Start-RollingReboot
- [x] Test-Connections
- [x] Test-TcpPort
- [x] Unblock-TrafficToIpAddress
- [ ] Update-AdDescriptionWithLastLogon
- [x] Update-GitHubRepo

### Get-EventViewer.ps1
Get-EventViewer.ps1 is a PowerShell script that parses your local Windows Event logs and adds events to an Excel workbook, organizing the data into different tabs. I developed this tool to make it easier for me to review successful logons, process creation, and PowerShell events on my personal computer. Below are screenshots of the end-result.

**Screenshot #1**
![Screenshot1](/Screenshots/Screenshot1.PNG)

**Screenshot #2**
![Screenshot2](/Screenshots/Screenshot2.PNG)

**Screenshot #3**
![Screenshot3](/Screenshots/Screenshot3.PNG)
