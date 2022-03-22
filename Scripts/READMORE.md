## Table of Contents
### Basic PowerShell
* [Navigating the File System](#navigating-the-file-system)
* [Concepts](#concepts)
* [Essentials](#essentials)
### Advanced PowerShell
* [Script Compatibility](#script-compatibility)
* [Tips and Tricks](#tips-and-tricks)
* [Getting Help](#getting-help)
* [Aliases](#aliases)
* [Variables, Classes, Objects, Properties, and Methods](#variables-classes-objects-properties-and-methods)
* [Environment Variables and Drives](#environment-variables-and-drives)
* [Profile Scripts](#profile-scripts)
* [Modules](#modules)
* [PowerShell Remoting](#powershell-remoting)
* [Run a script on multiple machines](#run-a-script-on-multiple-machines)
* [Exporting, Importing, and Converting Object Data](#exporting-importing-and-converting-object-data)

# Basic PowerShell
## Quick Reference Guide
```pwsh
# get number of cores
Get-WmiObject -Class Win32_Processor | Select -ExpandProperty NumberOfCores
(gwmi win32_processor).numberofcores
```

## Navigating the File System
```powershell
pwd # print working directory
ls # list contents of current working directory
cd Desktop # change directories to 'Desktop'
cd C:\
cls # clear screen
pwd
cd ~ # change directories and go 'home'
New-Item -Type file -Name goals.txt
Add-Content goals.txt "Learn PowerShell"
Get-Content goals.txt
Add-Content goals.txt "Learn Python"
Rename-Items goals.txt -NewName accomplished.txt
Get-Content goals.txt
Get-ChildItem # list contents of current working directory
Remove-Item accomplished.txt
```

## Concepts
```powershell
Get-Host
Get-PSDrive
cd HKCU:\
pwd
ls
cd C:\
Get-Command *process
Get-Commmand rename*
Get-Process | Get-Member
Get-Process | gm
Get-Alias gm
Get-Alias -Definition Get-Process
```

## Essentials
```powershell
# learn about an object's members
ps | gm

# Select specific strings to filter output
ps | Select processname
ps | Select processname | gm

# Selecting objects of a specified criteria
ps | Where-Object { $_.processname -eq 'powershell' }
ps | Where-Object { $_.processname -eq 'powershell' } | gm
$weird = ps | Where-Object { $_.processname -eq 'powershell' }
$weird.kill()

# Interating through a group of objects
New-Item -Type file -Name computers.txt
Add-Content notes.txt "localhost"
Add-Content notes.txt "t800.sky.net"
Add-Content notes.txt "127.0.0.1"
Get-Content nodes.txt
Get-Alias -Definition Get-Content
gc nodes.txt | ForEach-Object { if (Test-Connnection $_ -Quiet) { echo "$_ is up!" } }

# Getting help
Get-Help Get-Process
Get-Help Get-Process -Examples

```

# Advanced PowerShell

## Script Compatibility
```powershell
# Editions: Desktop = "Windows PowerShell", Core = "PowerShell Core" 
$PSVersionTable.PSEdition # Core edition can't run all Desktop scripts

# Hosts: PowerShell Console, ISE, VS Code, WAC, PowerShell Web Access 
$host # PowerShell ISE doesn't support interactive console utilities
Get-Host # $host and 'Get-Host' will also tell you the version in use

# Version numbers & CPU architecture
$PSVersionTable # check what version is running
$PSVersionTable.PSCompatibleVersions # other versions shell can work with
[Environment]::Is64BitOperatingSystem # check if OS is running x64-bit 
[Environment]::Is64BitProcess # check if current process is x64-bit
```

## Tips and Tricks
```powershell
# Hit ESC x2 to return your mouse cursor to the console prompt
# Tab completion automatically puts "./" in front of your script
# "Run Selection" button (F8) will execute one line of a script in ISE
ise .\script.ps1 # opens an ISE tab for the script
```

## Getting Help
```powershell
get-help set-*
get-help *loc* # can use multiple wildcards
get-help -full get-process
get-help about* # list of topical essays
```

## Aliases
```powershell
get-alias # show all aliases
get-alias ps # show aliases for a single cmdlet
get-help about_alias # print the essay about aliases
new-alias nn notepad.exe # create an alias for notepad.exe
set-alias nn netsh.exe # change what an existing alias points to
```

## Variables, Classes, Objects, Properties, and Methods
```powershell
$Process = Get-Process -Name powershell_ise # create a variable 
$Process # print the object your variable contains (ex: PoSH process) 
$Process.Name # print a single property of an object
$Process.Kill() # execute an object's method (ex: kill a process)
# some methods still execute without (), depends on required arguments
# print an object's methods, properties, and class (object type)
$Process | get-member
```

## Environment Variables and Drives
```powershell
# list all HDD & RAM drives (they only exist in memory, anchor w/scripts)
Get-PSDrive

# user variables
dir Variable:\ # list all user variables
get-item Variable:\ # change into "variable" drive (contains all vars)

# environment variables
get-item env:\ # list all env variables (kept in the 'env:' RAM drive)
$env:PATH # print specific environment variables
$env:COMPUTERNAME # print specific environment variables
```

## Profile Scripts
```powershell
# edit your profile scripts to make your env persistent (ex: drives)
# - these profile scripts are ran in this order
$profile.AllusersAllHosts # shared by all users via any hosting process 
$profile.AllusersCurrentHost # shared by all via this hosting process
$profile.CurrentUserAllHost # your profile script via any hosting process 
$profile.CurrentUserCurrentHost # your profile via this hosting proc

# open PowerShell w/o your profile script if you think it’s infected
powershell.exe -noprofile
```

## Modules
```powershell
# modules = DLLs or .psm1 scripts (functions only, no executable code!)
Get-Module -ListAvailable # searches $env:PSModulePath for all modules
Import-Module -Name AppLocker # copies a module into your Function drive
Import-Module -Name .\script.psm1 # import a script as a module
Get-Command -Module AppLocker # lists all functions of a module

# download & import a module from the Internet
Import-Module -Name (Invoke-WebRequest -Uri 'http://www.malware.com')

# PowerShell Gallery (NuGet provider) - https://www.powershellgallery.com/
Find-Module <module> # search PowerShell Gallery for a module
Install-Module # install a module from the PowerShell Gallery
Save-Module # download & save - do not install module from the Gallery
Get-InstalledModule # show all modules downloaded from PowerShell Gallery
Update-Module # update a module from PowerShell Gallery
```

## PowerShell Remoting
```powershell
# Requirements:
# - PowerShell 2.0+, WinRM service, TCP ports 5985 & 5986 (WSMAN) open
# -- TCP port 5985: native Windows authentication (Kerberos, Net-NTLM)
# -- TCP port 5986: certificate based authentication (SSL/TLS)
# - member of Local Administrators groups
Enable-PSRemoting -Force # enable PowerShell Remoting (do via GPO)

# interactive command shell
Enter-PSSession -ComputerName $env:COMPUTERNAME # use native Windows auth
Enter-PSSession -UseSSL -Computer box.sans.org # use cert-based auth
Exit-PSSession

# non-interactive command shell
$Output = Invoke-Command -FilePath .\script.ps1 # captures script output
# - opens a PSSession on the local box, and runs a single script

Invoke-Command -FilePath .\script.ps1 -Computer $Box # a remote PSSession
Invoke-Command -ScriptBlock {...} -Computer $Box
# - opens a PSSession on a box somewhere, and runs multiple scripts/cmds
```

## Run a script on multiple machines
```powershell
# first, build an array (a.k.a list)
$TargetsArray = Get-ADComputer -Filter * # list of hostnames via AD
$TargetsArray = Get-Content -Path ComputerList.txt # list of hostnames
$TargetsArray = @{"Server1","Server2","Server3"} # list of hostnames
# - @{"foo","bar","bug"} = PowerShell's syntax for declaring lists

# then, use open a PSSession on 1000+ hosts to run your script
$Output = Invoke-Command -Computer $TargetsArray -FilePath .\script.ps1
```

## Exporting, Importing, and Converting Object Data
```powershell
enter-pssession -computername $env:computername
get-help share
get-smbshare | select-object -property Name,Path
get-smbshare | export-csv -path C:\SANS\shares.csv
get-content -path C:\SANS\shares.csv
exit

import-csv -path C:\SANS\shares.csv
$array = import-csv -path C:\SANS\shares.csv
$array
$array |
ConvertTo-JSON |
Out-File -filepath shares.json

$array |
converto-html -property Name,Path |
Out-File -Filepath .\shares.html
Invoke-Command -computername $env:COMPUTERNAME -scriptblock {
    get-smbshare
    } | export-clixml -path shares.xml
```
