function Block-TrafficToIpAddress {
    param([Parameter(Mandatory)][ipaddress]$IpAddress)
    New-NetFirewallRule -DisplayName "Block $IpAddress" -Direction Outbound -Action Block -RemoteAddress $IpAddress
}

function Block-TrafficToRemotePort {
    param([Parameter(Mandatory)][int]$Port)
    New-NetFirewallRule -DisplayName "Block Outbound Port $Port" -Direction Outbound -Protocol TCP -RemotePort $Port -Action Block
}

function ConvertFrom-Base64 {
    param([Parameter(Mandatory, ValueFromPipeline)]$String)
    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
}

function ConvertTo-Base64 {
    param([Parameter(Mandatory, ValueFromPipeline)]$String)
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
    [Convert]::ToBase64String($Bytes)
}

function ConvertTo-BinaryString {
    Param([IPAddress]$IpAddress)
    $Integer = $IpAddress.Address
    $ReverseIpAddress = [IPAddress][String]$Integer
    $BinaryString = [Convert]::toString($ReverseIpAddress.Address,2)
    return $BinaryString
}

function ConvertTo-IpAddress {
    Param($BinaryString)
    $Integer = [System.Convert]::ToInt64($BinaryString,2).ToString()
    $IpAddress = ([System.Net.IPAddress]$Integer).IpAddressToString
    return $IpAddress
}

function ConvertFrom-CsvToMarkdownTable {
    <# .EXAMPLE 
    ConvertFrom-CsvToMarkdownTable -Path .\Report.csv
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -Path $Path) {
        $Csv = Get-Content $Path
        $Headers = $Csv | Select-Object -First 1
        $NumberOfHeaders = ($Headers.ToCharArray() | Where-Object { $_ -eq ',' }).Count + 1
        $MarkdownTable = $Csv | ForEach-Object { '| ' + $_.Replace(',',' | ') + ' |' }
        $MarkdownTable[0] += "`r`n" + ('| --- ' * $NumberOfHeaders) + '|'
        return $MarkdownTable 
    }
}

function Edit-CustomModule {
    param([string]$Name)
    $Module = "C:\Program Files\WindowsPowerShell\Modules\$Name\$Name.psm1"
    $Expression = 'powershell_ise.exe "$Module"'
    if (Test-Path -Path $Module) {
        Invoke-Expression $Expression
    } else {
        Write-Output "[x] The $Name module does not exist."
    }
}

function Enable-WinRm {
    param([Parameter(Mandatory)]$ComputerName)
    $Expression = "wmic /node:$ComputerName process call create 'winrm quickconfig'"
    Invoke-Expression $Expression
    #Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c 'winrm qc'"
}

function Get-App {
    param([string]$Name)
    $Apps = @()
    $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    return $Apps | Where-Object { $_.DisplayName -like "*$Name*"}
}

function Get-Asset {
    param([switch]$Verbose)
    $NetworkAdapterConfiguration = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'"
    $IpAddress = $NetworkAdapterConfiguration.IpAddress[0]
    $MacAddress = $NetworkAdapterConfiguration.MACAddress[0]
    $SystemInfo = Get-ComputerInfo
    $Asset = [pscustomobject] @{
        "Hostname" = $env:COMPUTERNAME
        "IpAddress" = $IpAddress
        "MacAddress" = $MacAddress
        "SerialNumber" = $SystemInfo.BiosSeralNumber
        "Make" = $SystemInfo.CsManufacturer
        "Model" = $SystemInfo.CsModel
        "OperatingSystem" = $SystemInfo.OsName
        "Architecture" = $SystemInfo.OsArchitecture
        "Version" = $SystemInfo.OsVersion
    }
    if ($Verbose) { $Asset }
    else { $Asset | Select-Object -Property HostName,IpAddress,MacAddress,SerialNumber}
}

function Get-BaselineConnections {
    Get-NetTcpConnection -State Established | 
    Select-Object -Property `
        OwningProcess,`
        @{ Name = "ProcessName"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } },`
        @{ Name = "Path"; Expression = { (Get-Process -Id $_.OwningProcess).Path } },`
        RemoteAddress,`
        RemotePort -Unique | 
    Sort-Object -Property Path,RemotePort |
    Format-Table -AutoSize
}

function Get-BaselinePorts {
    Get-NetTcpConnection -State Listen | 
    Select-Object -Property `
        OwningProcess,`
        @{ Name = "ProcessName"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } },`
        @{ Name = "Path"; Expression = { (Get-Process -Id $_.OwningProcess).Path } },`
        LocalPort |
    Sort-Object -Property Path,LocalPort |
    Format-Table -AutoSize
}

function Get-BaselineProcesses {
    Get-Process | 
    Select-Object -Property ProcessName,Path -Unique | 
    Sort-Object -Property Path
}

function Get-CallSign {
    $Adjectives = @("Bastard","Brass","Cannibal","Dark","Liquid","Solid","Doom","Gray","Silent","Steel","Stone")
    $Animals = @("Bat","Bear","Bison","Beetle","Cat","Cobra","Fox","Snake","Mantis","Mustang","Tiger")
    $CallSign = $($Adjectives | Get-Random -Count 1) + ' ' + $($Animals | Get-Random -Count 1)
    return $CallSign
}

function Get-CustomModule {
    param([string]$Name)
    Get-Module -ListAvailable | 
    Where-Object { $_.Path -like "C:\Program Files\WindowsPowerShell\Modules\*$Name*" }
}

function Get-DiskSpace {
    Get-CimInstance -Class Win32_LogicalDisk |
    Select-Object -Property @{
        Label = 'DriveLetter'
        Expression = { $_.Name }
    },@{
        Label = 'FreeSpace (GB)'
        Expression = { ($_.FreeSpace / 1GB).ToString('F2') }
    },@{
        Label = 'TotalSpace (GB)'
        Expression = { ($_.Size / 1GB).ToString('F2') }
    },@{
        Label = 'SerialNumber'
        Expression = { $_.VolumeSerialNumber }
    }
}

function Get-DomainAdministrators {
    Get-AdGroupMember -Identity "Domain Admins" |
    Select-Object -Property Name,SamAccountName,Sid |
    Format-Table -AutoSize
}

function Get-EnterpriseVisbility {
    param(
        [Parameter(Mandatory)][string]$Network,
        [Parameter(Mandatory)][string]$EventCollector
    )
    $ActiveIps = Get-IpAddressRange -Network $Network | Test-Connections
    $AdObjects = (Get-AdComputer -Filter "*").Name
    $EventForwarders = Get-EventForwarders -ComputerName $EventCollector
    $WinRmclients = Get-WinRmClients
    $Visbility = New-Object -TypeName psobject
    $Visbility | Add-Member -MemberType NoteProperty -Name ActiveIps -Value $ActiveIps.Count
    $Visbility | Add-Member -MemberType NoteProperty -Name AdObjects -Value $AdObjects.Count
    $Visbility | Add-Member -MemberType NoteProperty -Name EventForwarders -Value $EventForwarders.Count
    $Visbility | Add-Member -MemberType NoteProperty -Name WinRmClients -Value $WinRmclients.Count
    return $Visbility
}

function Get-EventFieldNumber {
    param(
        [parameter(Mandatory)][int]$EventId,
        [parameter(Mandatory)][string]$Field
    )
    $LookupTable = "windows-event-fields.json"
    if (Test-Path $LookupTable) {
        $FieldNumber = $(Get-Content $LookupTable | ConvertFrom-Json) |
            Where-Object { $_.Id -eq $EventId } |
            Select-Object -ExpandProperty Fields |
            Select-Object -ExpandProperty $Field -ErrorAction Ignore
        if ($FieldNumber -eq $null) {
            Write-Error "Event ID $EventId does not have a field called $Field."
            break
        } else {
            return $FieldNumber
        }
    } else {
        Write-Error "File not found: $LookupTable"
        break
    }
}

function Get-EventForwarders {
    param(
      [string]$ComputerName,
      [string]$Subscription = "Forwarded Events"
    )
    Invoke-Command -ComputerName $ComputerName -ArgumentList $Subscription -ScriptBlock {
        $Subscription = $args[0]
        $Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\$Subscription\EventSources"
        $EventForwarders = (Get-ChildItem $Key).Name | ForEach-Object { $_.Split("\")[9] }
        return $EventForwarders
    }
}

function Get-Indicator {
    param(
        [string]$Path = "C:\Users",
        [Parameter(Mandatory)][string]$FileName
    )
    Get-ChildItem -Path $Path -Recurse -Force -ErrorAction Ignore |
    Where-Object { $_.Name -like $FileName } |
    Select-Object -ExpandProperty FullName
}

function Get-IpAddressRange {
    param([Parameter(Mandatory)][string[]]$Network)
    $IpAddressRange = @()
    $Network |
    foreach {
        if ($_.Contains('/')) {
            $NetworkId = $_.Split('/')[0]
            $SubnetMask = $_.Split('/')[1]
            if ([ipaddress]$NetworkId -and ($SubnetMask -eq 32)) {
                $IpAddressRange += $NetworkId          
            } elseif ([ipaddress]$NetworkId -and ($SubnetMask -le 32)) {
                $Wildcard = 32 - $SubnetMask
                $NetworkIdBinary = ConvertTo-BinaryString $NetworkId
                $NetworkIdIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('0' * $Wildcard)
                $BroadcastIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('1' * $Wildcard)
                $NetworkIdIpAddress = ConvertTo-IpAddress $NetworkIdIpAddressBinary
                $BroadcastIpAddress = ConvertTo-IpAddress $BroadcastIpAddressBinary
                $NetworkIdInt32 = [convert]::ToInt32($NetworkIdIpAddressBinary,2)
                $BroadcastIdInt32 = [convert]::ToInt32($BroadcastIpAddressBinary,2)
                $NetworkIdInt32..$BroadcastIdInt32 | 
                foreach {
                    $BinaryString = [convert]::ToString($_,2)
                    $Address = ConvertTo-IpAddress $BinaryString
                    $IpAddressRange += $Address
                }            
            }
        }
    }
    return $IpAddressRange
}

function Get-LocalAdministrators {
    (net localgroup administrators | Out-String).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) |
    Select-Object -Skip 4 |
    Select-String -Pattern "The command completed successfully." -NotMatch |
    ForEach-Object {
        New-Object -TypeName PSObject -Property @{ Name = $_ }
    }
}

function Get-ModuleFunctions {
    param([string]$Module)
    (Get-Module $Module | Select-Object -Property ExportedCommands).ExportedCommands.Keys 
}

function Get-Permissions {
    param(
        [string]$File = $pwd,
        [int]$Depth = 1
    )
    if (Test-Path -Path $File) {
        Get-ChildItem -Path $File -Recurse -Depth $Depth |
        ForEach-Object {
            $Object = New-Object -TypeName PSObject
            $Object | Add-Member -MemberType NoteProperty -Name Name -Value $_.PsChildName
            $Acl = Get-Acl -Path $_.FullName | Select-Object -ExpandProperty Access
            $AclAccount = $Acl.IdentityReference
            $AclRight = ($Acl.FileSystemRights -split ',').Trim()
            for ($Ace = 0; $Ace -lt $AclAccount.Count; $Ace++) {
                $Object | Add-Member -MemberType NoteProperty -Name $AclAccount[$Ace] -Value $AclRight[$Ace]
            }
            return $Object
        }
    }
}

function Get-Privileges {
    # powershell.exe "whoami /priv | findstr Enabled | % { $_.Split(" ")[0] } > C:\Users\Public\privileges-$env:USERNAME.txt"
    # create a scheduled task and run this command...using the Users group

    SecEdit.exe /export /areas USER_RIGHTS /cfg ./user-rights.txt /quiet
    $Privileges = Get-Content .\user-rights.txt | Where-Object { $_.StartsWith("Se") }
    Remove-Item .\user-rights.txt | Out-Null

    $Privileges |
    ForEach-Object {
        $Assignment = $_.Split(" = ")
        $Privilege = $Assignment[0]
        $Sids = $Assignment[3].Split(",") |
            ForEach-Object {
                if ($_.StartsWith("*")) {
                    $_.Substring(1)
                } else {
                    $_
                }
            }
        $Sids | 
        ForEach-Object {
            $Sid = $_
            $UserAccount = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Sid -eq $Sid } | Select-Object -ExpandProperty Name
            $BuiltInAccount = Get-WmiObject -Class Win32_Account | Where-Object { $_.Sid -eq $Sid } | Select-Object -ExpandProperty Name
            $BuiltInGroup = Get-WmiObject -Class Win32_Group | Where-Object { $_.Sid -eq $Sid } | Select-Object -ExpandProperty Name

            if ($UserAccount) {
                $Username = $UserAccount
            } elseif ($BuiltInAccount) {
                $Username = $BuiltInAccount
            } elseif ($BuiltInGroup) {
                $Username = $BuiltInGroup
            } else {
                $Username = $Sid
            }
        
            $Output = New-Object psobject
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Privilege -Value $Privilege
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Sid -Value $_
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Username -Value $Username
            $Output
        }
    }
}

function Get-ProcessToKill {
    param([Parameter(Mandatory)]$Name)
    $Process = Get-Process | Where-Object { $_.Name -like $Name }
    $Process.Kill()
}

function Get-Shares {
    param([string[]]$Whitelist = @("ADMIN$","C$","IPC$"))
    Get-SmbShare | 
    Where-Object { $Whitelist -notcontains $_.Name } |
    Select-Object -Property Name, Path, Description
}

function Get-TcpPort {
    Get-NetTCPConnection | 
    Select-Object @{ "Name" = "ProcessId"; "Expression" = { $_.OwningProcess }},LocalPort,@{ "Name" = "ProcessName"; "Expression" = { (Get-Process -Id $_.OwningProcess).Name }},RemoteAddress |
    Sort-Object -Property ProcessId -Descending
}

function Get-WhoIs {
    $FilterHashTable = @{
        LogName = 'Microsoft-Windows-Sysmon/Operational' 
        Id = 3
    }
    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Select-Object SourceIp,DestinationIp,DestinationPort | 
    Sort-Object -Property DestinationIp -Unique | 
    ForEach-Object {
        $Header = @{"Accept" = "application/xml"}
        $Response = Invoke-Restmethod -Uri $("http://whois.arin.net/rest/ip/" + $_.DestinationIp) -Headers $Header -ErrorAction Ignore
        $Organization = $Response.net.orgRef.name
        if ($Organization -ne 'Microsoft Corporation') {
            return New-Object -TypeName psobject -Property @{SourceIp = $_.SourceIp; DestinationIp = $_.DestinationIp; DestinationPort = $_.DestinationPort; Organization = $Organization}
        } 
    }
}

function Get-WinRmClients {
    $ComputerNames = $(Get-AdComputer -Filter *).Name
    Invoke-Command -ComputerName $ComputerNames -ScriptBlock { $env:HOSTNAME } -ErrorAction Ignore
}

function Get-WirelessNetAdapter {
    param([string]$ComputerName = $env:COMPUTERNAME)
    Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapter |
    Where-Object { $_.Name -match 'wi-fi|wireless' }
}

function Get-WordWheelQuery {
    $Key = "Registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
    Get-Item $Key | 
    Select-Object -Expand Property | 
    ForEach-Object {
        if ($_ -ne "MRUListEx") {
            $Value = (Get-ItemProperty -Path $Key -Name $_).$_
            [System.Text.Encoding]::Unicode.GetString($Value)
        }
    }
}

function Import-CustomViews {
    param([string]$Path = "C:\Program Files\WindowsPowerShell\Modules\SOAP-Modules\Custom-Views")
    $CustomViewsFolder = "C:\ProgramData\Microsoft\Event Viewer\Views"
    $CustomViews = Get-ChildItem -Recurse $CustomViewsFolder
    Get-ChildItem -Recurse "$Path\*.xml" |
    Where-Object { $_.Name -notin $CustomViews } | 
    Copy-Item -Destination $CustomViewsFolder
}

function Invoke-WinEventParser {
    param(
        [Parameter(Position=0)][string]$ComputerName,
        [ValidateSet("Application","Security","System","ForwardedEvents","Microsoft-Windows-PowerShell/Operational")][Parameter(Position=1)][string]$LogName,
        [ValidateSet("4104","4624","4625","4663","4672","4688","4697","5140","5156","6416")][Parameter(Position=2)]$EventId,
        [Parameter(Position=3)][int]$DaysAgo=1,
        [Parameter(Position=4)][switch]$TurnOffOutputFilter
    )
    if ($TurnOffOutputFilter) {
        Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$EventId } |
        Read-WinEvent
    } else {
        if ($EventId -eq "4104") { $Properties = "TimeCreated","SecurityUserId","ScriptBlockText" }
        elseif ($EventId -eq "4624") { $Properties = "TimeCreated","IpAddress","TargetUserName","LogonType" }
        elseif ($EventId -eq "4625") { $Properties = "TimeCreated","IpAddress","TargetUserName","LogonType" }
        elseif ($EventId -eq "4663") { $Properties = "*" }
        elseif ($EventId -eq "4672") { $Properties = "TimeCreated","SubjectUserSid","SubjectUserName" }
        elseif ($EventId -eq "4688") { $Properties = "TimeCreated","TargetUserName","NewProcessName","CommandLine" }
        elseif ($EventId -eq "4697") { $Properties = "*" }
        elseif ($EventId -eq "5140") { $Properties = "*" }
        elseif ($EventId -eq "5156") { $Properties = "TimeCreated","SourceAddress","DestAddress","DestPort" }
        elseif ($EventId -eq "6416") { $Properties = "TimeCreated","SubjectUserName","ClassName","DeviceDescription" }
        else { $Properties = "*" }
        Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$EventId } |
        Read-WinEvent |
        Select-Object -Property $Properties
    }
}

function New-CustomModule {
    param(
        [Parameter(Mandatory,Position=0)][string]$Name,
        [Parameter(Mandatory,Position=1)][string]$Author,
        [Parameter(Mandatory,Position=2)][string]$Description
    )
    $Directory = "C:\Program Files\WindowsPowerShell\Modules\$Name"
    $Module = "$Directory\$Name.psm1"
    $Manifest = "$Directory\$Name.psd1"
    if (Test-Path -Path $Directory) {
        Write-Output "[x] The $Name module already exists."
    } else { 
        New-Item -ItemType Directory -Path $Directory | Out-Null
        New-Item -ItemType File -Path $Module | Out-Null
        New-ModuleManifest -Path $Manifest `
            -Author $Author `
            -RootModule "$Name.psm1" `
            -Description $Description
        if (Test-Path -Path $Module) {
            Write-Output "[+] Created the $Name module."
        }
    }
}

filter Read-WinEvent {
        $WinEvent = [ordered]@{} 
        $XmlData = [xml]$_.ToXml()
        $SystemData = $XmlData.Event.System
        $SystemData | 
        Get-Member -MemberType Properties | 
        Select-Object -ExpandProperty Name |
        ForEach-Object {
            $Field = $_
            if ($Field -eq 'TimeCreated') {
                $WinEvent.$Field = Get-Date -Format 'yyyy-MM-dd hh:mm:ss' $SystemData[$Field].SystemTime
            } elseif ($SystemData[$Field].'#text') {
                $WinEvent.$Field = $SystemData[$Field].'#text'
            } else {
                $SystemData[$Field]  | 
                Get-Member -MemberType Properties | 
                Select-Object -ExpandProperty Name |
                ForEach-Object { 
                    $WinEvent.$Field = @{}
                    $WinEvent.$Field.$_ = $SystemData[$Field].$_
                }
            }
        }
        $XmlData.Event.EventData.Data |
        ForEach-Object { 
            $WinEvent.$($_.Name) = $_.'#text'
        }
        return New-Object -TypeName PSObject -Property $WinEvent
}

function Remove-App {
    param([Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$UninstallString)
    if ($UninstallString -contains "msiexec") {
        $App = ($UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X","").Trim()
        Start-Process "msiexec.exe" -ArgumentList "/X $App /qb" -NoNewWindow
    } else {
        Start-Process $UninstallString -NoNewWindow
    }
}

function Remove-CustomModule {
    param([Parameter(Mandatory)][string]$Name)
    $Module = "C:\Program Files\WindowsPowerShell\Modules\$Name"
    if (Test-Path -Path $Module) {
        Remove-Item -Path $Module -Recurse -Force
        if (-not (Test-Path -Path $Module)) {
            Write-Output "[+] Deleted the $Name module."
        }
    } else {
        Write-Output "[x] The $Name module does not exist."
    }
}

function Start-AdScrub {
    Import-Module ActiveDirectory

    $30DaysAgo = (Get-Date).AddDays(-30)
    $AtctsReport = Import-Csv $Report | Select Name, @{Name='TrainingDate';Expression={$_.'Date Awareness Training Completed'}}
    $AdSearchBase = ''
    $DisabledUsersOu = '' + $AdSearchBase
    $AdUserAccounts = Get-AdUser -Filter * -SearchBase $AdSearchBase -Properties LastLogonDate
    $VipUsers = $(Get-AdGroup -Identity 'VIP Users').Sid
    $UsersInAtctsReport = $AtctsReport.Name.ToUpper() |
    foreach {
        $SpaceBetweenFirstAndMiddle = $_.Substring($_.Length -2).Substring(0,1)
        if ($SpaceBetweenFirstAndMiddle) { $_ -replace ".$" }
    }

    $AdUserAccounts |
    Where-Object { $VipUsers -notcontains $_.Sid } |
    foreach {
        $NotCompliant = $false
        $Reason = 'Disabled:'

        if ($_.Surname -and $_.GivenName) {
            $FullName = ($_.Surname + ', ' + $_.GivenName).ToUpper()
        } else {
            $FullName = ($_.SamAccountName).ToUpper()
        }

        $AtctsProfile = $UsersInAtctsReport | Where-Object { $_ -like "$FullName*" }

        if (-not $AtctsProfile) {
            $NotCompliant = $true
            $Reason = $Reason + ' ATCTS profile does not exist.'
        }

        if ($AtctsProfile) {
            $TrainingDate = ($AtctsReport | Where-Object { $_.Name -like "$FullName*" }).TrainingDate
            $NewDate = $TrainingDate.Split('-')[0]+ $TrainingDate.Split('-')[2] + $TrainingDate.Split('-')[1]
            $ExpirationDate = (Get-Date $NewDate).AddYears(1).ToString('yyyy-MM-dd')
            if ($ExpirationDate -lt $(Get-Date -Format 'yyyy-MM-dd')){
                $NotCompliant = $true
                $Reason = $Reason + ' Training has expired.'
            }
        }

        if ($_.LastLogonDate -le $30DaysAgo) {
            $NotCompliant = $true
            $Reason = $Reason + 'Inactive for 30 days.'
        }

        if ($NotCompliant) {
            Set-AdUser $_.SamAccountName -Description $Reason
            Disable-AdAccount $_.SamAccountName
            Move-AdObject -Identity $_.DistinguishedName -TargetPath $DisabledUsersOu
            Write-Output "[+] $($_.Name) - $Reason"
        }
    }
}

function Import-AdUsersFromCsv {
    $Password = ConvertTo-SecureString -String '1qaz2wsx!QAZ@WSX' -AsPlainText -Force
    Import-Csv -Path .\users.csv |
    ForEach-Object {
        $Name = $_.LastName + ', ' + $_.FirstName
        $SamAccountName = ($_.FirstName + '.' + $_.LastName).ToLower()
        $UserPrincipalName = $SamAccountName + '@evilcorp.local'
        $Description = $_.Description
        $ExpirationDate = Get-Date -Date 'October 31 2022'
        New-AdUser `
            -Name $Name `
            -DisplayName $Name `
            -GivenName $_.FirstName `
            -Surname $_.LastName `
            -SamAccountName $SamAccountName `
            -UserPrincipalName $UserPrincipalName `
            -Description $Description `
            -ChangePasswordAtLogon $true `
            -AccountExpirationDate $ExpirationDate `
            -Enabled $true `
            -Path 'OU=Users,OU=evilcorp,DC=local' `
            -AccountPassword $Password
    }
}

function Start-AdBackup {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [string]$Share = "Backups",
        [string]$Prefix = "AdBackup"
    )
    $BackupFeature = (Install-WindowsFeature -Name Windows-Server-Backup).InstallState
    $BackupServerIsOnline = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet
    if ($BackupFeature -eq "Installed") {
        if ($BackupServerIsOnline) {
            $Date = Get-Date -Format "yyyy-MM-dd"
            $Target = "\\$ComputerName\$Share\$Prefix-$Date"
            $LogDirectory = "C:\BackupLogs"
    	    $LogFile = "$LogDirectory\$Prefix-$Date"
            if (Test-Path $Target) { Remove-Item -Path $Target -Recurse -Force }
            New-Item -ItemType Directory -Path $Target -Force | Out-Null
            if (Test-Path $LogDirectory) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
            $Expression = "wbadmin START BACKUP -systemState -vssFull -backupTarget:$Target -noVerify -quiet"
            Invoke-Expression $Expression | Out-File -FilePath $LogFile
        } else {
            Write-Output "[x] The computer specified is not online."
        }
    } else {
        Write-Output "[x] The Windows-Server-Backup feature is not installed. Use the command below to install it."
        Write-Output " Install-WindowsFeature -Name Windows-Server-Backup"
    }
}

function Start-Coffee {
    while ($true) {
        (New-Object -ComObject Wscript.Shell).Sendkeys(' '); sleep 60
    }
}

function Start-ImperialMarch {
    [console]::beep(440,500)      
    [console]::beep(440,500)
    [console]::beep(440,500)       
    [console]::beep(349,350)       
    [console]::beep(523,150)       
    [console]::beep(440,500)       
    [console]::beep(349,350)       
    [console]::beep(523,150)       
    [console]::beep(440,1000)
    [console]::beep(659,500)       
    [console]::beep(659,500)       
    [console]::beep(659,500)       
    [console]::beep(698,350)       
    [console]::beep(523,150)       
    [console]::beep(415,500)       
    [console]::beep(349,350)       
    [console]::beep(523,150)       
    [console]::beep(440,1000)
}

function Start-Panic {
    param([string]$ComputerName = 'localhost')
    #shutdown /r /f /m ComputerName /d P:0:1 /c "Your comment"
    Stop-Computer -ComputerName $ComputerName
}

function Start-RollingReboot {
    param(
        [int]$Interval = 4,
        [int]$Duration = 60
    )
    $TaskName = "Rolling Reboot"
    $Action= New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /t 0" 
    $Trigger= New-ScheduledTaskTrigger -At $(Get-Date) -Once -RepetitionInterval $(New-TimeSpan -Minutes $Interval) -RepetitionDuration $(New-TimeSpan -Minutes $Duration)
    $User= "NT AUTHORITY\SYSTEM" 
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -User $User -RunLevel Highest Force
    Start-ScheduledTask -TaskName $TaskName
}

function Test-Connections {
    param([Parameter(ValueFromPipeline)][string]$IpAddress)
    Begin{ $IpAddressRange = @() }
    Process{ $IpAddressRange += $IpAddress }
    End{ 
        $Test = $IpAddressRange | ForEach-Object { (New-Object Net.NetworkInformation.Ping).SendPingAsync($_,2000) }
        [Threading.Tasks.Task]::WaitAll($Test)
        $Test.Result | Where-Object { $_.Status -eq 'Success' } | Select-Object @{ Label = 'ActiveIp'; Expression = { $_.Address } }
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)][ipaddress]$IpAddress,
        [Parameter(Mandatory)][int]$Port
    )
    $TcpClient = New-Object System.Net.Sockets.TcpClient
    $State = $TcpClient.ConnectAsync($IpAddress,$Port).Wait(1000)
    if ($State -eq 'True') { $State = 'Open' }
    else { $State = 'Closed' }
    $TcpPort = [pscustomobject] @{
        'IpAddress' = $IpAddress
        'Port'      = $Port
        'State'    = $State
    }
    return $TcpPort
}

function Update-AdDescriptionWithLastLogon {
    
}

function Update-GitHubRepo {
    param(
        [string]$Author,
        [string]$Repo,
        [string]$Branch,
        [string]$Path
    )
    $RepoToUpdate = "https://github.com/$Author/$Repo"
    $Response = Invoke-WebRequest -Uri "$RepoToUpdate/commits"
    if ($Response.StatusCode -eq '200') {
        $LastCommit = ($Response.Links.href | Where-Object { $_ -like "/$Author/$Repo/commit/*" } | Select-Object -First 1).Split("/")[4].Substring(0,7)
        $Git = "$Path\.git\"
        $FETCH_HEAD = "$Git\FETCH_HEAD"
        $LastCommitDownloaded = $null
        if ((Test-Path -Path $Path) -and (Test-Path -Path $Git)) {
            $LastCommitDownloaded = (Get-Content -Path $FETCH_HEAD).SubString(0,7)
        }
        if ($LastCommitDownloaded -ne $LastCommit) {
            Write-Output "[!] Updating the local branch of $Repo."
            Invoke-WebRequest -Uri "$RepoToUpdate/archive/refs/heads/$Branch.zip" -OutFile "$Repo.zip"
            Expand-Archive -Path "$Repo.zip"
            Move-Item -Path "$Repo\$Repo-$Branch" -Destination $Path
            New-Item -Path $FETCH_HEAD -Force | Out-Null
            (Get-Item -Path $Git).Attributes += "Hidden"
            Add-Content -Path $FETCH_HEAD -Value $LastCommit -Force
            Remove-Item -Path "$Repo.zip"
            Remove-Item -Path "$Repo" -Recurse
        } else {
            Write-Output "[+] Nothing to update for the local branch of $Repo."
        }
    }
}

function Unblock-TrafficToIpAddress {
    param([Parameter(Mandatory)][ipaddress]$IpAddress)
    Remove-NetFirewallRule -DisplayName "Block $IpAddress"
}
