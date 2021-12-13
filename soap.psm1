function Block-TrafficToIpAddress {
    param(
        [Parameter(Mandatory)][ipaddress]$IpAddress
    )

    New-NetFirewallRule -DisplayName "Block $IpAddress" -Direction Outbound -Action Block -RemoteAddress $IpAddress
}

function ConvertFrom-Base64 {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$String
    )

    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
}

function ConvertTo-Base64 {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$String
    )

    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
    [Convert]::ToBase64String($Bytes)
}

function Enable-WinRm {
    param(
        [Parameter(Mandatory)]$ComputerName
    )

    $Expression = "wmic /node:$ComputerName process call create 'winrm quickconfig'"
    Invoke-Expression $Expression
    #Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c 'winrm qc'"
}

function Get-Asset {
    param(
        [switch]$Verbose
    )

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


function Get-Indicator {
    param(
        [string]$Path = "C:\Users",
        [Parameter(Mandatory)][string]$FileName
    )

    Get-ChildItem -Path $Path -Recurse -Force -ErrorAction Ignore |
    Where-Object { $_.Name -like $FileName } |
    Select-Object -ExpandProperty FullName
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

function Get-LocalAdministrators {
    (net localgroup administrators | Out-String).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) |
    Select-Object -Skip 4 |
    Select-String -Pattern "The command completed successfully." -NotMatch |
    ForEach-Object {
        New-Object -TypeName PSObject -Property @{ Name = $_ }
    }
}

function Get-TcpPorts {
    Get-NetTCPConnection | 
    Select-Object @{ "Name" = "ProcessId"; "Expression" = { $_.OwningProcess }},LocalPort,@{ "Name" = "ProcessName"; "Expression" = { (Get-Process -Id $_.OwningProcess).Name }},RemoteAddress |
    Sort-Object -Property ProcessId -Descending
}

function Get-WirelessNetAdapter {
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapter |
    Where-Object { $_.Name -match 'wi-fi|wireless' }
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

function Invoke-WinEventParser {
    param(
        [Parameter(Position=0)][string]$ComputerName,
        [ValidateSet("Application","Security","System","ForwardedEvents","Microsoft-Windows-PowerShell/Operational")][Parameter(Position=1)][string]$LogName,
        [ValidateSet("4104","4624","4625","4663","4672","4688","4697","5140","5156","6416")][Parameter(Position=2)]$EventId,
        [Parameter(Position=3)][int]$DaysAgo=1,
        [Parameter(Position=4)][switch]$TurnOffOutputFilter
    )

    filter Read-WinEvent {
        $XmlData = [xml]$_.ToXml()
        $Event = New-Object -TypeName PSObject
        $Event = New-Object -TypeName PSObject
        $Event | Add-Member -MemberType NoteProperty -Name LogName -Value $XmlData.Event.System.Channel
        $Event | Add-Member -MemberType NoteProperty -Name EventId -Value $XmlData.Event.System.EventId
        $Event | Add-Member -MemberType NoteProperty -Name TimeCreated -Value $_.TimeCreated
        $Event | Add-Member -MemberType NoteProperty -Name Hostname -Value $XmlData.Event.System.Computer
        $Event | Add-Member -MemberType NoteProperty -Name RecordId -Value $XmlData.Event.System.EventRecordId
        if ($XmlData.Event.System.Security.UserId) {
            $Event | Add-Member -MemberType NoteProperty -Name SecurityUserId -Value $XmlData.Event.System.Security.UserId
        }
        $EventData = $XmlData.Event.EventData.Data
        for ($Property = 0; $Property -lt $EventData.Count; $Property++) {
            $Event | Add-Member -MemberType NoteProperty -Name $EventData[$Property].Name -Value $EventData[$Property].'#text'
        }
        return $Event
    }

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

function Get-ProcessToKill {
    param(
        [Parameter(Mandatory)]$Name
    )

    $Process = Get-Process | Where-Object { $_.Name -like $Name }
    $Process.Kill()
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

function Test-TcpPort {
    param(
        [Parameter(Mandatory)][ipaddress]$IpAddress,
        [Parameter(Mandatory)][int]$Port
    )

    $TcpClient = New-Object System.Net.Sockets.TcpClient
    $TcpClient.ConnectAsync($IpAddress,$Port).Wait(1000)
}

function Unblock-TrafficToIpAddress {
    param(
        [Parameter(Mandatory)][ipaddress]$IpAddress
    )

    Remove-NetFirewallRule -DisplayName "Block $IpAddress"
}
