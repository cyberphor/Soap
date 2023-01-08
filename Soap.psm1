function Block-Traffic {
    <#
        .SYNOPSIS
        Blocks network traffic destined to the provided IP address and/or port. 

        .DESCRIPTION
        Adds a rule to the local Windows Firewall policy so network traffic destined to the provided IP address and/or port is blocked.

        .PARAMETER Protocol
        Specifies the protocol to block.

        .PARAMETER IpAddress
        Specifies the IP address to block traffic.

        .PARAMETER Port
        Specifies the port to block traffic.

        .INPUTS
        None. You cannot pipe objects to this function.

        .OUTPUTS
        None. 

        .EXAMPLE
        PS> Block-Traffic -Protocol UDP -IpAddress 8.8.8.8 -Port 53

        .LINK
        https://github.com/cyberphor/Soap
    #>
    Param(
        [ValidateSet("Any","TCP","UDP","ICMPv4","ICMPv6")][string]$Protocol = "Any",
        [Parameter(Mandatory)][ipaddress]$IpAddress,
        $Port = "Any"
    )
    New-NetFirewallRule `
        -DisplayName "Block '$Protocol' traffic to '$Port' port on $IpAddress" `
        -Direction Outbound `
        -Protocol $Protocol `
        -RemoteAddress $IpAddress `
        -RemotePort $RemotePort `
        -Action Block
} 

function Clear-AuditPolicy {
    <#
        .SYNOPSIS
        Clears the local audit policy. 

        .DESCRIPTION
        Uses "auditpol.exe" to clear the local audit (logging) policy. 

        .INPUTS
        None. You cannot pipe objects to this function.

        .OUTPUTS
        None. 

        .EXAMPLE
        PS> Clear-AuditPolicy

        .LINK
        https://github.com/cyberphor/Soap
    #>
    Start-Process -FilePath "auditpol.exe" -ArgumentList "/clear","/y"
}

function Disable-Firewall {
    <#
        .SYNOPSIS
        Disables the firewall. 

        .DESCRIPTION
        Disables the domain, public, and private firewall profile. 

        .INPUTS
        None. This function does not accept piped objects.

        .OUTPUTS
        None.

        .EXAMPLE
        PS> Disable-Firewall

        .LINK
        https://github.com/cyberphor/Soap
    #>
    Set-NetFirewallProfile -Name domain,public,private -Enabled False
} 

function Disable-Ipv6 {
    <#
        .SYNOPSIS
        Disables IPv6. 

        .DESCRIPTION
        Disables IPv6 binding on all network adapters. 

        .INPUTS
        None. This function does not accept piped objects.

        .OUTPUTS
        None.

        .EXAMPLE
        PS> Disable-Firewall

        .LINK
        https://github.com/cyberphor/Soap
    #>
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
}

function Edit-Module {
    <#
        .SYNOPSIS
        Opens the specified PowerShell module using PowerShell ISE. 

        .DESCRIPTION
        Opens the specified PowerShell script module file (.psm1) using PowerShell ISE. 

        .INPUTS
        None. This function does not accept piped objects.

        .OUTPUTS
        None.

        .EXAMPLE
        PS> Edit-Module "soap"

        .LINK
        https://github.com/cyberphor/Soap
    #>
    Param([Parameter(Mandatory)][string]$Name)
    $Module = Get-Module | Where-Object { $_.Path -like "*$Name.psm1" }
    if ($Module) { 
        ise $Module.Path
    } else {
        Write-Error "A module called '$Name' does not exist."
    }
}

function Enable-Firewall {
    <#
        .SYNOPSIS
        Enables the firewall. 

        .DESCRIPTION
        Enables the domain, public, and private firewall profile. 

        .INPUTS
        None. This function does not accept piped objects.

        .OUTPUTS
        None.

        .EXAMPLE
        PS> Enable-Firewall

        .LINK
        https://github.com/cyberphor/Soap
    #>
    Set-NetFirewallProfile -Name domain,public,private -Enabled true
}

function Enable-Ipv6 {
    <#
        .SYNOPSIS
        Enables IPv6. 

        .DESCRIPTION
        Enables IPv6 binding for on network adapters. 

        .INPUTS
        None. This function does not accept piped objects.

        .OUTPUTS
        None.

        .EXAMPLE
        PS> Disable-Firewall

        .LINK
        https://github.com/cyberphor/Soap
    #>
    Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
}

function Enable-WinRm {
    param([Parameter(Mandatory)]$ComputerName)
    $Expression = "wmic /node:$ComputerName process call create 'winrm quickconfig'"
    Invoke-Expression $Expression
    #Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c 'winrm qc'"
}

function Find-IpAddressInWindowsEventLog {
    param(
        [string]$IpAddress
    )
    $FilterHashTable = @{
        LogName = "Security"
        Id = 5156
    }
    Get-WinEvent -FilterHashtable $FilterHashTable | 
    Read-WinEvent  | 
    Where-Object { 
        ($_.DestAddress -eq $IpAddress) -or 
        ($_.SourceAddress -eq $IpAddress) } | 
    Select-Object TimeCreated, EventRecordId, SourceAddress, DestAddress
}

function Find-WirelessComputer {
    $Computers = Get-AdComputer -Filter * | Select-Object -ExpandProperty DnsHostname
    Invoke-Command -ComputerName $Computers -ErrorAction Ignore -ScriptBlock {
      Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.Name -like '*Wireless*' }
    }
}

function Get-AuditPolicy {
    Param(
        [ValidateSet("System",`
                     "Logon/Logoff",`
                     "Object Access",`
                     "Privilege Use",`
                     "Detailed Tracking",`
                     "Policy Change",`
                     "Account Management",`
                     "DS Access",`
                     "Account Logon"
        )]$Category
    )
    if ($Category -eq $null) {
        $Category = "System",`
                    "Logon/Logoff",`
                    "Object Access",`
                    "Privilege Use",`
                    "Detailed Tracking",`
                    "Policy Change",`
                    "Account Management",`
                    "DS Access",`
                    "Account Logon"    
    }
    $Category | 
    ForEach-Object {
        $Category = $_
        $Policy = @{}
        ((Invoke-Expression -Command 'auditpol.exe /get /category:"$Category"') `
        -split "`r" -match "\S" | 
        Select-Object -Skip 3).Trim() |
        ForEach-Object {
            $Setting = ($_ -replace "\s{2,}","," -split ",")
            $Policy.Add($Setting[0],$Setting[1])
        }
        $Policy.GetEnumerator() |
        ForEach-Object {
            [PSCustomObject]@{
                Subcategory = $_.Key
                Setting = $_.Value
            }
        }
    }
}

function Get-AutoRuns {
    $RegistryKeys = @(
        "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    )
    $AutoRunsFound = @{}
    $RegistryKeys | 
    ForEach-Object {
        $RegistryKey = $_ 
        if (Test-Path $RegistryKey) {
            $AutoRunsExist = Get-Item $RegistryKey | Select -ExpandProperty Property

            if ($AutoRunsExist) {
                $Count = (Get-Item $RegistryKey).Property.Count 
                (Get-Item $RegistryKey).Property[0..$Count] |
                ForEach-Object { 
                    $App = $_
                    $AppPath = (Get-ItemProperty $RegistryKey).$App 
                    $AutoRunsFound.Add($App,$AppPath)
                }
            }
        }
    }
    return $AutoRunsFound 
}

function Get-WinEventDns {
    Param(
        [string]$Whitelist,
        [switch]$Verbose
    )
    if ($Whitelist) {
        $Exclusions = Get-Content $Whitelist -ErrorAction Stop
    }
    $FilterHashTable = @{
        LogName = "Microsoft-Windows-DNS-Client/Operational"
        Id = 3006
    }
    if ($Verbose) {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Where-Object { $_.QueryName -notin $Exclusions }
    } else {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Where-Object { $_.QueryName -notin $Exclusions } |
        Group-Object -Property QueryName -NoElement |
        Sort-Object -Property Count -Descending |
        Format-Table -AutoSize
    }
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

function Get-DomainAdministrator {
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

function Get-EventForwarder {
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

function Get-LocalAdministrator {
    <#
        .EXAMPLE
        Get-LocalAdministrators
        Name         
        ----         
        Administrator
        Cristal      
        Victor 

        .EXAMPLE
        $Computers = (Get-AdComputer -Filter *).Name
        Invoke-Command -ComputerName $Computers -ScriptBlock ${function:Get-LocalAdministrators} |
        Select-Object Name, PsComputerName
    #>
    (net localgroup administrators | Out-String).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) |
    Select-Object -Skip 4 |
    Select-String -Pattern "The command completed successfully." -NotMatch |
    ForEach-Object {
        New-Object -TypeName PSObject -Property @{ Name = $_ }
    }
}

function Get-WinEventFirewall {
    Param(
        [ValidateSet("SourceAddress","DestAddress")]$Direction = "DestAddress",
        [string]$Whitelist,
        [switch]$Verbose
    )
    if ($Whitelist) {
        $Exclusions = Get-Content $Whitelist -ErrorAction Stop
    }
    $FilterHashTable = @{
        LogName = "Security"
        Id = 5156
    }
    if ($Verbose) {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Where-Object { $_.$Direction -notin $Exclusions }
    } else {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent | 
        Where-Object { $_.$Direction -notin $Exclusions } |
        Group-Object -Property $Direction -NoElement |
        Sort-Object -Property Count -Descending |
        Format-Table -AutoSize
    }
}

function Get-WinEventLogon {
    Param(
        [ValidateSet("Failed","Successful")]$Type = "Failed",
        [switch]$Verbose
    )
    if ($Type -eq "Failed") {
        $Id = 4625
    } elseif ($Type -eq "Successful") {
        $Id = 4624
    }
    $FilterHashTable = @{
        LogName = "Security"
        Id = $Id
    }
    if ($Verbose) {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent
    } else {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Group-Object -Property TargetUserName -NoElement |
        Sort-Object -Property Count -Descending |
        Format-Table -AutoSize
    }
}

function Get-WinEventPowerShell {
    Param(
        [string]$Whitelist,
        [switch]$Verbose    
    )
    if ($Whitelist) {
        $Exclusions = Get-Content $Whitelist -ErrorAction Stop
    }
    $FilterHashTable = @{
        LogName = "Microsoft-Windows-PowerShell/Operational"
        Id = 4104
    }
    if ($Verbose) {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Where-Object { $_.ScriptBlockText -notin $Exclusions }
    } else {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent  | 
        Where-Object { $_.ScriptBlockText -notin $Exclusions } |
        Group-Object -Property ScriptBlockText -NoElement |
        Sort-Object -Property Count -Descending |
        Format-Table -AutoSize
    }
}

function Get-ProcessByNetworkConnection {
    $NetworkConnections = Get-NetTCPConnection -State Established
    Get-Process -IncludeUserName |
    ForEach-Object {
        $OwningProcess = $_.Id
        $OwningProcessName = $_.ProcessName
        $OwningProcessPath = $_.Path
        $OwningProcessUsername = $_.UserName
        $NetworkConnections |
        Where-Object {
            $_.LocalAddress -ne "::1" -and
            $_.LocalAddress -ne "127.0.0.1" -and
            $_.OwningProcess -eq $OwningProcess
        } | Select-Object `
            @{ Name = "Username"; Expression = {$OwningProcessUsername} },`
            @{ Name = "ProcessId"; Expression = {$_.OwningProcess} },`
            @{ Name = "ProcessName"; Expression = {$OwningProcessName} },`
            LocalAddress,LocalPort,RemoteAddress,RemotePort,`
            @{ Name = "Path"; Expression = {$OwningProcessPath} }`
    } | 
    Sort-Object -Property ProcessId | 
    Format-Table -AutoSize
}

function Get-WinEventProcessCreation {
    Param(
        [string]$Whitelist,
        [switch]$Verbose    
    )
    if ($Whitelist) {
        $Exclusions = Get-Content $Whitelist -ErrorAction Stop
    }
    $FilterHashTable = @{
        LogName = "Security"
        Id = 4688
    }
    if ($Verbose) {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Where-Object { $_.NewProcessName -notin $Exclusions }
    } else {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Where-Object { $_.NewProcessName -notin $Exclusions } |
        Group-Object -Property NewProcessName -NoElement |
        Sort-Object -Property Count -Descending |
        Format-Table -AutoSize
    }
}

function Get-WinEventService {
    Param(
        [string]$Whitelist,
        [switch]$Verbose
    )
    if ($Whitelist) {
        $Exclusions = Get-Content $Whitelist -ErrorAction Stop
    }
    $FilterHashTable = @{
        LogName = "System"
        Id = 7045
    }
    if ($Verbose) {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Where-Object { $_.ServiceName -notin $Exclusions }
    } else {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent  | 
        Where-Object { $_.ServiceName -notin $Exclusions }
        Group-Object -Property ServiceName -NoElement |
        Sort-Object -Property Count -Descending |
        Format-Table -AutoSize
    }
}

function Get-WinEventUsb {
    Param(
        [string]$Whitelist,
        [switch]$Verbose
    )
    if ($Whitelist) {
        $Exclusions = Get-Content $Whitelist -ErrorAction Stop
    }
    $FilterHashTable = @{
        LogName = "Security"
        Id = 6416
    }
    if ($Verbose) {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent | 
        Where-Object { 
            ($_.ClassName -notin $Exclusions) -and 
            ($_.ClassName -ne $null)
        } 
    } else {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent | 
        Where-Object { 
            ($_.ClassName -notin $Exclusions) -and 
            ($_.ClassName -ne $null)
        } |
        Group-Object -Property ClassName -NoElement |
        Sort-Object -Property Count -Descending |
        Format-Table -AutoSize
    } 
}

function Get-WinEventWindowsDefender {
    Param(
        [string]$Whitelist,
        [switch]$Verbose
    )
    if ($Whitelist) {
        $Exclusions = Get-Content $Whitelist -ErrorAction Stop
    }
    $FilterHashTable = @{
        LogName = "Microsoft-Windows-Windows Defender/Operational"
        Id = 1116,1117
    }
    if ($Verbose) {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Where-Object { $_."Threat Name" -notin $Exclusions }
    } else {
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent | 
        Where-Object { $_."Threat Name" -notin $Exclusions } |
        Group-Object -Property "Threat Name" -NoElement |
        Sort-Object -Property "Count" -Descending |
        Format-Table -AutoSize
    }
}

function Get-WinRmClient {
    $ComputerNames = $(Get-AdComputer -Filter *).Name
    Invoke-Command -ComputerName $ComputerNames -ScriptBlock { $env:HOSTNAME } -ErrorAction Ignore
}

function Get-WirelessNetAdapter {
    <#
        .EXAMPLE
        Get-WirelessNetAdapter
        ServiceName      : RtlWlanu
        MACAddress       : 00:13:EF:F3:6F:F5
        AdapterType      : Ethernet 802.3
        DeviceID         : 16
        Name             : Realtek 8812BU Wireless LAN 802.11ac USB NIC
        NetworkAddresses : 
        Speed            : 144400000

        ServiceName      : vwifimp
        MACAddress       : 02:13:EF:F3:6F:F5
        AdapterType      : Ethernet 802.3
        DeviceID         : 17
        Name             : Microsoft Wi-Fi Direct Virtual Adapter #2
        NetworkAddresses : 
        Speed            : 9223372036854775807
    #>
    Param([string]$ComputerName = $env:COMPUTERNAME)
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

function New-Alert {
    Param([Parameter(Mandatory, ValueFromPipeline)][string]$Message)
    New-EventLog -LogName "Alerts" -Source "Custom" -ErrorAction SilentlyContinue
    Write-EventLog `
        -Category 0 `
        -EntryType Warning `
        -EventID 5000 `
        -LogName "Alerts" `
        -Message $Message `
        -Source "Custom" 
}

function New-CustomViewsForSysmon {
    $SysmonFolder = "C:\ProgramData\Microsoft\Event Viewer\Views\Sysmon"
    if (-not (Test-Path -Path $SysmonFolder)) {
        New-Item -ItemType Directory -Path $SysmonFolder
    }
    $Events = @{
        "1" = "Process-Creation"
        "2" = "A-Process-Changed-A-File-Creation-Time"
        "3" = "Network-Connection"
        "4" = "Sysmon-Service-State-Changed"
        "5" = "Process-Terminated"
        "6" = "Driver-Loaded"
        "7" = "Image-Loaded"
        "8" = "Create-Remote-Thread"
        "9" = "Raw-Access-Read"
        "10" = "Process-Access"
        "11" = "File-Create"
        "12" = "Registry-Event-Object-Create-Delete"
        "13" = "Registry-Event-Value-Set"
        "14" = "Registry-Event-Key-and-Value-Rename"
        "15" = "File-Create-Stream-Hash"
        "16" = "Service-Configuration-Change"
        "17" = "Pipe-Event-Pipe-Created"
        "18" = "Pipe-Event-Pipe-Connected"
        "19" = "Wmi-Event-WmiEventFilter-Activity-Detected"
        "20" = "Wmi-Event-WmiEventConsumer-Activity-Detected"
        "21" = "Wmi-Event-WmiEventConsumerToFilter-Activity-Detected"
        "22" = "DNS-Event"
        "23" = "File-Delete-Archived"
        "24" = "Clipboard-Change"
        "25" = "Process-Tampering"
        "26" = "File-Delete-Logged"
        "255" = "Error"
    }
    $Events.GetEnumerator() | 
    ForEach-Object {
        $CustomViewFilePath = "$SysmonFolder\Sysmon-EventId-" + $_.Name + ".xml"
        if (-not (Test-Path -Path $CustomViewFilePath)) {
            $CustomViewConfig = '<ViewerConfig><QueryConfig><QueryParams><Simple><Channel>Microsoft-Windows-Sysmon/Operational</Channel><EventId>' + $_.Key + '</EventId><RelativeTimeInfo>0</RelativeTimeInfo><BySource>False</BySource></Simple></QueryParams><QueryNode><Name>' + $_.Value + '</Name><QueryList><Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"><Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=' + $_.Key + ')]]</Select></Query></QueryList></QueryNode></QueryConfig><ResultsConfig><Columns><Column Name="Level" Type="System.String" Path="Event/System/Level" Visible="">217</Column><Column Name="Keywords" Type="System.String" Path="Event/System/Keywords">70</Column><Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">267</Column><Column Name="Source" Type="System.String" Path="Event/System/Provider/@Name" Visible="">177</Column><Column Name="Event ID" Type="System.UInt32" Path="Event/System/EventID" Visible="">177</Column><Column Name="Task Category" Type="System.String" Path="Event/System/Task" Visible="">181</Column><Column Name="User" Type="System.String" Path="Event/System/Security/@UserID">50</Column><Column Name="Operational Code" Type="System.String" Path="Event/System/Opcode">110</Column><Column Name="Log" Type="System.String" Path="Event/System/Channel">80</Column><Column Name="Computer" Type="System.String" Path="Event/System/Computer">170</Column><Column Name="Process ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessID">70</Column><Column Name="Thread ID" Type="System.UInt32" Path="Event/System/Execution/@ThreadID">70</Column><Column Name="Processor ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessorID">90</Column><Column Name="Session ID" Type="System.UInt32" Path="Event/System/Execution/@SessionID">70</Column><Column Name="Kernel Time" Type="System.UInt32" Path="Event/System/Execution/@KernelTime">80</Column><Column Name="User Time" Type="System.UInt32" Path="Event/System/Execution/@UserTime">70</Column><Column Name="Processor Time" Type="System.UInt32" Path="Event/System/Execution/@ProcessorTime">100</Column><Column Name="Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@ActivityID">85</Column><Column Name="Relative Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@RelatedActivityID">140</Column><Column Name="Event Source Name" Type="System.String" Path="Event/System/Provider/@EventSourceName">140</Column></Columns></ResultsConfig></ViewerConfig>'
            Add-Content -Path $CustomViewFilePath -Value $CustomViewConfig
        } 
    }
}
filter Read-WinEvent {
    <#
        .EXAMPLE
        Get-WinEvent -FilterHashTable @{LogName="Security";Id=4625} | Read-WinEvent | Select-Object -Property TimeCreated,Hostname,TargetUserName,LogonType | Format-Table -AutoSize
        TimeCreated          TargetUserName LogonType
        -----------          -------------- ---------
        9/12/2021 8:23:27 AM Victor         2        
        9/12/2021 8:23:27 AM Victor         2        
        9/12/2021 7:49:37 AM Victor         2        
        9/12/2021 7:49:37 AM Victor         2
    #>
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

function Send-Alert {
    <#
        .SYNOPSIS
        Sends an alert. 

        .DESCRIPTION
        When called, this function will either write to the Windows Event log, send an email, or generate a Windows balloon tip notification.
        
        .LINK
        https://mcpmag.com/articles/2017/09/07/creating-a-balloon-tip-notification-using-powershell.aspx
    #>
    [CmdletBinding(DefaultParameterSetName = 'Log')]
    Param(
        [Parameter(Mandatory, Position = 0)][ValidateSet("Balloon","Log","Email")][string]$AlertMethod,
        [Parameter(Mandatory, Position = 1)]$Subject,
        [Parameter(Mandatory, Position = 2)]$Body,
        [Parameter(ParameterSetName = "Log")][string]$LogName,
        [Parameter(ParameterSetName = "Log")][string]$LogSource,
        [Parameter(ParameterSetName = "Log")][ValidateSet("Information","Warning")]$LogEntryType = "Warning",
        [Parameter(ParameterSetName = "Log")][int]$LogEventId = 1,
        [Parameter(ParameterSetName = "Email")][string]$EmailServer,
        [Parameter(ParameterSetName = "Email")][string]$EmailServerPort,
        [Parameter(ParameterSetName = "Email")][string]$EmailAddressSource,
        [Parameter(ParameterSetName = "Email")][string]$EmailPassword,
        [Parameter(ParameterSetName = "Email")][string]$EmailAddressDestination
    )
    if ($AlertMethod -eq "Balloon") {
        Add-Type -AssemblyName System.Windows.Forms
        Unregister-Event -SourceIdentifier IconClicked -ErrorAction Ignore
        Remove-Job -Name IconClicked -ErrorAction Ignore
        Remove-Variable -Name Balloon -ErrorAction Ignore
        $Balloon = New-Object System.Windows.Forms.NotifyIcon
        [void](Register-ObjectEvent `
            -InputObject $Balloon `
            -EventName MouseDoubleClick `
            -SourceIdentifier IconClicked `
            -Action { $Balloon.Dispose() }
        )
        $IconPath = (Get-Process -Id $pid).Path
        $Balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($IconPath)
        $Balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
        $Balloon.BalloonTipTitle = $Subject
        $Balloon.BalloonTipText = $Body
        $Balloon.Visible = $true
        $Balloon.ShowBalloonTip(10000)
    } elseif ($AlertMethod -eq "Log") {
        $LogExists = Get-EventLog -LogName $LogName -Source $LogSource -ErrorAction Ignore -Newest 1
        if (-not $LogExists) {
            New-EventLog -LogName $LogName -Source $LogSource -ErrorAction Ignore
        }
        Write-EventLog `
            -LogName $LogName `
            -Source $LogSource `
            -EntryType $LogEntryType `
            -EventId $LogEventId `
            -Message $Body
    } elseif ($AlertMethod -eq "Email") {
        $EmailClient = New-Object Net.Mail.SmtpClient($EmailServer, $EmailServerPort)
        $EmailClient.EnableSsl = $true
        $EmailClient.Credentials = New-Object System.Net.NetworkCredential($EmailAddressSource, $EmailPassword)
        $EmailClient.Send($EmailAddressSource, $EmailAddressDestination, $Subject, $Body)
    }
}

function Start-AdAccountAudit {
   <#
        .SYNOPSIS
        Disables inactive domain accounts. 
        
        .DESCRIPTION
        Disables domain accounts that have been inactive for 45 days and moves them into a container called "Disabled." This function will create a Active Directory container called "Disabled" if it does not exist.  

        .INPUTS
        None. You cannot pipe objects to this function.

        .OUTPUTS
        None. 

        .EXAMPLE
        PS> Start-AdAccountAudit

        .LINK
        https://github.com/cyberphor/Soap
    #>
    $Domain = (Get-ADDomain).DistinguishedName
    $DisabledContainer = "OU=Disabled,$Domain"
    $DisabledContainerDoesNotExist = [bool](Get-ADOrganizationalUnit -Identity $DisabledContainer) -eq $false
    if ($DisabledContainerDoesNotExist) {
        New-ADOrganizationalUnit -Name "Disabled" -Path $Domain
    }

    # search for accounts w/lastlogondate beyond 45 days, disable them, and then move them to a "Disabled" container
    Get-ADUser -Filter { LastLogonDate -le (Get-Date).AddDays(-45) } | 
    ForEach-Object {
        Disable-ADAccount $_.SamAccountName
        Move-ADObject -Identity $_.DistinguishedName -TargetPath $DisabledContainer
    } 
}

function Start-Eradication {
    Param(
        [string[]]$Service,
        [string[]]$Process,
        [string[]]$File
    )
    <#
        .SYNOPSIS
        TBD.

        .DESCRIPTION
        TBD.

        .INPUTS
        None.

        .OUTPUTS
        None.

        .EXAMPLE
        Start-Eradication -Service "rshell" -Process "mimikatz" -File "c:\trojan.exe","c:\ransomware.exe"

        .LINK
        https://github.com/cyberphor/soap
        https://gist.github.com/ecapuano/d18b3b914021171da42e13e5a56cce42
    #>
    if ($Service) {
        $Service |
        ForEach-Object {
            if (Get-Service $_ -ErrorAction SilentlyContinue) {
                Write-Output "Removing service: $_"
                Stop-Service $_ -Force
                Start-Process -FilePath sc.exe -ArgumentList "delete",$_
            }
        }
    }
    if ($Process) {
        $Process |
        ForEach-Object {
            if (Get-Process $_ -ErrorAction SilentlyContinue) {
                Write-Output "Killing process: $_"
                Stop-Process -Name $_ -Force
            }
        }
    }
    if ($File) {
        $File |
        ForEach-Object {
            if (Test-Path $_ -PathType Leaf -ErrorAction SilentlyContinue) {
                Write-Output "Deleting file: $_"
                Remove-Item $_
            }
        }
    }
}

function Start-Heartbeat {
    Param([string]$Target)
    while (-not $TimeToStop) {
        if (Test-Connection -ComputerName $Target -Count 2 -Quiet) {
            $Timestamp = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')
            Write-Host "[$Timestamp] [$Target] " -NoNewline
            Write-Host " ONLINE  " -BackgroundColor Green -ForegroundColor Black
        } else {
            $Timestamp = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')
            Write-Host "[$Timestamp] [$Target] " -NoNewline
            Write-Host " OFFLINE " -BackgroundColor Red -ForegroundColor Black
        }
        Start-Sleep -Seconds 60
        $TimeToStop = (Get-Date).ToString('hh:mm') -le (Get-Date '17:00').ToString('hh:mm')
    }

    $Timestamp = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')
    Write-Host "[$Timestamp] Time has expired."
}

function Set-AuditPolicy {
    <#
        .SYNOPSIS
        Configures the local audit policy. 

        .DESCRIPTION
        Configures the local audit policy using recommendations from Microsoft, DISA, or Malware Archaeology.

        .INPUTS
        None.

        .OUTPUTS
        None.

        .EXAMPLE
        Set-AuditPolicy.ps1 -Source "Malware Archaeology"

        .LINK
        https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations 
        https://www.malwarearchaeology.com/s/Windows-Logging-Cheat-Sheet_ver_Feb_2019.pdf
        https://cryptome.org/2014/01/nsa-windows-event.pdf
        https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ 
    #>
    Param(
        [ValidateSet('Microsoft','DISA','Malware Archaeology')]$Source,
        [switch]$EnableDnsLogging,
        [switch]$DisableDnsLogging
    )

    function Set-AuditPolicyUsingMicrosoftRecommendations {
        auditpol /clear /y

        # Account Logon
        # - Event IDs: 4774, 4776
        auditpol /set /subcategory:"Credential Validation" /success:enable

        # Account Management
        # - Event IDs: 4741, 4742, 4743
        auditpol /set /subcategory:"Computer Account Management" /success:enable

        # - Event IDs: 4739, 4782, 4793
        auditpol /set /subcategory:"Other Account Management Events" /success:enable

        # - Event IDs: 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764, 4799
        auditpol /set /subcategory:"Security Group Management" /success:enable

        # - Event IDs: 4738, 4740, 4765, 4767, 4780, 4781, 
        auditpol /set /subcategory:"User Account Management" /success:enable

        # Detailed Tracking
        # - Event ID: 4688
        auditpol /set /subcategory:"Process Creation" /success:enable

        # Logon/Logoff
        # - Event IDs: 4624, 4625
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable

        # - Event IDs: 4634, 4647
        auditpol /set /subcategory:"Logoff" /success:enable

        # - Event IDs: 4672, 4964
        auditpol /set /subcategory:"Special Logon" /success:enable

        # Policy Change
        # - Event IDs: 4715, 4719, 4817, 4902, 4904, 4905, 4906, 4907, 4908, 4912
        auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

        # - Event IDs: 4706, 4707, 4713, 4716, 4717, 4718, 4865, 4866, 4867
        auditpol /set /subcategory:"Authentication Policy Change" /success:enable

        # System
        # - Event IDs: 5478, 5479, 5480, 5483, 5484, 5485
        auditpol /set /subcategory:"IPSec Driver" /success:enable /failure:enable

        # - Event IDs: 4608, 4609, 4616, 4621
        auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

        # - Event IDs: 4610, 4611, 4614, 4622, 4697
        auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

        # - Event IDs: 4612, 4615, 4618, 5038, 5056, 5061, 5890, 6281, 6410
        auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
    }

    function Set-AuditPolicyUsingMalwareArchaeologyRecommendations {
        # DNS 
        wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true

        # DHCP
        wevtutil sl "Microsoft-Windows-Dhcp-Client/Operational" /e:true

        auditpol /clear /y

        # Account Logon
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

        auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

        # Account Management
        auditpol /set /category:"Account Management" /success:enable /failure:enable

        # Detailed Tracking
        auditpol /set /subcategory:"Plug and Play Events" /success:enable

        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

        auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

        auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable

        # Logon/Logoff
        auditpol /set /subcategory:"Account Lockout" /success:enable

        auditpol /set /subcategory:"Group Membership" /success:enable

        auditpol /set /subcategory:"Logon" /success:enable

        auditpol /set /subcategory:"Logoff" /success:enable

        auditpol /set /subcategory:"Network Policy Server" /success:enable

        auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

        auditpol /set /subcategory:"Special Logon" /success:enable

        # Object Access
        auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable

        auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

        auditpol /set /subcategory:"Detailed File Share" /success:enable

        auditpol /set /subcategory:"File Share" /success:enable /failure:enable

        auditpol /set /subcategory:"File System" /success:enable

        auditpol /set /subcategory:"Filtering Platform Connection" /success:enable

        auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

        auditpol /set /subcategory:"Registry" /success:enable

        auditpol /set /subcategory:"SAM" /success:enable

        # Policy Change
        auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

        auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

        auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable

        auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable 

        # Privilege Use
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

        # System
        auditpol /set /subcategory:"IPsec Driver" /success:enable

        auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

        auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

        auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

        # Process Command Line
        reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
    }

    function Set-AuditPolicyUsingTheDisaStigForWindows10 {
        auditpol /clear /y

        # V-220748
        auditpol /set /subcategory:"Credential Validation" /failure:enable

        # V-220749
        auditpol /set /subcategory:"Credential Validation" /success:enable

        # V-220750
        auditpol /set /subcategory:"Security Group Management" /success:enable

        # V-220751
        auditpol /set /subcategory:"User Account Management" /failure:enable

        # V-220752
        auditpol /set /subcategory:"User Account Management" /success:enable

        # V-220753
        auditpol /set /subcategory:"Plug and Play Events" /success:enable

        # V-220754
        auditpol /set /subcategory:"Process Creation" /success:enable

        # V-220755
        auditpol /set /subcategory:"Account Lockout" /failure:enable

        # V-220756
        auditpol /set /subcategory:"Group Membership" /success:enable

        # V-220757
        auditpol /set /subcategory:"Logoff" /success:enable

        # V-220758
        auditpol /set /subcategory:"Logon" /failure:enable

        # V-220759
        auditpol /set /subcategory:"Logon" /success:enable

        # V-220760
        auditpol /set /subcategory:"Special Logon" /success:enable

        # V-220761
        auditpol /set /subcategory:"File Share" /failure:enable

        # V-220762
        auditpol /set /subcategory:"File Share" /success:enable

        # V-220763
        auditpol /set /subcategory:"Other Object Access Events" /success:enable

        # V-220764
        auditpol /set /subcategory:"Other Object Access Events" /failure:enable

        # V-220765
        auditpol /set /subcategory:"Removable Storage" /failure:enable

        # V-220766
        auditpol /set /subcategory:"Removable Storage" /success:enable

        # V-220767
        auditpol /set /subcategory:"Audit Policy Change" /success:enable

        # V-220768
        auditpol /set /subcategory:"Authentication Policy Change" /success:enable

        # V-220769
        auditpol /set /subcategory:"Authorization Policy Change" /success:enable

        # V-220770
        auditpol /set /subcategory:"Sensitive Privilege Use" /failure:enable

        # V-220771
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable

        # V-220772
        auditpol /set /subcategory:"IPSec Driver" /failure:enable

        # V-220773
        auditpol /set /subcategory:"Other System Events" /success:enable

        # V-220774
        auditpol /set /subcategory:"Other System Events" /failure:enable

        # V-220775
        auditpol /set /subcategory:"Security State Change" /success:enable

        # V-220776
        auditpol /set /subcategory:"Security System Extension" /success:enable

        # V-220777
        auditpol /set /subcategory:"System Integrity" /failure:enable

        # V-220778
        auditpol /set /subcategory:"System Integrity" /success:enable

        # V-220779: the Application event log size must be configured to 32768 KB or greater
        wevtutil sl "Application" /ms:32768000

        # V-220780: the Security event log size must be configured to 1024000 KB or greater
        wevtutil sl "Security" /ms:1024000000

        # V-220781: the System event log size must be configured to 32768 KB or greater
        wevtutil sl "System" /ms:32768000

        # V-220782: the Application event log must be restricted to the following accounts/groups: Eventlog, SYSTEM, Administrators


        # V-220783: the Security event log must be restricted to the following accounts/groups: Eventlog, SYSTEM, Administrators


        # V-220784: the System event log must be restricted to the following accounts/groups: Eventlog, SYSTEM, Administrators


        # V-220785
        auditpol /set /subcategory:"Other Policy Change Events" /success:enable

        # V-220786
        auditpol /set /subcategory:"Other Policy Change Events" /failure:enable

        # V-220787
        auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

        # V-220787
        auditpol /set /subcategory:"Other Logon/Logoff Events" /failure:enable

        # V-220789
        auditpol /set /subcategory:"Detailed File Share" /success:enable

        # V-220790
        auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable

        # V-220791
        auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /failure:enable

        # V-220809: Command line data must be included in process creation events.
        reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

        # V-220860: PowerShell script block logging must be enabled on Windows 10.
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

        # V-220913: Audit policy using subcategories must be enabled
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

        # V-220978: the Manage auditing and security log user right must only be assigned to the Administrators group.
        $SecurityTemplate = @"
            [Unicode]
            Unicode=yes
            [Registry Values]
            [Privilege Rights]
            SeSecurityPrivilege = *S-1-5-32-544
            [Version]
            signature=`"`$CHICAGO`$`"
            Revision=1
"@

        $FileName = "V-220978.inf"
        if (Test-Path $FileName) {
            Remove-Item $FileName
            New-Item -ItemType File -Name $FileName | Out-Null
        }
        Add-Content -Value $SecurityTemplate -Path $FileName 
        secedit /configure /db secedit.sdb /cfg $FileName
        Remove-Item $FileName

        # V-250318: PowerShell Transcription must be enabled on Windows 10.
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
    }

    if ($Source) {
        $SourcePrompt = Read-Host -Prompt "This script will implement the baseline Windows 10 audit policy recommended by $Source.`nDo you want to continue? (y/n)"
        if ($SourcePrompt.ToLower() -eq "y") {
            switch ($Source) {
                "Microsoft" { Set-AuditPolicyUsingMicrosoftRecommendations }
                "Malware Archaeology" { Set-AuditPolicyUsingMalwareArchaeologyRecommendations }
                "DISA" { Set-AuditPolicyUsingTheDisaStigForWindows10 }
            }
        }
    }

    if ($EnableDnsLogging) {
        $EnableDnsLoggingPrompt = Read-Host -Prompt "This script will configure the local DNS client to log all DNS queries. `nDo you want to continue? (y/n)"
        if ($EnableDnsLoggingPrompt.ToLower() -eq "y") {
            wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true   
        }
    } elseif ($DisableDnsLogging) {
        $DisableDnsLoggingPrompt = Read-Host -Prompt "This script will configure the local DNS client to NOT log all DNS queries. `nDo you want to continue? (y/n)"
        if ($DisableDnsLoggingPrompt.ToLower() -eq "y") {
            wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:false  
        }
    }
}

function Set-FirewallPolicy {
    Param(
        [string[]]$AuthorizedProtocol = "ICMP",
        [int[]]$AuthorizedPorts = @(53,80,443,5985),
        [int[]]$RemoteManagementPorts = @(5985),
        [ipaddress]$ManagementIpAddress
    )

    Write-Output "Configuring DoD Windows 10 STIG Requirement V-220725 (Inbound exceptions to the firewall on Windows 10 domain workstations must only allow authorized remote management hosts)."
    
    # enable Windows Remote Management
    Enable-PSRemoting -Force
    if ($ManagementIpAddress) {
        Set-Item -Path WSMan:\localhost\Service\ -Name IPv4Filter -Value $ManagementIpAddress
    }

    # disable all rules allowing inbound connections (except for Windows Remote Management)
    Get-NetFirewallRule -Direction Inbound -Action Allow |
    ForEach-Object { 
        $NotAuthorizedPort = $RemoteManagementPorts -notcontains $($_ | Get-NetFirewallPortFilter).RemotePort
        if ($NotAuthorizedPort) {
            $_ | Set-NetFirewallRule -Enabled False
        }
    }

    # disable all rules allowing outbound connections except for those authorized
    Get-NetFirewallRule -Direction Outbound -Action Allow | 
    ForEach-Object { 
        $NotAuthorizedProtocol = $AuthorizedProtocols -notcontains $($_ | Get-NetFirewallPortFilter).Protocol
        $NotAuthorizedPort = $AuthorizedPorts -notcontains $($_ | Get-NetFirewallPortFilter).RemotePort
        if ($NotAuthorizedProtocol -or $NotAuthorizedPort) {
            $_ | Set-NetFirewallRule -Enabled False
        }
    }
}

function Start-Panic {
    $DomainController = (Get-AdDomainController).Name
    $ComputerName = (Get-AdComputer -Filter *).Name | Where-Object { $_ -ne $env:COMPUTERNAME -and $_ -ne $DomainController }
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        shutdown.exe /s /t 0
    }
}