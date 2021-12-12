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

function Get-AssetInventory {
    param(
        [Parameter(Position = 0)]$NetworkId = "10.11.12.",
        [Parameter(Position = 1)]$NetworkRange = (1..254)
    )

    $IpAddresses = @()
    $NetworkRange |
    ForEach-Object { $IpAddress = $NetworkId + $_ }
    Get-Event -SourceIdentifier "Ping-*" | Remove-Event -ErrorAction Ignore
    Get-EventSubscriber -SourceIdentifier "Ping-*" | Unregister-Event -ErrorAction Ignore
    
    $IpAddresses |
    ForEach-Object{
        $Event = "Ping-" + $_
        New-Variable -Name $Event -Value (New-Object System.Net.NetworkInformation.Ping)
        Register-ObjectEvent -InputObject (Get-Variable $Event -ValueOnly) -EventName PingCompleted -SourceIdentifier $Event
        (Get-Variable $Event -ValueOnly).SendAsync($_,2000,$Event)
    } 

    while ($Pending -lt $IpAddresses.Count) {
        Wait-Event -SourceIdentifier "Ping-*" | Out-Null
        Start-Sleep -Milliseconds 10
        $Pending = (Get-Event -SourceIdentifier "Ping-*").Count
    }

    $Assets = @()
    Get-Event -SourceIdentifier "Ping-*" |
    ForEach-Object {
        if ($_.SourceEventArgs.Reply.Status -eq "Success") {
            $Asset = New-Object psobject
            $IpAddress = $_.SourceEventArgs.Reply.Address.IpAddressToString
            $Resolved = Resolve-DnsName -Name $IpAddress -Type PTR -DnsOnly -ErrorAction Ignore
            if ($Resolved) { $Hostname = $Resolved.NameHost }
            else { $Hostname = "" }
            Add-Member -InputObject $Asset -MemberType NoteProperty -Name IpAddress -Value $IpAddress
            Add-Member -InputObject $Asset -MemberType NoteProperty -Name Hostname -Value $Hostname
            $Assets += $Asset
        }

        Remove-Event $_.SourceIdentifier
        Unregister-Event $_.SourceIdentifier
    }

    $Assets
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
        [ValidateSet("Application","Security","System","ForwardedEvents")][Parameter(Position=1)][string]$LogName,
        [ValidateSet("4624","4625","4688","5156","6416")][Parameter(Position=2)]$EventId,
        [Parameter(Position=3)][int]$Days=1
    )

    $Date = (Get-Date -Format yyyy-MM-dd-HHmm)
    $Path = "C:\EventId-$EventId-$Date.csv"

    if ($EventId -eq "4624") {
        $FilterXPath = "*[
            System[
                (EventId=4624)
            ] and
            EventData[
                Data[@Name='TargetUserSid'] != 'S-1-5-18' and
                Data[@Name='LogonType'] = '2' or
                Data[@Name='LogonType'] = '3' or
                Data[@Name='LogonType'] = '7' or
                Data[@Name='LogonType'] = '10' or
                Data[@Name='LogonType'] = '11'
            ]
        ]"

        filter Read-WinEvent {
            $TimeCreated = $_.TimeCreated
            $XmlData = [xml]$_.ToXml()
            $Hostname = $XmlData.Event.System.Computer
            $Username = $XmlData.Event.EventData.Data[5].'#text'
            $LogonType = $XmlData.Event.EventData.Data[8].'#text'
            $Event = New-Object psobject
            Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $TimeCreated
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Username -Value $Username
            Add-Member -InputObject $Event -MemberType NoteProperty -Name LogonType -Value $LogonType
            if ($Event.Username -notmatch '(.*\$$|DWM-|ANONYMOUS*)') { $Event }
        }
    } elseif ($EventId -eq "4625") {
        $FilterXPath = "*[
            System[
                (EventId=4625)
            ] and
            EventData[
                Data[@Name='TargetUserName'] != '-'
            ]
        ]"

        filter Read-WinEvent {
            $TimeCreated = $_.TimeCreated
            $XmlData = [xml]$_.ToXml()
            $Hostname = $XmlData.Event.System.Computer
            $Username = $XmlData.Event.EventData.Data[5].'#text'
            $LogonType = $XmlData.Event.EventData.Data[10].'#text'
            $Event = New-Object psobject
            Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $TimeCreated
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Username -Value $Username
            Add-Member -InputObject $Event -MemberType NoteProperty -Name LogonType -Value $LogonType
            $Event
        }
    } elseif ($EventId -eq "4688") {
        $FilterXPath = "*[
            System[
                (EventId=4688)
            ] and
            EventData[
                Data[@Name='TargetUserName'] != '-' and
                Data[@Name='TargetUserName'] != 'LOCAL SERVICE'
            ]
        ]"

        filter Read-WinEvent {
            $TimeCreated = $_.TimeCreated
            $XmlData = [xml]$_.ToXml()
            $Hostname = $XmlData.Event.System.Computer
            $Username = $XmlData.Event.EventData.Data[8].'#text'
            $CommandLine = $XmlData.Event.EventData.Data[10].'#text'
            $Event = New-Object psobject
            Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $TimeCreated
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Username -Value $Username
            Add-Member -InputObject $Event -MemberType NoteProperty -Name CommandLine -Value $CommandLine
            if ($Event.Username -notmatch '(.*\$$|DWM-)') { $Event }
        }
    } elseif ($EventId -eq "5156") {
        $FilterXPath = "*[
            System[
                (EventId=4688)
            ] and
            EventData[
                Data[@Name='DestAddress'] != '127.0.0.1' and
                Data[@Name='DestAddress'] != '::1'
            ]
        ]"

        filter Read-WinEvent {
            $TimeCreated = $_.TimeCreated
            $XmlData = [xml]$_.ToXml()
            $Hostname = $XmlData.Event.System.Computer
            $DestAddress = $XmlData.Event.EventData.Data[5].'#text'
            $DestPort = $XmlData.Event.EventData.Data[6].'#text'
            $Event = New-Object psobject
            Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $TimeCreated
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Event -MemberType NoteProperty -Name DestinationAddress -Value $DestAddress
            Add-Member -InputObject $Event -MemberType NoteProperty -Name DestinationPort -Value $DestPort
            $Event
        }
    } elseif ($EventId -eq "6416") {
        $FilterXPath = "*[
            System[
                (EventId=6416)
            ] 
        ]"

        filter Read-WinEvent {
            $TimeCreated = $_.TimeCreated
            $XmlData = [xml]$_.ToXml()
            $Hostname = $XmlData.Event.System.Computer
            $DeviceDescription = $XmlData.Event.EventData.Data[5].'#text'
            $ClassName = $XmlData.Event.EventData.Data[7].'#text'
            $Event = New-Object psobject
            Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $TimeCreated
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Event -MemberType NoteProperty -Name ClassName -Value $ClassName
            Add-Member -InputObject $Event -MemberType NoteProperty -Name DeviceDescription -Value $DeviceDescription
            $Event
        }
    } 

    try {
        Get-WinEvent -ComputerName $ComputerName -LogName $LogName -FilterXPath $FilterXPath |
        Read-WinEvent |
        ConvertTo-Csv -NoTypeInformation |
        Tee-Object -FilePath $Path |
        ConvertFrom-Csv

        $Events = Get-Content $Path
        Remove-Item -Path $Path
        $Events | ConvertFrom-Csv | Export-Csv -NoTypeInformation -Path $Path
    } catch {
        Write-Output "[x] Error."
    }
}

function Kill-Process {
    param(
        [Parameter(Mandatory)]$Name
    )

    $Process = Get-Process | Where-Object { $_.Name -like $Name }
    $Process.Kill()
}

function New-IncidentResponse {
    # New-IncidentResponse -Category "Root-Level Intrusion" 
 
     <# case
        case-001/ 
            001-case-checklist.csv
            001-case-file.csv
            001-case-journal.csv
            001-case-summary.txt

        001-case-checklist.csv/
            | procedures                    | initials | dtg             |   
            | ----------------------------- | -------- | --------------- |
            | step 1                        | vf       | 2021-08-28 1130 |
            | step 2                        | vf       | 2021-08-28 1130 |
            | step 3                        | vf       | 2021-08-28 1130 |

        001-case-file.csv/tab01-detection
            | check number | observation | evidence | initials | dtg             | 
            | ------------ | ----------- | -------- | -------- | --------------- |
            | 05           |             |          | vf       | 2021-08-28 1130 |
            | 05           |             |          | vf       | 2021-08-28 1130 |
            | 05           |             |          | vf       | 2021-08-28 1130 |
        001-case-file.csv/tab02-analysis
            | question     | hypothesis | data source | answer | initials | dtg             |
            | ------------ | ---------- | ----------- | ------ | -------- | --------------- |
            |              |            |             |        | vf       | 2021-08-28 1130 | 
            |              |            |             |        | vf       | 2021-08-28 1130 | 
            |              |            |             |        | vf       | 2021-08-28 1130 | 
        001-case-file.csv/tab03-containment
        001-case-file.csv/tab04-eradication
        001-case-file.csv/tab05-recovery
        001-case-file.csv/tab06-post-incident-activity
    
        001-case-journal.csv/
            | notes                         | initials | dtg             |   
            | ----------------------------- | -------- | --------------- |
            | started exsum                 | vf       | 2021-08-28 1130 |
            | conducted analysis            | vf       | 2021-08-28 1130 |
        
        001-case-summary.txt/
            | field              | value                | initials | dtg              |   
            | ------------------ | -------------------- | -------- | ---------------- |
            | case number        | 001                  | vf       | 2021-08-28 1143  |
            | description        | odd logins to admin  | vf       | 2021-08-28 1143  | 
            | incident responder | victor               | vf       | 2021-08-28 1143  |
            | incident category  | root-level intrusion | vf       | 2021-08-28 1143  | 
            | operational impact | medium               | vf       | 2021-08-28 1143  | 
            | technical impact   | medium               | vf       | 2021-08-28 1143  | 
            | time detected      | 2021-08-28 1130      | vf       | 2021-08-28 1143  |
            | time contained     | 2021-08-28 1700      | vf       | 2021-08-28 1700  | 
            | time resolved      | 2021-08-29 0900      | vf       | 2021-08-29 0900  | 
     #>
 }

filter Read-WinEvent {
    <#
    .SYNOPSIS
    Returns all the properties of a given Windows event.
    #>
    $Event = New-Object psobject
    $XmlData = [xml]$_.ToXml()
    Add-Member -InputObject $Event -MemberType NoteProperty -Name LogName -Value $XmlData.Event.System.Channel
    Add-Member -InputObject $Event -MemberType NoteProperty -Name EventId -Value $XmlData.Event.System.EventId
    Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $_.TimeCreated
    Add-Member -InputObject $Event -MemberType NoteProperty -Name Hostname -Value $XmlData.Event.System.Computer
    Add-Member -InputObject $Event -MemberType NoteProperty -Name RecordId -Value $XmlData.Event.System.EventRecordId
    $EventData = $XmlData.Event.EventData.Data
    
    for ($Property = 0; $Property -lt $EventData.Count; $Property++) {
        Add-Member -InputObject $Event -MemberType NoteProperty -Name $EventData[$Property].Name -Value $EventData[$Property].'#text'
    }

    $Event
}

function Start-AdBackup {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [string]$Share = "Backups",
        [string]$Prefix = "AdBackup"
    )

    $BackupFeature = (Install-WindowsFeature -Name Windows-Server-Backup).InstallState
    if ($BackupFeature -eq "Installed") {
        $Date = Get-Date -Format "yyyy-MM-dd"
        $Target = "\\$ComputerName\$Share\$Prefix-$Date"
        if (Test-Path $Target) { Remove-Item -Path $Target -Recurse -Force }
        New-Item -ItemType Directory -Path $Target -Force
        $Expression = "wbadmin START BACKUP -systemState -vssFull -backupTarget:$Target -noVerify -quiet"
        Invoke-Expression $Expression
    } else {
        Write-Output "[!] The Windows-Server-Backup feature is not installed. Use the command below to install it."
        Write-Output " Install-WindowsFeature -Name Windows-Server-Backup"
    }
}

function Test-Port {
    param(
        [Parameter(Mandatory)][ipaddress]$IpAddress,
        [Parameter(Mandatory)][int]$Port,
        [ValidateSet("TCP","UDP")][string]$Protocol = "TCP"
    )

    if ($Protocol -eq "TCP") {
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        $TcpClient.ConnectAsync($IpAddress,$Port).Wait(1000)
    }
}

function Unblock-TrafficToIpAddress {
    param(
        [Parameter(Mandatory)][ipaddress]$IpAddress
    )

    Remove-NetFirewallRule -DisplayName "Block $IpAddress"
}