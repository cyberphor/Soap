function Import-SoapModule {
    $Owner = "cyberphor"
    $Repo = "soap"
    $RepoFolder = "$Repo\$Repo-main\"
    $RepoContents = $RepoFolder + "*"
    $Download = $Repo + ".zip"
    $ModulesFolder = "C:\Program Files\WindowsPowerShell\Modules\"
    $Uri = "https://github.com/$Owner/$Repo/archive/refs/heads/main.zip"
    $SoapModule = $ModulesFolder + $Repo + "\$Repo.psm1"
    if (-not (Test-Path -Path $SoapModule)) {
        Invoke-WebRequest -Uri $Uri -OutFile $Download
        Expand-Archive -Path $Download -DestinationPath $Repo
        Move-Item -Path $RepoContents -Destination $Repo
        Remove-Item $Download 
        Remove-Item $RepoFolder
        Move-Item -Path $Repo -Destination $ModulesFolder
    }
    Import-Module $Repo -Force
}

function Read-SoapModule {
    ise "C:\Program Files\WindowsPowerShell\Modules\soap\soap.psm1"
}

function Remove-SoapModule {
    Remove-Item -Path "C:\Program Files\WindowsPowerShell\Modules\soap" -Recurse
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

function Get-LocalAdministrators {
    $Computers = (Get-AdComputer -Filter "ObjectClass -like 'Computer'").Name
    Invoke-Command -ErrorAction Ignore -ComputerName $Computers -ScriptBlock{
        (Get-LocalGroupMember -Group "Administrators").Name | 
        Where-Object { $_ -notmatch '(.*Domain Admins|.*Administrator)' }
    }
}

filter ConvertTo-Base64 {
    $Text = $_
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
    $EncodedText = [Convert]::ToBase64String($Bytes)
    $EncodedText 
}

filter ConvertFrom-Base64 {
    $EncodedText = $_
    $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
    $DecodedText
}
