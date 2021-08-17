function Get-Logs {
    param(
        [Parameter()][string]$ComputerName = $env:COMPUTERNAME,
        [ValidateSet("Security","ForwardedEvents")][string]$LogName = "Security",
        [ValidateSet("4624")][string]$EventId
    )
    
    $Query = "*[System[EventId='$EventId']] and
        *[EventData[Data[@Name='TargetUserSid'] != 'S-1-5-18']]
        "
        
    Get-WinEvent -LogName $LogName -FilterXpath $Query
}

function Test-Port {
    param(
        [Parameter(Mandatory)][ipaddress]$IpAddress,
        [Parameter(Mandatory)][int]$Port,
        [ValidateSet("TCP","UDP")[string]$Protocol = "TCP"
    )

    if ($Protocol -eq "TCP") {
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        $TcpClient.ConnectAsync($IpAddress,$Port).Wait(1000)
    }
}

function Get-AssetInventory {
    [CmdletBinding(DefaultParameterSetName = "IP")]
    param(
        [Parameter(ParameterSetName = "IP",Position = 0)]$NetworkId = "10.11.12.",
        [Parameter(ParameterSetName = "IP",Position = 1)]$NetworkRange = (1..254),
        [Parameter(ParameterSetName = "DNS",Position = 0)]$Filter = "*"
    )

    $Assets = @()
    if ($PSCmdlet.ParameterSetName -eq "IP") {
        $NetworkRange |
        ForEach-Object {
            $IpAddress = $NetworkId + $_
            $NameResolved = Resolve-DnsName -Name $IpAddress -Type PTR -DnsOnly -ErrorAction Ignore
            if ($NameResolved -and $IpAddress -notin $Assets.IpAddress) {
                $Hostname = $NameResolved.NameHost | Where-Object { $_ -notlike "*_site*" }
            } else {
                $Hostname = "-"
            }
            $Asset = New-Object psobject
            Add-Member -InputObject $Asset -MemberType NoteProperty -Name IpAddress -Value $IpAddress
            Add-Member -InputObject $Assets -MemberType NoteProperty -Name Hostname -Value $Hostname
            $Assets += $Asset
        }
    } elseif ($PSCmdlet.ParameterSetName -eq "DNS") {
        Get-AdComputer -Filter $Filter |
        Select-Object -ExpandProperty DnsHostname |
        ForEach-Object {
            $NameResolved = Resolve-DnsName -Name $_ -DnsOnly -ErrorAction Ignore
            if ($NameResolved -and $NameResolved.IpAddress -notin $Assets.IpAddress) {
                $Asset = New-Object psobject
                Add-Member -InputObject $Asset -MemberType NoteProperty -Name IpAddress -Value $IpAddress
                Add-Member -InputObject $Assets -MemberType NoteProperty -Name Hostname -Value $Hostname
                $Assets += $Asset    
            }
        }
    }
}

function Get-ComputersOnline {
    <#
    Param(
        [Parameter(Position=0,Mandatory=$true)][string]$NetworkId,
        [Parameter(Position=1,Mandatory=$true)][string]$NetworkRange
    )
    #>
    
    $NetworkId = "10.11.12"
    $NetworkRange = 1..254
    Get-Event -SourceIdentifier "Ping-*" | Remove-Event -ErrorAction Ignore
    Get-EventSubscriber -SourceIdentifier "Ping-*" | Unregister-Event -ErrorAction Ignore

    $NetworkRange |
    ForEach-Object {
        $IpAddress = $NetworkId + $_
        $Event = "Ping-" + $IpAddress
        New-Variable -Name $Event -Value (New-Object System.Net.NetworkInformation.Ping)
        Register-ObjectEvent -InputObject (Get-Variable $Event -ValueOnly) -EventName PingCompleted -SourceIdentifier $Event
        (Get-Variable $Event -ValueOnly).SendAsync($IpAddress,2000,$Event)
    }

    while ($Pending -lt $NetworkRange.Count) {
        Wait-Event -SourceIdentifier "Ping-*" | Out-Null
        Start-Sleep -Milliseconds 10
        $Pending = (Get-Event -SourceIdentifier "Ping-*").Count
    }

    $ComputersOnline = @()
    Get-Event -SourceIdentifier "Ping-*" |
    ForEach-Object {
        if ($_.SourceEventArgs.Reply.Status -eq "Success") {
            $ComputersOnline += $_.SourceEventArgs.Reply.Address.IpAddressToString
            Remove-Event $_.SourceIdentifier
            Unregister-Event $_.SourceIdentifier
        }
    }

    $ComputersOnline | Sort-Object { $_ -as [Version] } -Unique
}

function Get-LocalGroupAdministrators {
    $Computers = Get-Computers
    Invoke-Command -ComputerName $Computers -ScriptBlock {
      Get-LocalGroupMember -Group "administrators"
    } | Select-Object @{Name="Hostname";Expression={$_.PSComputerName}}, @{Name="Member";Expression={$_.Name}}
}

function ConvertTo-Base64 {
    $Text = ""
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
    $EncodedText =[Convert]::ToBase64String($Bytes)
    $EncodedText
}

function ConvertFrom-Base64 {
    $EncodedText = ""
    $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
    $DecodedText
}
