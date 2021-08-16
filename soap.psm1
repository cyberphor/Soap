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

function Get-ComputersInActiveDirectory {
    Get-AdComputer -Filter * | Select-Object -ExpandProperty Name | Sort-Object
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
