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
                    #if ($Address -ne $NetworkIdIpAddress -and $Address -ne $BroadcastIpAddress) {
                       $IpAddressRange += $Address
                    #}
                }            
            }
        }
    }
    return $IpAddressRange
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

function Test-Connections ([string[]]$IpAddressRange) {
    Get-Event -SourceIdentifier "Ping-*" | Remove-Event -ErrorAction Ignore
    Get-EventSubscriber -SourceIdentifier "Ping-*" | Unregister-Event -ErrorAction Ignore
    $IpAddressRange | 
    foreach {
        [string]$Event = "Ping-" + $_
        New-Variable -Name $Event -Value (New-Object System.Net.NetworkInformation.Ping)
        Register-ObjectEvent -InputObject (Get-Variable $Event -ValueOnly) -EventName PingCompleted -SourceIdentifier $Event
        (Get-Variable $Event -ValueOnly).SendAsync($_,2000,$Event)
        Remove-Variable $Event
    }
    while ($Pending -lt $IpAddressRange.Count) {
        Wait-Event -SourceIdentifier "Ping-*" | Out-Null
        Start-Sleep -Milliseconds 10
        $Pending = (Get-Event -SourceIdentifier "Ping-*").Count
    }
    Get-Event -SourceIdentifier "Ping-*" | 
    foreach {
        $IpAddress = $_.SourceEventArgs.Reply
        if ($IpAddress.Status -eq 'Success') {
            $IpAddress.Address.IpAddressToString
            Remove-Event $_.SourceIdentifier
            Unregister-Event $_.SourceIdentifier
        }
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