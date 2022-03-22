<#
    .NOTES
        Original Author: G.A.F.F. Jakobs
        Originally Created: August 30, 2014
    .LINK
        https://gallery.technet.microsoft.com/scriptcenter/Fast-asynchronous-ping-IP-d0a5cf0e
#>

[CmdletBinding(ConfirmImpact='Low')]
Param(
    [parameter(Mandatory = $true, Position = 0)]
    [System.Net.IPAddress]$StartAddress,
    [parameter(Mandatory = $true, Position = 1)]
    [System.Net.IPAddress]$EndAddress,
    [int]$Interval = 30
)

$Timeout = 2000

function New-Range ($start, $end) {
    [byte[]]$BySt = $start.GetAddressBytes()
    [Array]::Reverse($BySt)
    [byte[]]$ByEn = $end.GetAddressBytes()
    [Array]::Reverse($ByEn)
    $i1 = [System.BitConverter]::ToUInt32($BySt,0)
    $i2 = [System.BitConverter]::ToUInt32($ByEn,0)
    for ($x = $i1;$x -le $i2;$x++) {
        $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
        [Array]::Reverse($ip)
        [System.Net.IPAddress]::Parse($($ip -join '.'))
    }
}
    
$IpRange = New-Range $StartAddress $EndAddress
$IpTotal = $IpRange.Count
Get-Event -SourceIdentifier "ID-Ping*" | Remove-Event
Get-EventSubscriber -SourceIdentifier "ID-Ping*" | Unregister-Event

$IpRange | 
ForEach {
    [string]$VarName = "Ping_" + $_.Address
    New-Variable -Name $VarName -Value (New-Object System.Net.NetworkInformation.Ping)
    Register-ObjectEvent -InputObject (Get-Variable $VarName -ValueOnly) -EventName PingCompleted -SourceIdentifier "ID-$VarName"
    (Get-Variable $VarName -ValueOnly).SendAsync($_,$Timeout,$VarName)
    Remove-Variable $VarName
}

while ($Pending -lt $IpTotal) {
    Wait-Event -SourceIdentifier "ID-Ping*" | Out-Null
    Start-Sleep -Milliseconds 10
    $Pending = (Get-Event -SourceIdentifier "ID-Ping*").Count
}

$Reply = Get-Event -SourceIdentifier "ID-Ping*" | 
    ForEach { 
        if ($_.SourceEventArgs.Reply.Status -eq "Success") {
            $_.SourceEventArgs.Reply | 
            Select @{ Name="IPAddress"; Expression={$_.Address} },
                   @{ Name="Bytes"; Expression={$_.Buffer.Length} },
                   @{ Name="Ttl"; Expression={$_.Options.Ttl} },
                   @{ Name="ResponseTime"; Expression={$_.RoundtripTime} }
            }
            Unregister-Event $_.SourceIdentifier
            Remove-Event $_.SourceIdentifier
    }
    
return $Reply 
