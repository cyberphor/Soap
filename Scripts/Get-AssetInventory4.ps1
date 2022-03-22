<#
    .NOTES
        Original Author: G.A.F.F. Jakobs
        Originally Created: August 30, 2014
    .LINK
        https://gallery.technet.microsoft.com/scriptcenter/Fast-asynchronous-ping-IP-d0a5cf0e
#>

Param(
    [parameter(Mandatory = $true, Position = 0)]
    [System.Net.IPAddress]$StartAddress,
    [parameter(Mandatory = $true, Position = 1)]
    [System.Net.IPAddress]$EndAddress
)

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
    [string]$VarName = 'Ping_' + $_.Address
    New-Variable -Name $VarName -Value (New-Object System.Net.NetworkInformation.Ping)
    Register-ObjectEvent -InputObject (Get-Variable $VarName -ValueOnly) -EventName PingCompleted -SourceIdentifier "ID-$VarName"
    (Get-Variable $VarName -ValueOnly).SendAsync($_,2000,$VarName)
    Remove-Variable $VarName
}

while ($Pending -lt $IpTotal) {
    Wait-Event -SourceIdentifier "ID-Ping*" | Out-Null
    Start-Sleep -Milliseconds 10
    $Pending = (Get-Event -SourceIdentifier "ID-Ping*").Count
}

$Assets = Get-Event -SourceIdentifier "ID-Ping*" | 
    ForEach { 
        if ($_.SourceEventArgs.Reply.Status -eq 'Success') {
            $Asset = New-Object -TypeName psobject

            $IpAddress = ($_.SourceEventArgs.Reply).Address.IpAddressToString
            Unregister-Event $_.SourceIdentifier
            Remove-Event $_.SourceIdentifier
            Add-Member -InputObject $Asset -MemberType NoteProperty -Name Address -Value $IpAddress

            $Client = New-Object Net.Sockets.TcpClient
            $Client.Connect($IpAddress,135)
            if ($Client.Connected) {
                Add-Member -InputObject $Asset -MemberType NoteProperty -Name OperatingSystem -Value 'Windows'
            } else {
                Add-Member -InputObject $Asset -MemberType NoteProperty -Name OperatingSystem -Value '-'
            }
            $Client.Close()

            $Asset
        }
    } | Sort-Object { $_.Address -as [Version] } 
    
return $Assets

<# REFERENCES
https://stackoverflow.com/questions/9566052/how-to-check-network-port-access-and-display-useful-message
https://adamtheautomator.com/building-asynchronous-powershell-functions/
https://stackoverflow.com/questions/11888342/how-do-i-add-an-event-handler-to-a-net-object-in-powershell
https://powershell.org/forums/topic/event-handler-in-powershell/
https://devblogs.microsoft.com/scripting/use-asynchronous-event-handling-in-powershell/
http://www.powershellcookbook.com/recipe/WguS/create-and-respond-to-custom-events
#>
