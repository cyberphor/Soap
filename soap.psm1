function Get-Computers {
    Get-AdComputer -Filter * | Select-Object -ExpandProperty Name
}

function Get-ComputersOnline {
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

    $ComputersOnline | Sort-Object { $_ -as [Version] }
}

function Get-LocalGroupAdministrators {
    $Computers = Get-Computers
    Invoke-Command -ComputerName $Computers -ScriptBlock {
      Get-LocalGroupMember -Group "administrators"
    } | Select-Object @{Name="Hostname";Expression={$_.PSComputerName}}, @{Name="Member";Expression={$_.Name}}
}
