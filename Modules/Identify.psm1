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

function Start-AdScrub {
    Import-Module ActiveDirectory

    $30DaysAgo = (Get-Date).AddDays(-30)
    $AtctsReport = Import-Csv $Report | Select Name, @{Name='TrainingDate';Expression={$_.'Date Awareness Training Completed'}}
    $AdSearchBase = ''
    $DisabledUsersOu = '' + $AdSearchBase
    $AdUserAccounts = Get-AdUser -Filter * -SearchBase $AdSearchBase -Properties LastLogonDate
    $VipUsers = $(Get-AdGroup -Identity 'VIP Users').Sid
    $UsersInAtctsReport = $AtctsReport.Name.ToUpper() |
    foreach {
        $SpaceBetweenFirstAndMiddle = $_.Substring($_.Length -2).Substring(0,1)
        if ($SpaceBetweenFirstAndMiddle) { $_ -replace ".$" }
    }

    $AdUserAccounts |
    Where-Object { $VipUsers -notcontains $_.Sid } |
    foreach {
        $NotCompliant = $false
        $Reason = 'Disabled:'

        if ($_.Surname -and $_.GivenName) {
            $FullName = ($_.Surname + ', ' + $_.GivenName).ToUpper()
        } else {
            $FullName = ($_.SamAccountName).ToUpper()
        }

        $AtctsProfile = $UsersInAtctsReport | Where-Object { $_ -like "$FullName*" }

        if (-not $AtctsProfile) {
            $NotCompliant = $true
            $Reason = $Reason + ' ATCTS profile does not exist.'
        }

        if ($AtctsProfile) {
            $TrainingDate = ($AtctsReport | Where-Object { $_.Name -like "$FullName*" }).TrainingDate
            $NewDate = $TrainingDate.Split('-')[0]+ $TrainingDate.Split('-')[2] + $TrainingDate.Split('-')[1]
            $ExpirationDate = (Get-Date $NewDate).AddYears(1).ToString('yyyy-MM-dd')
            if ($ExpirationDate -lt $(Get-Date -Format 'yyyy-MM-dd')){
                $NotCompliant = $true
                $Reason = $Reason + ' Training has expired.'
            }
        }

        if ($_.LastLogonDate -le $30DaysAgo) {
            $NotCompliant = $true
            $Reason = $Reason + 'Inactive for 30 days.'
        }

        if ($NotCompliant) {
            Set-AdUser $_.SamAccountName -Description $Reason
            Disable-AdAccount $_.SamAccountName
            Move-AdObject -Identity $_.DistinguishedName -TargetPath $DisabledUsersOu
            Write-Output "[+] $($_.Name) - $Reason"
        }
    }
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