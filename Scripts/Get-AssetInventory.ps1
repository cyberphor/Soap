Param(
    [Parameter(Mandatory = $false, Position = 0)][switch]$Monitor,
    [Parameter(Mandatory = $true, Position = 1)][string[]]$Network,
    [Parameter(Mandatory = $false, Position = 2)][string]$Highlight
)

function Get-Credentials {
    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $AdminId = [Security.Principal.WindowsBuiltInRole]::Administrator
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal($UserId)
    $RunningAsAdmin = $CurrentUser.IsInRole($AdminId)
    if (-not $RunningAsAdmin) { 
        Write-Output "`n[x] This script requires administrator privileges.`n"
        break
    }
}

function Get-IpAddressRange {
    Param([Parameter(Mandatory)][string[]]$Network)

    function ConvertIpAddressTo-BinaryString {
        Param([IPAddress]$IpAddress)
        $Integer = $IpAddress.Address
        $ReverseIpAddress = [IPAddress][String]$Integer
        $BinaryString = [Convert]::toString($ReverseIpAddress.Address,2)
        return $BinaryString
    }

    function ConvertBinaryStringTo-IpAddress {
        Param($BinaryString)
        $Integer = [System.Convert]::ToInt64($BinaryString,2).ToString()
        $IpAddress = ([System.Net.IPAddress]$Integer).IpAddressToString
        return $IpAddress
    }

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
                $NetworkIdBinary = ConvertIpAddressTo-BinaryString $NetworkId
                
                $NetworkIdIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('0' * $Wildcard)
                $BroadcastIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('1' * $Wildcard)
                
                $NetworkIdIpAddress = ConvertBinaryStringTo-IpAddress $NetworkIdIpAddressBinary
                $BroadcastIpAddress = ConvertBinaryStringTo-IpAddress $BroadcastIpAddressBinary
                
                $NetworkIdInt32 = [convert]::ToInt32($NetworkIdIpAddressBinary,2)
                $BroadcastIdInt32 = [convert]::ToInt32($BroadcastIpAddressBinary,2)

                $NetworkIdInt32..$BroadcastIdInt32 | 
                foreach {
                    $BinaryString = [convert]::ToString($_,2)
                    $Address = ConvertBinaryStringTo-IpAddress $BinaryString
                    if ($Address -ne $NetworkIdIpAddress -and $Address -ne $BroadcastIpAddress) {
                       $IpAddressRange += $Address
                    }
                }            
            }
        }
    }

    return $IpAddressRange
}

function Format-Color {
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]$Input,
        [Parameter(Mandatory = $true, Position = 1)][string]$Value,
        [Parameter(Mandatory = $true, Position = 2)][string]$BackgroundColor,
        [Parameter(Mandatory = $true, Position = 3)][string]$ForegroundColor
    )

	$Lines = ($Input | Format-Table -AutoSize | Out-String) -replace "`r", "" -split "`n"
	foreach ($Line in $Lines) {
        foreach ($Pattern in $Value) { 
            if ($Line -match $Value) { $LineMatchesValue = $true } 
            else { $LineMatchesValue = $false }

            if ($LineMatchesValue) { Write-Host $Line -BackgroundColor $BackgroundColor -ForegroundColor $ForegroundColor } 
            else { Write-Host $Line }
	    }
    }
}

function Get-AssetInventory {
    <#
        .SYNOPSIS
        Given an IP address range, returns information about computers discovered online. 
        .PARAMETER Network
        Specifies the network ID in CIDR notation.
        .INPUTS
        None. You cannot pipe objects to Get-AssetInventory.
        .OUTPUTS
        System.Array. Get-AssetInventory returns an array of custom PS objects.
        .EXAMPLE
        ./Get-AssetInventory.ps1 -Network 192.168.2.0/24
        IpAddress    MacAddress        HostName SerialNumber   UserName       FirstSeen        LastSeen
        ---------    ----------        -------- ------------   --------       ---------        --------
        192.168.2.1  -                 -        -              -              2020-12-31 17:44 2021-01-01 09:30               
        192.168.2.3  -                 -        -              -              2021-01-01 09:14 2021-01-01 09:14                                
        192.168.2.57 -                 -        -              -              2020-12-31 17:44 2021-01-01 09:30               
        192.168.2.60 -                 -        -              -              2021-01-01 09:33 2021-01-01 09:30                             
        192.168.2.75 aa:bb:cc:11:22:33 Windows  T6UsW9N8       WINDOWS\Victor 2020-12-31 17:44 2021-01-01 09:30
        .LINK
        https://www.github.com/cyberphor/scripts/PowerShell/Get-AssetInventory.ps1
        .NOTES
        https://devblogs.microsoft.com/scripting/parallel-processing-with-jobs-in-powershell/
        https://stackoverflow.com/questions/8751187/how-to-capture-the-exception-raised-in-the-scriptblock-of-start-job
        https://ss64.com/ps/start-job.html
        https://codeandkeep.com/PowerShell-Get-Subnet-NetworkID/
        https://stackoverflow.com/questions/27613836/how-to-pass-multiple-objects-via-the-pipeline-between-two-functions-in-powershel
        https://info.sapien.com/index.php/scripting/scripting-how-tos/take-values-from-the-pipeline-in-powershell
        https://stackoverflow.com/questions/48946924/powershell-function-not-accepting-array-of-objects
        https://www.reddit.com/r/PowerShell/comments/6eyhpv/whats_the_quickest_way_to_ping_a_computer/
        https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/sort-ipv4-addresses-correctly
        https://www.sans.org/reading-room/whitepapers/critical/leveraging-asset-inventory-database-37507
        https://stackoverflow.com/questions/17696149/invoke-command-in-a-background-job
        https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-pscustomobject?view=powershell-7.1
        https://devblogs.microsoft.com/scripting/two-simple-powershell-methods-to-remove-the-last-letter-of-a-string/
        https://www.pluralsight.com/blog/tutorials/measure-powershell-scripts-speed
        https://stackoverflow.com/questions/34113755/need-to-make-a-powershell-script-faster/34114444
        https://gallery.technet.microsoft.com/scriptcenter/Fast-asynchronous-ping-IP-d0a5cf0e
        https://stackoverflow.com/questions/55971796/powershell-parameters-validation-and-positioning
        https://social.technet.microsoft.com/Forums/Lync/en-US/ff644fca-1b25-4c8a-9a8a-ce90eb024389/
            in-powershell-how-do-i-pass-startjob-arguments-to-a-script-using-param-style-arguments?forum=ITCG
    #>

    Get-Credentials 
    $IpAddressRange = Get-IpAddressRange -Network $Network

    $Database = './AssetInventory.csv'
    if (Test-Path $Database) { 
        $Inventory = Import-Csv $Database 
    } else { 
        New-Item -ItemType File -Name $Inventory -ErrorAction Ignore | Out-Null
    }

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

    $Assets = @()
    Get-Event -SourceIdentifier "Ping-*" | 
    foreach { 
        if ($_.SourceEventArgs.Reply.Status -eq 'Success') {
            $Asset = New-Object -TypeName psobject
            $IpAddress = ($_.SourceEventArgs.Reply).Address.IpAddressToString
            Remove-Event $_.SourceIdentifier
            Unregister-Event $_.SourceIdentifier
            Add-Member -InputObject $Asset -MemberType NoteProperty -Name IpAddress -Value $IpAddress
            $Assets += $Asset

            Start-Job -Name "Query-$IpAddress" -ArgumentList $IpAddress -ScriptBlock {
                $Hostname = [System.Net.Dns]::GetHostEntryAsync($args[0]).Result.HostName
                $MacAddress, $SerialNumber, $UserName = '-', '-', '-'
                if ($Hostname -eq $null) {
                    $Hostname = '-'
                } else { 
                    $Query = Invoke-Command -ComputerName $Hostname -ArgumentList $args[0] -ErrorAction Ignore -ScriptBlock {
                        (Get-WmiObject -Class Win32_BIOS).SerialNumber
                        (Get-WmiObject -Class Win32_ComputerSystem).UserName
                         Get-WmiObject -Class Win32_NetworkAdapterConfiguration | 
                            Where-Object { $_.IpAddress -eq $args[0] } | 
                            Select -ExpandProperty MacAddress
                    }
                    if ($Query -ne $null) {
                        $MacAddress = $Query[2]
                        $SerialNumber = $Query[0]
                        $UserName = $Query[1]
                    }
                }
                return $Hostname, $MacAddress, $SerialNumber, $UserName
            } | Out-Null
        }
    }

    While ((Get-Job -Name "Query-*").State -ne 'Completed') { Start-Sleep -Milliseconds 10 }

    $Assets |
    foreach {
        $CurrentAsset = $_
        $Job = Receive-Job -Name "Query-$($CurrentAsset.IpAddress)"
        Add-Member -InputObject $CurrentAsset -MemberType NoteProperty -Name MacAddress -Value $Job[1]
        Add-Member -InputObject $CurrentAsset -MemberType NoteProperty -Name HostName -Value $Job[0]
        Add-Member -InputObject $CurrentAsset -MemberType NoteProperty -Name SerialNumber -Value $Job[2]
        Add-Member -InputObject $CurrentAsset -MemberType NoteProperty -Name UserName -Value $Job[3]
        Add-Member -InputObject $CurrentAsset -MemberType NoteProperty -Name FirstSeen -Value $(Get-Date -Format 'yyyy-MM-dd HH:mm')
        Add-Member -InputObject $CurrentAsset -MemberType NoteProperty -Name LastSeen -Value $(Get-Date -Format 'yyyy-MM-dd HH:mm')

        $OldAsset = $Inventory | Where-Object { $_.IpAddress -eq $CurrentAsset.IpAddress }
        if ($OldAsset) { $CurrentAsset.FirstSeen = $OldAsset.FirstSeen }
    }

    $Inventory |
    foreach {
        $IdleAsset = $_
        $Added = $Assets | Where-Object { $_.IpAddress -eq $IdleAsset.IpAddress }
        if (-not $Added) {
            $Assets += $IdleAsset
        }
    }

    Remove-Job -Name "Query-*"
    $Assets | Sort-Object { $_.IpAddress -as [Version] } | Export-Csv -NoTypeInformation $Database

    if ($Highlight) {
        $Assets | Sort-Object { $_.IpAddress -as [Version] } | Format-Color -Value $Highlight -BackgroundColor Red -ForegroundColor White
    } else {
        $Assets | Sort-Object { $_.IpAddress -as [Version] } | Format-Table -AutoSize
    }
}

if ($Monitor) {
    While ($true) {
        Clear-Host
        Get-AssetInventory -Network $Network
        Start-Sleep -Seconds 300
    }
} else { Get-AssetInventory -Network $Network }
