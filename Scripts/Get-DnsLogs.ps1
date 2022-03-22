<#
    HOW TO ENABLE DNS LOGGING
    wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true

    HOW TO DISABLE DNS LOGGING
    wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:false

    REFERENCES
    https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732848(v=ws.10)?redirectedfrom=MSDN
    https://www.powershellmagazine.com/2013/07/15/pstip-how-to-enable-event-logs-using-windows-powershell/
    https://www.reddit.com/r/sysadmin/comments/7wgxsg/dns_log_on_windows_10_pro/du0bjds/
#>

$LoggingIsEnabled = (Get-WinEvent -ListLog Microsoft-Windows-DNS-Client/Operational).IsEnabled

if ($LoggingIsEnabled) {
    $SearchCriteria = @{
        LogName = 'Microsoft-Windows-DNS-Client/Operational';
        StartTime = (Get-Date).AddDays(-7);
        EndTime = (Get-Date);
        Id = 3006;
    }

    Get-WinEvent -FilterHashtable $SearchCriteria |
    foreach {
        $XmlData = [xml]$_.ToXml()
        $ProcessId = $XmlData.Event.System.Execution.ProcessID
        $DnsQuery = $XmlData.Event.EventData.Data[0].'#text'
        $Sid = $XmlData.Event.System.Security.UserID
        
        $Event = New-Object -TypeName psobject
        Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $_.TimeCreated
        Add-Member -InputObject $Event -MemberType NoteProperty -Name ProcessId -Value $ProcessId
        Add-Member -InputObject $Event -MemberType NoteProperty -Name DnsQuery -Value $DnsQuery
        Add-Member -InputObject $Event -MemberType NoteProperty -Name Sid -Value $Sid
        $Event

    }
} else {
    Write-Host '[x] DNS logging is not enabled.'
}
