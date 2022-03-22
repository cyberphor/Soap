## PowerShell Scripts
FYI, I am in the process of merging these scripts into the main "soap" PowerShell module. Use these scripts at your own risk.

## Examples

Get-AssetInventory
```powershell
.\Get-AssetInventory.ps1 -Network 192.168.2.0/24

IpAddress    MacAddress        HostName SerialNumber   UserName       FirstSeen        LastSeen
---------    ----------        -------- ------------   --------       ---------        --------
192.168.2.1  -                 -        -              -              2020-12-31 17:44 2021-01-01 09:30
192.168.2.3  -                 -        -              -              2021-01-01 09:14 2021-01-01 09:14                                       
192.168.2.57 -                 -        -              -              2020-12-31 17:44 2021-01-01 09:30
192.168.2.60 -                 -        -              -              2021-01-01 09:33 2021-01-01 09:30                             
192.168.2.75 aa:aa:bb:bb:cc:cc DC1      T6UsW9N8       WINDOWS\Victor 2020-12-31 17:44 2021-01-01 09:30
```

Get-DnsLogs
```powershell
.\Get-DnsLogs.ps1

[x] DNS logging is not enabled.

wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true

.\Get-DnsLogs.ps1

TimeCreated           ProcessId DnsQuery                                 Sid                                           
-----------           --------- --------                                 ---  
2/26/2021 9:45:59 AM  1464      www.google.com                           S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:59 AM  1464      tpc.googlesyndication.com                S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:59 AM  1464      a3422.casalemedia.com                    S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:58 AM  1464      cdn.ampproject.org                       S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:58 AM  1464      px.moatads.com                           S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:58 AM  1464      aax-us-east.amazon-adsystem.com          S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:58 AM  1464      csi.gstatic.com                          S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:58 AM  12564     gov.teams.microsoft.us                   S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:42 AM  1464      clients4.google.com                      S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:31 AM  1464      alive.github.com                         S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:31 AM  1464      collector.githubapp.com                  S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:31 AM  1464      user-images.githubusercontent.com        S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:31 AM  1464      github-cloud.s3.amazonaws.com            S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:31 AM  1464      avatars.githubusercontent.com            S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:30 AM  1464      api.github.com                           S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:30 AM  1464      github.githubassets.com                  S-1-5-21-3603040224-2895699255-2127603579-1001
2/26/2021 9:45:30 AM  1464      github.com                               S-1-5-21-3603040224-2895699255-2127603579-1001
```

Get-IpAddressRange
```powershell
.\Get-IpAddressRange.ps1 -Network 192.168.1.0/30, 192.168.2.0/30, 192.168.3.1/32

192.168.1.1
192.168.2.2
192.168.2.1
192.168.2.2
192.168.3.1
```

Format-Color
```powershell
Get-ChildItem | Format-Color -Value passwords.txt -BackgroundColor Red -ForegroundColor White
```
