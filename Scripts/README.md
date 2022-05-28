## PowerShell Scripts
FYI, I am in the process of merging these scripts into the Soap PowerShell module. Use these scripts at your own risk.

### Examples

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
