## XPath Filters

### Example XPath Filters
```pwsh
# Event ID: 4624
# Exclude: S-1-5-18 (SYSTEM)
# Logon Type: 2 (Logon via keyboard) or 3 (Network logon)

$FilterXPath = "
  System[
    (EventId=4624)
  ] and
  EventData[
    Data[@Name='TargetUserSid'] != 'S-1-5-18' and
    Data[@Name='LogonType'] = '2' or Data[@Name='LogonType'] = '3'
  ]
"
```

### How to Use XPath Filters with Powershell and the Get-WinEvent Cmdlet
```pwsh
Get-WinEvent -LogName Security -FilterXPath $FilterXPath
```
