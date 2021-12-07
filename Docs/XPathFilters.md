## PowerShell XPath Filters
### How to Use Filters with Get-WinEvent
```pwsh
Get-WinEvent -LogName Security -FilterXPath $FilterXPath
```

### FilterXPath Examples
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
