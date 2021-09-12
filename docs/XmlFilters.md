## PowerShell XML Filters
Logons.xml
```xml
<QueryList>
  <Query Id="0">
    <Select Path="Security">
        *[System[(EventID=4624)]]
        and 
        *[EventData[
            Data[@Name='LogonType'] = '2' or
            Data[@Name='LogonType'] = '3' 
        ]]
    </Select>
  </Query>
</QueryList>
```

```pwsh
Get-WinEvent -FilterXml ([xml](gc .\Logons.xml))
```
