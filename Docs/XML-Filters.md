### How to Use XML Filters with PowerShell and the Get-WinEvent Cmdlet
**Step 1.** Create and open a file to house your XMl filter. 
```pwsh
New-Item -ItemType File -Name "Last24Hrs-Security-Logons.xml" | Out-Null
powershell_ise.exe "Last24Hrs-Security-Logons.xml"
```

**Step 2.** Add your desired XMl filter to the open file. For example, copy/paste the code below to query the "Security" log for events in the last 24 hours that meet specific SID and logon type criteria. 
```xml
<QueryList>
  <Query Id="0">
    <Select Path="Security">
        *[System[
            (EventID=4624) and
            TimeCreated[timediff(@SystemTime) &lt;= 86400000] <!-- LAST 24 HRS -->
        ]] and 
        *[EventData[
            Data[@Name='TargetUserSid'] != 'S-1-5-7' and <!-- ANONYMOUS -->
            Data[@Name='TargetUserSid'] != 'S-1-5-18' and <!-- SYSTEM -->
            Data[@Name='TargetUserSid'] != 'S-1-5-90-0-1' and <!-- DESKTOP WINDOWS MANAGER -->
            Data[@Name='TargetUserSid'] != 'S-1-5-96-0-0' and <!-- USER MODE DRIVER FRAMEWORK -->
            Data[@Name='TargetUserSid'] != 'S-1-5-96-0-1' and <!-- USER MODE DRIVER FRAMEWORK -->
            (Data[@Name='LogonType'] = '2' or <!-- LOCAL -->
            Data[@Name='LogonType'] = '3' or <!-- NETWORK -->
            Data[@Name='LogonType'] = '7' or <!-- LOCKSCREEN -->
            Data[@Name='LogonType'] = '10' or <!-- RDP -->
            Data[@Name='LogonType'] = '11') <!-- CACHED -->
        ]]
    </Select>
  </Query>
</QueryList>
```

**Step 3.** Copy/paste the command sentence below into a PowerShell session. 
```pwsh
Get-WinEvent -FilterXml ([xml](Get-Content Last24Hrs-Security-Logons.xml))
```
