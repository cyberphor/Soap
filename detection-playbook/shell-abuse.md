## Shell Abuse

**Step 1.** Setup.
```pwsh
$Computers = (Get-AdComputer -Filter "ObjectClass -like 'Computer'").Name | Sort-Object
$DaysAgo = 1
$FilterHashTable = @{
    LogName = "Security"
    Id = 4688
    StartTime = (Get-Date).AddDays(-$DaysAgo)
    EndTime = Get-Date
}
```

**Step 2.** Query.
```pwsh
Invoke-Command -ComputerName $Computers -ArgumentList $FilterHashTable -ScriptBlock {
    Get-WinEvent -FilterHashTable $args[0] |
    ForEach-Object {
        $XmlData = [xml]$_.ToXml()
        $Event = [PSCustomObject] @{
            TimeCreated = $_.TimeCreated
            Hostname = $XmlData.Event.System.Computer
            Username = $XmlData.Event.EventData.Data[10].'#text'
            NewProcessName = $XmlData.Event.EventData.Data[5].'#text'
        }
    
    if ($Event.NewProcessName -like '*powershell*') { return $Event }
    }
} -ErrorAction Ignore

```
