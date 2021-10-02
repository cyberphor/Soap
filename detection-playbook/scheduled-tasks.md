## Scheduled Tasks

**Step 1.** Setup.
```pwsh
$Computers = (Get-AdComputer -Filter "ObjectClass -like 'Computer'").Name | Sort-Object
$DaysAgo = 1
$FilterHashTable = @{
  LogName = "Security"
  Id = 4698
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
        Username = $XmlData.Event.EventData.Data[1].'#text'
        TaskName = $XmlData.Event.EventData.Data[4].'#text'
    }
    return $Event
  }
} -ErrorAction Ignore
```
