## Removable Media

**Step 1.** Setup.
```pwsh
$Computers = (Get-AdComputer -Filter "ObjectClass -like 'Computer'").Name | Sort-Object
$DaysAgo = 1
$FilterHashTable = @{
  LogName = "Security"
  Id = 6416
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
        DeviceDescription = $XmlData.Event.EventData.Data[5].'#text'
        ClassName = $XmlData.Event.EventData.Data[7].'#text'
    }
    # if ($Event.ClassName -notmatch '(*print*|*smartcard*)') { return $Event }
    return $Event
  }
} -ErrorAction Ignore
```
