## Process Execution

**Step 1.** Setup.
```pwsh
#$Computers = (Get-AdComputer -Filter "ObjectClass -like 'Computer'").Name | Sort-Object
$Computers = $env:COMPUTERNAME
$Benign = 'C\:\\Windows\\System32\\*'
$DaysAgo = 90
$FilterHashTable = @{
    LogName = "Security"
    Id = 4688
    StartTime = (Get-Date).AddDays(-$DaysAgo)
    EndTime = Get-Date
}
```

**Step 2.** Query.
```pwsh
#Invoke-Command -ComputerName $Computers -ArgumentList $FilterHashTable -ScriptBlock {
    Get-WinEvent -FilterHashTable $FilterHashTable |
    ForEach-Object {
        $XmlData = [xml]$_.ToXml()
        $Event = [PSCustomObject] @{
            TimeCreated = $_.TimeCreated
            Username = $XmlData.Event.EventData.Data[1].'#text'
            ParentProcessName = $XmlData.Event.EventData.Data[13].'#text'
            NewProcessName = $XmlData.Event.EventData.Data[5].'#text'
        }
        
        if ($Event.ParentProcessName) {
            if ($Event.ParentProcessName -notmatch $Benign) { 
                if ($Event.NewProcessName -notmatch 'C\:\\Windows\\System32\\*') { return $Event } 
            }
        }
    }
#} -ErrorAction Ignore
```
