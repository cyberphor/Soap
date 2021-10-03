## Process Execution

**Frequency.** Daily. 

**Purpose.** Process creation events must be monitored in order to detect the execution of malicious commands, scripts, and/or binaries. 

**Task.** Search for evidence of suspicious process execution.

**Conditions.** An audit policy has been configured and WinRM is enabled across the network. You are given a list of computer names, domain administrator permissions, access to PowerShell, knowledge of the accepted configuration baseline (ex: STIGs, SHB, etc.), and knowledge of benign process names.  

**Standards.** You were able to query the network for process creation events and determine if suspicious activity has occurred.  

**Incident Category.** CAT 7 - Malicious Logic.

**Step 1.** Declare your variables.
```pwsh
$Computers = (Get-AdComputer -Filter "ObjectClass -like 'Computer'").Name | Sort-Object
$DaysAgo = 1
$FilterHashTable = @{
    LogName = "Security"
    Id = 4688
    StartTime = (Get-Date).AddDays(-$DaysAgo)
    EndTime = Get-Date
}

$BenignProcessNames = @(
    'C:\\Windows\\System32\\*',
    'C:\\Program Files \(x86\)\\Google\\Chrome\\Application\\chrome.exe'
) -join '|'
```

**Step 2.** Query the network.
```pwsh
Invoke-Command -ComputerName $Computers -ArgumentList $FilterHashTable,$BenignProcessNames -ScriptBlock {
    $FilterHashTable = $args[0]
    $BenignProcessNames = $args[1]
    Get-WinEvent -FilterHashTable $FilterHashTable |
    ForEach-Object {
        $XmlData = [xml]$_.ToXml()
        $Event = [PSCustomObject] @{
            TimeCreated = $_.TimeCreated
            Username = $XmlData.Event.EventData.Data[1].'#text'
            ParentProcessName = $XmlData.Event.EventData.Data[13].'#text'
            NewProcessName = $XmlData.Event.EventData.Data[5].'#text'
        }
        if ($Event.ParentProcessName -notmatch $BenignProcessNames -and $Event.NewProcessName -notmatch $BenignProcessNames) { 
            return $Event
        }
    }
} -ErrorAction Ignore
```
