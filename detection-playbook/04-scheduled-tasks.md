## Scheduled Tasks

**Tactic.** ID - TA0003: Persistence (https://attack.mitre.org/tactics/TA0003/).

**Technique.** ID - T1053: Scheduled Task/Job (https://attack.mitre.org/techniques/T1053/).

**Sub-Technique.** ID - T1053.005: Scheduled Task (https://attack.mitre.org/techniques/T1053/005/).

**Frequency.** Daily. 

**Purpose.** The creation of scheduled tasks must be monitored in order to detect threat actors who have gained accessed and are now seeking to maintain their access.

**Task.** Search for evidence of suspicious task scheduling.

**Conditions.** An audit policy has been configured and WinRM is enabled across the network. You are given a list of computer names, domain administrator permissions, access to PowerShell, and knowledge of the accepted configuration baseline (ex: STIGs, SHB, etc.).

**Standards.** You were able to query the network for task scheduling events and determine if suspicious activity has occurred.  

**Incident Category.** CAT 8 - Investigation.

**Step 1.** Declare your variables.
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

**Step 2.** Query the network.
```pwsh
Invoke-Command -ComputerName $Computers -ArgumentList $FilterHashTable -ScriptBlock {
    Get-WinEvent -FilterHashTable $args[0] |
    ForEach-Object {
        $XmlData = [xml]$_.ToXml()
        $Task = [xml]$XmlData.Event.EventData.Data[5].'#text'
        if ($Task.Task.Triggers.CalendarTrigger) {
            $StartBoundary = $Task.Task.Triggers.CalendarTrigger.StartBoundary
            $DaysInterval = $Task.Task.Triggers.CalendarTrigger.ScheduleByDay.DaysInterval  
        } elseif ($Task.Task.Triggers.TimeTrigger) {
            $StartBoundary = $Task.Task.Triggers.TimeTrigger.StartBoundary
            $DaysInterval = $Task.Task.Triggers.TimeTrigger.Repetition.Interval
        }
        $Time = Get-Date $([DateTime]$StartBoundary) -Format 'HH:mm:ss'
        $Event = [PSCustomObject] @{
            TimeCreated = $_.TimeCreated
            Author = $Task.Task.RegistrationInfo.Author
            TaskName = $Task.Task.RegistrationInfo.Uri.Split('\\')[1]
            DaysInterval = $DaysInterval
            Time = $Time
            Command = $Task.Task.Actions.Exec.Command     
        }
        return $Event
    }
} | Select-Object * -ExcludeProperty RunspaceId
```
