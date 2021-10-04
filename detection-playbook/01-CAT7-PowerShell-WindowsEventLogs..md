### PowerShell Abuse

---

**Play ID.** 01-CAT7-PowerShell-WindowsEventLogs.

**Purpose.** The purpose of this play is to detect suspicious PowerShell use.

**Task.** Search for evidence of suspicious PowerShell use.

**Conditions.** An audit policy has been configured and WinRM is enabled across the network. You are given a list of computer names, domain administrator permissions, access to PowerShell, and knowledge of the accepted configuration baseline (ex: STIGs, SHB, etc.).

**Standards.** You were able to query the network for PowerShell-specific process creation events and determine if suspicious activity has occurred. 

**Incident Category.** CAT 8 - Investigation.

**How Often to Run This Play.** Daily. 

**Tactic ID.** TA0002 - Execution (https://attack.mitre.org/tactics/TA0002/).

**Technique ID.** T1059 - Command and Scripting Interpreter. (https://attack.mitre.org/techniques/T1059/).

**Sub-Technique ID.** T1059.001 - PowerShell. (https://attack.mitre.org/techniques/T1059/001/).

---

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
```

**Step 2.** Query the network.
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
