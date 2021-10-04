### Removable Media

---

**Play ID.** 03-CAT5-ExfiltrationOverUsb-WindowsEventLogs.

**Purpose.** Process creation events must be monitored in order to detect the execution of malicious commands, scripts, and/or binaries. 

**Task.** Search for evidence of suspicious process execution.

**Conditions.** An audit policy has been configured and WinRM is enabled across the network. You are given a list of computer names, domain administrator permissions, access to PowerShell, knowledge of the accepted configuration baseline (ex: STIGs, SHB, etc.), and knowledge of benign process names.  

**Standards.** You were able to query the network for process creation events and determine if suspicious activity has occurred.

**How Often to Run This Play.** Daily. 

**Tactic ID.** TA002 - Exfiltration (https://attack.mitre.org/tactics/TA0010/).

**Technique ID.** T1052 - Exfiltration Over Physical Medium (https://attack.mitre.org/techniques/T1052/).

**Sub-Technique ID.** T1052.001 - Exfiltration over USB (https://attack.mitre.org/techniques/T1052/001/).

**Incident Category.** CAT 5 - Non-Compliance Activity.

---

**Step 1.** Declare your variables.
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

**Step 2.** Query the network.
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
