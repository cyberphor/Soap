### Domain Admin Logon Failures

---

**Play ID.** 02-CAT8-PasswordGuessing-WindowsEventLogs.

**Purpose.** The purpose of this play is to detect logon attempts to Domain Admin accounts.

**Task.** Search for evidence of suspicious logon attempts to Domain Admin accounts.

**Conditions.** An audit policy has been configured and WinRM is enabled across the network. You are given a list of computer names, domain administrator permissions, access to PowerShell, and knowledge of the accepted configuration baseline (ex: STIGs, SHB, etc.).

**Standards.** You were able to query the network for failed logon attempts to Domain Admin accounts and determine if suspicious activity has occurred. 

**How Often to Run This Play.** Daily. 

**Tactic ID.** TA0006 - Credential Access. (https://attack.mitre.org/tactics/TA0006/).

**Technique ID.** T1110 - Brute Force. (https://attack.mitre.org/techniques/).

**Sub-Technique ID.** T1110.001 - Password Guessing. (https://attack.mitre.org/techniques/T1110/001/).

**Incident Category.** CAT 8 - Investigation.

---

**Step 1.** Declare your variables.
```pwsh
$DomainAdmins = (Get-AdGroupMember -Identity "Domain Admins").SamAccountName
$Computers = (Get-AdComputer -Filter "ObjectClass -like 'Computer'").Name | Sort-Object
$DaysAgo = 1
$FilterHashTable = @{
  LogName = "Security"
  Id = 4625
  StartTime = (Get-Date).AddDays(-$DaysAgo)
  EndTime = Get-Date
}
```

**Step 2.** Query the network.
```pwsh
Invoke-Command -ComputerName $Computers -ArgumentList $FilterHashTable,$DomainAdmins -ScriptBlock {
  $FilterHashTable = $args[0]
  $DomainAdmins = $args[1]
  
  Get-WinEvent -FilterHashTable $FilterHashTable |
  ForEach-Object {
    $XmlData = [xml]$_.ToXml()
    $Username = $XmlData.Event.EventData.Data[5].'#text'
    if ($DomainAdmins -contains $Username) {
      $TimeCreated = $_.TimeCreated
      $Hostname = $XmlData.Event.System.Computer
      $LogonType = $XmlData.Event.EventData.Data[10].'#text'
      $Event = [PSCustomObject] @{
        TimeCreated = $TimeCreated
        Hostname = $Hostname
        Username = $Username
        LogonType = $LogonType
      }
      return $Event
    }
  }

} -ErrorAction Ignore

```
