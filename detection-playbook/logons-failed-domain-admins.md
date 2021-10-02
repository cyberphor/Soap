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
