function Get-EnterpriseVisbility {
  param(
      [Parameter(Mandatory)][string]$Network,
      [Parameter(Mandatory)][string]$EventCollector
  )
  $ActiveIps = Get-IpAddressRange -Network $Network | Test-Connections
  $AdObjects = (Get-AdComputer -Filter "*").Name
  $EventForwarders = Get-EventForwarders -ComputerName $EventCollector
  $WinRmclients = Get-WinRmClients
  $Visbility = New-Object -TypeName psobject
  $Visbility | Add-Member -MemberType NoteProperty -Name ActiveIps -Value $ActiveIps.Count
  $Visbility | Add-Member -MemberType NoteProperty -Name AdObjects -Value $AdObjects.Count
  $Visbility | Add-Member -MemberType NoteProperty -Name EventForwarders -Value $EventForwarders.Count
  $Visbility | Add-Member -MemberType NoteProperty -Name WinRmClients -Value $WinRmclients.Count
  return $Visbility
}