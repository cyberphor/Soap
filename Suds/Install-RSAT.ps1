function Install-RSAT {
  Get-WindowsCapability -Name RSAT* -Online | 
  Add-WindowsCapability -Online
}