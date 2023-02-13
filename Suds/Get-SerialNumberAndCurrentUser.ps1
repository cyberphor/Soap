function Get-SerialNumberAndCurrentUser {
  Param([string[]]$ComputerName)
  Invoke-Command -ComputerName $ComputerName -ScriptBlock {
      Get-WmiObject -Class Win32_Bios | Select-Object -ExpandProperty SerialNumber
      Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
  }
}