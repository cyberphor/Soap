function Enable-WinRm {
  param([Parameter(Mandatory)]$ComputerName)
  $Expression = "wmic /node:$ComputerName process call create 'winrm quickconfig'"
  Invoke-Expression $Expression
  #Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c 'winrm qc'"
}