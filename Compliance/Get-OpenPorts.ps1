function Get-OpenPorts {
  $Administrator = Get-NetTCPConnection -State Listen | 
    Select-Object LocalPort,@{ "Name" = "ProcessName"; "Expression" = { (Get-Process -Id $_.OwningProcess).Name }} |
    Where-Object {
      $_.ProcessName -notlike "java*" -and
      $_.ProcessName -notlike "lsass" -and
      $_.ProcessName -notlike "services" -and
      $_.ProcessName -notlike "spoolsv" -and
      $_.ProcessName -notlike "svchost" -and
      $_.ProcessName -notlike "System" -and
      $_.ProcessName -notlike "wininit"
    } | Sort-Object -Property LocalPort
    
  if ($OpenPorts) {
    $Username = (Get-WmiObject -Class Win32_NetworkLoginProfile | 
      Where-Object { $_.Name -notlike "*admin*" -and $_.Name -notlike "*service*" } |
      Sort-Object -Property LastLogon -Descending |
      Select-Object -First 1 -ExpandProperty Name).Split("\")[1]
    $Model = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
    $SerialNumber = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
    
    $ComputerInformation = New-Object psobject
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Hostname -Value $Hostname
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Username -Value $Username
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Model -Value $Model
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name SerialNumber -Value $SerialNumber
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name OpenPorts -Value $OpenPorts
    $ComputerInformation
  }
}

Get-OpenPorts
