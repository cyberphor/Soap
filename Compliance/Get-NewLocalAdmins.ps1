function Get-NewLocalAdmins {
  $BaselineAdmins = "Administrator","elliot.alderson"
  $Administrator = Get-LocalGroupMember -Group "Administrators" |
    Where-Object { $_.ObjectClass -notmatch "Group" } |
    Select-Object -ExpandProperty Name |
    ForEach-Object { $_.Split("\")[1] } |
    Where-Object { $BaselineAdmins -notcontains $_ }
    
  if ($Administrator) {
    if ($Administrator.Count -gt 1) { $Administrator = $Administrator[0] }
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
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Administrator -Value $Administrator
    $ComputerInformation
  }
}

Get-NetLocalAdmins
