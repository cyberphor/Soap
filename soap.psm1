function Get-Computers {
  Get-AdComputer -Filter * | Select-Object -ExpandProperty Name
}

function Get-LocalGroupAdministrators {
  $Computers = Get-Computers
  Invoke-Command -ComputerName $Computers -ScriptBlock {
    Get-LocalGroupMember -Group "administrators"
  } | Select-Object @{Name="Hostname";Expression={$_.PSComputerName}}, @{Name="Member";Expression={$_.Name}}
}
