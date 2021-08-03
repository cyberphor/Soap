function Get-Computers {
  Get-AdComputer -Filter * | Select-Object -ExpandProperty Name
}

function Get-LocalGroupAdministrators {
  $Computers = Get-Computers
  Invoke-Command -ComputerName $Computers -ScriptBlock {
    net localgroup "administrators"
  }
}
