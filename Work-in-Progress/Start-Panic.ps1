function Start-Panic {
  $DomainController = (Get-AdDomainController).Name
  $ComputerName = (Get-AdComputer -Filter *).Name | Where-Object { $_ -ne $env:COMPUTERNAME -and $_ -ne $DomainController }
  Invoke-Command -ComputerName $ComputerName -ScriptBlock {
      shutdown.exe /s /t 0
  }
}