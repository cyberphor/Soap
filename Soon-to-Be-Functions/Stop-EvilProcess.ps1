function Stop-EvilProcess {
  $EvilProcessName = "PowerPnt"
  $EvilProcess = Get-Process | Where-Object { $_.Name -like $EvilProcessName }
  $EvilProcess.Kill()
}

Stop-EvilProcess
