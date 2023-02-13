function Start-Heartbeat {
  Param([string]$Target)
  while (-not $TimeToStop) {
      if (Test-Connection -ComputerName $Target -Count 2 -Quiet) {
          $Timestamp = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')
          Write-Host "[$Timestamp] [$Target] " -NoNewline
          Write-Host " ONLINE  " -BackgroundColor Green -ForegroundColor Black
      } else {
          $Timestamp = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')
          Write-Host "[$Timestamp] [$Target] " -NoNewline
          Write-Host " OFFLINE " -BackgroundColor Red -ForegroundColor Black
      }
      Start-Sleep -Seconds 60
      $TimeToStop = (Get-Date).ToString('hh:mm') -le (Get-Date '17:00').ToString('hh:mm')
  }

  $Timestamp = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')
  Write-Host "[$Timestamp] Time has expired."
}