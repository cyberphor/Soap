function Get-ProcessByNetworkConnection {
  $NetworkConnections = Get-NetTCPConnection -State Established
  Get-Process -IncludeUserName |
  ForEach-Object {
      $OwningProcess = $_.Id
      $OwningProcessName = $_.ProcessName
      $OwningProcessPath = $_.Path
      $OwningProcessUsername = $_.UserName
      $NetworkConnections |
      Where-Object {
          $_.LocalAddress -ne "::1" -and
          $_.LocalAddress -ne "127.0.0.1" -and
          $_.OwningProcess -eq $OwningProcess
      } | Select-Object `
          @{ Name = "Username"; Expression = {$OwningProcessUsername} },`
          @{ Name = "ProcessId"; Expression = {$_.OwningProcess} },`
          @{ Name = "ProcessName"; Expression = {$OwningProcessName} },`
          LocalAddress,LocalPort,RemoteAddress,RemotePort,`
          @{ Name = "Path"; Expression = {$OwningProcessPath} }`
  } | 
  Sort-Object -Property ProcessId | 
  Format-Table -AutoSize
}