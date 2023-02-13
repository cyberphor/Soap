function Get-WinRmClient {
  $ComputerNames = $(Get-AdComputer -Filter *).Name
  Invoke-Command -ComputerName $ComputerNames -ScriptBlock { $env:HOSTNAME } -ErrorAction Ignore
}