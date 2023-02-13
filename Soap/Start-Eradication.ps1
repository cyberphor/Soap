function Start-Eradication {
  Param(
      [string[]]$Service,
      [string[]]$Process,
      [string[]]$File
  )
  <#
      .SYNOPSIS
      TBD.

      .DESCRIPTION
      TBD.

      .INPUTS
      None.

      .OUTPUTS
      None.

      .EXAMPLE
      Start-Eradication -Service "rshell" -Process "mimikatz" -File "c:\trojan.exe","c:\ransomware.exe"

      .LINK
      https://github.com/cyberphor/soap
      https://gist.github.com/ecapuano/d18b3b914021171da42e13e5a56cce42
  #>
  if ($Service) {
      $Service |
      ForEach-Object {
          if (Get-Service $_ -ErrorAction SilentlyContinue) {
              Write-Output "Removing service: $_"
              Stop-Service $_ -Force
              Start-Process -FilePath sc.exe -ArgumentList "delete",$_
          }
      }
  }
  if ($Process) {
      $Process |
      ForEach-Object {
          if (Get-Process $_ -ErrorAction SilentlyContinue) {
              Write-Output "Killing process: $_"
              Stop-Process -Name $_ -Force
          }
      }
  }
  if ($File) {
      $File |
      ForEach-Object {
          if (Test-Path $_ -PathType Leaf -ErrorAction SilentlyContinue) {
              Write-Output "Deleting file: $_"
              Remove-Item $_
          }
      }
  }
}