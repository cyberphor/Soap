$Computers = ""

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Start-RollingReboot.ps1
