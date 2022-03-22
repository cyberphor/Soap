$Printer = Read-Host 'What is the IP address of the printer?'

while (-not $COB) {
    if (Test-Connection -ComputerName $Printer -Count 2 -Quiet) {
        Write-Host "[+] $Printer is online."
    } else {
        Write-Host "[x] $Printer is offline."
    }

    Start-Sleep -Seconds 60
    $COB = (Get-Date).ToString('hh:mm') -ge (Get-Date 05:00).ToString('hh:mm')
}

Write-Host "[!] It's close-of-business, stopping script."
