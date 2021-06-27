While ($true) {
    $Speed = Test-Connection -Count 1 -ComputerName 8.8.8.8 | 
    Select-Object -ExpandProperty ResponseTime
    
    Clear-Host
    Write-Host "`n[+] Bandwidth (ms): $($Speed)"
    Start-Sleep -Seconds 1
}
