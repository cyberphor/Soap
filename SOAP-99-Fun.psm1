function Start-ImperialMarch {
    [console]::beep(440,500)      
    [console]::beep(440,500)
    [console]::beep(440,500)       
    [console]::beep(349,350)       
    [console]::beep(523,150)       
    [console]::beep(440,500)       
    [console]::beep(349,350)       
    [console]::beep(523,150)       
    [console]::beep(440,1000)
    [console]::beep(659,500)       
    [console]::beep(659,500)       
    [console]::beep(659,500)       
    [console]::beep(698,350)       
    [console]::beep(523,150)       
    [console]::beep(415,500)       
    [console]::beep(349,350)       
    [console]::beep(523,150)       
    [console]::beep(440,1000)
}

function Start-RollingReboot {
    param(
        [int]$Interval = 4,
        [int]$Duration = 60
    )
    $TaskName = "Rolling Reboot"
    $Action= New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /t 0" 
    $Trigger= New-ScheduledTaskTrigger -At $(Get-Date) -Once -RepetitionInterval $(New-TimeSpan -Minutes $Interval) -RepetitionDuration $(New-TimeSpan -Minutes $Duration)
    $User= "NT AUTHORITY\SYSTEM" 
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -User $User -RunLevel Highest –Force
    Start-ScheduledTask -TaskName $TaskName
}