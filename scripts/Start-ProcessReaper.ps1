function Start-ProcessReaper {
    Param([string]$Process)
    
    While ($True) {
        $Process | 
        ForEach-Object {
            Stop-Process -Name $_ -ErrorAction Ignore -Force
        }
        
        Start-Sleep -Seconds 60
    }
}

Start-ProcessReaper -Process $Process
