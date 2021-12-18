function Remove-App {
    param([Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$UninstallString)
    if ($UninstallString -contains "msiexec") {
        $App = ($UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X","").Trim()
        Start-Process "msiexec.exe" -ArgumentList "/X $App /qb" -NoNewWindow
    } else {
        Start-Process $UninstallString -NoNewWindow
    }
}